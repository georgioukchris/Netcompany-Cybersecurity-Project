import hashlib
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
import random
import time

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ai_shield:dev_password@db:5432/ai_shield",
)


def get_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=5)


SCHEMA_PATH_CANDIDATES = [
    Path(__file__).resolve().parent / "init.sql",
    Path(__file__).resolve().parent.parent / "database" / "init.sql",
]


def init_db(attempts: int = 1, delay: float = 2.0) -> None:
    """Create or upgrade the schema safely (idempotent). Retries while the database is starting."""
    for path in SCHEMA_PATH_CANDIDATES:
        if path.is_file():
            sql = path.read_text(encoding="utf-8")
            break
    else:
        raise FileNotFoundError("init.sql not found")
    for attempt in range(1, attempts + 1):
        try:
            with get_connection() as conn:
                conn.execute(sql)
            return
        except psycopg.OperationalError:
            if attempt == attempts:
                raise
            time.sleep(delay)


INCIDENT_COLUMNS = """id, user_id, tool_name, action, risk, findings, created_at,
    status, assigned_to, resolution_category, resolution_note, status_updated_at, user_confirmed_at, content_type"""


def save_incident(user_id: str, tool_name: str, action: str, risk: str, findings: list[dict],
                  content_type: str = "text") -> dict:
    # ALLOW (clean, or only low-risk basic data such as names) is logged for statistics
    # but needs no investigation.
    status = "AUTO_CLOSED" if action == "ALLOW" else "OPEN"
    query = f"""
        INSERT INTO incidents (user_id, tool_name, action, risk, findings, status, content_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING {INCIDENT_COLUMNS};
    """
    with get_connection() as conn:
        return conn.execute(query, (user_id, tool_name, action, risk, Jsonb(findings), status,
                                    "pdf" if content_type == "pdf" else "text")).fetchone()


def confirm_warning_incident(incident_id: int, user_id: str, tool_name: str) -> dict | None:
    """Mark a recent WARN incident as confirmed by the user (same source/provider, last 15 min)."""
    with get_connection() as conn:
        return conn.execute(
            f"""UPDATE incidents SET user_confirmed_at = NOW()
                WHERE id = %s AND user_id = %s AND tool_name = %s AND action = 'WARN'
                  AND user_confirmed_at IS NULL AND created_at > NOW() - INTERVAL '15 minutes'
                RETURNING {INCIDENT_COLUMNS}""",
            (incident_id, user_id, tool_name),
        ).fetchone()


def get_recent_incidents(limit: int = 100, include_auto_closed: bool = True) -> list[dict]:
    where = "" if include_auto_closed else "WHERE status <> 'AUTO_CLOSED'"
    query = f"""
        SELECT {INCIDENT_COLUMNS}
        FROM incidents {where} ORDER BY created_at DESC LIMIT %s;
    """
    with get_connection() as conn:
        return conn.execute(query, (limit,)).fetchall()


# ---------------------- Incident Investigation Center ----------------------

class TransitionError(Exception):
    pass


def get_incident(incident_id: int) -> dict | None:
    with get_connection() as conn:
        return conn.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,)).fetchone()


def get_incident_activity(incident_id: int) -> list[dict]:
    with get_connection() as conn:
        return conn.execute(
            """SELECT id, action, analyst, from_status, to_status, note, created_at
               FROM incident_activity WHERE incident_id = %s ORDER BY created_at, id""",
            (incident_id,),
        ).fetchall()


def get_incident_context(incident: dict) -> tuple[dict, str | None]:
    """Related-incident counts (same provider / same source, 24h) and the provider's Shadow AI status."""
    with get_connection() as conn:
        related = conn.execute(
            """SELECT
                 COUNT(*) FILTER (WHERE tool_name = %(tool)s)::int AS same_provider_24h,
                 COUNT(*) FILTER (WHERE user_id = %(user)s)::int AS same_source_24h,
                 COUNT(*) FILTER (WHERE user_id = %(user)s AND status IN ('OPEN','ACKNOWLEDGED','INVESTIGATING'))::int AS same_source_open
               FROM incidents
               WHERE id <> %(id)s AND status <> 'AUTO_CLOSED'
                 AND created_at BETWEEN %(at)s - INTERVAL '24 hours' AND %(at)s + INTERVAL '24 hours'""",
            {"tool": incident["tool_name"], "user": incident["user_id"], "id": incident["id"],
             "at": incident["created_at"]},
        ).fetchone()
        tool = conn.execute(
            "SELECT status FROM shadow_ai_tools WHERE provider_key = %s ORDER BY id LIMIT 1",
            (incident["tool_name"],),
        ).fetchone()
    return related, (tool["status"] if tool else None)


def transition_incident(incident_id: int, action: str, to_status: str, allowed_from: set[str],
                        analyst: str, note: str | None, resolution_category: str | None) -> dict | None:
    """Atomically move an incident to a new workflow state and log who/why."""
    with get_connection() as conn:
        with conn.transaction():
            row = conn.execute("SELECT id, status FROM incidents WHERE id = %s FOR UPDATE",
                               (incident_id,)).fetchone()
            if row is None:
                return None
            if row["status"] not in allowed_from:
                raise TransitionError(f"Δεν επιτρέπεται {action} από κατάσταση {row['status']}.")
            updated = conn.execute(
                f"""UPDATE incidents SET status = %s, status_updated_at = NOW(),
                        assigned_to = COALESCE(assigned_to, %s),
                        resolution_category = CASE WHEN %s = 'RESOLVED' THEN %s ELSE resolution_category END,
                        resolution_note = CASE WHEN %s = 'RESOLVED' THEN %s ELSE resolution_note END
                    WHERE id = %s RETURNING {INCIDENT_COLUMNS}""",
                (to_status, analyst, to_status, resolution_category, to_status, note, incident_id),
            ).fetchone()
            conn.execute(
                """INSERT INTO incident_activity (incident_id, action, analyst, from_status, to_status, note)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (incident_id, action, analyst, row["status"], to_status, note),
            )
            return updated


def get_intelligence_rows(hours: int, bucket_seconds: int) -> tuple[list[dict], list[dict], list[dict], dict]:
    """Counts per finding type (overall, per time bucket, per provider). Types and counts only.
    Buckets are aligned to the Unix epoch (UTC): bucket = start of the interval in epoch seconds."""
    window = "i.created_at >= NOW() - make_interval(hours => %(hours)s)"
    params = {"hours": hours, "bucket": bucket_seconds}
    with get_connection() as conn:
        type_rows = conn.execute(f"""
            SELECT f->>'type' AS type,
                   SUM(COALESCE((f->>'count')::int, 1))::int AS findings,
                   COUNT(DISTINCT i.id)::int AS incidents
            FROM incidents i, jsonb_array_elements(i.findings) f
            WHERE {window} GROUP BY 1""", params).fetchall()
        bucket_rows = conn.execute(f"""
            SELECT (floor(extract(epoch FROM i.created_at) / %(bucket)s) * %(bucket)s)::bigint AS bucket,
                   f->>'type' AS type,
                   SUM(COALESCE((f->>'count')::int, 1))::int AS findings
            FROM incidents i, jsonb_array_elements(i.findings) f
            WHERE {window} GROUP BY 1, 2""", params).fetchall()
        provider_rows = conn.execute(f"""
            SELECT i.tool_name AS provider, f->>'type' AS type,
                   SUM(COALESCE((f->>'count')::int, 1))::int AS findings
            FROM incidents i, jsonb_array_elements(i.findings) f
            WHERE {window} GROUP BY 1, 2""", params).fetchall()
        totals = conn.execute(f"""
            SELECT COUNT(*)::int AS total,
                   COUNT(*) FILTER (WHERE jsonb_array_length(i.findings) > 0)::int AS with_findings
            FROM incidents i WHERE {window}""", params).fetchone()
    return type_rows, bucket_rows, provider_rows, totals


# --------------------------- Shadow AI Radar ---------------------------

def get_shadow_catalog() -> list[dict]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, provider_key, provider_name, domain FROM shadow_ai_tools ORDER BY provider_name, domain"
        ).fetchall()


def record_shadow_event(domain: str, install_id: str, team_label: str) -> dict | None:
    """Store domain-only telemetry. A ten-second per-install dedupe limits noisy events."""
    install_hash = hashlib.sha256(install_id.encode("utf-8")).hexdigest()
    with get_connection() as conn:
        tool = conn.execute(
            "SELECT id, provider_key, provider_name, domain, status FROM shadow_ai_tools WHERE domain = %s",
            (domain,),
        ).fetchone()
        if not tool:
            return None
        duplicate = conn.execute(
            """SELECT id FROM shadow_ai_events
               WHERE install_id_hash = %s AND tool_id = %s
                 AND observed_at > NOW() - INTERVAL '10 seconds'
               ORDER BY observed_at DESC LIMIT 1""",
            (install_hash, tool["id"]),
        ).fetchone()
        if duplicate:
            return {"recorded": False, "duplicate": True, "provider_name": tool["provider_name"]}
        conn.execute(
            """INSERT INTO shadow_ai_events
               (tool_id, event_type, source, install_id_hash, team_label, status_at_time)
               VALUES (%s, 'domain_visit', 'browser-extension', %s, %s, %s)""",
            (tool["id"], install_hash, team_label, tool["status"]),
        )
        return {"recorded": True, "duplicate": False, "provider_name": tool["provider_name"], "status": tool["status"]}


def get_shadow_inventory() -> list[dict]:
    query = """
        SELECT t.id, t.provider_key, t.provider_name, t.domain, t.category, t.status,
               t.updated_at,
               COUNT(e.id)::int AS total_events,
               COUNT(e.id) FILTER (WHERE e.observed_at >= NOW() - INTERVAL '7 days')::int AS events_7d,
               COUNT(e.id) FILTER (WHERE e.observed_at >= NOW() - INTERVAL '7 days'
                                   AND e.status_at_time = 'UNAPPROVED')::int AS unapproved_events_7d,
               COUNT(DISTINCT e.install_id_hash)::int AS installations,
               MAX(e.observed_at) AS last_seen,
               COALESCE(array_agg(DISTINCT e.team_label) FILTER (WHERE e.team_label <> 'Unassigned'), ARRAY[]::varchar[]) AS teams
        FROM shadow_ai_tools t
        LEFT JOIN shadow_ai_events e ON e.tool_id = t.id
        GROUP BY t.id
        ORDER BY events_7d DESC, t.provider_name ASC;
    """
    with get_connection() as conn:
        return conn.execute(query).fetchall()


def get_shadow_events(limit: int = 100) -> list[dict]:
    query = """
        SELECT e.id, t.provider_name, t.domain, e.team_label, e.source,
               e.status_at_time, e.observed_at
        FROM shadow_ai_events e
        JOIN shadow_ai_tools t ON t.id = e.tool_id
        ORDER BY e.observed_at DESC LIMIT %s;
    """
    with get_connection() as conn:
        return conn.execute(query, (limit,)).fetchall()


def update_shadow_tool_status(tool_id: int, status: str) -> dict | None:
    with get_connection() as conn:
        return conn.execute(
            """UPDATE shadow_ai_tools SET status = %s, updated_at = NOW()
               WHERE id = %s RETURNING id, provider_name, domain, status, updated_at""",
            (status, tool_id),
        ).fetchone()


def seed_demo_shadow_events() -> int:
    """Insert clearly synthetic events for a repeatable hackathon demo."""
    rng = random.Random(20261116)
    teams = ["Engineering", "Finance", "HR", "Customer-Operations", "Marketing"]
    installs = [f"synthetic-install-{i:02d}" for i in range(1, 13)]
    with get_connection() as conn:
        tools = conn.execute("SELECT id, status FROM shadow_ai_tools ORDER BY id").fetchall()
        if not tools:
            return 0
        rows = []
        now = datetime.now(timezone.utc)
        for i in range(48):
            tool = rng.choice(tools)
            team = rng.choice(teams)
            install = hashlib.sha256(installs[rng.randrange(len(installs))].encode()).hexdigest()
            observed = now - timedelta(minutes=rng.randint(5, 10080))
            status = tool["status"]
            rows.append((tool["id"], install, team, status, observed))
        conn.executemany(
            """INSERT INTO shadow_ai_events
               (tool_id, event_type, source, install_id_hash, team_label, status_at_time, observed_at)
               VALUES (%s, 'domain_visit', 'synthetic-demo', %s, %s, %s, %s)""",
            rows,
        )
    return len(rows)

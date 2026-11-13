
import os

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ai_shield:dev_password@db:5432/ai_shield",
)


def get_connection():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=5,
    )


def save_incident(
    user_id: str,
    tool_name: str,
    action: str,
    risk: str,
    findings: list[dict],
) -> dict:
    query = """
        INSERT INTO incidents
            (user_id, tool_name, action, risk, findings)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, user_id, tool_name, action, risk,
                  findings, created_at;
    """

    with get_connection() as conn:
        row = conn.execute(
            query,
            (
                user_id,
                tool_name,
                action,
                risk,
                Jsonb(findings),
            ),
        ).fetchone()

    return row


def get_recent_incidents(limit: int = 100) -> list[dict]:
    query = """
        SELECT id, user_id, tool_name, action, risk,
               findings, created_at
        FROM incidents
        ORDER BY created_at DESC
        LIMIT %s;
    """

    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()

    return rows

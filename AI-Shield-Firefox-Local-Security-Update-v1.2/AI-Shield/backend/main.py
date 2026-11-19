import base64
import binascii
import io
import json
import logging
import zipfile
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
import re

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool
from urllib.parse import quote, urlsplit

import auth

from scanner import scan_prompt, TOKEN_PREFIX
from policy import evaluate_policy, rule_for, REDACT_RULES, POLICY_TABLE, CATEGORY_LABELS
from pseudonymizer import Vault, pseudonymize, restore
from pdf_extract import MAX_PDF_BYTES, PdfInspectionError, extract_pdf_text, is_pdf
from database import (
    init_db, save_incident, get_recent_incidents,
    get_shadow_catalog, record_shadow_event, get_shadow_inventory,
    get_shadow_events, update_shadow_tool_status,
    seed_demo_shadow_events,
    get_incident, get_incident_activity, get_incident_context, transition_incident,
    get_intelligence_rows, TransitionError, confirm_warning_incident,
)
from intelligence import (
    categorize_findings, build_intelligence, analyse_incident,
    TRANSITIONS, RESOLUTION_CATEGORIES,
)
from ai.gateway import chat as ai_chat, SUPPORTED_PROVIDERS

logger = logging.getLogger("ai_shield")

@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        init_db()
        auth.bootstrap_users()
    except Exception as exc:
        logger.warning("Database schema init failed: %s", exc)
    yield

app = FastAPI(title="AI Shield API", version="2.0.0",
              description="Secure AI gateway with prompt scanning and policy enforcement",
              lifespan=lifespan)

cors_origins = [o.strip().rstrip("/") for o in os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()]
@app.middleware("http")
async def revalidate_dashboards(request, call_next):
    """Dashboards must never be served stale from the browser cache after an upgrade
    (new index.html + old style.css = broken page). "no-cache" = always revalidate (ETag)."""
    response = await call_next(request)
    if not request.url.path.startswith(("/api", "/downloads", "/health")):
        response.headers["Cache-Control"] = "no-cache"
    return response


def _is_page(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


@app.middleware("http")
async def require_login_for_dashboards(request, call_next):
    """/app (users) and /admin (admins) are served only to a signed-in session; others go to /login."""
    path = request.url.path
    if _is_page(path, "/app") or _is_page(path, "/admin"):
        user = await run_in_threadpool(session_user_from, request)
        if user is None:
            return RedirectResponse(f"/login/?next={quote(path if path.endswith('/') else path + '/')}", status_code=303)
        if _is_page(path, "/admin") and user["role"] != "admin":
            return RedirectResponse("/app/?denied=admin", status_code=303)
    return await call_next(request)


# Content-Security-Policy for the dashboards. Every script is an external file served
# by this backend (no inline <script>, no on*= attributes, no eval), so script-src is
# 'self' only. Inline style attributes are used for chart colours, hence 'unsafe-inline'
# for styles. Fonts are bundled locally: no third-party origin is allowed anywhere.
DASHBOARD_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' http://localhost:* http://127.0.0.1:*",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

@app.middleware("http")
async def security_headers(request, call_next):
    """Defence in depth on every response; the CSP is applied to the HTML dashboards."""
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if not request.url.path.startswith(("/api", "/downloads", "/health")):
        h["Content-Security-Policy"] = DASHBOARD_CSP
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    # Localhost aliases/ports are accepted for development. Browser extension
    # origins are accepted because the opt-in extension talks to this API.
    # The dashboard itself uses same-origin relative API paths (see script.js).
    allow_origin_regex=(
        r"^(?:(?:chrome-extension|moz-extension)://[A-Za-z0-9_-]+|"
        r"https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?)$"
    ),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization", "X-Admin-Token", "X-Discovery-Token"],
)

class ScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    user_id: str = Field(default="demo-user", max_length=100)
    tool_name: str = Field(default="unknown", max_length=100)
    confirm_warning: bool = False
    warn_incident_id: int | None = None

class ChatMessage(BaseModel):
    role: str
    content: str = Field(min_length=1, max_length=20000)
    @field_validator("role")
    @classmethod
    def valid_role(cls, value):
        if value not in {"user", "assistant"}:
            raise ValueError("role must be user or assistant")
        return value

class ShadowEventRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    install_id: str = Field(min_length=8, max_length=80)
    team_label: str = Field(default="Unassigned", max_length=40)

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value):
        value = value.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]+", value) or ".." in value or value.startswith("."):
            raise ValueError("domain must be a hostname only; URL paths and schemes are not accepted")
        return value

    @field_validator("install_id")
    @classmethod
    def valid_install_id(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", value):
            raise ValueError("invalid extension installation identifier")
        return value

    @field_validator("team_label")
    @classmethod
    def valid_team_label(cls, value):
        value = value.strip() or "Unassigned"
        if not re.fullmatch(r"[\w .-]{1,40}", value):
            raise ValueError("Use a team code/name only; do not enter an employee name")
        return value


class VaultMatch(BaseModel):
    """A value already in the extension's local vault was found again in the prompt.
    Only the pseudonym TYPE and a count are sent, never the value or the token."""
    token_type: str = Field(min_length=2, max_length=30)
    count: int = Field(ge=1, le=1000)

    @field_validator("token_type")
    @classmethod
    def valid_token_type(cls, value):
        value = value.upper().strip()
        if not re.fullmatch(r"[A-Z_]{2,30}", value):
            raise ValueError("Invalid token type")
        return value


TOKEN_TYPE_TO_FINDING = {prefix: ftype for ftype, prefix in TOKEN_PREFIX.items()}
# Finding types the DLP matrix hides as pseudonyms (REDACT / WARN_REDACT).
POLICY_RULES_REDACTABLE = {t for t in CATEGORY_LABELS if rule_for(t) in REDACT_RULES}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# The only AI services AI Shield supports (catalog, extension and Prompt Guard).
SUPPORTED_AI_PROVIDERS = {"chatgpt", "gemini", "claude"}


class ShadowPromptScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    provider_key: str = Field(min_length=2, max_length=80)
    team_label: str = Field(default="Unassigned", max_length=40)
    confirm_warning: bool = False
    # When confirming a WARN, the id returned by the first scan: that incident is marked
    # "confirmed by the user" instead of logging a second incident.
    warn_incident_id: int | None = None
    vault_matches: list[VaultMatch] = Field(default_factory=list, max_length=50)

    @field_validator("provider_key")
    @classmethod
    def valid_prompt_provider(cls, value):
        value = value.lower().strip()
        if value not in SUPPORTED_AI_PROVIDERS:
            raise ValueError("provider_key must be chatgpt, gemini or claude")
        return value

    @field_validator("team_label")
    @classmethod
    def valid_prompt_team_label(cls, value):
        value = value.strip() or "Unassigned"
        if not re.fullmatch(r"[\w .-]{1,40}", value):
            raise ValueError("Use a team code/name only; do not enter an employee name")
        return value


class ShadowToolStatusRequest(BaseModel):
    status: str
    @field_validator("status")
    @classmethod
    def valid_status(cls, value):
        value = value.upper().strip()
        if value not in {"APPROVED", "UNAPPROVED", "REVIEW"}:
            raise ValueError("status must be APPROVED, UNAPPROVED or REVIEW")
        return value


class IncidentActionRequest(BaseModel):
    action: str
    analyst: str = Field(min_length=2, max_length=60)
    note: str | None = Field(default=None, max_length=1000)
    resolution_category: str | None = None

    @field_validator("action")
    @classmethod
    def valid_action(cls, value):
        value = value.upper().strip()
        if value not in TRANSITIONS:
            raise ValueError("action must be ACKNOWLEDGE, INVESTIGATE or RESOLVE")
        return value

    @field_validator("analyst")
    @classmethod
    def valid_analyst(cls, value):
        value = value.strip()
        if not re.fullmatch(r"[\w .@-]{2,60}", value):
            raise ValueError("Analyst: γράμματα, αριθμοί, κενό, . @ - (2-60 χαρακτήρες)")
        return value

    @field_validator("note")
    @classmethod
    def clean_note(cls, value):
        value = (value or "").strip()
        return value or None

    @field_validator("resolution_category")
    @classmethod
    def valid_resolution(cls, value):
        if value is None or value == "":
            return None
        value = value.upper().strip()
        if value not in RESOLUTION_CATEGORIES:
            raise ValueError("Unknown resolution category")
        return value


class ChatRequest(BaseModel):
    provider: str = Field(default="gemini", max_length=30)
    model: str | None = None
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)
    user_id: str = Field(default="demo-user", max_length=100)
    confirm_warning: bool = False
    warn_incident_id: int | None = None

def verify_admin(token: str | None):
    expected = os.getenv("ADMIN_API_TOKEN", "")
    if not expected or not token:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid admin token")


def session_user_from(request: Request) -> dict | None:
    try:
        return auth.session_user(request.cookies.get(auth.SESSION_COOKIE))
    except Exception:
        logger.exception("Session lookup failed")
        return None


def check_same_origin(request: Request):
    """CSRF defence for cookie-authenticated requests (in addition to SameSite=Lax):
    a browser always sends Origin on cross-site POSTs; it must be this site."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")


def require_admin(request: Request, x_admin_token: str | None = Header(default=None)):
    """FastAPI dependency, run BEFORE the body is validated (unauthenticated -> always 401).
    Accepts the admin token (automation / API) or a signed-in admin session (the console)."""
    if x_admin_token:
        verify_admin(x_admin_token)
        return
    user = session_user_from(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    check_same_origin(request)


def require_user(request: Request):
    """Signed-in user (any role) for the Secure AI Chat."""
    user = session_user_from(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Απαιτείται σύνδεση.")
    check_same_origin(request)


def require_discovery(x_discovery_token: str | None = Header(default=None)):
    """Same for the browser-extension endpoints (X-Discovery-Token)."""
    expected = os.getenv("SHADOW_INGEST_TOKEN", "")
    if not expected or not x_discovery_token or not secrets.compare_digest(x_discovery_token, expected):
        raise HTTPException(status_code=401, detail="Invalid discovery token")

def record_event(user_id, provider, action, risk, findings, content_type="text"):
    try:
        return save_incident(user_id=user_id, tool_name=provider, action=action,
                             risk=risk, findings=findings, content_type=content_type)
    except Exception as exc:
        logger.exception("Could not save incident")
        raise HTTPException(status_code=503,
                            detail="Database unavailable - security event could not be logged") from exc

def merge_vault_findings(findings: list[dict], vault_matches: list["VaultMatch"]) -> list[dict]:
    """Add values the extension will hide because they are already in its vault
    (e.g. an ΑΦΜ sent earlier, now mentioned without a label), so the audit records
    the DLP action for that data instead of ALLOW."""
    merged = {f["type"]: dict(f) for f in findings}
    for match in vault_matches:
        ftype = TOKEN_TYPE_TO_FINDING.get(match.token_type)
        if not ftype:
            continue
        current = merged.get(ftype)
        if current is None:
            merged[ftype] = {"type": ftype, "severity": "medium", "count": match.count, "source": "vault"}
        else:
            current["count"] = max(current["count"], match.count)
    return sorted(merged.values(), key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["type"]))


def redact_entities(entities: list[dict]) -> list[dict]:
    """Only values whose DLP rule is REDACT or WARN_REDACT are hidden; ALLOW/WARN-only data
    (names, addresses, health text, contracts) is sent as it is."""
    return [e for e in entities if rule_for(e["type"]) in REDACT_RULES]


def mask_text(text: str, entities: list[dict]) -> str:
    """Irreversible fallback masking for stateless API clients and AI responses."""
    for e in sorted(entities, key=lambda e: -e["start"]):
        text = text[:e["start"]] + f"[REDACTED:{e['type']}]" + text[e["end"]:]
    return text


def policy_check(text: str, user_id: str, provider: str, confirm_warning: bool,
                 vault_matches: list | None = None, warn_incident_id: int | None = None,
                 content_type: str = "text"):
    scan = scan_prompt(text)
    if vault_matches:
        scan["findings"] = merge_vault_findings(scan["findings"], vault_matches)
    policy = evaluate_policy(scan["findings"])
    action = policy["action"]
    # BLOCK is never forwarded; WARN only after the user confirmed.
    allowed = action in {"ALLOW", "REDACT"} or (action == "WARN" and confirm_warning)
    scan["entities"] = redact_entities(scan["entities"])
    safe_text = mask_text(text, scan["entities"])
    incident = None
    if action == "WARN" and confirm_warning and warn_incident_id:
        try:
            incident = confirm_warning_incident(warn_incident_id, user_id, provider)
        except Exception:
            logger.exception("Could not record WARN confirmation")
    if incident is None:
        incident = record_event(user_id, provider, action, policy["risk"], scan["findings"], content_type)
        if action == "WARN" and confirm_warning:
            try:
                incident = confirm_warning_incident(incident["id"], user_id, provider) or incident
            except Exception:
                logger.exception("Could not record WARN confirmation")
    return scan, policy, allowed, safe_text, incident

@app.get("/health")
def health():
    return {"status":"ok","service":"AI Shield","version":"2.0.0"}

@app.get("/api/providers")
def providers():
    return {"providers": SUPPORTED_PROVIDERS}

@app.post("/api/scan")
def scan(request: ScanRequest):
    scan_result, policy, allowed, safe_prompt, incident = policy_check(
        request.prompt, request.user_id, request.tool_name,
        request.confirm_warning, warn_incident_id=request.warn_incident_id)
    return {
        "incident_id": incident["id"], "action": policy["action"],
        "risk": policy["risk"], "reason": policy["reason"],
        "rules": policy["rules"], "redact_types": policy["redact_types"],
        "findings": scan_result["findings"], "forward_allowed": allowed,
        "safe_prompt": safe_prompt if allowed else None,
        "entities": scan_result["entities"] if allowed else [],
    }

@app.post("/api/chat", dependencies=[Depends(require_user)])
def chat(request: ChatRequest, http_request: Request):
    user = session_user_from(http_request)
    request.user_id = (user["email"] if user else request.user_id)[:100]
    provider = request.provider.lower().strip()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Μη υποστηριζόμενος AI provider.")
    # Scan the entire context that will be forwarded, not only the latest turn.
    combined = "\n\n".join(m.content for m in request.messages)
    scan_result, policy, allowed, _, incident = policy_check(
        combined, request.user_id, provider, request.confirm_warning,
        warn_incident_id=request.warn_incident_id)
    action = policy["action"]
    if not allowed:
        return {
            "status": "blocked" if action == "BLOCK" else "confirmation_required",
            "incident_id": incident["id"], "action": action,
            "risk": policy["risk"], "reason": policy["reason"],
            "findings": scan_result["findings"], "reply": None,
        }

    # Reversible pseudonymization: one in-memory vault for the whole request, so the
    # same person/AFM/account gets the same token in every message of the context.
    vault = Vault()
    outgoing = []
    for message in request.messages:
        content = message.content
        if action in {"REDACT", "WARN"}:
            content = pseudonymize(content, redact_entities(scan_prompt(content)["entities"]), vault)
        outgoing.append({"role": message.role, "content": content})

    try:
        answer = ai_chat(provider, request.model, outgoing)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("AI provider request failed")
        message = str(exc)[:300] if os.getenv("DEBUG", "false").lower() == "true" else "Ο AI provider δεν ήταν διαθέσιμος. Έλεγξε το API key, τα όρια χρήσης και τη σύνδεση."
        raise HTTPException(status_code=502, detail=message) from exc

    # Scan provider output (still containing tokens) for NEW sensitive data the model
    # produced itself; mask that irreversibly. Then restore the user's own values.
    response_scan = scan_prompt(answer)
    response_policy = evaluate_policy(response_scan["findings"])
    if response_policy["action"] == "BLOCK":
        answer = "Η απάντηση αποκλείστηκε από το AI Shield επειδή περιείχε ευαίσθητα δεδομένα."
    else:
        answer = mask_text(answer, redact_entities(response_scan["entities"]))
    answer = restore(answer, vault)

    return {
        "status":"ok", "incident_id":incident["id"],
        "action":action, "risk":policy["risk"],
        "reason":policy["reason"], "findings":scan_result["findings"],
        "rules":policy["rules"],
        "reply":answer,
        "pseudonymized_count":len(vault),
        "response_findings":response_scan["findings"],
    }

def with_categories(incident: dict) -> dict:
    return {**incident, **categorize_findings(incident.get("findings"))}


@app.get("/api/admin/incidents", dependencies=[Depends(require_admin)])
def admin_incidents(limit: int = 100, include_auto_closed: bool = False,
                    x_admin_token: str | None = Header(default=None)):
    try:
        rows = get_recent_incidents(max(1, min(limit, 500)), include_auto_closed)
        return {"incidents": [with_categories(r) for r in rows],
                "resolution_categories": RESOLUTION_CATEGORIES}
    except Exception as exc:
        logger.exception("Could not load incidents")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@app.get("/api/admin/incidents/{incident_id}", dependencies=[Depends(require_admin)])
def admin_incident_detail(incident_id: int, x_admin_token: str | None = Header(default=None)):
    """Full technical analysis for INVESTIGATE. Metadata only: no prompt, no values."""
    try:
        incident = get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        related, provider_status = get_incident_context(incident)
        return {
            "incident": with_categories(incident),
            "analysis": analyse_incident(incident, related, provider_status),
            "activity": get_incident_activity(incident_id),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Could not load incident detail")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@app.post("/api/admin/incidents/{incident_id}/actions", dependencies=[Depends(require_admin)])
def admin_incident_action(incident_id: int, request: IncidentActionRequest, http_request: Request,
                          x_admin_token: str | None = Header(default=None)):
    """ACKNOWLEDGE / INVESTIGATE / RESOLVE. RESOLVE requires a category and a reason."""
    if not x_admin_token:
        user = session_user_from(http_request)
        if user:
            request.analyst = (user["display_name"] or user["email"])[:60]
    rule = TRANSITIONS[request.action]
    if request.action == "RESOLVE":
        if not request.resolution_category:
            raise HTTPException(status_code=422, detail="Το RESOLVE απαιτεί κατηγορία επίλυσης.")
        if not request.note or len(request.note) < 10:
            raise HTTPException(status_code=422, detail="Το RESOLVE απαιτεί αιτιολογία (τουλάχιστον 10 χαρακτήρες).")
    try:
        updated = transition_incident(
            incident_id, request.action, rule["to"], rule["from"], request.analyst,
            request.note, request.resolution_category if request.action == "RESOLVE" else None,
        )
    except TransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Could not update incident status")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident": with_categories(updated)}


# Time windows offered by the dashboard and the trend granularity for each.
INTEL_WINDOWS = {1: 300, 24: 3600, 168: 86400}   # 1 h -> 5 min, 24 h -> 1 h, 7 d -> 1 day


@app.get("/api/admin/policy", dependencies=[Depends(require_admin)])
def admin_policy(x_admin_token: str | None = Header(default=None)):
    """The DLP matrix in force (category -> types -> action), for the dashboard."""
    return {"rows": [{**row, "type_labels": [CATEGORY_LABELS.get(t, t) for t in row["types"]]}
                     for row in POLICY_TABLE]}


@app.get("/api/admin/intelligence", dependencies=[Depends(require_admin)])
def admin_intelligence(hours: int = 24, x_admin_token: str | None = Header(default=None)):
    """Sensitive Data Intelligence: finding counts per category. Never values or prompts.
    hours: 1, 24 or 168 (7 days)."""
    if hours not in INTEL_WINDOWS:
        raise HTTPException(status_code=422, detail="hours must be 1, 24 or 168")
    bucket = INTEL_WINDOWS[hours]
    try:
        return build_intelligence(*get_intelligence_rows(hours, bucket), hours=hours, bucket_seconds=bucket)
    except Exception as exc:
        logger.exception("Could not build intelligence")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc

# --------------------------- AI Shadow Radar ---------------------------

@app.get("/api/shadow/catalog")
def shadow_catalog():
    """Minimal domain catalog consumed by the opt-in browser extension."""
    try:
        return {"tools": get_shadow_catalog()}
    except Exception as exc:
        logger.exception("Could not load Shadow AI catalog")
        raise HTTPException(status_code=503, detail="Shadow AI catalog unavailable") from exc


@app.post("/api/shadow/events", dependencies=[Depends(require_discovery)])
def ingest_shadow_event(request: ShadowEventRequest, x_discovery_token: str | None = Header(default=None)):
    expected = os.getenv("SHADOW_INGEST_TOKEN", "")
    if not expected or not x_discovery_token or not secrets.compare_digest(x_discovery_token, expected):
        raise HTTPException(status_code=401, detail="Invalid discovery token")
    try:
        result = record_shadow_event(request.domain, request.install_id, request.team_label)
        if result is None:
            return {"recorded": False, "recognized": False, "message": "Domain is not in the AI tool catalog"}
        return {"recognized": True, **result}
    except Exception as exc:
        logger.exception("Could not record Shadow AI event")
        raise HTTPException(status_code=503, detail="Shadow AI event could not be recorded") from exc


@app.post("/api/shadow/scan-prompt", dependencies=[Depends(require_discovery)])
def shadow_scan_prompt(request: ShadowPromptScanRequest,
                       x_discovery_token: str | None = Header(default=None)):
    """Inspect a prompt locally before an AI website sends it to its provider.

    The raw prompt is processed in memory only. The incident audit stores provider,
    team label, policy action/risk and finding types/counts, never prompt text or matches.
    """
    expected = os.getenv("SHADOW_INGEST_TOKEN", "")
    if not expected or not x_discovery_token or not secrets.compare_digest(x_discovery_token, expected):
        raise HTTPException(status_code=401, detail="Invalid discovery token")
    scan_result, policy, allowed, safe_prompt, incident = policy_check(
        request.prompt,
        user_id=f"team:{request.team_label}",
        provider=request.provider_key,
        confirm_warning=request.confirm_warning,
        vault_matches=request.vault_matches,
        warn_incident_id=request.warn_incident_id,
    )
    return {
        "incident_id": incident["id"],
        "provider": request.provider_key,
        "team_label": request.team_label,
        "action": policy["action"],
        "risk": policy["risk"],
        "reason": policy["reason"],
        "rules": policy["rules"],
        "block_types": policy["block_types"], "warn_types": policy["warn_types"],
        "redact_types": policy["redact_types"],
        # Pseudonym prefixes the extension may apply from its vault (e.g. AFM, IBAN).
        "redact_token_types": sorted({TOKEN_PREFIX.get(t, t) for t in POLICY_RULES_REDACTABLE}),
        "findings": scan_result["findings"],
        "forward_allowed": allowed,
        "safe_prompt": safe_prompt if allowed else None,
        # Positions only (code-point offsets + token type) of values whose DLP rule is
        # REDACT / WARN_REDACT. The extension replaces them with [AFM_001]-style tokens.
        "entities": scan_result["entities"] if allowed else [],
    }


class ShadowFileScanRequest(BaseModel):
    """A file the user is attaching on an AI website (PDF only). Sent base64-encoded by the
    extension to this local backend; processed in memory, never stored (not even its name)."""
    content_base64: str = Field(min_length=8, max_length=(MAX_PDF_BYTES * 4) // 3 + 4096)
    provider_key: str = Field(min_length=2, max_length=80)
    team_label: str = Field(default="Unassigned", max_length=40)
    confirm_warning: bool = False
    warn_incident_id: int | None = None

    @field_validator("provider_key")
    @classmethod
    def valid_file_provider(cls, value):
        value = value.lower().strip()
        if value not in SUPPORTED_AI_PROVIDERS:
            raise ValueError("Μη υποστηριζόμενος AI provider.")
        return value


@app.post("/api/shadow/scan-file", dependencies=[Depends(require_discovery)])
def shadow_scan_file(request: ShadowFileScanRequest):
    """DLP for a PDF attached on ChatGPT / Gemini / Claude, with the same rules as prompts.

    upload_original=True  -> the extension may let the original PDF upload (ALLOW, or WARN
                             confirmed with nothing to pseudonymize).
    text + entities       -> REDACT-type data inside: the PDF must NOT upload; the extension
                             pseudonymizes this text locally and puts it in the message instead.
    Files that cannot be inspected completely are never let through silently (fail closed).
    """
    try:
        data = base64.b64decode(request.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Μη έγκυρο περιεχόμενο αρχείου (base64).")
    if len(data) > MAX_PDF_BYTES:
        raise HTTPException(status_code=413, detail=f"Το PDF ξεπερνά τα {MAX_PDF_BYTES // (1024 * 1024)} MB.")
    if not is_pdf(data):
        raise HTTPException(status_code=415, detail="Υποστηρίζονται μόνο αρχεία PDF.")
    base = {"provider": request.provider_key, "team_label": request.team_label, "incident_id": None,
            "findings": [], "entities": [], "text": None, "rules": [], "block_types": [],
            "warn_types": [], "redact_types": [], "redact_token_types": [], "pages": None}
    try:
        extracted = extract_pdf_text(data)
    except PdfInspectionError as exc:
        # Encrypted, corrupt or too large to inspect in full: blocked, never forwarded unchecked.
        return {**base, "inspection": exc.code, "action": "BLOCK", "risk": "HIGH",
                "reason": f"{exc.message} Για ασφάλεια δεν ανεβαίνει.",
                "forward_allowed": False, "upload_original": False}
    finally:
        del data
    text = extracted["text"]
    if not text.strip():
        # Image-only PDF (e.g. a scan): there is no text to inspect. Treated as WARN.
        return {**base, "inspection": "no_text", "pages": extracted["pages"], "action": "WARN", "risk": "MEDIUM",
                "reason": "Το PDF δεν έχει αναγνώσιμο κείμενο (π.χ. σκαναρισμένο έγγραφο ή εικόνα), οπότε το περιεχόμενό του δεν μπορεί να ελεγχθεί.",
                "forward_allowed": request.confirm_warning, "upload_original": request.confirm_warning}
    scan_result, policy, allowed, _, incident = policy_check(
        text, user_id=f"team:{request.team_label}", provider=request.provider_key,
        confirm_warning=request.confirm_warning, warn_incident_id=request.warn_incident_id,
        content_type="pdf")
    entities = scan_result["entities"] if allowed else []
    return {
        **base,
        "inspection": "ok",
        "pages": extracted["pages"],
        "chars": len(text),
        "incident_id": incident["id"],
        "action": policy["action"], "risk": policy["risk"], "reason": policy["reason"],
        "rules": policy["rules"], "block_types": policy["block_types"],
        "warn_types": policy["warn_types"], "redact_types": policy["redact_types"],
        "redact_token_types": sorted({TOKEN_PREFIX.get(t, t) for t in POLICY_RULES_REDACTABLE}),
        "findings": scan_result["findings"],
        "forward_allowed": allowed,
        "upload_original": allowed and not entities,
        # Only when values must be pseudonymized: the text goes back to the user's own browser.
        "text": text if entities else None,
        "entities": entities,
    }


def verify_discovery(token: str | None):
    expected = os.getenv("SHADOW_INGEST_TOKEN", "")
    if not expected or not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid discovery token")


class PolicyPreviewRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=5000)


@app.get("/api/shadow/policy", dependencies=[Depends(require_discovery)])
def shadow_policy(x_discovery_token: str | None = Header(default=None)):
    """DLP matrix for the extension's settings page. Also used to validate the extension token."""
    verify_discovery(x_discovery_token)
    return {"rows": [{**row, "type_labels": [CATEGORY_LABELS.get(t, t) for t in row["types"]]}
                     for row in POLICY_TABLE]}


@app.post("/api/shadow/policy-preview", dependencies=[Depends(require_discovery)])
def shadow_policy_preview(request: PolicyPreviewRequest,
                          x_discovery_token: str | None = Header(default=None)):
    """Dry run from the extension's settings page: what would the DLP policy do with this text?
    Nothing is stored (no incident) and nothing is sent to any AI provider."""
    verify_discovery(x_discovery_token)
    scan = scan_prompt(request.prompt)
    policy = evaluate_policy(scan["findings"])
    entities = redact_entities(scan["entities"]) if policy["action"] != "BLOCK" else []
    return {
        "action": policy["action"], "risk": policy["risk"], "reason": policy["reason"],
        "rules": [{**r, "label": CATEGORY_LABELS.get(r["type"], r["type"])} for r in policy["rules"]],
        "findings": scan["findings"], "entities": entities, "stored": False,
    }


@app.get("/api/admin/shadow/inventory", dependencies=[Depends(require_admin)])
def admin_shadow_inventory(x_admin_token: str | None = Header(default=None)):
    try:
        return {"tools": get_shadow_inventory()}
    except Exception as exc:
        logger.exception("Could not load Shadow AI inventory")
        raise HTTPException(status_code=503, detail="Shadow AI inventory unavailable") from exc


@app.get("/api/admin/shadow/events", dependencies=[Depends(require_admin)])
def admin_shadow_events(limit: int = 100, x_admin_token: str | None = Header(default=None)):
    try:
        return {"events": get_shadow_events(max(1, min(limit, 500)))}
    except Exception as exc:
        logger.exception("Could not load Shadow AI events")
        raise HTTPException(status_code=503, detail="Shadow AI events unavailable") from exc


@app.patch("/api/admin/shadow/tools/{tool_id}", dependencies=[Depends(require_admin)])
def admin_update_shadow_tool(tool_id: int, request: ShadowToolStatusRequest,
                             x_admin_token: str | None = Header(default=None)):
    try:
        tool = update_shadow_tool_status(tool_id, request.status)
    except Exception as exc:
        logger.exception("Could not update Shadow AI policy")
        raise HTTPException(status_code=503, detail="Could not update AI tool status") from exc
    if tool is None:
        raise HTTPException(status_code=404, detail="AI tool not found")
    return {"tool": tool}


@app.post("/api/admin/shadow/demo-seed", dependencies=[Depends(require_admin)])
def admin_seed_shadow_demo(x_admin_token: str | None = Header(default=None)):
    try:
        count = seed_demo_shadow_events()
        return {"inserted": count, "source": "synthetic-demo"}
    except Exception as exc:
        logger.exception("Could not seed synthetic Shadow AI events")
        raise HTTPException(status_code=503, detail="Could not create demo events") from exc


# --------------------- Browser extension download ---------------------
def _find_extension_dir():
    candidates = [os.getenv("EXTENSION_DIR"),
                  Path(__file__).resolve().parent / "browser-extension",
                  Path(__file__).resolve().parent.parent / "browser-extension"]
    for candidate in candidates:
        if candidate and (Path(candidate) / "firefox" / "manifest.json").is_file():
            return Path(candidate)
    return None


EXTENSION_DIR = _find_extension_dir()
EXTENSION_BROWSERS = {"firefox": "Mozilla Firefox (121+)", "chrome": "Google Chrome / Edge / Brave"}


def _extension_zip(browser: str) -> bytes:
    """Zip of the extension folder, built on request so it always matches the running version.
    manifest.json sits at the root of the archive (required by Firefox and Chrome)."""
    folder = EXTENSION_DIR / browser
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(folder.rglob("*")):
            if path.is_file() and not path.name.startswith(".") and "__pycache__" not in path.parts:
                zf.write(path, path.relative_to(folder).as_posix())
    return buf.getvalue()


@app.get("/api/extension/info")
def extension_info():
    """Version and availability of the browser extension downloads (no secrets)."""
    if not EXTENSION_DIR:
        return {"available": False, "builds": []}
    builds = []
    for key, label in EXTENSION_BROWSERS.items():
        manifest = EXTENSION_DIR / key / "manifest.json"
        if manifest.is_file():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            builds.append({"browser": key, "label": label, "version": data.get("version"),
                           "file": f"ai-shield-{key}.zip", "url": f"/downloads/ai-shield-{key}.zip",
                           "size_kb": round(len(_extension_zip(key)) / 1024)})
    return {"available": bool(builds), "builds": builds}


@app.get("/downloads/ai-shield-{browser}.zip", include_in_schema=False)
def download_extension(browser: str):
    if browser not in EXTENSION_BROWSERS or not EXTENSION_DIR or not (EXTENSION_DIR / browser).is_dir():
        raise HTTPException(status_code=404, detail="Extension build not found")
    version = json.loads((EXTENSION_DIR / browser / "manifest.json").read_text(encoding="utf-8")).get("version", "")
    return Response(content=_extension_zip(browser), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="ai-shield-{browser}-{version}.zip"',
                             "Cache-Control": "no-store"})


# =============================== Accounts (/login) ===============================
class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=200)
    remember: bool = False
    next: str | None = Field(default=None, max_length=200)


class ForgotRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class ResetRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def safe_next(path: str | None, user: dict | None = None) -> str:
    """Only same-site relative paths (no open redirect); default by role."""
    default = "/admin/" if user and user["role"] == "admin" else "/app/"
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path or "://" in path:
        return default
    if path.startswith("/admin") and user and user["role"] != "admin":
        return "/app/"
    if not (path.startswith("/app") or path.startswith("/admin")):
        return default
    return path


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def with_session(response: Response, request: Request, token: str, max_age: int) -> Response:
    secure = request.url.scheme == "https" or os.getenv("COOKIE_SECURE", "").lower() == "true"
    response.set_cookie(auth.SESSION_COOKIE, token, max_age=max_age, httponly=True,
                        samesite="lax", secure=secure, path="/")
    return response


def base_url(request: Request) -> str:
    return (os.getenv("PUBLIC_BASE_URL") or str(request.base_url)).rstrip("/")


@app.get("/api/auth/config")
def auth_config():
    """What the login page can offer (no secrets)."""
    return {"google": auth.google_config() is not None, "password_reset_email": auth.mail_configured(),
            "password_min": auth.PASSWORD_MIN}


@app.post("/api/auth/login")
def auth_login(body: LoginRequest, request: Request):
    check_same_origin(request)
    email, ip = auth.normalize_email(body.email), client_ip(request)
    if auth.login_by_email.blocked(email) or auth.login_by_ip.blocked(ip):
        raise HTTPException(status_code=429, detail="Πολλές αποτυχημένες προσπάθειες. Δοκίμασε ξανά σε 15 λεπτά.")
    user = auth.get_user_by_email(email)
    ok = auth.verify_password(body.password, user["password_hash"] if user else None)
    if not ok or user is None or user["disabled"]:
        auth.login_by_email.hit(email)
        auth.login_by_ip.hit(ip)
        # Same message whether the email exists, the password is wrong or the account is disabled.
        raise HTTPException(status_code=401, detail="Λάθος email ή κωδικός.")
    auth.login_by_email.clear(email)
    token, max_age = auth.create_session(user["id"], body.remember)
    payload = {"user": auth.public_user(user), "redirect": safe_next(body.next, user)}
    return with_session(JSONResponse(payload), request, token, max_age)


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    check_same_origin(request)
    auth.delete_session(request.cookies.get(auth.SESSION_COOKIE))
    response = JSONResponse({"ok": True})
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response


@app.get("/api/auth/me")
def auth_me(request: Request):
    user = session_user_from(request)
    if user is None:
        return {"user": None}          # not signed in (the public pages ask this on every load)
    return {"user": {"id": user["id"], "email": user["email"], "name": user["display_name"], "role": user["role"]}}


FORGOT_REPLY = {"ok": True, "message": "Αν υπάρχει λογαριασμός με αυτό το email, θα λάβεις σύνδεσμο επαναφοράς σε λίγα λεπτά."}


@app.post("/api/auth/forgot")
def auth_forgot(body: ForgotRequest, request: Request):
    check_same_origin(request)
    ip, email = client_ip(request), auth.normalize_email(body.email)
    if auth.reset_by_ip.blocked(ip) or auth.reset_by_email.blocked(email):
        raise HTTPException(status_code=429, detail="Πολλά αιτήματα. Δοκίμασε ξανά σε 15 λεπτά.")
    auth.reset_by_ip.hit(ip)
    auth.reset_by_email.hit(email)
    user = auth.get_user_by_email(email) if auth.valid_email(email) else None
    if user and not user["disabled"]:
        token = auth.create_reset(user["id"])
        # The token travels in the #fragment: browsers never send it to servers, proxies or logs.
        link = f"{base_url(request)}/login/#reset={token}"
        body_text = (f"Γεια σου {user['display_name']},\n\nΖητήθηκε επαναφορά του κωδικού σου στο NexGuard.\n"
                     f"Άνοιξε τον σύνδεσμο μέσα σε {auth.RESET_MINUTES} λεπτά:\n\n{link}\n\n"
                     "Αν δεν το ζήτησες εσύ, αγνόησε αυτό το μήνυμα· ο κωδικός σου δεν αλλάζει.\n\n— NexGuard")
        if not auth.send_mail(user["email"], "NexGuard · Επαναφορά κωδικού", body_text):
            if os.getenv("DEBUG", "false").lower() == "true":
                # Local development without SMTP only: the link appears in the server console.
                logger.warning("[DEV] Password reset link for %s: %s", user["email"], link)
            else:
                logger.warning("Password reset requested but SMTP is not configured (set SMTP_HOST in .env).")
    return FORGOT_REPLY


@app.post("/api/auth/reset")
def auth_reset(body: ResetRequest, request: Request):
    check_same_origin(request)
    if (problem := auth.password_problem(body.password)):
        raise HTTPException(status_code=422, detail=problem)
    link = auth.consume_reset(body.token)
    if link is None:
        raise HTTPException(status_code=400, detail="Ο σύνδεσμος δεν είναι έγκυρος ή έχει λήξει. Ζήτησε νέο.")
    user_id = link["user_id"]
    auth.set_password(user_id, body.password)
    auth.delete_user_sessions(user_id)          # sign out everywhere
    if link["purpose"] == "invite":
        user = auth.get_user(user_id)
        if user:
            auth.log_activity(user["email"], "ACTIVATE", user["email"], "ενεργοποίηση από πρόσκληση")
        return {"ok": True, "message": "Ο λογαριασμός σου ενεργοποιήθηκε. Συνδέσου με τον κωδικό που όρισες."}
    return {"ok": True, "message": "Ο κωδικός άλλαξε. Συνδέσου με τον νέο κωδικό."}


def google_redirect_uri(cfg: dict, request: Request) -> str:
    return cfg["redirect_uri"] or f"{base_url(request)}/api/auth/google/callback"


@app.get("/api/auth/google/start", include_in_schema=False)
def auth_google_start(request: Request, next: str | None = None):
    cfg = auth.google_config()
    if cfg is None:
        return RedirectResponse("/login/?error=google_not_configured", status_code=303)
    path = next if next and next.startswith("/") and not next.startswith("//") else ""
    state, verifier, nonce = auth.create_oauth_state(path[:200])
    return RedirectResponse(auth.google_auth_url(cfg, google_redirect_uri(cfg, request), state, verifier, nonce), status_code=303)


@app.get("/api/auth/google/callback", include_in_schema=False)
def auth_google_callback(request: Request, code: str | None = None, state: str | None = None,
                         error: str | None = None):
    cfg = auth.google_config()
    if cfg is None:
        return RedirectResponse("/login/?error=google_not_configured", status_code=303)
    saved = auth.consume_oauth_state(state or "")
    if error or not code or saved is None:
        return RedirectResponse(f"/login/?error={'google_cancelled' if error else 'google_failed'}", status_code=303)
    try:
        claims = auth.google_exchange(cfg, code, saved["code_verifier"], google_redirect_uri(cfg, request), saved["nonce"])
        user = auth.google_user(cfg, claims)
    except auth.GoogleError as exc:
        return RedirectResponse(f"/login/?error={exc.code}", status_code=303)
    except Exception:
        logger.exception("Google sign-in failed")
        return RedirectResponse("/login/?error=google_failed", status_code=303)
    token, max_age = auth.create_session(user["id"], False)
    return with_session(RedirectResponse(safe_next(saved["next_path"], user), status_code=303), request, token, max_age)


# ============================ Users (Admin Console → Χρήστες) ============================
NAME_BAD = re.compile(r"[<>\x00-\x1f\x7f]")


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(default="", max_length=80)
    role: str = Field(default="user")

    @field_validator("email")
    @classmethod
    def valid_user_email(cls, value):
        value = auth.normalize_email(value)
        if not auth.valid_email(value):
            raise ValueError("Μη έγκυρο email.")
        return value

    @field_validator("name")
    @classmethod
    def valid_user_name(cls, value):
        value = value.strip()
        if NAME_BAD.search(value):
            raise ValueError("Το όνομα περιέχει μη επιτρεπτούς χαρακτήρες.")
        return value

    @field_validator("role")
    @classmethod
    def valid_user_role(cls, value):
        if value not in ("user", "admin"):
            raise ValueError("Ο ρόλος πρέπει να είναι user ή admin.")
        return value


class UserUpdateRequest(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    name: str | None = Field(default=None, max_length=80)

    @field_validator("role")
    @classmethod
    def valid_update_role(cls, value):
        if value is not None and value not in ("user", "admin"):
            raise ValueError("Ο ρόλος πρέπει να είναι user ή admin.")
        return value

    @field_validator("name")
    @classmethod
    def valid_update_name(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value or NAME_BAD.search(value):
            raise ValueError("Μη έγκυρο όνομα.")
        return value


def admin_actor(request: Request) -> tuple[str, int | None]:
    """Who is acting: the signed-in admin (email, id), or the API token."""
    user = session_user_from(request) if not request.headers.get("x-admin-token") else None
    return (user["email"], user["id"]) if user else ("API token", None)


ROLE_EL = {"admin": "Διαχειριστής", "user": "Χρήστης"}


def send_invitation(request: Request, user: dict, actor: str) -> dict:
    token = auth.create_reset(user["id"], "invite")
    link = f"{base_url(request)}/login/#invite={token}"
    text = (f"Γεια σου {user['display_name']},\n\nΣε προσκάλεσαν στο NexGuard ως {ROLE_EL[user['role']]}.\n"
            f"Όρισε τον κωδικό σου μέσα σε {auth.INVITE_HOURS} ώρες:\n\n{link}\n\n"
            "Αν η εταιρεία σου χρησιμοποιεί Google, μπορείς επίσης να συνδέεσαι με «Σύνδεση με Google» με αυτό το email.\n\n— NexGuard")
    sent = auth.send_mail(user["email"], "NexGuard · Πρόσκληση στην πλατφόρμα", text)
    auth.log_activity(actor, "INVITE", user["email"], "email πρόσκλησης" if sent else "σύνδεσμος πρόσκλησης (χωρίς email)")
    # Without SMTP the admin gets the link to pass on; with SMTP it travels only by email.
    return {"invite_sent": sent, "invite_link": None if sent else link, "invite_hours": auth.INVITE_HOURS}


def user_view(u: dict) -> dict:
    status = "disabled" if u["disabled"] else ("invited" if not u["has_password"] and not u["has_google"] else "active")
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "status": status,
            "password": u["has_password"], "google": u["has_google"], "created_at": u["created_at"],
            "last_login_at": u["last_login_at"], "invite_expires_at": u["invite_expires_at"],
            "active_sessions": int(u["active_sessions"] or 0)}


@app.get("/api/admin/users", dependencies=[Depends(require_admin)])
def admin_users(request: Request):
    actor, me_id = admin_actor(request)
    return {"users": [user_view(u) for u in auth.list_users()], "activity": auth.recent_activity(30),
            "me": me_id, "mail_configured": auth.mail_configured(), "invite_hours": auth.INVITE_HOURS}


@app.post("/api/admin/users", dependencies=[Depends(require_admin)])
def admin_create_user(body: UserCreateRequest, request: Request):
    actor, _ = admin_actor(request)
    if auth.get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="Υπάρχει ήδη λογαριασμός με αυτό το email.")
    user = auth.create_user(body.email, body.name or body.email.split("@")[0], body.role, None)
    auth.log_activity(actor, "CREATE", user["email"], ROLE_EL[user["role"]])
    return {"user": {"id": user["id"], "email": user["email"], "name": user["display_name"], "role": user["role"]},
            **send_invitation(request, user, actor)}


def _target(user_id: int) -> dict:
    user = auth.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Ο λογαριασμός δεν βρέθηκε.")
    return user


@app.patch("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
def admin_update_user(user_id: int, body: UserUpdateRequest, request: Request):
    actor, me_id = admin_actor(request)
    user = _target(user_id)
    loses_admin = user["role"] == "admin" and not user["disabled"] and (
        (body.role is not None and body.role != "admin") or body.disabled is True)
    if loses_admin and user_id == me_id:
        raise HTTPException(status_code=409, detail="Δεν μπορείς να αφαιρέσεις τη δική σου πρόσβαση διαχειριστή.")
    if loses_admin and auth.active_admins_except(user_id) == 0:
        raise HTTPException(status_code=409, detail="Πρέπει να μείνει τουλάχιστον ένας ενεργός διαχειριστής.")
    auth.update_user(user_id, body.role, body.disabled, body.name)
    if body.role is not None and body.role != user["role"]:
        auth.log_activity(actor, "ROLE", user["email"], f"{ROLE_EL[user['role']]} → {ROLE_EL[body.role]}")
    if body.disabled is not None and body.disabled != user["disabled"]:
        auth.log_activity(actor, "DISABLE" if body.disabled else "ENABLE", user["email"])
        if body.disabled:
            auth.delete_user_sessions(user_id)      # signed out immediately
    if body.name is not None and body.name != user["display_name"]:
        auth.log_activity(actor, "RENAME", user["email"], body.name)
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/invite", dependencies=[Depends(require_admin)])
def admin_reinvite_user(user_id: int, request: Request):
    """New invitation link (also usable as an admin-initiated password reset). Old links stop working."""
    actor, _ = admin_actor(request)
    user = _target(user_id)
    if user["disabled"]:
        raise HTTPException(status_code=409, detail="Ο λογαριασμός είναι απενεργοποιημένος.")
    return send_invitation(request, user, actor)


@app.delete("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
def admin_delete_user(user_id: int, request: Request):
    actor, me_id = admin_actor(request)
    user = _target(user_id)
    if user_id == me_id:
        raise HTTPException(status_code=409, detail="Δεν μπορείς να διαγράψεις τον δικό σου λογαριασμό.")
    if user["role"] == "admin" and not user["disabled"] and auth.active_admins_except(user_id) == 0:
        raise HTTPException(status_code=409, detail="Πρέπει να μείνει τουλάχιστον ένας ενεργός διαχειριστής.")
    auth.delete_user(user_id)
    auth.log_activity(actor, "DELETE", user["email"], ROLE_EL[user["role"]])
    return {"ok": True}


def _find_frontend_dir():
    candidates = [os.getenv("FRONTEND_DIR"),
                  Path(__file__).resolve().parent / "frontend",
                  Path(__file__).resolve().parent.parent / "frontend"]
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None

FRONTEND_DIR = _find_frontend_dir()
if FRONTEND_DIR:
    # nexguard.com/ (public website) -> /login -> /app (users) and /admin (admins)
    for mount_path, folder in (("/app", "user-dashboard"), ("/admin", "technical-dashboard"),
                               ("/login", "login"), ("/assets", "shared"), ("/", "website")):
        if (FRONTEND_DIR / folder).is_dir():
            app.mount(mount_path, StaticFiles(directory=FRONTEND_DIR / folder, html=True), name=folder)


import os
import secrets

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from scanner import scan_prompt
from policy import evaluate_policy
from database import save_incident, get_recent_incidents


app = FastAPI(
    title="AI Shield API",
    version="1.0.0",
    description="Shadow AI protection and data protection system",
)


class ScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    user_id: str = Field(default="demo-user", max_length=100)
    tool_name: str = Field(default="unknown", max_length=100)
    confirm_warning: bool = False


def verify_admin(token: str | None):
    expected_token = os.getenv("ADMIN_API_TOKEN", "")

    if not expected_token or not token:
        raise HTTPException(
            status_code=401,
            detail="Admin authentication required",
        )

    if not secrets.compare_digest(token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid admin token",
        )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "AI Shield",
    }


@app.post("/api/scan")
def scan(request: ScanRequest):
    scan_result = scan_prompt(request.prompt)

    policy_result = evaluate_policy(
        scan_result["findings"]
    )

    action = policy_result["action"]

    if action in {"ALLOW", "REDACT"}:
        forward_allowed = True
    elif action == "WARN":
        forward_allowed = request.confirm_warning
    else:
        forward_allowed = False

    safe_prompt = None

    if forward_allowed:
        if action == "REDACT":
            safe_prompt = scan_result["redacted_prompt"]
        else:
            safe_prompt = request.prompt

    incident = save_incident(
        user_id=request.user_id,
        tool_name=request.tool_name,
        action=action,
        risk=policy_result["risk"],
        findings=scan_result["findings"],
    )

    return {
        "incident_id": incident["id"],
        "action": action,
        "risk": policy_result["risk"],
        "reason": policy_result["reason"],
        "findings": scan_result["findings"],
        "forward_allowed": forward_allowed,
        "safe_prompt": safe_prompt,
    }


@app.get("/api/admin/incidents")
def admin_incidents(
    limit: int = 100,
    x_admin_token: str | None = Header(default=None),
):
    verify_admin(x_admin_token)

    safe_limit = max(1, min(limit, 500))

    return {
        "incidents": get_recent_incidents(safe_limit)
    }

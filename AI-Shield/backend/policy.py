
from typing import Any


def evaluate_policy(findings: list[dict[str, Any]]) -> dict[str, str]:
    """
    Applies the initial AI Shield policy.

    Priority:
    BLOCK > REDACT > WARN > ALLOW
    """

    finding_types = {
        finding["type"]
        for finding in findings
    }

    if "API_SECRET" in finding_types:
        return {
            "action": "BLOCK",
            "reason": "Possible secret or API credential detected.",
            "risk": "CRITICAL",
        }

    if finding_types.intersection({"AFM", "AMKA", "EMAIL", "PHONE"}):
        return {
            "action": "REDACT",
            "reason": "Personal information detected. Sensitive values must be redacted.",
            "risk": "HIGH",
        }

    if "SOURCE_CODE" in finding_types:
        return {
            "action": "WARN",
            "reason": "Possible source code or internal technical information detected.",
            "risk": "MEDIUM",
        }

    return {
        "action": "ALLOW",
        "reason": "No configured sensitive patterns detected.",
        "risk": "LOW",
    }

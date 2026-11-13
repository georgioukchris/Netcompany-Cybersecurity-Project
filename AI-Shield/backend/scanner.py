
import re
from typing import Any


PATTERNS = [
    {
        "type": "API_SECRET",
        "severity": "critical",
        "regex": r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b",
    },
    {
        "type": "AMKA",
        "severity": "high",
        "regex": r"(?<!\d)\d{11}(?!\d)",
    },
    {
        "type": "AFM",
        "severity": "high",
        "regex": r"(?<!\d)\d{9}(?!\d)",
    },
    {
        "type": "EMAIL",
        "severity": "medium",
        "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    },
    {
        "type": "PHONE",
        "severity": "medium",
        "regex": r"(?<!\w)(?:\+30\s?)?69\d{8}(?!\d)",
    },
]


SOURCE_CODE_PATTERN = re.compile(
    r"\b(def\s+\w+\s*\(|class\s+\w+|SELECT\s+.+\s+FROM|"
    r"password\s*=|api_key\s*=)\b",
    re.IGNORECASE,
)


def scan_prompt(prompt: str) -> dict[str, Any]:
    """
    Scans a prompt for sensitive data.

    Raw matched values are never included in the findings.
    Returns findings and a redacted version of the prompt.
    """

    findings = []
    redacted_prompt = prompt

    for pattern in PATTERNS:
        matches = list(re.finditer(pattern["regex"], prompt))

        if matches:
            findings.append({
                "type": pattern["type"],
                "severity": pattern["severity"],
                "count": len(matches),
            })

            redacted_prompt = re.sub(
                pattern["regex"],
                f"[REDACTED:{pattern['type']}]",
                redacted_prompt,
            )

    source_matches = list(SOURCE_CODE_PATTERN.finditer(prompt))

    if source_matches:
        findings.append({
            "type": "SOURCE_CODE",
            "severity": "medium",
            "count": len(source_matches),
        })

    return {
        "has_sensitive_data": len(findings) > 0,
        "findings": findings,
        "redacted_prompt": redacted_prompt,
    }

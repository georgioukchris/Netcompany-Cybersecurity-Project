"""Sensitive Data Intelligence + investigation helpers: categories, shares, privacy."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from intelligence import categorize_findings, build_intelligence, analyse_incident, TRANSITIONS

bad = 0
def check(name, cond):
    global bad
    if not cond: bad += 1
    print(("ok   " if cond else "FAIL ") + name)

c = categorize_findings([{"type": "PERSON_NAME", "severity": "medium", "count": 2},
                         {"type": "IBAN", "severity": "critical", "count": 1}])
check("primary = most severe category (IBAN -> FINANCIAL)", c["primary_category"] == "FINANCIAL")
check("all categories listed in fixed order", c["categories"] == ["PERSONAL", "FINANCIAL"])
c = categorize_findings([{"type": "API_SECRET", "severity": "critical", "count": 1},
                         {"type": "HEALTH_DATA", "severity": "critical", "count": 1}])
check("severity tie -> credentials win", c["primary_category"] == "CREDENTIALS")
check("injection only -> THREAT", categorize_findings([{"type": "PROMPT_INJECTION", "severity": "high", "count": 1}])["primary_category"] == "THREAT")
check("no findings -> none", categorize_findings([])["primary_category"] is None)

intel = build_intelligence(
    [{"type": "EMAIL", "findings": 3, "incidents": 2}, {"type": "IBAN", "findings": 1, "incidents": 1},
     {"type": "PROMPT_INJECTION", "findings": 2, "incidents": 2}],
    [{"bucket": 1763460000, "type": "EMAIL", "findings": 3}],
    [{"provider": "chatgpt", "type": "EMAIL", "findings": 3}],
    {"total": 10, "with_findings": 4}, hours=24, bucket_seconds=3600)
cats = {c["key"]: c for c in intel["categories"]}
check("five categories always returned", list(cats) == ["PERSONAL", "FINANCIAL", "CREDENTIALS", "BUSINESS", "MEDICAL"])
check("shares: 75% / 25%", cats["PERSONAL"]["share"] == 75.0 and cats["FINANCIAL"]["share"] == 25.0)
check("trend keyed by epoch bucket", intel["trend"] == [{"bucket": 1763460000, "PERSONAL": 3, "FINANCIAL": 0, "CREDENTIALS": 0, "BUSINESS": 0, "MEDICAL": 0}])
check("window echoed", intel["hours"] == 24 and intel["bucket_seconds"] == 3600)
check("injection counted separately", intel["threat_signals"] == 2 and intel["total_findings"] == 4)
check("shares sum to 100", abs(sum(c["share"] for c in intel["categories"]) - 100) < 0.2)

a = analyse_incident({"id": 1, "user_id": "team:Finance", "tool_name": "chatgpt", "action": "PSEUDONYMIZE",
                      "findings": [{"type": "PERSON_NAME", "severity": "medium", "count": 1, "source": "vault"}]},
                     {"same_provider_24h": 0, "same_source_24h": 0, "same_source_open": 0}, "UNAPPROVED")
check("vault findings labelled", "vault" in a["findings"][0]["detected_by"])
check("unapproved provider -> first recommendation", "UNAPPROVED" in a["recommendations"][0])
check("team source parsed", a["team_or_user"] == "Finance" and "extension" in a["source"].lower())
check("RESOLVED is final", all("RESOLVED" not in t["from"] for t in TRANSITIONS.values()))
check("no value fields in output", not any(k in json.dumps(intel) + json.dumps(a) for k in ("prompt\"", "value\"", "match\"")))
print(f"failures: {bad}")
sys.exit(1 if bad else 0)

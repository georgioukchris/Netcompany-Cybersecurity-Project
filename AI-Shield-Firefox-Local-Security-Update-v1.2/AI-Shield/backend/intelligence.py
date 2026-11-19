"""
Sensitive Data Intelligence + Incident Investigation helpers.

Everything here works on finding TYPES and COUNTS only. No prompt text, matched
value or pseudonym mapping is ever read, stored or returned.
"""
from __future__ import annotations

from typing import Any

from policy import rule_for

# The five business-level categories shown in the Technical Dashboard.
CATEGORIES: dict[str, dict[str, Any]] = {
    "PERSONAL": {
        "label": "Personal Data",
        "label_el": "Προσωπικά δεδομένα",
        "examples": "Ονόματα, email, κινητά, διευθύνσεις, ΑΦΜ, ΑΜΚΑ, Π.Α., ταυτότητες, διαβατήρια",
        "types": ["PERSON_NAME", "EMAIL", "PHONE", "ADDRESS", "AFM", "AMKA", "PERSONAL_NUMBER", "ID_CARD", "PASSPORT"],
    },
    "FINANCIAL": {
        "label": "Financial Data",
        "label_el": "Οικονομικά δεδομένα",
        "examples": "IBAN, BIC/SWIFT, λογαριασμοί, κάρτες (PAN, λήξη, CVV), μισθοδοσίες, τιμολόγια, φορολογικά",
        "types": ["IBAN", "BIC_SWIFT", "ACCOUNT_NUMBER", "CREDIT_CARD", "CARD_MASKED", "CARD_CVV", "CARD_EXPIRY",
                  "FINANCIAL_SALARY", "FINANCIAL_DOCUMENT"],
    },
    "CREDENTIALS": {
        "label": "Credentials",
        "label_el": "Διαπιστευτήρια",
        "examples": "Passwords, API keys (AWS, Google Cloud, Stripe), JWT, private keys (.pem), DB connection strings",
        "types": ["API_SECRET", "PASSWORD", "PRIVATE_KEY", "CONNECTION_STRING"],
    },
    "BUSINESS": {
        "label": "Business Data",
        "label_el": "Εταιρικά δεδομένα",
        "examples": "Συμβάσεις, NDA, M&A, εμπιστευτικά emails διοίκησης, αδημοσίευτα δελτία τύπου, κώδικας",
        "types": ["CONFIDENTIAL", "LEGAL_DOCUMENT", "INTERNAL_COMMS", "SOURCE_CODE"],
    },
    "MEDICAL": {
        "label": "Medical Data",
        "label_el": "Ιατρικά δεδομένα",
        "examples": "Διαγνώσεις, φάρμακα, εξετάσεις, γνωματεύσεις, βιομετρικά & γενετικά (GDPR άρθρο 9)",
        "types": ["HEALTH_DATA", "BIOMETRIC_DATA"],
    },
}
CATEGORY_ORDER = ["PERSONAL", "FINANCIAL", "CREDENTIALS", "BUSINESS", "MEDICAL"]
TYPE_TO_CATEGORY = {t: key for key, c in CATEGORIES.items() for t in c["types"]}
THREAT_TYPES = {"PROMPT_INJECTION"}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# Category priority when severities tie: the costliest leak first.
CATEGORY_PRIORITY = {"CREDENTIALS": 5, "MEDICAL": 4, "FINANCIAL": 3, "PERSONAL": 2, "BUSINESS": 1}

# Incident workflow. RESOLVED is final; AUTO_CLOSED rows (clean scans) are not actionable.
TRANSITIONS = {
    "ACKNOWLEDGE": {"from": {"OPEN"}, "to": "ACKNOWLEDGED"},
    "INVESTIGATE": {"from": {"OPEN", "ACKNOWLEDGED"}, "to": "INVESTIGATING"},
    "RESOLVE": {"from": {"OPEN", "ACKNOWLEDGED", "INVESTIGATING"}, "to": "RESOLVED"},
}
RESOLUTION_CATEGORIES = {
    "FALSE_POSITIVE": "Ψευδώς θετικό",
    "EXPECTED_USE": "Αναμενόμενη επιχειρησιακή χρήση",
    "USER_INFORMED": "Ενημερώθηκε ο χρήστης / ομάδα",
    "CREDENTIALS_ROTATED": "Έγινε αλλαγή κλειδιών / κωδικών",
    "POLICY_UPDATED": "Ενημερώθηκε η πολιτική",
    "OTHER": "Άλλο",
}

RECOMMENDATIONS = {
    "CREDENTIALS": "Θεώρησε το διαπιστευτήριο εκτεθειμένο αν η αποστολή έγινε χωρίς Prompt Guard: κάνε rotation και έλεγξε τα logs πρόσβασης.",
    "MEDICAL": "Ειδική κατηγορία GDPR (άρθρο 9): επιβεβαίωσε νομική βάση και ενημέρωσε τον DPO αν η χρήση δεν είναι αναμενόμενη.",
    "FINANCIAL": "Επιβεβαίωσε ότι η ομάδα έχει επιχειρησιακό λόγο να επεξεργάζεται οικονομικά στοιχεία πελατών με AI.",
    "PERSONAL": "Έλεγξε αν η επεξεργασία προσωπικών δεδομένων με AI καλύπτεται από την πολιτική και το αρχείο δραστηριοτήτων.",
    "BUSINESS": "Ενημέρωσε την ομάδα για τη χρήση εμπιστευτικών εταιρικών πληροφοριών σε εξωτερικά AI εργαλεία.",
    "THREAT": "Πιθανή prompt injection: έλεγξε την προέλευση του περιεχομένου που επικολλήθηκε.",
}


def categorize_findings(findings: list[dict] | None) -> dict[str, Any]:
    """Primary detection category + all categories of one incident's findings."""
    best = None
    cats: dict[str, int] = {}
    threat = 0
    for f in findings or []:
        ftype = f.get("type")
        count = int(f.get("count") or 1)
        if ftype in THREAT_TYPES:
            threat += count
            continue
        cat = TYPE_TO_CATEGORY.get(ftype)
        if not cat:
            continue
        cats[cat] = cats.get(cat, 0) + count
        key = (SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0), CATEGORY_PRIORITY[cat])
        if best is None or key > best[0]:
            best = (key, cat)
    primary = best[1] if best else ("THREAT" if threat else None)
    return {
        "primary_category": primary,
        "categories": [c for c in CATEGORY_ORDER if c in cats] + (["THREAT"] if threat else []),
    }


def build_intelligence(type_rows: list[dict], bucket_rows: list[dict], provider_rows: list[dict],
                       totals: dict, hours: int, bucket_seconds: int) -> dict[str, Any]:
    """Aggregate per-type SQL rows into the five categories (counts and percentages only)."""
    per_cat = {k: {"key": k, "label": CATEGORIES[k]["label"], "label_el": CATEGORIES[k]["label_el"],
                   "examples": CATEGORIES[k]["examples"], "findings": 0, "incidents": 0, "types": []}
               for k in CATEGORY_ORDER}
    threat = 0
    for row in type_rows:
        ftype, findings, incidents = row["type"], int(row["findings"] or 0), int(row["incidents"] or 0)
        if ftype in THREAT_TYPES:
            threat += findings
            continue
        cat = TYPE_TO_CATEGORY.get(ftype)
        if not cat:
            continue
        c = per_cat[cat]
        c["findings"] += findings
        # An incident with two types of one category is counted once per type; cap at
        # the true total so the share stays meaningful.
        c["incidents"] = min(c["incidents"] + incidents, int(totals.get("with_findings") or 0))
        c["types"].append({"type": ftype, "findings": findings})
    total_findings = sum(c["findings"] for c in per_cat.values())
    for c in per_cat.values():
        c["share"] = round(100 * c["findings"] / total_findings, 1) if total_findings else 0.0
        c["types"].sort(key=lambda t: -t["findings"])

    trend: dict[int, dict[str, int]] = {}
    for row in bucket_rows:
        cat = TYPE_TO_CATEGORY.get(row["type"])
        if not cat:
            continue
        bucket = int(row["bucket"])
        trend.setdefault(bucket, {k: 0 for k in CATEGORY_ORDER})[cat] += int(row["findings"] or 0)

    providers: dict[str, dict[str, Any]] = {}
    for row in provider_rows:
        cat = TYPE_TO_CATEGORY.get(row["type"])
        if not cat:
            continue
        p = providers.setdefault(row["provider"], {"provider": row["provider"], "findings": 0,
                                                    **{k: 0 for k in CATEGORY_ORDER}})
        p[cat] += int(row["findings"] or 0)
        p["findings"] += int(row["findings"] or 0)

    return {
        "hours": hours,
        "bucket_seconds": bucket_seconds,
        "total_incidents": int(totals.get("total") or 0),
        "incidents_with_findings": int(totals.get("with_findings") or 0),
        "total_findings": total_findings,
        "threat_signals": threat,
        "categories": [per_cat[k] for k in CATEGORY_ORDER],
        # bucket = interval start in Unix epoch seconds (UTC)
        "trend": [{"bucket": b, **v} for b, v in sorted(trend.items())],
        "providers": sorted(providers.values(), key=lambda p: -p["findings"]),
    }


def analyse_incident(incident: dict, related: dict, provider_status: str | None) -> dict[str, Any]:
    """Technical analysis for INVESTIGATE. Uses only metadata already stored."""
    cats = categorize_findings(incident.get("findings"))
    findings = []
    for f in incident.get("findings") or []:
        cat = TYPE_TO_CATEGORY.get(f.get("type")) or ("THREAT" if f.get("type") in THREAT_TYPES else None)
        findings.append({**f, "category": cat, "policy_action": rule_for(f.get("type")),
                         "detected_by": "vault (επανεμφάνιση γνωστής τιμής)" if f.get("source") == "vault" else "scanner"})
    user_id = str(incident.get("user_id") or "")
    source = ("Browser extension · Prompt Guard" if user_id.startswith("team:")
              else "AI Shield gateway · User Dashboard")
    if incident.get("content_type") == "pdf":
        source = "Browser extension · Συνημμένο PDF"
    action = str(incident.get("action") or "")
    confirmed = bool(incident.get("user_confirmed_at"))
    exposure = {
        "REDACT": "Δεν εκτέθηκαν πραγματικές τιμές: τα ευαίσθητα στοιχεία στάλθηκαν μόνο ως αναστρέψιμα ψευδώνυμα και η αντιστοίχιση έμεινε στον browser/gateway.",
        "PSEUDONYMIZE": "Δεν εκτέθηκαν πραγματικές τιμές: στάλθηκαν μόνο αναστρέψιμα ψευδώνυμα.",
        "BLOCK": "Δεν εκτέθηκαν δεδομένα: η πολιτική DLP μπλόκαρε την αποστολή (διαπιστευτήρια ή στοιχεία κάρτας).",
        "WARN": ("Ο χρήστης προειδοποιήθηκε και ΕΠΙΒΕΒΑΙΩΣΕ την αποστολή: το κείμενο (π.χ. υγεία, συμβάσεις) στάλθηκε όπως ήταν· τυχόν IBAN/ΑΦΜ στάλθηκαν ως ψευδώνυμα."
                 if confirmed else
                 "Ο χρήστης προειδοποιήθηκε. Δεν υπάρχει επιβεβαίωση αποστολής: πιθανότατα ακύρωσε ή δεν συνέχισε."),
        "ALLOW": "Μόνο βασικά δεδομένα χαμηλού κινδύνου ή κανένα εύρημα· το κείμενο στάλθηκε όπως ήταν.",
    }.get(action, "Άγνωστη ενέργεια πολιτικής.")
    ordered = sorted(cats["categories"], key=lambda c: -CATEGORY_PRIORITY.get(c, 0))
    recs = [RECOMMENDATIONS[c] for c in ordered if c in RECOMMENDATIONS]
    if provider_status == "UNAPPROVED":
        recs.insert(0, "Ο AI provider είναι UNAPPROVED στο Shadow AI inventory: εξέτασε μπλοκάρισμα ή έγκριση.")
    return {
        **cats,
        "findings": findings,
        "source": source,
        "team_or_user": user_id[5:] if user_id.startswith("team:") else user_id,
        "data_exposure": exposure,
        "user_confirmed": confirmed,
        "provider_policy_status": provider_status,
        "related": related,
        "recommendations": recs,
        "privacy_note": "Η ανάλυση βασίζεται μόνο σε τύπους και πλήθη ευρημάτων. Το AI Shield δεν αποθηκεύει prompts ή πραγματικές τιμές.",
    }

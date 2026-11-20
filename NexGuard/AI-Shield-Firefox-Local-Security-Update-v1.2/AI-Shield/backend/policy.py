from typing import Any

# Human-readable (Greek) labels for the block reason shown to the user.
CATEGORY_LABELS = {
    "PRIVATE_KEY": "ιδιωτικό κλειδί",
    "API_SECRET": "API key / token",
    "CONNECTION_STRING": "connection string με κωδικό",
    "PASSWORD": "κωδικός πρόσβασης",
    "IBAN": "IBAN",
    "ACCOUNT_NUMBER": "αριθμός λογαριασμού",
    "CREDIT_CARD": "αριθμός κάρτας",
    "CARD_MASKED": "καλυμμένος αριθμός κάρτας",
    "CARD_CVV": "CVV κάρτας",
    "CARD_EXPIRY": "λήξη κάρτας",
    "FINANCIAL_SALARY": "μισθοδοτικά στοιχεία",
    "AFM": "ΑΦΜ",
    "AMKA": "ΑΜΚΑ",
    "ID_CARD": "αριθμός ταυτότητας",
    "PASSPORT": "αριθμός διαβατηρίου",
    "PERSONAL_NUMBER": "Προσωπικός Αριθμός (Π.Α.)",
    "BIC_SWIFT": "BIC/SWIFT",
    "FINANCIAL_DOCUMENT": "οικονομικά έγγραφα (τιμολόγια, δηλώσεις, εκκαθαριστικά)",
    "EMAIL": "email",
    "PHONE": "τηλέφωνο",
    "ADDRESS": "διεύθυνση",
    "PERSON_NAME": "ονοματεπώνυμο",
    "HEALTH_DATA": "δεδομένα υγείας (GDPR άρθρο 9)",
    "BIOMETRIC_DATA": "βιομετρικά / γενετικά δεδομένα (GDPR άρθρο 9)",
    "CONFIDENTIAL": "εμπιστευτικά εταιρικά δεδομένα",
    "PROMPT_INJECTION": "πιθανή prompt injection",
    "SOURCE_CODE": "πηγαίος κώδικας",
    "LEGAL_DOCUMENT": "νομικά / στρατηγικά έγγραφα (συμβάσεις, NDA, M&A)",
    "INTERNAL_COMMS": "εσωτερική επικοινωνία διοίκησης / αδημοσίευτα δελτία τύπου",
}

CRITICAL_TYPES = {
    "PRIVATE_KEY", "API_SECRET", "CONNECTION_STRING", "PASSWORD", "IBAN",
    "CREDIT_CARD", "CARD_CVV", "HEALTH_DATA", "BIOMETRIC_DATA",
}

# ---------------------------------------------------------------------------
# DLP policy matrix - "Πίνακας αντιστοίχισης κατηγοριών δεδομένων και ενεργειών"
#
#   BLOCK        not sent at all
#   WARN         the user must confirm; then sent as it is
#   WARN_REDACT  the user must confirm; then the values are sent as reversible pseudonyms
#   REDACT       sent as reversible pseudonyms ([AFM_001]); real values restored locally
#   ALLOW        sent as it is (still counted in the dashboard)
#
# Rows marked (*) are not in the table; they follow the closest row.
# ---------------------------------------------------------------------------
POLICY_RULES: dict[str, str] = {
    # Διαπιστευτήρια & Secrets -> BLOCK
    "API_SECRET": "BLOCK", "PASSWORD": "BLOCK", "PRIVATE_KEY": "BLOCK", "CONNECTION_STRING": "BLOCK",
    # Οικονομικά & Πληρωμές: PAN & CVV -> BLOCK (PCI-DSS)
    "CREDIT_CARD": "BLOCK", "CARD_CVV": "BLOCK",
    "CARD_EXPIRY": "BLOCK",                       # (*) part of full card data
    "CARD_MASKED": "REDACT",                      # (*) already masked, not full card data
    # Ευαίσθητα Προσωπικά (PII) -> REDACT
    "AFM": "REDACT", "AMKA": "REDACT", "ID_CARD": "REDACT", "PASSPORT": "REDACT",
    "PERSONAL_NUMBER": "REDACT",
    "EMAIL": "REDACT", "PHONE": "REDACT",         # (*) personal contact data, like PII
    # Δεδομένα Υγείας (GDPR Art. 9) -> WARN
    "HEALTH_DATA": "WARN", "BIOMETRIC_DATA": "WARN",
    # Τραπεζικοί Λογαριασμοί: IBAN, SWIFT/BIC -> WARN / REDACT
    "IBAN": "WARN_REDACT", "BIC_SWIFT": "WARN_REDACT",
    "ACCOUNT_NUMBER": "WARN_REDACT",              # (*) bank account
    "FINANCIAL_SALARY": "WARN_REDACT", "FINANCIAL_DOCUMENT": "WARN_REDACT",   # (*) financial documents
    # Εταιρικό Απόρρητο: NDAs, συμβόλαια, εσωτερικά emails -> WARN
    "LEGAL_DOCUMENT": "WARN", "INTERNAL_COMMS": "WARN", "CONFIDENTIAL": "WARN",
    "PROMPT_INJECTION": "WARN", "SOURCE_CODE": "WARN",   # (*) security signals (unchanged behaviour)
    # Βασικά Δεδομένα: ονοματεπώνυμο, διευθύνσεις -> ALLOW
    "PERSON_NAME": "ALLOW", "ADDRESS": "ALLOW",
}
ACTION_RANK = {"ALLOW": 0, "REDACT": 1, "WARN": 2, "BLOCK": 3}
REDACT_RULES = {"REDACT", "WARN_REDACT"}
WARN_RULES = {"WARN", "WARN_REDACT"}

# Table rows, for the dashboard's policy panel (type groups shown per row).
POLICY_TABLE = [
    {"category": "Διαπιστευτήρια & Secrets", "types": ["API_SECRET", "PASSWORD", "PRIVATE_KEY", "CONNECTION_STRING"],
     "action": "BLOCK", "why": "Καμία νόμιμη χρήση σε LLMs· η διαρροή σημαίνει άμεση παραβίαση."},
    {"category": "Οικονομικά & Πληρωμές", "types": ["CREDIT_CARD", "CARD_CVV", "CARD_EXPIRY"],
     "action": "BLOCK", "why": "PCI-DSS: τα πλήρη στοιχεία καρτών δεν διακινούνται ακάλυπτα."},
    {"category": "Ευαίσθητα Προσωπικά (PII)", "types": ["AFM", "AMKA", "ID_CARD", "PASSPORT", "PERSONAL_NUMBER", "EMAIL", "PHONE", "CARD_MASKED"],
     "action": "REDACT", "why": "Στέλνονται ως αναστρέψιμα ψευδώνυμα· οι τιμές επανέρχονται μόνο τοπικά."},
    {"category": "Δεδομένα Υγείας (GDPR Art. 9)", "types": ["HEALTH_DATA", "BIOMETRIC_DATA"],
     "action": "WARN", "why": "Πλαίσιο HR/ασφαλιστικών: απαιτείται προειδοποίηση και επιβεβαίωση."},
    {"category": "Τραπεζικοί Λογαριασμοί", "types": ["IBAN", "BIC_SWIFT", "ACCOUNT_NUMBER", "FINANCIAL_SALARY", "FINANCIAL_DOCUMENT"],
     "action": "WARN_REDACT", "why": "Αναγκαία για πληρωμές: προειδοποίηση και αποστολή ως ψευδώνυμα."},
    {"category": "Εταιρικό Απόρρητο", "types": ["LEGAL_DOCUMENT", "INTERNAL_COMMS", "CONFIDENTIAL", "PROMPT_INJECTION", "SOURCE_CODE"],
     "action": "WARN", "why": "Προειδοποίηση για αποφυγή ακούσιας διαρροής εκτός εταιρείας."},
    {"category": "Βασικά Δεδομένα", "types": ["PERSON_NAME", "ADDRESS"],
     "action": "ALLOW", "why": "Χαμηλός κίνδυνος, απαραίτητα για την καθημερινή επικοινωνία."},
]


def rule_for(finding_type: str) -> str:
    # Unknown future detector types are handled safely (warned), never silently allowed.
    return POLICY_RULES.get(finding_type, "WARN")


def redact_types(findings: list[dict[str, Any]]) -> set[str]:
    """Finding types whose values must be replaced by pseudonyms before sending."""
    return {f["type"] for f in findings if rule_for(f["type"]) in REDACT_RULES}


def _labels(types: list[str]) -> str:
    return ", ".join(CATEGORY_LABELS.get(t, t) for t in types)


def evaluate_policy(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply the DLP matrix. The strictest action wins: BLOCK > WARN > REDACT > ALLOW."""
    types = [t for t in list(CATEGORY_LABELS) if t in {f["type"] for f in findings}]
    types += sorted({f["type"] for f in findings} - set(types))
    block = [t for t in types if rule_for(t) == "BLOCK"]
    warn = [t for t in types if rule_for(t) in WARN_RULES]
    redact = [t for t in types if rule_for(t) in REDACT_RULES]
    allow = [t for t in types if rule_for(t) == "ALLOW"]
    action = "BLOCK" if block else "WARN" if warn else "REDACT" if redact else "ALLOW"
    found = set(types)

    if action == "BLOCK":
        reason = f"Η αποστολή μπλοκαρίστηκε: {_labels(block)}. Αφαίρεσέ τα από το μήνυμα και ξαναστείλε."
        risk = "CRITICAL"
    elif action == "WARN":
        reason = f"Περιέχει {_labels(warn)}. Χρειάζεται επιβεβαίωση πριν από την αποστολή."
        if redact:
            reason += f" Θα σταλούν ως ψευδώνυμα: {_labels(redact)}."
        risk = "CRITICAL" if found & CRITICAL_TYPES else "HIGH"
        if set(warn) <= {"PROMPT_INJECTION", "SOURCE_CODE"} and not redact:
            risk = "MEDIUM"
    elif action == "REDACT":
        reason = f"Στάλθηκαν ως αναστρέψιμα ψευδώνυμα: {_labels(redact)}."
        risk = "HIGH"
    else:
        reason = (f"Επιτρέπεται: {_labels(allow)} (βασικά δεδομένα χαμηλού κινδύνου)." if allow
                  else "Δεν εντοπίστηκαν γνωστά ευαίσθητα μοτίβα.")
        risk = "LOW"

    return {
        "action": action, "reason": reason, "risk": risk,
        "rules": [{"type": t, "action": rule_for(t)} for t in types],
        "block_types": block, "warn_types": warn, "redact_types": redact, "allow_types": allow,
    }

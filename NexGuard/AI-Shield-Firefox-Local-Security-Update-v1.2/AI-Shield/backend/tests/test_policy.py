"""DLP policy matrix (Πίνακας αντιστοίχισης κατηγοριών δεδομένων και ενεργειών). Synthetic data only."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from scanner import scan_prompt
from policy import evaluate_policy, rule_for, REDACT_RULES

# (prompt, expected action, types that must be pseudonymized, types that must stay visible)
CASES = [
    # Διαπιστευτήρια & Secrets -> BLOCK
    ("Το API key είναι sk-proj-abcdefghijklmnop1234", "BLOCK", [], []),
    ("password: Summer2026!x", "BLOCK", [], []),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "BLOCK", [], []),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "BLOCK", [], []),
    # Οικονομικά & Πληρωμές: PAN & CVV -> BLOCK
    ("κάρτα 4111 1111 1111 1111", "BLOCK", [], []),
    ("CVV: 345", "BLOCK", [], []),
    # Ευαίσθητα Προσωπικά (PII) -> REDACT
    ("Ο ΑΦΜ του είναι 094014201", "REDACT", ["AFM"], []),
    ("ΑΜΚΑ: 15038501234", "REDACT", ["AMKA"], []),
    ("Αρ. ταυτότητας Χ-123456", "REDACT", ["ID_CARD"], []),
    ("Το διαβατήριό του είναι AB1234567", "REDACT", ["PASSPORT"], []),
    # Δεδομένα Υγείας -> WARN (sent as is after confirmation)
    ("Επισυνάπτω την ιατρική γνωμάτευση του ορθοπεδικού", "WARN", [], ["HEALTH_DATA"]),
    ("Διάγνωση: διαβήτης τύπου 2", "WARN", [], ["HEALTH_DATA"]),
    # Τραπεζικοί Λογαριασμοί -> WARN / REDACT
    ("IBAN GR1601101250000000012300695", "WARN", ["IBAN"], []),
    ("BIC/SWIFT: ETHNGRAA", "WARN", ["BIC_SWIFT"], []),
    # Εταιρικό Απόρρητο -> WARN
    ("Το NDA που υπογράψαμε με την Alpha ισχύει 3 χρόνια", "WARN", [], ["LEGAL_DOCUMENT"]),
    ("Από: Διευθύνων Σύμβουλος\nΘέμα: Μειώσεις προσωπικού", "WARN", [], ["INTERNAL_COMMS"]),
    # Βασικά Δεδομένα -> ALLOW
    ("Ονοματεπώνυμο: Μαρία Στασινοπούλου", "ALLOW", [], ["PERSON_NAME"]),
    ("Η έδρα μας είναι στη Λεωφόρο Κηφισίας 12, Αθήνα", "ALLOW", [], ["ADDRESS"]),
    # The strictest action wins
    ("Γιάννης Παπαδόπουλος, ΑΦΜ 094014201, IBAN GR1601101250000000012300695", "WARN", ["AFM", "IBAN"], ["PERSON_NAME"]),
    ("ΑΦΜ 094014201 και password: Summer2026!x", "BLOCK", [], []),
    ("client John Smith, AFM 123456789, account number 987654321", "WARN", ["AFM", "ACCOUNT_NUMBER"], ["PERSON_NAME"]),
    ("Γράψε μου ένα email για συνάντηση την Τρίτη", "ALLOW", [], []),
]

bad = 0
for text, expected, hidden, visible in CASES:
    r = scan_prompt(text)
    pol = evaluate_policy(r["findings"])
    redacted = {e["type"] for e in r["entities"] if rule_for(e["type"]) in REDACT_RULES}
    shown = {e["type"] for e in r["entities"] if rule_for(e["type"]) not in REDACT_RULES} | \
            {f["type"] for f in r["findings"] if rule_for(f["type"]) not in REDACT_RULES}
    ok = pol["action"] == expected and set(hidden) <= redacted and set(visible) <= shown
    if expected == "BLOCK":
        ok = ok and pol["risk"] == "CRITICAL"
    if not ok:
        bad += 1
    print("ok  " if ok else "FAIL", f"{pol['action']:6} (expected {expected:6})", text.split(chr(10))[0][:60],
          "| hidden:", sorted(redacted), "| visible:", sorted(shown))
print(f"{len(CASES)} policy cases, failures: {bad}")
sys.exit(1 if bad else 0)

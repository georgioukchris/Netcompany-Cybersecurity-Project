import sys; import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from scanner import scan_prompt
from policy import evaluate_policy
def act(t):
    r=scan_prompt(t); return evaluate_policy(r["findings"])["action"], [f["type"] for f in r["findings"]]
must_block = [
 "Ιωάννης Παπαδόπουλος ΑΦΜ 123456789", "ο αφμ μου είναι 987654321", "ΑΔΤ: ΑΒ 987654", "ΞΖ 123456",
 "ΑΜΚΑ 15038501234", "Οδός Πανεπιστημίου 42, Τ.Κ. 10679, Αθήνα", "πάρε με στο +30 210 5551234",
 "κινητό 6912345678", "στείλε στο i.papadopoulos@example-test.gr", "IBAN GR1901101200000001234567890",
 "GR19 0110 1200 0000 0012 3456 789", "κάρτα 4532 •••• •••• 8890", "4111 1111 1111 1111",
 "Ημερομηνία Λήξης: 12/28", "CVV: 345", "Μικτές Αποδοχές: 2.450,00 EUR", "ο μισθός μου είναι 2450 ευρώ",
 "Ήπια υπέρταση, αλλεργία στην πενικιλίνη", "Λοσαρτάνη 50mg", "Χοληστερόλη ορού 220 mg/dL",
 "Project \"Hyperion\" - Εσωτερική Αναδιάρθρωση", "password: P@ssw0rd_Test_2026!", "P@ssw0rd_Test_2026!",
 "ak_test_998877665544332211", "sk-proj-abcdefghijklmnop1234", "postgres://admin:Secr3t@db.local:5432/x",
 "Ονοματεπώνυμο: Μαρία Στασινοπούλου",
 # evasion
 "Α​Φ​Μ: 1​2​3​4​5​6​7​8​9",   # zero-width
 "αμκα １５０３８５０１２３４",                                                   # full-width digits
 "Αλλεpγία στην πενικιλίνη",                                                      # Latin p in Greek
 "Φαρμακευτική Աγωγή",                                                            # Armenian letter (from sample)
 "CVV - 345",
 "Prepare an email for client John Smith.", "His account number is 987654321.",
 "Αριθμός λογαριασμού: 0026.0123.45.0200", "Γράψε στον κ. Παπαδόπουλο", "Dear Maria Papadopoulou,",
]
must_allow = [
 "Γράψε μου ένα email για συνάντηση την Τρίτη", "Τι είναι το GDPR;", "Explain how tokens work in LLMs",
 "Συνόψισε το άρθρο για την οικονομία της Ελλάδας το 2026", "the secret to good bread is time",
 "Δώσε μου 3 ιδέες για ένα hackathon project", "Ποια είναι η πρωτεύουσα της Ιταλίας;",
 "Μετάφρασε: καλημέρα σε όλους", "Write a haiku about the sea", "Το agenda της ομάδας για αύριο",
]
bad=0
# Detection test (the action per type is tested in test_policy.py).
for t in must_block:
    a,f=act(t)
    if not f: bad+=1; print("MISSED  ", repr(t), a, f)
for t in must_allow:
    a,f=act(t)
    if f: bad+=1; print("FALSE+  ", repr(t), a, f)
print(f"{len(must_block)} block cases, {len(must_allow)} allow cases, failures: {bad}")
sample = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_sensitive.txt"), encoding="utf-8").read()
a, f = act(sample)
print("sample_sensitive.txt ->", a, sorted(set(f)))
leaks = ["Παπαδόπουλος", "123456789", "987654", "15038501234", "Πανεπιστημίου", "5551234",
         "i.papadopoulos", "GR1901101200000001234567890", "8890", "12/28", "345", "2.450,00",
         "υπέρταση", "πενικιλίνη", "Λοσαρτάνη", "Χοληστερόλη", "Hyperion", "P@ssw0rd", "ak_test_",
         "Στασινοπούλου", "Τσιμισκή", "22119004321", "ΞΖ 123456"]
redacted = scan_prompt(sample)["redacted_prompt"]
leaked = [x for x in leaks if x in redacted]
print("leaked values after redaction:", leaked or "none")
# --- Reversible privacy engine: pseudonymize -> AI -> restore ---
from pseudonymizer import Vault, pseudonymize, restore
demo = "Prepare an email for client John Smith.\nHis AFM is 123456789.\nHis account number is 987654321."
v = Vault()
pseudo = pseudonymize(demo, scan_prompt(demo)["entities"], v)
print("pseudonymized:", pseudo.replace("\n", " | "))
expected = "Prepare an email for client [PERSON_001].\nHis AFM is [AFM_001].\nHis account number is [ACCOUNT_001]."
if pseudo != expected: bad += 1; print("PSEUDO MISMATCH")
follow = pseudonymize("Make it shorter for John Smith", scan_prompt("Make it shorter for John Smith")["entities"], v)
if follow != "Make it shorter for [PERSON_001]": bad += 1; print("CONSISTENCY FAIL", follow)
reply = "Dear [PERSON_001],\nYour AFM [AFM_001] and account ACCOUNT_001 are verified."
restored = restore(reply, v)
print("restored:", restored.replace("\n", " | "))
if "John Smith" not in restored or "123456789" not in restored or "987654321" not in restored: bad += 1; print("RESTORE FAIL")
v2 = Vault(); p2 = pseudonymize(sample, scan_prompt(sample)["entities"], v2)
leaked2 = [x for x in leaks if x in p2]
if leaked2: bad += 1; print("PSEUDO LEAK", leaked2)
if restore(p2, v2) != sample: bad += 1; print("ROUND-TRIP FAIL on sample_sensitive.txt")
print("round-trip sample_sensitive.txt:", "ok" if restore(p2, v2) == sample else "FAIL")
sys.exit(1 if bad or a != "BLOCK" or leaked else 0)   # the sample contains an API key -> BLOCK

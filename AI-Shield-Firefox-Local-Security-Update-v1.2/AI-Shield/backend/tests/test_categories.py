"""Coverage of the requested sensitive-data categories (all values are synthetic).

1. PII: ΑΦΜ, ΑΜΚΑ, ταυτότητα (παλιά/νέα), διαβατήριο, Π.Α., όνομα + διεύθυνση/κινητό/email
2. Οικονομικά: IBAN, BIC/SWIFT, κάρτες (PAN/λήξη/CVV), μισθοδοσία, τιμολόγια, φορολογικά, εκκαθαριστικά
3. Υγεία: διαγνώσεις, αγωγή, εξετάσεις, γνωματεύσεις, βιομετρικά & γενετικά
4. Credentials: passwords, AWS/Google/Stripe keys, JWT, Bearer, SSH/PGP keys, DB connection strings
5. Εταιρικά: NDA, συμβάσεις, M&A, αδημοσίευτα δελτία τύπου, emails διοίκησης, πρακτικά ΔΣ
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from scanner import scan_prompt
from policy import evaluate_policy
from pseudonymizer import Vault, pseudonymize, restore

POS = {
 "1 ΑΦΜ": "Ο ΑΦΜ του είναι 094014201", "1 ΑΜΚΑ": "ΑΜΚΑ: 15038501234",
 "1 ΑΔΤ παλιό": "Αρ. ταυτότητας Χ-123456", "1 ΑΔΤ 2 γράμματα": "ταυτότητα ΑΚ 482913",
 "1 Διαβατήριο": "Το διαβατήριό του είναι AB1234567", "1 Διαβ. χωρίς ετικέτα": "στοιχεία ταξιδιού ΑΕ7654321 για την πτήση",
 "1 Π.Α.": "Προσωπικός Αριθμός: 3K7 094 014 201", "1 Π.Α. χωρίς ετικέτα": "ΠΑ πολίτη 3K7094014201",
 "1 Όνομα+διεύθυνση": "Γιώργος Παπαδόπουλος, Πανεπιστημίου 42, Αθήνα",
 "1 Όνομα+κινητό": "Μαρία Κωνσταντίνου 6944123456", "1 Όνομα+email": "Nikos Georgiou - n.georgiou@gmail.com",
 "2 IBAN": "IBAN GR1601101250000000012300695", "2 BIC": "BIC/SWIFT: ETHNGRAA", "2 BIC χωρίς ετικέτα": "μεταφορά μέσω PIRBGRAA",
 "2 SWIFT ξένο": "SWIFT code: DEUTDEFF500", "2 PAN": "κάρτα 4111 1111 1111 1111", "2 Λήξη": "Λήξη: 09/27", "2 CVC": "CVC 512",
 "2 Μισθοδοσία": "Καθαρές αποδοχές: 1.850,40 €",
 "2 Τιμολόγιο": "ΤΙΜΟΛΟΓΙΟ ΠΑΡΟΧΗΣ ΥΠΗΡΕΣΙΩΝ\nΑρ. Τιμολογίου: ΤΠΥ-2026/0142\nΣύνολο: 3.720,00 €",
 "2 Εκκαθαριστικό": "Από το εκκαθαριστικό: φόρος εισοδήματος 2.315,00 ευρώ, πληρωτέο 1.100 €",
 "2 Φορολογική": "Στη φορολογική δήλωση έχω δηλώσει εισόδημα 24.500 €",
 "3 Διάγνωση": "Διάγνωση: διαβήτης τύπου 2", "3 Αγωγή": "Φαρμακευτική αγωγή: μετφορμίνη 850 mg",
 "3 Εξετάσεις": "Αποτελέσματα εξετάσεων: HbA1c 7,2%", "3 Γνωμάτευση": "Επισυνάπτω την ιατρική γνωμάτευση του ορθοπεδικού",
 "3 Γενετικά": "Το τεστ DNA έδειξε μετάλλαξη BRCA1", "3 Δακτυλικά": "Τα δακτυλικά αποτυπώματα των υπαλλήλων αποθηκεύονται στο σύστημα",
 "4 Password": "password: Summer2026!x", "4 AWS key": "AKIAIOSFODNN7EXAMPLE",
 "4 AWS secret": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
 "4 Google": "key=AIzaSyA1234567890abcdefghijklmnopqrstuv", "4 Stripe": "sk_live_51HxYzAbCdEfGhIjKlMn",
 "4 JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
 "4 Bearer": "Authorization: Bearer abcdef1234567890ABCDEF.xyz",
 "4 SSH key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----",
 "4 PGP key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
 "4 DB URI": "mongodb+srv://admin:Pa55word@cluster0.example.net/prod",
 "4 DB ADO": "Server=sql01;Database=crm;User Id=sa;Password=Xy12345!;",
 "5 NDA": "Το NDA που υπογράψαμε με την Alpha ισχύει 3 χρόνια", "5 Σύμβαση": "Τα συμβαλλόμενα μέρη συμφωνούν ότι η αξία σύμβασης ανέρχεται σε 120.000 €",
 "5 M&A": "Σχέδιο εξαγοράς της Beta ΑΕ μέσα στο Q2", "5 Due diligence": "Ολοκληρώθηκε το due diligence για τη συμφωνία",
 "5 Δελτίο τύπου": "Προσχέδιο δελτίου τύπου: η εταιρεία ανακοινώνει νέο CEO", "5 Embargo": "Under embargo until 1 Dec: results Q3",
 "5 Email διοίκησης": "Από: Διευθύνων Σύμβουλος\nΘέμα: Μειώσεις προσωπικού", "5 Πρακτικά ΔΣ": "Στα πρακτικά ΔΣ της 12/11 αποφασίστηκε",
}
NEG = ["Τι είναι το NDA;", "Πώς φτιάχνω ένα τιμολόγιο στο Excel;", "Πόσο κάνει 10 € σε δολάρια;",
 "Εξήγησε τι είναι το DNA", "Τι σημαίνει BIC και SWIFT;", "Γράψε ένα δελτίο τύπου για την έκθεση της Πέμπτης",
 "Explain JWT authentication", "Τι είναι η φορολογική δήλωση;", "Η Αθήνα είναι η πρωτεύουσα της Ελλάδας",
 "Πρότεινε μου ταινίες για το Σαββατοκύριακο", "Ο Νίκος Καζαντζάκης έγραψε τον Ζορμπά", "Γράψε ένα email για συνάντηση την Τρίτη",
 "Τι είναι το due diligence;", "Πώς λειτουργεί η αναγνώριση φωνής;", "Έκανα 10000 βήματα σήμερα"]
NEG += ["Τι πρέπει να περιέχει ένα NDA;", "Ποια είναι τα συμπτώματα του διαβήτη;",
        "Γιατί η εξαγορά της Activision από τη Microsoft πήρε χρόνια;", "Τι είναι το IBAN και πώς δομείται;",
        "Explain how OAuth 2.0 bearer tokens work", "Πώς υπολογίζεται ο ΦΠΑ 24% σε ένα ποσό;",
        "Θέλω ιδέες για δώρο γενεθλίων 50 €", "Η Python 3, η Java και η Go είναι γλώσσες"]
POS.update({"personal health question": "Ποια φάρμακα παίρνω για την υπέρταση που μου διέγνωσαν;",
            "our NDA": "Πώς να απαντήσω στο NDA που μας έστειλαν;",
            "unannounced deal": "Η εξαγορά της Beta ΑΕ θα ανακοινωθεί τον Δεκέμβριο"})

# Regression: an address must not swallow the next line.
_t = "Γιώργος Παπαδόπουλος, Πανεπιστημίου 42, Αθήνα\nΠροσωπικός Αριθμός: 3K7094014201"
_p = pseudonymize(_t, scan_prompt(_t)["entities"], Vault())
if _p.split("\n")[1] != "Προσωπικός Αριθμός: [PA_001]":
    print("ADDRESS CROSSED LINE:", _p); sys.exit(1)

bad = 0
for name, text in POS.items():
    r = scan_prompt(text)
    v = Vault(); p = pseudonymize(text, r["entities"], v)
    if not r["findings"] or p == text or restore(p, v) != text:
        bad += 1; print("MISSED   ", name, [f["type"] for f in r["findings"]])
for text in NEG:
    r = scan_prompt(text)
    if r["findings"]:
        bad += 1; print("FALSE+   ", text, [f["type"] for f in r["findings"]])
print(f"{len(POS)} sensitive cases, {len(NEG)} benign cases, failures: {bad}")
sys.exit(1 if bad else 0)

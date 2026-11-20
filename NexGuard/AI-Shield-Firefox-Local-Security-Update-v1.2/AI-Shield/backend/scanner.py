"""
AI Shield - local, deterministic sensitive-data scanner.

Design
------
1. The prompt is normalised before matching (zero-width characters removed,
   full-width digits/letters folded, accents stripped, Cyrillic/Armenian/Latin
   look-alike letters folded) so simple evasion tricks do not bypass detection.
   Every normalised character maps back to an index in the original text, so
   redaction is always applied to the ORIGINAL prompt.
2. Detectors produce spans. Overlapping spans are resolved by priority
   (more specific detector wins, e.g. IBAN beats AMKA on the same digits).
3. The scanner never returns matched values - only types, severities, counts
   and the positions (entities) of sensitive values, so the caller can replace
   them with reversible pseudonyms such as [PERSON_001].

These are heuristics: they raise the bar a lot, but they are not a guarantee.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Callable

# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u180e"}

# Cyrillic / Armenian look-alikes folded to the Greek letter they imitate.
# Used for the "cased" text that ID / name patterns run on.
CONFUSABLES_TO_GREEK = {
    "А": "Α", "В": "Β", "Е": "Ε", "К": "Κ", "М": "Μ", "Н": "Η", "О": "Ο",
    "Р": "Ρ", "С": "Σ", "Т": "Τ", "Х": "Χ", "а": "α", "е": "ε", "о": "ο",
    "р": "ρ", "х": "χ", "у": "υ", "к": "κ", "Ա": "Α", "ա": "α", "Օ": "Ο",
    "օ": "ο", "Ս": "Σ", "Տ": "Τ",
}

# Skeleton used only for keyword matching: lower-case, Latin look-alikes
# folded onto Greek so "Diagnosis"/"διάγνωση" style keywords and mixed-script
# spellings such as "Αλλεpγία" (Latin p) still match.
LATIN_TO_GREEK_SKELETON = {
    "a": "α", "b": "β", "e": "ε", "i": "ι", "k": "κ", "n": "η", "o": "ο",
    "p": "ρ", "t": "τ", "u": "υ", "v": "ν", "x": "χ", "y": "γ", "z": "ζ",
    "h": "η", "m": "μ", "ς": "σ",
}


def _fold_char(ch: str) -> str:
    """Return a single normalised character ('' to drop it)."""
    if ch in ZERO_WIDTH:
        return ""
    ch = CONFUSABLES_TO_GREEK.get(ch, ch)
    decomposed = unicodedata.normalize("NFKD", ch)
    base = "".join(c for c in decomposed if not unicodedata.combining(c))
    if not base:
        return ""
    # NFKD can expand (e.g. ligatures); keep length 1 so indexes stay aligned.
    return base[0]


def normalise(text: str) -> tuple[str, str, list[int]]:
    """
    Returns (cased, skeleton, index_map) where cased/skeleton have equal length
    and index_map[i] is the index in the original text of normalised char i.
    """
    cased_chars, index_map = [], []
    for i, ch in enumerate(text):
        folded = _fold_char(ch)
        if folded:
            cased_chars.append(folded)
            index_map.append(i)
    cased = "".join(cased_chars)
    skeleton = "".join(LATIN_TO_GREEK_SKELETON.get(c, c) for c in cased.lower())
    if len(skeleton) != len(cased):  # extremely defensive; lower() can expand
        skeleton = "".join(LATIN_TO_GREEK_SKELETON.get(c.lower()[:1] or c, c.lower()[:1] or c)
                           for c in cased)
    return cased, skeleton, index_map


def skel(word: str) -> str:
    """Skeleton form of a keyword (same transform as the text)."""
    return normalise(word)[1]


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def luhn_ok(number: str) -> bool:
    d = _digits(number)
    if not 12 <= len(d) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def afm_ok(value: str) -> bool:
    """Greek tax number (ΑΦΜ) checksum."""
    d = _digits(value)
    if len(d) != 9 or d == "000000000":
        return False
    total = sum(int(d[i]) * (2 ** (8 - i)) for i in range(8))
    return (total % 11) % 10 == int(d[8])


def amka_ok(value: str) -> bool:
    """ΑΜΚΑ = DDMMYY + 5 digits; real ones pass Luhn. Accept plausible dates too."""
    d = _digits(value)
    if len(d) != 11:
        return False
    day, month = int(d[0:2]), int(d[2:4])
    return 1 <= day <= 31 and 1 <= month <= 12


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------
# Each detector: type, severity, priority (higher wins on overlap),
# target ("cased" or "skeleton"), regex, optional validator, optional group
# (only that capture group is redacted).
Detector = dict[str, Any]

SEP = r"[\s.\-]?"
LABEL_SEP = r"[\s\*\_`\"'«»“”()\[\]]*[:=\-–—]?[\s\*\_`\"'«»“”]*"
# Same, but a ':' or '=' is mandatory (for generic words like "token", "name").
LABEL_REQ = r"[\s\*\_`\"'«»“”()\[\]]*[:=][\s\*\_`\"'«»“”]*"


def kw(*words: str) -> str:
    """Alternation of keywords in skeleton form, escaped for regex."""
    return r"(?<![^\W\d_])(?:" + "|".join(re.escape(skel(w)) for w in words) + ")"


DETECTORS: list[Detector] = [
    # ---------------- Secrets & credentials ----------------
    {
        "type": "PRIVATE_KEY", "severity": "critical", "priority": 100, "target": "cased",
        # RSA / EC / DSA / OPENSSH / ENCRYPTED / PGP private keys (.pem, .key, id_rsa ...)
        "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)",
    },
    {
        "type": "API_SECRET", "severity": "critical", "priority": 95, "target": "cased",
        "regex": (
            r"(?<![A-Za-z0-9])(?:"
            r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}"            # OpenAI / Anthropic
            r"|(?:sk|pk|rk|ak)_(?:test|live)_[A-Za-z0-9]{8,}"   # Stripe-style & ak_test_
            r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
            r"|glpat-[A-Za-z0-9_\-]{20,}"
            r"|xox[abposr]-[A-Za-z0-9\-]{10,}"
            r"|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}"
            r"|AIza[A-Za-z0-9_\-]{35}"                          # Google Cloud / Firebase
            r"|ya29\.[A-Za-z0-9_\-]{20,}"                        # Google OAuth access token
            r"|whsec_[A-Za-z0-9]{16,}"                           # Stripe webhook secret
            r"|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"      # SendGrid
            r"|hf_[A-Za-z0-9]{30,}"                              # Hugging Face
            r"|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"  # JWT
            r")"
        ),
    },
    {
        "type": "CONNECTION_STRING", "severity": "critical", "priority": 94, "target": "cased",
        "regex": r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@]+:[^\s@]+@[^\s/]+",
    },
    {   # ADO.NET / ODBC / Azure style: Server=...;User Id=...;Password=...  |  AccountKey=...
        "type": "CONNECTION_STRING", "severity": "critical", "priority": 94, "target": "cased",
        "regex": r"(?i:(?:server|data source|host|endpoint|defaultendpointsprotocol)=[^;\n]+;(?:[^;\n]*;){0,8}?"
                 r"[^;\n]*(?:password|pwd|accountkey|sharedaccesskey)=)[^;\s\n\"']+",
    },
    {   # "Authorization: Bearer <token>" / "Basic <base64>" (no colon after the scheme)
        "type": "API_SECRET", "severity": "critical", "priority": 93, "target": "cased",
        "regex": r"(?i:\b(?:bearer|basic))\s+(?P<v>[A-Za-z0-9\-._~+/]{16,}=*)",
        "group": "v",
    },
    {   # GCP service-account JSON: "private_key_id": "<40 hex>"
        "type": "API_SECRET", "severity": "critical", "priority": 93, "target": "cased",
        "regex": r"\"private_key_id\"\s*:\s*\"(?P<v>[a-f0-9]{40})\"",
        "group": "v",
    },
    {   # "API Key: <anything>", "Token = ...", "Secret: ..."
        "type": "API_SECRET", "severity": "critical", "priority": 93, "target": "skeleton",
        "regex": kw("api key", "api_key", "apikey", "api-key", "access key", "secret key",
                    "client secret", "secret", "token", "bearer", "private key",
                    "aws_secret_access_key", "aws_access_key_id", "stripe key", "jwt", "κλειδι api")
                 + r"[^:\n=]{0,40}?" + LABEL_REQ + r"(?P<v>[^\s`\"'<>]{8,})",
        "group": "v",
    },
    {   # "Password: ...", "Κωδικός Πρόσβασης ...: ...", "pwd=..."
        "type": "PASSWORD", "severity": "critical", "priority": 92, "target": "skeleton",
        "regex": kw("password", "passwd", "pwd", "passcode", "κωδικος προσβασης",
                    "κωδικος προσβασης βασης δεδομενων", "συνθηματικο", "κωδικος χρηστη", "pin")
                 + r"[^:\n=]{0,40}?" + LABEL_REQ + r"(?P<v>[^\s`\"'<>]{4,})",
        "group": "v",
    },
    {   # Strong-password-looking tokens even without a label
        "type": "PASSWORD", "severity": "high", "priority": 40, "target": "cased",
        "regex": r"(?<![\w@])(?=[^\s]*[A-Z])(?=[^\s]*[a-z])(?=[^\s]*\d)(?=[^\s]*[!@#$%^&*_+=?])[^\s`\"'<>]{10,}(?![\w])",
        "validator": lambda v: not re.search(r"@[\w\-]+\.[A-Za-z]{2,}", v),  # not an e-mail
    },

    # ---------------- Financial ----------------
    {
        "type": "IBAN", "severity": "critical", "priority": 90, "target": "cased",
        "regex": r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
        "validator": lambda v: len(re.sub(r"\s", "", v)) >= 15,
    },
    {   # BIC / SWIFT with a label (any country): "BIC: ETHNGRAA", "SWIFT code PIRBGRAA"
        "type": "BIC_SWIFT", "severity": "high", "priority": 91, "target": "skeleton",
        "regex": kw("bic/swift", "bic", "swift code", "swift", "κωδικος swift", "κωδικος bic")
                 + r"[^:\n]{0,15}?" + LABEL_SEP + r"(?P<v>[a-zα-ω]{6}[a-zα-ω0-9]{2}(?:[a-zα-ω0-9]{3})?)(?![\w])",
        "group": "v",
    },
    {   # Unlabelled Greek BIC (country code GR in positions 5-6): ETHNGRAA, PIRBGRAA, ERBKGRAA, CRBAGRAA
        "type": "BIC_SWIFT", "severity": "high", "priority": 90, "target": "cased",
        "regex": r"(?<![A-Za-z0-9])[A-Z]{4}GR[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])",
    },
    {   # Bank account numbers: "account number 987654321", "Αριθμός λογαριασμού: 0026.0123.45"
        "type": "ACCOUNT_NUMBER", "severity": "high", "priority": 89, "target": "skeleton",
        "regex": r"(?:" + kw("account number", "account no", "account", "acct", "bank account",
                             "αριθμος λογαριασμου", "αρ. λογαριασμου", "λογαριασμος", "λογαριασμου")
                 + r")[^:\n\d]{0,30}?" + LABEL_SEP + r"(?P<v>\d[\d\s.\-]{4,28}\d)(?!\d)",
        "group": "v",
    },
    {
        "type": "CREDIT_CARD", "severity": "critical", "priority": 88, "target": "cased",
        "regex": r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)",
        "validator": luhn_ok,
    },
    {   # Masked / partially shown cards: 4532 •••• •••• 8890, 4532-XXXX-XXXX-8890 (not full card data)
        "type": "CARD_MASKED", "severity": "medium", "priority": 87, "target": "cased",
        "regex": r"(?<!\d)\d{4}(?:[ \-]?[•*xX●·#]{4}){1,3}[ \-]?\d{4}(?!\d)",
    },
    {   # Card-number label followed by any digits
        "type": "CREDIT_CARD", "severity": "critical", "priority": 86, "target": "skeleton",
        "regex": kw("αριθμος καρτας", "card number", "credit card", "πιστωτικη καρτα", "χρεωστικη καρτα")
                 + LABEL_SEP + r"(?P<v>[\d •*xX●\-]{8,23}\d)",
        "group": "v",
    },
    {
        "type": "CARD_CVV", "severity": "critical", "priority": 85, "target": "skeleton",
        "regex": r"(?:" + kw("cvv2", "cvv", "cvc", "csc", "κωδικος ασφαλειας", "security code")
                 + r")[^:\n\d]{0,30}?" + LABEL_SEP + r"(?P<v>\d{3,4})(?!\d)",
        "group": "v",
    },
    {
        "type": "CARD_EXPIRY", "severity": "high", "priority": 84, "target": "skeleton",
        "regex": kw("ημερομηνια ληξης", "ληξη", "expiry", "expiration", "exp date", "valid thru", "exp")
                 + LABEL_SEP + r"(?P<v>(?:0[1-9]|1[0-2])\s?/\s?(?:\d{2}|\d{4}))\b",
        "group": "v",
    },
    {   # Invoice / document numbers: "Αρ. Τιμολογίου: ΤΠΥ-2026/0142", "Invoice No. INV-88231"
        "type": "FINANCIAL_DOCUMENT", "severity": "high", "priority": 61, "target": "skeleton",
        "regex": kw("αριθμος τιμολογιου", "αρ. τιμολογιου", "αρ τιμολογιου", "αριθμος παραστατικου",
                    "αρ. παραστατικου", "invoice number", "invoice no", "invoice #", "αρ. δηλωσης",
                    "αριθμος δηλωσης", "αρ. εκκαθαριστικου")
                 + LABEL_SEP + r"(?P<v>[a-zα-ω0-9][a-zα-ω0-9/\-.]{2,24})",
        "group": "v",
    },
    {   # Amounts inside financial documents (invoices, tax returns, assessments, payslips):
        # only when such a document keyword is within ~300 characters, so "how much is 10 €?" passes.
        "type": "FINANCIAL_DOCUMENT", "severity": "high", "priority": 59, "target": "skeleton",
        "regex": r"(?:€\s?\d[\d.,]*\d|\d[\d.,]*\d\s?(?:€|" + kw("eur", "ευρω") + r"))",
        "context": kw("τιμολογιο", "τιμολογιου", "τιμολογια", "invoice", "παραστατικο", "αποδειξη πληρωμης", "receipt",
       "φορολογικη δηλωση", "φορολογικης δηλωσης", "εντυπο ε1", "εντυπο ε9", "εκκαθαριστικο", "εκκαθαριστικου",
       "tax return", "payslip", "pay slip", "μισθοδοσια", "μισθοδοτικη", "βεβαιωση αποδοχων", "ενφια",
       "φορος εισοδηματος", "φορολογητεο", "πληρωτεο ποσο", "πληρωτεο", "συνολο πληρωμης", "αξια χωρις φπα",
       "φπα 24", "καθαρη αξια"), "proximity": 300,
    },
    {   # Salary / payroll amounts
        "type": "FINANCIAL_SALARY", "severity": "high", "priority": 60, "target": "skeleton",
        "regex": kw("μικτες αποδοχες", "καθαρες αποδοχες", "καθαρη πληρωμη", "κρατησεις φορου",
                    "κρατησεις", "αποδοχες", "μισθος", "μισθοδοσια", "salary", "gross pay",
                    "net pay", "payroll", "bonus")
                 + r"[^:\n\d]{0,30}?" + LABEL_SEP
                 + r"(?P<v>(?:€|" + kw("eur", "ευρω") + r")?\s?\d[\d.,\s]*\d(?:\s?(?:€|" + kw("eur", "ευρω") + r"))?)",
        "group": "v",
    },

    # ---------------- Greek national identifiers ----------------
    {   # Προσωπικός Αριθμός (Π.Α., 2025+): 12 characters = 3 alphanumeric + the 9-digit ΑΦΜ
        "type": "PERSONAL_NUMBER", "severity": "high", "priority": 86, "target": "skeleton",
        "regex": r"(?:" + kw("προσωπικος αριθμος", "π.α.", "personal number") + r")[^:\n\d]{0,20}?"
                 + LABEL_SEP + r"(?P<v>[a-zα-ω0-9]{3}\s?\d{3}\s?\d{3}\s?\d{3})(?![\w])",
        "group": "v",
    },
    {   # Unlabelled Π.Α.: 3 alphanumeric (at least one letter) + 9 digits that pass the ΑΦΜ checksum
        "type": "PERSONAL_NUMBER", "severity": "high", "priority": 85, "target": "cased",
        "regex": r"(?<![A-Za-z0-9Α-Ωα-ω])(?=[A-Z0-9Α-Ω]{0,2}[A-ZΑ-Ω])[A-Z0-9Α-Ω]{3}\d{9}(?![\w])",
        "validator": lambda v: afm_ok(v[3:]),
    },
    {   # Labelled ΑΦΜ - any 9 digits, even if checksum fails (test data)
        "type": "AFM", "severity": "high", "priority": 83, "target": "skeleton",
        "regex": r"(?:" + kw("αφμ", "afm", "α.φ.μ", "αριθμος φορολογικου μητρωου", "vat number", "tax id")
                 + r")[^:\n\d]{0,40}?" + LABEL_SEP + r"(?P<v>(?:el|gr)?\s?\d{3}\s?\d{3}\s?\d{3})(?!\d)",
        "group": "v",
    },
    {   # Unlabelled 9-digit number: block (conservative), stronger if checksum OK
        "type": "AFM", "severity": "high", "priority": 30, "target": "cased",
        "regex": r"(?<![\d,.])\d{9}(?![\d,])",
    },
    {
        "type": "AMKA", "severity": "high", "priority": 82, "target": "skeleton",
        "regex": r"(?:" + kw("αμκα", "α.μ.κ.α", "αριθμος μητρωου κοινωνικης ασφαλισης", "social security", "ssn")
                 + r")[^:\n\d]{0,40}?" + LABEL_SEP + r"(?P<v>\d[\d\s\-]{8,13}\d)",
        "group": "v",
    },
    {
        "type": "AMKA", "severity": "high", "priority": 31, "target": "cased",
        "regex": r"(?<![\d,.])\d{11}(?![\d,])",
        "validator": amka_ok,
    },
    {   # Greek passport: 2 capital letters + 7 digits (AB1234567). Greek look-alike letters accepted.
        "type": "PASSPORT", "severity": "high", "priority": 82, "target": "cased",
        "regex": r"(?<![^\W\d_])[A-ZΑ-Ω]{2}[ \-]?\d{7}(?![\d])",
    },
    {   # Labelled passport number (any country format)
        "type": "PASSPORT", "severity": "high", "priority": 82, "target": "skeleton",
        "regex": r"(?:" + kw("αριθμος διαβατηριου", "αρ. διαβατηριου", "διαβατηριο", "passport number",
                             "passport no", "passport") + r")[^:\n\d]{0,20}?" + LABEL_SEP
                 + r"(?P<v>[a-zα-ω0-9]{1,3}\s?\d{5,9})(?![\w])",
        "group": "v",
    },
    {   # Greek ID card: ΑΒ 987654 / AB-123456 / Χ 123456 (Greek or Latin letters)
        "type": "ID_CARD", "severity": "high", "priority": 81, "target": "cased",
        "regex": r"(?<![^\W\d_])[Α-ΩA-Z]{1,2}[ \-]?\d{6}(?!\d)",
    },
    {
        "type": "ID_CARD", "severity": "high", "priority": 80, "target": "skeleton",
        "regex": r"(?:" + kw("αριθμος δελτιου ταυτοτητας", "δελτιο ταυτοτητας", "αδτ", "α.δ.τ",
                             "αριθμος ταυτοτητας", "id card", "identity card", "card number",
                             "αριθμος διπλωματος", "driving licence", "driver license")
                 + r")[^:\n\d]{0,30}?" + LABEL_SEP + r"(?P<v>[^\s,;]{1,3}\s?\d{5,9})",
        "group": "v",
    },

    # ---------------- Contact / location ----------------
    {
        "type": "EMAIL", "severity": "medium", "priority": 70, "target": "cased",
        "regex": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    },
    {   # Greek phones: +30 / 0030 optional, landline 2xx, mobile 69x
        "type": "PHONE", "severity": "medium", "priority": 65, "target": "cased",
        "regex": r"(?<![\d+])(?:(?:\+|00)30[\s.\-]?)?(?:2\d|69)\d(?:[\s.\-]?\d){7}(?!\d)",
    },
    {   # Other international numbers
        "type": "PHONE", "severity": "medium", "priority": 64, "target": "cased",
        "regex": r"(?<![\d\w])\+\d{1,3}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){2,4}\d{2,4}(?!\d)",
        "validator": lambda v: 9 <= len(_digits(v)) <= 15,
    },
    {   # Greek street address: Οδός Πανεπιστημίου 42, Λεωφ. Κηφισίας 12
        "type": "ADDRESS", "severity": "medium", "priority": 62, "target": "skeleton",
        "regex": r"(?:" + kw("οδος", "οδ.", "λεωφορος", "λεωφ.", "πλατεια", "πλ.", "street", "st.",
                             "avenue", "ave.", "road", "διευθυνση κατοικιας", "διευθυνση")
                 + r")" + LABEL_SEP + r"(?P<v>[^\n,;:]{2,40}?\s\d{1,4}[a-zα-ω]?\b(?:,?\s*(?:" + kw("τ.κ.", "τκ", "τ.κ")
                 + r")?\s*\d{3}\s?\d{2})?(?:,\s*[^\n,;]{2,30})?)",
        "group": "v",
    },
    {   # Unlabelled Greek street address: street in genitive + number + city or postcode
        "type": "ADDRESS", "severity": "medium", "priority": 60, "target": "cased",
        "regex": r"(?<![^\W\d_])(?:[Α-Ω][α-ω]+ )?[Α-Ω][α-ω]{2,}(?:ου|ων|ας|ης|ους|η)\s\d{1,4}[Α-Ωα-ωA-Za-z]?"
                 r",[ \t]*(?:(?:Τ\.?[ ]?Κ\.?[ ]*)?\d{3}[ ]?\d{2}|[Α-Ω][α-ω]{3,}(?:[ ][Α-Ω][α-ω]+)?)",
    },
    {
        "type": "ADDRESS", "severity": "medium", "priority": 61, "target": "skeleton",
        "regex": r"(?:" + kw("τ.κ.", "τ.κ", "τκ", "ταχυδρομικος κωδικας", "postal code", "zip")
                 + r")" + LABEL_SEP + r"(?P<v>\d{3}\s?\d{2})(?!\d)",
        "group": "v",
    },

    # ---------------- Names (label-based) ----------------
    {
        "type": "PERSON_NAME", "severity": "medium", "priority": 55, "target": "skeleton",
        "regex": r"(?:" + kw("ονοματεπωνυμο", "ονομα", "επωνυμο", "ασθενης", "πελατης", "υπαλληλος",
                             "εργαζομενος", "full name", "name", "patient", "customer", "employee")
                 + r")" + LABEL_REQ + r"(?P<v>[^\W\d_]{2,}(?:[ \-][^\W\d_]{2,}){1,3})",
        "group": "v",
    },

    {   # Role words without a colon: "client John Smith", "Dear Maria Papadopoulou",
        # "πελάτη Γιάννη Παπαδόπουλο". Requires 2-3 capitalised words.
        "type": "PERSON_NAME", "severity": "medium", "priority": 54, "target": "cased",
        "regex": r"(?<![^\W\d_])(?i:client|customer|patient|employee|colleague|dear|for user|"
                 r"πελατη|πελατης|πελατισσα|ασθενη|ασθενης|υπαλληλο|υπαλληλος|συναδελφο|συναδελφος|"
                 r"αγαπητε|αγαπητη)\s+(?P<v>[A-ZΑ-Ω][a-zα-ω]+(?:[ \-][A-ZΑ-Ω][a-zα-ω]+){1,2})",
        "group": "v",
    },
    {   # Honorifics: "Mr Smith", "Dr. John Smith", "κ. Παπαδόπουλος", "κος Ιωάννου"
        "type": "PERSON_NAME", "severity": "medium", "priority": 53, "target": "cased",
        "regex": r"(?<![^\W\d_])(?:Mr|Mrs|Ms|Miss|Dr|κ|κος|κα|Κος|Κα|κυριος|κυρια|Κυριος|Κυρια|κυριο|Κυριο)\.?\s+"
                 r"(?P<v>[A-ZΑ-Ω][a-zα-ω]+(?:[ \-][A-ZΑ-Ω][a-zα-ω]+){0,2})",
        "group": "v",
    },

    # ---------------- Health (GDPR Art. 9) ----------------
    {   # Lab values / dosages
        "type": "HEALTH_DATA", "severity": "critical", "priority": 56, "target": "skeleton",
        "regex": r"\b\d+(?:[.,]\d+)?\s?(?:" + "|".join(re.escape(skel(u)) for u in
                 ["mg/dl", "mmol/l", "mmhg", "mcg", "μg", "mg", "ml", "iu"]) + r")(?![^\W\d_])",
    },
    {   # Medical keywords - redact the whole line they occur in
        "type": "HEALTH_DATA", "severity": "critical", "priority": 57, "target": "skeleton",
        "regex": r"[^\n]*" + kw(
            "διαγνωση", "ιστορικο υγειας", "κατασταση υγειας", "ασθενεια", "νοσος", "υπερταση",
            "αλλεργια", "φαρμακευτικη αγωγη", "φαρμακ", "χοληστερολ", "διαβητ", "καρκιν", "ογκο",
            "καταθλιψ", "αγχωδ", "ψυχιατρ", "ψυχοθεραπ", "εγκυμοσυν", "hiv", "aids", "ηπατιτιδ",
            "αποτελεσματα εξετασεων", "εξετασεις αιματος", "νοσηλει", "χειρουργ", "αναπηρι",
            "πενικιλιν", "ινσουλιν", "λοσαρταν", "diagnosis", "diagnosed", "medical history",
            "medication", "prescription", "allergy", "hypertension", "diabetes", "cancer",
            "depression", "blood test", "cholesterol", "pregnan", "disability",
            "ιατρικη γνωματευση", "γνωματευση", "ιατρικη βεβαιωση", "εργαστηριακ", "αποτελεσμα εξετασ",
            "μικροβιολογικ", "ακτινογραφι", "μαγνητικη τομογραφ", "αξονικη τομογραφ", "βιοψι",
            "παραπεμπτικ", "συνταγογραφ", "χημειοθεραπ", "αντιβιοτικ", "θεραπευτικη αγωγη",
            "lab result", "medical report", "treatment plan", "chemotherapy", "biopsy",
        ) + r"[^\n]*",
    },
    {   # Biometric & genetic data (GDPR Art. 9) - whole line
        "type": "BIOMETRIC_DATA", "severity": "critical", "priority": 58, "target": "skeleton",
        "regex": r"[^\n]*" + kw(
            "γενετικ", "γονιδι", "γονιδιωμ", "dna", "αλληλουχησ", "brca", "genetic", "genome",
            "δακτυλικο αποτυπωμα", "δακτυλικα αποτυπωματα", "δακτυλικων αποτυπωματων", "fingerprints",
            "fingerprint scan", "biometric", "βιομετρικ", "αναγνωριση προσωπου", "facial recognition",
            "σαρωση ιριδας", "iris scan", "φωνητικο αποτυπωμα", "voiceprint",
        ) + r"[^\n]*",
    },

    # ---------------- Corporate confidential ----------------
    {
        "type": "CONFIDENTIAL", "severity": "high", "priority": 50, "target": "skeleton",
        "regex": r"[^\n]*" + kw(
            "confidential", "εμπιστευτικ", "απορρητ", "internal only", "εσωτερικη χρηση",
            "μονο για εσωτερικη", "do not distribute", "αναδιαρθρωσ", "restructuring",
            "απολυσεις", "layoff", "trade secret", "εμπορικο μυστικο",
        ) + r"[^\n]*",
    },
    {   # Contracts, NDAs, M&A - phrases that appear in the documents themselves (whole line)
        "type": "LEGAL_DOCUMENT", "severity": "high", "priority": 51, "target": "skeleton",
        "regex": r"[^\n]*" + kw(
            "nda", "non-disclosure", "συμφωνητικο εμπιστευτικοτητας", "συμφωνια εμπιστευτικοτητας",
            "συμφωνια εχεμυθειας", "ρητρα εχεμυθειας", "συμβαλλομεν", "αντισυμβαλλομεν", "εφεξης καλουμεν",
            "hereinafter", "the parties agree", "this agreement is made", "governing law", "αξια συμβασης",
            "contract value", "μισθωτηριο", "συμβαση παροχης υπηρεσιων", "συμβαση προμηθειας",
            "term sheet", "letter of intent", "due diligence", "μνημονιο συνεννοησης",
            "memorandum of understanding", "share purchase agreement", "εξαγορα", "acquisition", "merger",
            "συγχωνευσ", "αποτιμηση της εταιρ", "valuation of",
        ) + r"[^\n]*",
    },
    {   # Internal communications: unpublished press releases, board/management mail, memos (whole line)
        "type": "INTERNAL_COMMS", "severity": "high", "priority": 52, "target": "skeleton",
        "regex": r"[^\n]*" + kw(
            "προσχεδιο δελτιου τυπου", "σχεδιο δελτιου τυπου", "draft press release", "embargo",
            "δεν εχει ανακοινωθει", "μη δημοσιευμεν", "πριν την ανακοινωση", "πριν απο την ανακοινωση",
            "not yet announced", "before the announcement", "εσωτερικο σημειωμα", "internal memo",
            "πρακτικα δσ", "πρακτικα του δσ", "πρακτικα διοικητικου συμβουλιου", "συνεδριαση δσ",
            "συνεδριαση του διοικητικου", "board meeting", "board minutes", "μονο για τη διοικηση",
            "management only", "executive committee",
        ) + r"[^\n]*",
    },
    {   # E-mail headers from/to top management: "From: CEO", "Από: Διευθύνων Σύμβουλος"
        "type": "INTERNAL_COMMS", "severity": "high", "priority": 52, "target": "skeleton",
        "regex": r"(?m)^[^\S\n]*" + kw("from", "to", "cc", "subject", "απο", "προς", "κοινοποιηση", "θεμα")
                 + r"\s*:[^\n]*" + kw("ceo", "cfo", "coo", "cto", "board", "διευθυνων συμβουλος",
                                         "διευθυνουσα συμβουλος", "γενικος διευθυντης", "διοικητικο συμβουλιο",
                                         "δσ", "διοικηση") + r"[^\n]*",
    },
    {   # Project "Hyperion", Project Hyperion, Έργο «Ήλιος»
        "type": "CONFIDENTIAL", "severity": "high", "priority": 49, "target": "cased",
        "regex": r"(?i:project|codename|code name|έργο|εργο)\s*[\"'«“]?[A-ZΑ-Ω][\w\-]+[\"'»”]?",
    },
]

for _d in DETECTORS:
    _d["compiled"] = re.compile(_d["regex"], 0 if _d["target"] == "cased" else re.IGNORECASE)
    if "context" in _d:   # optional: keep a match only if this keyword is nearby (skeleton text)
        _d["context_re"] = re.compile(_d["context"], re.IGNORECASE)

# Whole-line categories: still counted when a more specific span overlaps them.
LINE_TYPES = {"HEALTH_DATA", "BIOMETRIC_DATA", "CONFIDENTIAL", "LEGAL_DOCUMENT", "INTERNAL_COMMS"}

# A full name written next to a contact detail or national identifier
# ("Γιώργος Παπαδόπουλος, Πανεπιστημίου 42, 6912345678") is personal data even without a label.
NAME_ANCHORS = {"EMAIL", "PHONE", "ADDRESS", "AFM", "AMKA", "ID_CARD", "PASSPORT", "PERSONAL_NUMBER", "IBAN"}
NAME_RE = re.compile(r"(?<![^\W\d_])[A-ZΑ-Ω][a-zα-ως]{1,}(?:[ \-][A-ZΑ-Ω][a-zα-ως]{1,}){1,2}(?![^\W\d_])")
NAME_STOPWORDS = {skel(w) for w in (
    "οδος", "οδου", "λεωφορος", "λεωφορου", "πλατεια", "τηλεφωνο", "κινητο", "email", "διευθυνση",
    "αφμ", "αμκα", "iban", "αθηνα", "θεσσαλονικη", "πειραιας", "πατρα", "ηρακλειο", "λαρισα",
    "ελλαδα", "greece", "athens", "street", "avenue", "road", "dear", "hello", "αγαπητε", "αγαπητη",
    "γεια", "καλημερα", "προς", "θεμα", "subject", "mobile", "phone", "τ.κ", "τκ", "national", "bank",
    "τραπεζα", "πειραιως", "eurobank", "alpha", "εθνικη", "account", "card", "αριθμος", "προσωπικος",
    "ταυτοτητα", "ταυτοτητας", "διαβατηριο", "ονομα", "επωνυμο", "ονοματεπωνυμο", "κωδικος",
    "λογαριασμος", "στοιχεια", "πελατης", "πελατη", "personal", "number", "name")}

# Short definitional questions ("Τι είναι το NDA;", "Explain what DNA is") are about a TOPIC,
# not about someone's data: whole-line categories ignore them unless they contain personal
# markers or numbers ("Τι σημαίνει η διάγνωση που μου έκαναν;" is still caught).
GENERIC_QUESTION = re.compile(
    r"^\s*(?:" + "|".join(re.escape(skel(w)) for w in (
        "τι ειναι", "τι σημαινει", "τι ειναι το", "τι ειναι η", "εξηγησε", "εξηγησε μου", "περιγραψε",
        "πως λειτουργει", "πως λειτουργουν", "ποια ειναι η διαφορα", "ορισμος", "what is", "what are",
        "what does", "explain", "define", "how does", "how do", "τι πρεπει", "τι περιεχει", "πως",
        "ποια", "ποιο", "ποιες", "ποιοι", "γιατι", "how", "which", "why")) + r")\b", re.IGNORECASE)
PERSONAL_MARKERS = re.compile(
    r"(?<![^\W\d_])(?:" + "|".join(re.escape(skel(w)) for w in (
        "μου", "μας", "μοι", "εχω", "εχουμε", "μου εκαναν", "υπογραψαμε", "μας", "δικο μου", "δικη μου",
        "my", "our", "we have", "i have", "attached", "επισυναπτω", "παρακατω", "below")) + r")(?![^\W\d_])"
    r"|\d", re.IGNORECASE)


def _generic_question(line: str) -> bool:
    return len(line) <= 90 and bool(GENERIC_QUESTION.search(line)) and not PERSONAL_MARKERS.search(line)

# --------------------------------------------------------------------------
# Prompt injection & source code (kept as WARN-level signals)
# --------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions\b",
    r"\b(disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions\b",
    r"\b(reveal|print|show|disclose|expose)\s+(?:the\s+)?(?:system prompt|hidden instructions|developer message)\b",
    r"\b(?:system prompt|developer message)\b.{0,80}\b(?:reveal|print|show|ignore|override)\b",
    r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken)\s+(?:AI|assistant|model)\b",
    r"αγνοησε\s+(?:ολεσ\s+)?(?:τισ\s+)?(?:προηγουμενεσ|παραπανω)\s+οδηγιεσ",  # skeleton form
]
COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

SOURCE_CODE_PATTERN = re.compile(
    r"\b(def\s+\w+\s*\(|class\s+\w+\s*[:({]|SELECT\s+.+\s+FROM|import\s+\w+|function\s+\w+\s*\()",
    re.IGNORECASE,
)

SENSITIVE_TYPES = {d["type"] for d in DETECTORS}

# Prefix used for reversible pseudonyms, e.g. PERSON_NAME -> [PERSON_001].
TOKEN_PREFIX = {
    "PERSON_NAME": "PERSON", "AFM": "AFM", "AMKA": "AMKA", "ID_CARD": "ID",
    "EMAIL": "EMAIL", "PHONE": "PHONE", "ADDRESS": "ADDRESS", "IBAN": "IBAN",
    "ACCOUNT_NUMBER": "ACCOUNT", "CREDIT_CARD": "CARD", "CARD_CVV": "CVV",
    "CARD_EXPIRY": "CARD_EXPIRY", "FINANCIAL_SALARY": "AMOUNT", "API_SECRET": "SECRET",
    "PASSWORD": "PASSWORD", "PRIVATE_KEY": "PRIVATE_KEY", "CONNECTION_STRING": "CONNECTION",
    "HEALTH_DATA": "HEALTH", "CONFIDENTIAL": "CONFIDENTIAL",
    "PASSPORT": "PASSPORT", "PERSONAL_NUMBER": "PA", "BIC_SWIFT": "BIC", "CARD_MASKED": "CARD",
    "FINANCIAL_DOCUMENT": "FIN_DOC", "BIOMETRIC_DATA": "BIOMETRIC",
    "LEGAL_DOCUMENT": "LEGAL", "INTERNAL_COMMS": "INTERNAL",
}


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------
def _collect_spans(cased: str, skeleton: str, index_map: list[int]) -> list[dict[str, Any]]:
    candidates = []
    for det in DETECTORS:
        text = cased if det["target"] == "cased" else skeleton
        validator: Callable[[str], bool] | None = det.get("validator")
        group = det.get("group")
        context_re = det.get("context_re")
        for m in det["compiled"].finditer(text):
            start, end = (m.span(group) if group else m.span())
            if context_re is not None:
                window = skeleton[max(0, start - det.get("proximity", 300)): end + 80]
                if not context_re.search(window):
                    continue
            if start < 0 or end <= start:
                continue
            value = cased[start:end]
            if not value.strip():
                continue
            if det["type"] in LINE_TYPES:
                ls = skeleton.rfind("\n", 0, start) + 1
                le = skeleton.find("\n", end - 1 if end > start else end)
                if _generic_question(skeleton[ls: le if le != -1 else len(skeleton)]):
                    continue
            if validator and not validator(value):
                continue
            # trim whitespace so redaction is tidy
            while start < end and cased[start].isspace():
                start += 1
            while end > start and cased[end - 1].isspace():
                end -= 1
            orig_start = index_map[start]
            orig_end = index_map[end - 1] + 1
            candidates.append({
                "type": det["type"], "severity": det["severity"],
                "priority": det["priority"], "start": orig_start, "end": orig_end,
            })

    # Names on the same line as (or the line just before) an identifier / contact detail.
    anchor_lines = set()
    line_of = lambda pos: cased.count("\n", 0, pos)
    orig_to_norm = {o: n for n, o in enumerate(index_map)}
    for c in candidates:
        if c["type"] in NAME_ANCHORS:
            ln = line_of(orig_to_norm.get(c["start"], 0))
            anchor_lines.update({ln, ln - 1})
    if anchor_lines:
        for m in NAME_RE.finditer(cased):
            if line_of(m.start()) not in anchor_lines:
                continue
            if any(skel(w) in NAME_STOPWORDS for w in re.split(r"[ \-]", m.group())):
                continue
            if cased[m.end():m.end() + 3].lstrip().startswith(":"):   # it is a label, not a name
                continue
            candidates.append({"type": "PERSON_NAME", "severity": "medium", "priority": 52,
                               "start": index_map[m.start()], "end": index_map[m.end() - 1] + 1})

    # Higher priority first, then longer spans; keep non-overlapping.
    candidates.sort(key=lambda c: (-c["priority"], -(c["end"] - c["start"])))
    chosen: list[dict[str, Any]] = []
    for c in candidates:
        if any(c["start"] < k["end"] and k["start"] < c["end"] for k in chosen):
            # Overlap with a higher-priority span. Still count line-level
            # categories (health/confidential) so the finding is not lost.
            if c["type"] in LINE_TYPES and not any(
                    k["type"] == c["type"] and c["start"] < k["end"] and k["start"] < c["end"]
                    for k in chosen):
                c = {**c, "shadow": True}
                chosen.append(c)
            continue
        chosen.append(c)
    return chosen


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def scan_prompt(prompt: str) -> dict[str, Any]:
    """Scan locally; never return matched values or persist raw prompt text."""
    cased, skeleton, index_map = normalise(prompt)
    spans = _collect_spans(cased, skeleton, index_map)

    # Aggregate findings by type
    agg: dict[str, dict[str, Any]] = {}
    for s in spans:
        f = agg.setdefault(s["type"], {"type": s["type"], "severity": s["severity"], "count": 0})
        f["count"] += 1
        if SEVERITY_RANK[s["severity"]] > SEVERITY_RANK[f["severity"]]:
            f["severity"] = s["severity"]
    findings = sorted(agg.values(), key=lambda f: (-SEVERITY_RANK[f["severity"]], f["type"]))

    # Positions of every value to hide (skip "shadow" spans inside other spans).
    # Offsets are Unicode code points in the ORIGINAL prompt. Values are not returned:
    # the caller already holds the text and builds its own reversible mapping.
    entities = sorted(
        ({"type": s["type"], "token_type": TOKEN_PREFIX.get(s["type"], s["type"]),
          "start": s["start"], "end": s["end"]}
         for s in spans if not s.get("shadow")),
        key=lambda e: e["start"],
    )

    # Irreversible fallback (used for AI responses and legacy clients).
    redacted = prompt
    for e in reversed(entities):
        redacted = redacted[:e["start"]] + f"[REDACTED:{e['type']}]" + redacted[e["end"]:]

    injection_spans = {m.span() for p in COMPILED_INJECTION for m in p.finditer(skeleton)}
    injection_spans |= {m.span() for p in COMPILED_INJECTION for m in p.finditer(cased)}
    if injection_spans:
        findings.append({"type": "PROMPT_INJECTION", "severity": "high", "count": len(injection_spans)})

    source_matches = list(SOURCE_CODE_PATTERN.finditer(cased))
    if source_matches:
        findings.append({"type": "SOURCE_CODE", "severity": "medium", "count": len(source_matches)})

    return {
        "has_sensitive_data": any(f["type"] in SENSITIVE_TYPES for f in findings),
        "findings": findings,
        "redacted_prompt": redacted,
        "entities": entities,
    }

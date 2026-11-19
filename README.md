# NexGuard

**AI Security, Data Loss Prevention (DLP) και Shadow AI Governance**

Το NexGuard είναι μια πλατφόρμα προστασίας και εποπτείας της χρήσης υπηρεσιών τεχνητής νοημοσύνης. Συνδυάζει έλεγχο ευαίσθητων δεδομένων πριν από την αποστολή τους σε AI υπηρεσίες, πολιτικές DLP, reversible pseudonymization, καταγραφή περιστατικών και αναγνώριση χρήσης μη εγκεκριμένων AI εργαλείων (Shadow AI).

Η έκδοση του παρόντος πακέτου είναι **NexGuard v1.9.2**. Το backend δηλώνει έκδοση API `2.0.0`, ενώ τα manifests της browser extension δηλώνουν έκδοση `1.5.1`.

> **Σημαντικό:** Το NexGuard αποτελεί τεχνική βάση προστασίας και demo/hackathon implementation, όχι πιστοποιημένο ή πλήρες enterprise DLP προϊόν. Ο έλεγχος βασίζεται σε κανόνες και heuristics και δεν εγγυάται τον εντοπισμό κάθε ευαίσθητου δεδομένου ή κάθε τρόπου διαρροής.

---

## Περιεχόμενα

- [Βασικές δυνατότητες](#βασικές-δυνατότητες)
- [Αρχιτεκτονική](#αρχιτεκτονική)
- [Τεχνολογίες](#τεχνολογίες)
- [Γρήγορη εκκίνηση](#γρήγορη-εκκίνηση)
- [Ρύθμιση περιβάλλοντος](#ρύθμιση-περιβάλλοντος)
- [Πρόσβαση στην εφαρμογή](#πρόσβαση-στην-εφαρμογή)
- [DLP και πολιτικές προστασίας](#dlp-και-πολιτικές-προστασίας)
- [Browser Extension και Prompt Guard](#browser-extension-και-prompt-guard)
- [Reversible Pseudonymization](#reversible-pseudonymization)
- [PDF Inspection](#pdf-inspection)
- [Shadow AI Radar](#shadow-ai-radar)
- [Incident Investigation και Intelligence](#incident-investigation-και-intelligence)
- [API](#api)
- [Δομή project](#δομή-project)
- [Τοπική ανάπτυξη χωρίς Docker](#τοπική-ανάπτυξη-χωρίς-docker)
- [Έλεγχοι και tests](#έλεγχοι-και-tests)
- [Ασφάλεια και ιδιωτικότητα](#ασφάλεια-και-ιδιωτικότητα)
- [Περιορισμοί](#περιορισμοί)
- [Troubleshooting](#troubleshooting)

---

## Βασικές δυνατότητες

### 1. AI Data Protection / DLP
- Έλεγχος prompts για προσωπικά, οικονομικά, ιατρικά και εταιρικά ευαίσθητα δεδομένα.
- Πολιτική ενεργειών `ALLOW`, `WARN`, `REDACT` και `BLOCK`.
- Εφαρμογή της αυστηρότερης ενέργειας όταν εντοπίζονται πολλαπλές κατηγορίες δεδομένων.
- Καταγραφή συμβάντων με κατηγορίες και πλήθος ευρημάτων, χωρίς αποθήκευση του αρχικού prompt.

### 2. Browser Prompt Guard
- Browser extension για ChatGPT, Gemini και Claude.
- Έλεγχος του prompt πριν από την αποστολή του.
- Επικοινωνία με το τοπικό NexGuard backend.
- Fail-closed συμπεριφορά όταν ο έλεγχος ή η επικοινωνία αποτυγχάνει.
- Επιβεβαίωση από τον χρήστη για περιπτώσεις `WARN`.

### 3. Reversible Pseudonymization
- Αντικατάσταση επιλεγμένων προσωπικών ή οικονομικών στοιχείων με tokens, όπως `[AFM_001]`.
- Διατήρηση αντιστοίχισης τιμών και tokens τοπικά στο browser session.
- Επαναφορά των πραγματικών τιμών στις απαντήσεις που εμφανίζονται στον χρήστη, όπου αυτό είναι εφικτό.
- Τα πραγματικά δεδομένα και το pseudonym vault δεν αποστέλλονται στο backend ως mapping.

### 4. PDF Inspection
- Έλεγχος συνημμένων PDF πριν προωθηθούν στην AI υπηρεσία.
- Εξαγωγή κειμένου και εφαρμογή της ίδιας DLP πολιτικής.
- Απόρριψη αρχείων όταν δεν μπορούν να ελεγχθούν με ασφάλεια.

### 5. Shadow AI Radar
- Αναγνώριση επισκέψεων σε γνωστά AI domains.
- Inventory AI εργαλείων και κατάσταση έγκρισης.
- Ομαδοποίηση συμβάντων ανά ομάδα/team label.
- Χρήση συνθετικών δεδομένων για demonstrations.

### 6. Dashboards και Incident Management
- User Dashboard με Secure AI Chat και δυνατότητα λήψης extension.
- Admin Console για διαχείριση χρηστών.
- Technical Dashboard για περιστατικά, DLP intelligence και Shadow AI.
- Ροή διερεύνησης περιστατικών με ιστορικό ενεργειών αναλυτών.

### 7. Authentication
- Σύνδεση χρηστών και διαχειριστών.
- Πρόσκληση χρηστών από το Admin Console.
- Επαναφορά κωδικού μέσω email, εφόσον έχει ρυθμιστεί SMTP.
- Προαιρετικό Google Sign-In με OAuth.

---

## Αρχιτεκτονική

```text
                    ┌────────────────────────────┐
                    │       Web Browser          │
                    │                            │
                    │ Public Website / Login     │
                    │ User Dashboard             │
                    │ Admin & Technical Dashboard│
                    │ Browser Extension          │
                    └──────────────┬─────────────┘
                                   │
                                   │ HTTP / REST
                                   ▼
                    ┌────────────────────────────┐
                    │      FastAPI Backend       │
                    │                            │
                    │ Authentication             │
                    │ Prompt Scanner             │
                    │ DLP Policy Engine          │
                    │ Pseudonymization           │
                    │ PDF Text Extraction        │
                    │ Shadow AI API              │
                    │ Incident & Intelligence    │
                    │ AI Gateway (Gemini)        │
                    └──────────────┬─────────────┘
                                   │
                       ┌───────────┴───────────┐
                       ▼                       ▼
             ┌─────────────────┐     ┌─────────────────┐
             │  PostgreSQL 16  │     │ Google Gemini   │
             │                 │     │ API (optional)  │
             │ Users           │     │                 │
             │ Incidents       │     │ Secure AI Chat  │
             │ Shadow AI       │     └─────────────────┘
             │ Audit Activity  │
             └─────────────────┘
```

Η browser extension επικοινωνεί με το backend για τον έλεγχο των prompts και την αποστολή metadata του Shadow AI Radar. Η αντιστοίχιση πραγματικών τιμών και pseudonyms διατηρείται τοπικά στην extension.

---

## Τεχνολογίες

| Επίπεδο | Τεχνολογία |
|---|---|
| Backend | Python 3.12, FastAPI |
| Database | PostgreSQL 16 |
| Database driver | psycopg 3 |
| Frontend | HTML, CSS, JavaScript |
| Browser Extension | Manifest V3 |
| AI integration | Google Gemini (`google-genai`) |
| PDF processing | pypdf |
| Deployment | Docker, Docker Compose |
| API documentation | FastAPI / OpenAPI |

---

## Γρήγορη εκκίνηση

### Προαπαιτούμενα

- Docker Engine
- Docker Compose plugin
- Git (προαιρετικά)
- Σύγχρονος browser για πρόσβαση στην εφαρμογή

### 1. Αποσυμπίεση του project

Αποσυμπιέστε το αρχείο και μεταβείτε στον φάκελο `AI-Shield`:

```bash
cd AI-Shield-Firefox-Local-Security-Update-v1.2/AI-Shield
```

### 2. Δημιουργία αρχείου περιβάλλοντος

```bash
cp .env.example .env
```

Σε Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

### 3. Ορισμός μυστικών τιμών

Δημιουργήστε ισχυρές, διαφορετικές τιμές για:
- `POSTGRES_PASSWORD`
- `ADMIN_API_TOKEN`
- `SHADOW_INGEST_TOKEN`
- `ADMIN_PASSWORD`

Παράδειγμα δημιουργίας τυχαίου token σε Linux/macOS:

```bash
openssl rand -hex 32
```

Μην χρησιμοποιείτε το ίδιο secret για διαφορετικούς σκοπούς και μην ανεβάζετε το `.env` σε Git.

### 4. Εκκίνηση

Από τον φάκελο που περιέχει το `docker-compose.yml`:

```bash
docker compose up --build -d
```

Έλεγχος κατάστασης:

```bash
docker compose ps
docker compose logs -f backend
```

### 5. Έλεγχος λειτουργίας

Ανοίξτε:

- Website: http://localhost:8000/
- Login: http://localhost:8000/login/
- Health check: http://localhost:8000/health
- API documentation: http://localhost:8000/docs

Το Docker Compose εκκινεί PostgreSQL και backend. Το backend εκτελεί initialization του schema και bootstrap του πρώτου administrator κατά την εκκίνηση, εφόσον η βάση είναι διαθέσιμη.

Για τερματισμό:

```bash
docker compose down
```

Για τερματισμό χωρίς διαγραφή των δεδομένων της βάσης, χρησιμοποιήστε την παραπάνω εντολή. **Μην χρησιμοποιείτε `docker compose down -v` αν θέλετε να διατηρήσετε το PostgreSQL volume.**

---

## Ρύθμιση περιβάλλοντος

Οι διαθέσιμες μεταβλητές τεκμηριώνονται στο `.env.example`.

### Βασικές μεταβλητές

| Μεταβλητή | Περιγραφή |
|---|---|
| `POSTGRES_DB` | Όνομα PostgreSQL database |
| `POSTGRES_USER` | Database username |
| `POSTGRES_PASSWORD` | Database password |
| `ADMIN_API_TOKEN` | Token για προστατευμένη admin API πρόσβαση |
| `SHADOW_INGEST_TOKEN` | Shared token της browser extension προς το backend |
| `CORS_ORIGINS` | Επιτρεπόμενα origins |
| `DEBUG` | Ενεργοποίηση debug συμπεριφοράς |

### Gemini

| Μεταβλητή | Περιγραφή |
|---|---|
| `GEMINI_API_KEY` | API key για το προαιρετικό Gemini chat |
| `GEMINI_MODEL` | Μοντέλο Gemini, προεπιλογή `gemini-2.5-flash` |

Το Gemini API key χρησιμοποιείται από το ξεχωριστό Secure AI Chat. **Δεν απαιτείται για το Prompt Guard της extension όταν ελέγχει prompts σε ChatGPT.com.**

### Administrator και χρήστες

| Μεταβλητή | Περιγραφή |
|---|---|
| `ADMIN_EMAIL` | Email πρώτου administrator |
| `ADMIN_PASSWORD` | Αρχικός κωδικός administrator |
| `ADMIN_NAME` | Εμφανιζόμενο όνομα administrator |
| `DEMO_USER_EMAIL` | Προαιρετικό demo user email |
| `DEMO_USER_PASSWORD` | Προαιρετικός demo user κωδικός |
| `DEMO_USER_NAME` | Εμφανιζόμενο όνομα demo user |
| `DEMO_ALLOW_WEAK_PASSWORD` | Επιτρέπει αδύναμο κωδικό μόνο για demo user σε local demo |

Ο αρχικός administrator δημιουργείται κατά το bootstrap. Ο κωδικός του δεν αντικαθίσταται σε επόμενες εκκινήσεις. Χρησιμοποιήστε ισχυρό κωδικό σύμφωνα με τους κανόνες της εφαρμογής.

### URL και cookies

| Μεταβλητή | Περιγραφή |
|---|---|
| `PUBLIC_BASE_URL` | Δημόσια διεύθυνση της εφαρμογής |
| `COOKIE_SECURE` | Ενεργοποίηση Secure cookie για HTTPS |

### SMTP και Google OAuth

Το SMTP χρησιμοποιείται για email επαναφοράς κωδικού και προσκλήσεις χρηστών:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_STARTTLS`

Για Google Sign-In:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_ALLOWED_DOMAINS`

Το OAuth redirect URI για τοπική εγκατάσταση είναι:

```text
http://localhost:8000/api/auth/google/callback
```

Σε εγκατάσταση με διαφορετικό domain, ενημερώστε αντίστοιχα το `PUBLIC_BASE_URL` και το redirect URI στο Google Cloud Console.

---

## Πρόσβαση στην εφαρμογή

| URL | Περιγραφή | Πρόσβαση |
|---|---|---|
| `/` | Δημόσιο website | Όλοι |
| `/login/` | Login και password recovery | Όλοι |
| `/app/` | User Dashboard και Secure AI Chat | Συνδεδεμένοι χρήστες |
| `/admin/` | Admin Console | Administrators |
| `/docs` | OpenAPI / Swagger documentation | Ανάλογα με τη ρύθμιση του deployment |
| `/health` | Health endpoint | Τοπικός έλεγχος |

### Διαχείριση χρηστών

Οι administrators μπορούν να δημιουργούν και να διαχειρίζονται λογαριασμούς από το Admin Console. Υπάρχει επίσης CLI εργαλείο:

```bash
docker compose exec backend python manage_users.py list
docker compose exec backend python manage_users.py create user@example.com --name "Example User" --role user
docker compose exec backend python manage_users.py set-password user@example.com
docker compose exec backend python manage_users.py disable user@example.com
```

Χρησιμοποιήστε `--role user` ή `--role admin` σύμφωνα με τα δικαιώματα που πρέπει να δοθούν.

---

## DLP και πολιτικές προστασίας

Ο DLP Policy Engine αξιολογεί τα ευρήματα του scanner και επιλέγει την αυστηρότερη ενέργεια.

**Σειρά αυστηρότητας:**

```text
BLOCK > WARN > REDACT > ALLOW
```

| Ενέργεια | Συμπεριφορά |
|---|---|
| `ALLOW` | Το περιεχόμενο επιτρέπεται να προχωρήσει. |
| `WARN` | Απαιτείται ρητή επιβεβαίωση χρήστη. |
| `REDACT` | Επιλεγμένα δεδομένα αντικαθίστανται με pseudonyms. |
| `BLOCK` | Το περιεχόμενο δεν προωθείται στην AI υπηρεσία. |

### Ενδεικτικές κατηγορίες

| Κατηγορία | Παραδείγματα | Πολιτική |
|---|---|---|
| Credentials & secrets | API keys, passwords, private keys, JWT, connection strings | `BLOCK` |
| Payment data | Card PAN, CVV, expiry | `BLOCK` |
| Sensitive PII | ΑΦΜ, ΑΜΚΑ, στοιχεία ταυτότητας, διαβατήριο, Π.Α., email, τηλέφωνο | `REDACT` |
| Health data | Διαγνώσεις, ιατρικές αναφορές, βιομετρικά/γενετικά δεδομένα | `WARN` |
| Banking data | IBAN, BIC/SWIFT, αριθμοί λογαριασμών, μισθοδοσία και οικονομικά έγγραφα | `WARN` και pseudonymization όπου ορίζει η πολιτική |
| Corporate confidential | NDA, συμβάσεις, M&A, εσωτερικά email, εμπιστευτικό υλικό | `WARN` |
| Basic data | Ονόματα και διευθύνσεις | `ALLOW` |

Η πραγματική αντιστοίχιση κατηγοριών και κανόνων βρίσκεται στο `backend/policy.py`. Για αλλαγές πολιτικής, ελέγξτε τον κώδικα και τα σχετικά tests πριν από deployment.

---

## Browser Extension και Prompt Guard

Η extension υποστηρίζει τις παρακάτω υπηρεσίες:

- ChatGPT: `chatgpt.com`, `chat.openai.com`
- Google Gemini: `gemini.google.com`
- Claude: `claude.ai`

### Εγκατάσταση Firefox

1. Ανοίξτε `about:debugging#/runtime/this-firefox`.
2. Επιλέξτε **This Firefox**.
3. Πατήστε **Load Temporary Add-on…**.
4. Επιλέξτε το αρχείο `browser-extension/firefox/manifest.json`.
5. Ανοίξτε τις επιλογές της extension.
6. Ορίστε API Base URL `http://localhost:8000`.
7. Εισαγάγετε το `SHADOW_INGEST_TOKEN` από το `.env`.
8. Επιλέξτε team label και ενεργοποιήστε το Prompt Guard.
9. Κάντε refresh στις ήδη ανοιχτές καρτέλες AI υπηρεσιών.

### Εγκατάσταση Chrome / Edge

1. Ανοίξτε `chrome://extensions`.
2. Ενεργοποιήστε το **Developer mode**.
3. Επιλέξτε **Load unpacked**.
4. Επιλέξτε τον φάκελο `browser-extension/chrome/`.
5. Ανοίξτε τις επιλογές της extension.
6. Ορίστε API Base URL, token και team label.
7. Ενεργοποιήστε το Prompt Guard και ανανεώστε τις καρτέλες AI υπηρεσιών.

### Συμπεριφορά Prompt Guard

Πριν από την αποστολή prompt, η extension ζητά από το τοπικό backend να εκτελέσει scan και να αξιολογήσει την πολιτική:

- `ALLOW`: επιτρέπεται η αποστολή.
- `WARN`: εμφανίζεται επιβεβαίωση χρήστη.
- `REDACT`: οι επιλεγμένες τιμές αντικαθίστανται με pseudonyms.
- `BLOCK`: η αποστολή σταματά.

Αν ο scanner, το backend, οι ρυθμίσεις ή η διαδικασία pseudonymization αποτύχουν, η extension εφαρμόζει fail-closed συμπεριφορά και δεν στέλνει μη ελεγμένο prompt.

Η extension δεν χρησιμοποιεί το Gemini ή άλλο model API για να σαρώσει prompts που γράφονται στο ChatGPT.com. Ο έλεγχος γίνεται από το τοπικό NexGuard backend.

Για περισσότερες τεχνικές λεπτομέρειες σχετικά με το Prompt Guard, δείτε το [`browser-extension/README.md`](browser-extension/README.md).

---

## Reversible Pseudonymization

Η extension μπορεί να αντικαθιστά ευαίσθητες τιμές με σταθερά tokens κατά τη διάρκεια του browser session.

Παράδειγμα:

```text
Αρχικό prompt:
Ο πελάτης John Smith έχει ΑΦΜ 123456789.

Περιεχόμενο προς την AI:
Ο πελάτης [PERSON_001] έχει ΑΦΜ [AFM_001].
```

Η αντιστοίχιση token και πραγματικής τιμής διατηρείται στο `storage.session` του extension background, στη μνήμη του browser session. Δεν αποστέλλεται στο backend ή στον AI provider ως mapping και διαγράφεται όταν κλείσει το browser session.

Η extension επιχειρεί να επαναφέρει τις πραγματικές τιμές στις απαντήσεις που εμφανίζονται στη σελίδα. Η αποκατάσταση δεν είναι εγγυημένη σε κάθε περίπτωση: αν το μοντέλο τροποποιήσει ένα token ή αν η σελίδα αλλάξει τη δομή της, η επαναφορά μπορεί να αποτύχει.

---

## PDF Inspection

Όταν ο χρήστης επισυνάπτει PDF σε υποστηριζόμενη AI υπηρεσία, η extension μπορεί να το κρατήσει προσωρινά και να το στείλει στο τοπικό backend για έλεγχο.

Η εφαρμογή εξάγει κείμενο με `pypdf` και εφαρμόζει την DLP πολιτική:

| Πολιτική | Συμπεριφορά |
|---|---|
| `BLOCK` | Το PDF δεν επισυνάπτεται. |
| `WARN` | Ζητείται επιβεβαίωση και, εφόσον εγκριθεί, προωθείται το αρχικό PDF. |
| `REDACT` / `WARN_REDACT` | Το αρχικό PDF δεν προωθείται· το εξαγόμενο κείμενο χρησιμοποιείται με pseudonyms. |
| `ALLOW` | Το αρχικό PDF μπορεί να προωθηθεί. |

Υπάρχουν όρια μεγέθους και επεξεργασίας. Encrypted PDFs, μεγάλα αρχεία, αρχεία με υπερβολικό αριθμό σελίδων ή κειμένου και PDF που δεν μπορούν να ελεγχθούν δεν προωθούνται. Τα image-only/scanned PDF χωρίς εξαγώγιμο κείμενο αντιμετωπίζονται ως `WARN`.

Το αρχείο, το όνομά του και το εξαγόμενο κείμενο δεν αποθηκεύονται ως incident data. Τα incidents καταγράφουν metadata, τύπους ευρημάτων και `content_type = pdf`.

---

## Shadow AI Radar

Το Shadow AI Radar παρακολουθεί επισκέψεις σε AI domains που υπάρχουν στον κατάλογο της εφαρμογής.

Η extension στέλνει:
- Το hostname του domain.
- Ένα τυχαίο installation identifier, το οποίο γίνεται hash στο backend.
- Ένα προαιρετικό team label.

Δεν στέλνει URL paths, query parameters, page titles, prompt text, page content, cookies, form values ή keystrokes.

Η επίσκεψη σε ένα domain αποτελεί ένδειξη επίσκεψης και **δεν αποδεικνύει** ότι υποβλήθηκε prompt ή ότι χρησιμοποιήθηκε ενεργά η υπηρεσία.

Οι administrators μπορούν να βλέπουν το inventory και να ορίζουν κατάσταση εργαλείου:
- `APPROVED`
- `REVIEW`
- `UNAPPROVED`

Υπάρχει δυνατότητα εισαγωγής συνθετικών demo events. Τα δεδομένα αυτά είναι τεχνητά και δεν πρέπει να παρουσιάζονται ως πραγματική δραστηριότητα χρηστών.

---

## Incident Investigation και Intelligence

Το Technical Dashboard συγκεντρώνει συμβάντα και στατιστικά ευρημάτων.

### Sensitive Data Intelligence
- Συγκεντρωτικά ευρήματα ανά κατηγορία.
- Χρονικές τάσεις.
- Ανάλυση ανά AI provider.
- Μετρήσεις τύπων και πλήθους ευρημάτων, όχι αποθήκευση prompts ή pseudonym mappings.

### Incident Investigation Center

Τα περιστατικά υποστηρίζουν τις ακόλουθες μεταβάσεις:

| Ενέργεια | Επιτρεπόμενη αρχική κατάσταση | Νέα κατάσταση |
|---|---|---|
| `ACKNOWLEDGE` | `OPEN` | `ACKNOWLEDGED` |
| `INVESTIGATE` | `OPEN`, `ACKNOWLEDGED` | `INVESTIGATING` |
| `RESOLVE` | `OPEN`, `ACKNOWLEDGED`, `INVESTIGATING` | `RESOLVED` |

Οι ενέργειες καταγράφονται στο activity history μαζί με τον analyst και τις σχετικές σημειώσεις. Για την επίλυση απαιτείται resolution category και αιτιολόγηση σύμφωνα με τους ελέγχους του backend.

Τα καθαρά scans `ALLOW` μπορούν να καταγράφονται ως `AUTO_CLOSED`.

---

## API

Το backend παρέχει REST API με τεκμηρίωση OpenAPI στο `/docs`.

Ενδεικτικά endpoints που περιλαμβάνονται στην εφαρμογή:

| Endpoint | Χρήση |
|---|---|
| `GET /health` | Έλεγχος διαθεσιμότητας |
| `GET /api/providers` | Διαθέσιμοι AI providers/models |
| `POST /api/scan` | Έλεγχος prompt |
| `POST /api/chat` | Secure AI Chat |
| `GET /api/shadow/catalog` | Κατάλογος AI domains |
| `POST /api/shadow/events` | Καταγραφή Shadow AI event |
| `GET /api/admin/incidents` | Λίστα περιστατικών |
| `GET /api/admin/intelligence` | Συγκεντρωτικά intelligence δεδομένα |
| `GET /api/admin/shadow/inventory` | Shadow AI inventory |
| `GET /api/admin/shadow/events` | Shadow AI events |
| `PATCH /api/admin/shadow/tools/{id}` | Αλλαγή κατάστασης AI εργαλείου |
| `GET /api/admin/incidents/{id}` | Λεπτομέρειες περιστατικού |
| `POST /api/admin/incidents/{id}/actions` | Ενέργεια διερεύνησης |

Τα admin API endpoints προστατεύονται με admin session ή `X-Admin-Token`, ανάλογα με το endpoint και τη μέθοδο πρόσβασης. Τα extension endpoints χρησιμοποιούν το `X-Discovery-Token`.

> Για τα ακριβή request/response schemas και τις απαιτήσεις authentication, ανατρέξτε στο `/docs` και στον κώδικα του `backend/main.py`. Ο παραπάνω πίνακας είναι συνοπτικός και όχι πλήρης προδιαγραφή API.

---

## Δομή project

```text
AI-Shield/
├── backend/
│   ├── main.py
│   ├── auth.py
│   ├── database.py
│   ├── scanner.py
│   ├── policy.py
│   ├── pseudonymizer.py
│   ├── intelligence.py
│   ├── pdf_extract.py
│   ├── manage_users.py
│   ├── ai/
│   │   ├── gemini.py
│   │   └── gateway.py
│   ├── tests/
│   └── requirements.txt
├── browser-extension/
│   ├── firefox/
│   ├── chrome/
│   ├── shared-background.js
│   └── README.md
├── database/
│   └── init.sql
├── frontend/
│   ├── website/
│   ├── login/
│   ├── user-dashboard/
│   ├── technical-dashboard/
│   └── shared/
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Τοπική ανάπτυξη χωρίς Docker

Απαιτείται διαθέσιμη PostgreSQL και σωστό `DATABASE_URL`.

```bash
cd backend

python -m venv .venv
```

Ενεργοποίηση virtual environment:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Εγκατάσταση dependencies:

```bash
pip install -r requirements.txt
```

Ορίστε τις απαιτούμενες μεταβλητές περιβάλλοντος, τουλάχιστον `DATABASE_URL`, `ADMIN_API_TOKEN` και `SHADOW_INGEST_TOKEN`, καθώς και τις προαιρετικές ρυθμίσεις Gemini αν χρειάζονται.

Εκκίνηση backend:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

---

## Έλεγχοι και tests

Τα backend tests βρίσκονται στο `backend/tests/`.

Εκτελέστε τα από τον φάκελο `backend` με ενεργό virtual environment:

```bash
python -m pytest
```

Αν το `pytest` δεν είναι εγκατεστημένο στο περιβάλλον, εγκαταστήστε το ξεχωριστά πριν από την εκτέλεση.

---

## Ασφάλεια και ιδιωτικότητα

- Μην κάνετε commit το `.env`.
- Χρησιμοποιείτε διαφορετικά και ισχυρά secrets για database, admin API και extension.
- Μην τοποθετείτε API keys σε frontend JavaScript.
- Για δημόσια εγκατάσταση χρησιμοποιήστε HTTPS και `COOKIE_SECURE=true`.
- Περιορίστε το CORS στα πραγματικά origins που χρειάζονται.
- Διατηρήστε ενημερωμένα τα dependencies και τη βάση δεδομένων.
- Εφαρμόστε κατάλληλη πολιτική backup, retention και διαγραφής δεδομένων.
- Μην χρησιμοποιείτε πραγματικά ευαίσθητα εταιρικά δεδομένα σε demo περιβάλλον.
- Το `SHADOW_INGEST_TOKEN` είναι shared credential της συγκεκριμένης υλοποίησης και πρέπει να προστατεύεται.
- Τοπικά, το Docker Compose δεσμεύει το backend στο `127.0.0.1:8000`, ώστε να μην εκτίθεται απευθείας στο LAN από αυτή τη ρύθμιση.

### Τι αποθηκεύεται

Τα incident records έχουν σχεδιαστεί να αποθηκεύουν στοιχεία όπως provider, policy action, risk, τύπους/πλήθος ευρημάτων, χρόνο και κατάσταση διερεύνησης — όχι το αρχικό prompt, τις πραγματικές τιμές που εντοπίστηκαν ή το pseudonym mapping.

Το Shadow AI Radar αποθηκεύει metadata επίσκεψης, όπως domain, χρόνο, team label και hashed installation identifier.

---

## Περιορισμοί

1. **Δεν είναι network proxy.** Η extension παρεμβάλλεται στη διεπαφή του browser και δεν ελέγχει κάθε πιθανό δίκτυο, συσκευή ή API client.
2. **Δεν είναι αδύνατο να παρακαμφθεί.** Χρήστης με έλεγχο του browser μπορεί να απενεργοποιήσει ή να παρακάμψει την extension.
3. **Εξαρτάται από τη δομή των AI websites.** Αλλαγές στο DOM ή στον τρόπο αποστολής των prompts μπορεί να επηρεάσουν τη λειτουργία της.
4. **Ο scanner δεν είναι τέλειος.** Υπάρχουν false positives και false negatives.
5. **Δεν εγγυάται πλήρη ανίχνευση prompt injection.** Οι heuristics δεν αποτελούν ολοκληρωμένο μηχανισμό προστασίας.
6. **Η επαναφορά pseudonyms δεν είναι πάντα εφικτή.** Αν ένα μοντέλο αλλάξει τα tokens ή η σελίδα τροποποιήσει το περιεχόμενο, η αποκατάσταση μπορεί να αποτύχει.
7. **Το PDF scanning αφορά εξαγώγιμο κείμενο.** Scanned/image-only PDF δεν παρέχει κείμενο για πλήρη έλεγχο.
8. **Το Shadow AI inventory δεν αναγνωρίζει κάθε πιθανό AI domain.** Καταγράφει domains που υπάρχουν στον κατάλογο.
9. **Η production χρήση απαιτεί πρόσθετα μέτρα.** Ενδεικτικά: managed browsers, per-device credentials, rate limiting, monitoring, secret management, security review και δοκιμές διείσδυσης.

Το NexGuard πρέπει να χρησιμοποιείται ως ένα επίπεδο άμυνας σε μια ευρύτερη στρατηγική ασφάλειας και όχι ως μοναδικός μηχανισμός προστασίας.

---

## Troubleshooting

### Το backend δεν ξεκινά

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f db
```

Ελέγξτε ότι έχουν οριστεί τα `POSTGRES_PASSWORD`, `ADMIN_API_TOKEN` και `SHADOW_INGEST_TOKEN` στο `.env`.

### Δεν λειτουργεί η σύνδεση με τη βάση

Ελέγξτε ότι το PostgreSQL service είναι healthy και ότι τα database credentials συμφωνούν μεταξύ Compose και `DATABASE_URL`.

### Η extension δεν συνδέεται στο backend

- Βεβαιωθείτε ότι το backend λειτουργεί στο `http://localhost:8000`.
- Ελέγξτε το `SHADOW_INGEST_TOKEN` στις ρυθμίσεις της extension.
- Βεβαιωθείτε ότι το API Base URL είναι σωστό.
- Ελέγξτε τα logs του backend.
- Κάντε refresh στην καρτέλα της AI υπηρεσίας μετά την ενεργοποίηση της extension.

### Εμφανίζεται `401 Unauthorized`

Ελέγξτε ότι χρησιμοποιείτε το σωστό token για το συγκεκριμένο endpoint:
- `X-Admin-Token` για admin API πρόσβαση με token.
- `X-Discovery-Token` για extension discovery/prompt endpoints.

Τα tokens είναι διαφορετικά και δεν πρέπει να ανταλλάσσονται.

### Δεν λειτουργεί το password reset

Ελέγξτε τις ρυθμίσεις SMTP. Χωρίς `SMTP_HOST` δεν αποστέλλεται email. Σε local testing, η συμπεριφορά debug τεκμηριώνεται στο `.env.example` και στα backend logs.

### Αλλαγές στο frontend δεν εμφανίζονται

Κάντε rebuild/recreate το backend:

```bash
docker compose up --build -d --force-recreate backend
```

Κάντε refresh στον browser. Αποφύγετε το `docker compose down -v`, εκτός αν θέλετε συνειδητά να διαγράψετε το database volume.

---

## License

Δεν προσδιορίζεται άδεια χρήσης στο παρόν πακέτο. Πριν από δημόσια διανομή ή εμπορική χρήση, προσθέστε κατάλληλο αρχείο `LICENSE` και επιβεβαιώστε τα δικαιώματα χρήσης όλων των dependencies και assets.

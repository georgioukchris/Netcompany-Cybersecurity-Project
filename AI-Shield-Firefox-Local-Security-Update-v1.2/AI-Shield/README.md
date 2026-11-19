# AI Shield — Secure AI Gateway

AI Shield is a FastAPI + PostgreSQL gateway. The user dashboard sends prompts to the backend; the backend scans the complete conversation context, applies the existing policy, redacts configured personal data, and only then calls the selected AI provider. Provider responses are scanned before being returned.

## 1. Configure

```bash
cp .env.example .env
```

Open `.env` and set:
- `GEMINI_API_KEY` — create one at https://aistudio.google.com/apikey
- `POSTGRES_PASSWORD` — change the local database password
- `ADMIN_API_TOKEN` — choose a long random admin token
- `SHADOW_INGEST_TOKEN` — choose a separate long random token for the Firefox extension (the Compose stack will require it). This is a local backend access credential, not an OpenAI API key.

The Gemini API key is needed only for the separate User Dashboard → Gemini feature. It is not used by Firefox Prompt Guard or ChatGPT.com. Never put API keys in frontend JavaScript, commit `.env`, or share secrets in screenshots/logs. The Gemini free tier has usage limits and its own data-use terms; do not send real sensitive or company data in this demo.

## 2. Run with Docker

```bash
docker compose up --build
```

Open:
- Website: http://localhost:8000/
- Sign in: http://localhost:8000/login/ (first admin: `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env`, see section 6b2)
- User chat: http://localhost:8000/app/ (signed-in users)
- Admin Console: http://localhost:8000/admin/ (admins)
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

`ADMIN_API_TOKEN` is now only for scripts/API access (`X-Admin-Token`); people sign in at /login.

## 3. Run backend without Docker

Start PostgreSQL first, then:

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Set `DATABASE_URL`, `GEMINI_API_KEY`, and `ADMIN_API_TOKEN` in the environment before starting.

## 4. Current functionality

- `GET /api/providers` — supported providers and models (Gemini in this version).
- `POST /api/scan` — standalone prompt scan.
- `POST /api/chat` — scan conversation context, apply policy, call Gemini, scan response.
- `GET /api/admin/incidents` — audit events (requires `X-Admin-Token`).
- `GET /api/shadow/catalog` — AI domain catalog consumed by the extension.
- `POST /api/shadow/events` — metadata-only discovery event ingestion (requires `X-Discovery-Token`).
- `GET /api/admin/shadow/inventory` — AI tool inventory and aggregates (admin token required).
- `GET /api/admin/shadow/events` — recent discovery events (admin token required).
- `PATCH /api/admin/shadow/tools/{id}` — change a tool to `APPROVED`, `REVIEW` or `UNAPPROVED`.
- `POST /api/admin/shadow/tools` — register an additional AI domain (new domains default to `UNAPPROVED`).
- `POST /api/admin/shadow/demo-seed` — insert clearly labelled synthetic events for a demo.

Example chat request:

```json
{
  "provider": "gemini",
  "model": "gemini-2.5-flash",
  "messages": [
    {"role": "user", "content": "Explain zero trust security."}
  ],
  "user_id": "demo-user",
  "confirm_warning": false
}
```

## 5. Policy behavior

- `ALLOW`: forwards the message.
- The DLP matrix in `backend/policy.py` (`POLICY_RULES`, shown in the Technical Dashboard → *DLP Policy*):

| Data category | Types | Action |
|---|---|---|
| Credentials & secrets | API keys, passwords, private keys, JWT, connection strings | 🛑 BLOCK |
| Payments | card PAN, CVV, expiry | 🛑 BLOCK |
| Sensitive PII | ΑΦΜ, ΑΜΚΑ, ID card, passport, Π.Α., e-mail, mobile, masked card | ✂️ REDACT (reversible pseudonyms) |
| Health (GDPR Art. 9) | diagnoses, medical reports, biometric / genetic | ⚠️ WARN |
| Bank accounts | IBAN, SWIFT/BIC, account numbers, payroll, invoices / tax documents | ⚠️ WARN + ✂️ REDACT |
| Corporate confidential | NDAs, contracts, M&A, internal e-mails, confidential, prompt injection, source code | ⚠️ WARN |
| Basic data | full name, addresses | ✅ ALLOW |

  The strictest action wins (BLOCK > WARN > REDACT > ALLOW). A confirmed WARN marks the same incident as
  "confirmed by the user". ALLOW scans are logged as `AUTO_CLOSED`. Email, mobile, account numbers, card expiry
  and financial documents are not in the original table; they follow the closest row.
- `WARN`: asks for explicit confirmation in the UI.
- `BLOCK`: does not call the provider.

The entire conversation sent to the provider is scanned, not just the newest message. The response is also scanned. Detected API secrets in a response cause the response to be blocked; detected personal data is redacted.

## 5b. What the scanner detects

| Category | Detected (all are pseudonymized, e.g. `[AFM_001]`) |
|---|---|
| Personal data (PII) | ΑΦΜ (9 digits, checksum), ΑΜΚΑ (11 digits), Προσωπικός Αριθμός Π.Α. (3 + ΑΦΜ), ID card (old `Χ-123456` and `ΑΚ 482913`), passport (`AB1234567`), full name next to an address / mobile / email / identifier, street addresses, personal email, mobile & landline phones |
| Financial | IBAN (esp. `GR…`), BIC/SWIFT (labelled, or Greek `xxxxGRxx`), card PAN (Luhn), expiry, CVV/CVC, account numbers, payroll amounts, invoice numbers and amounts inside invoices / tax returns / εκκαθαριστικά / payslips |
| Health (GDPR Art. 9) | diagnoses, medication & dosages, lab results, medical reports (γνωματεύσεις), biometric & genetic data (DNA, BRCA, fingerprints, facial recognition) |
| Credentials | passwords, AWS / Google Cloud / Stripe / OpenAI / GitHub / Slack keys, JWT, `Bearer`/`Basic` tokens, GCP service-account keys, SSH / SSL / PGP private keys (`.pem`), DB connection strings (URI and `Server=…;Password=…`) |
| Business confidential | NDAs, contract clauses, M&A / due diligence / term sheets, unpublished press releases & embargoes, management e-mails, board minutes, internal memos, «εμπιστευτικό» material |

Whole-line categories (health, contracts, internal communications) ignore short definitional questions such as
«Τι είναι το NDA;» unless they contain personal markers («μου», «μας») or numbers. Tests: `backend/tests/test_categories.py`.

## 6. AI Shadow Radar (new)

The Shadow Radar adds an opt-in browser extension and an AI-domain inventory.

### Install the browser extension

Easiest: open the User Dashboard (`http://localhost:8000/app/#extension`) → **Browser Extension** and download
the Firefox or Chrome build (`/downloads/ai-shield-firefox.zip`, `/downloads/ai-shield-chrome.zip`, built on
request from `browser-extension/`). Firefox: *about:debugging → Load Temporary Add-on* and pick the zip as is.
Chrome/Edge: extract it, then *chrome://extensions → Developer mode → Load unpacked*. Manual steps:

**Firefox (the Firefox build is included):**
1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on…**.
3. Choose `browser-extension/firefox/manifest.json`.
4. Open the extension's **AI Shield — Shadow Radar** options page.

**Chrome / Chromium / Edge:**
1. Open `chrome://extensions` (or the browser's equivalent).
2. Enable **Developer mode** and select **Load unpacked**.
3. Choose the `browser-extension/chrome/` folder.
4. Open the extension's **Details → Extension options** page.

Add a separate strong token to `.env` (for example generate one with `openssl rand -hex 32`) and restart Compose. In the extension options enter:
- API Base URL: `http://localhost:8000`
- Discovery ingest token: the exact `SHADOW_INGEST_TOKEN` value from `.env`
- Team label: an optional team code such as `Engineering` (do not enter employee names)

Save the settings. Visit a domain in the AI catalog (for example `chatgpt.com` or `claude.ai`) and refresh the Technical Dashboard. The extension obtains its domain catalog from the backend, so newly registered domains are picked up automatically on the next catalog refresh or settings save.

### What it collects

The extension checks tab navigation and sends only the matched hostname, a random extension-install identifier (hashed by the backend), and an optional team label. It does **not** send URL paths, query parameters, page titles, prompt text, page content, cookies, form values, or keystrokes. A visit is a domain-visit signal; it does not prove that a prompt was submitted or that the AI service was actively used.

The starter inventory is a demo policy. Change each tool's status in the Technical Dashboard to reflect the organisation's approved-provider list. The catalog detects known or administrator-registered domains; it cannot automatically classify every unknown website as an AI tool without additional proxy/DNS intelligence.

### Synthetic demonstration

Use **Demo data** in the Shadow Radar panel to insert synthetic events for several synthetic team labels. These records are marked `synthetic-demo` and must not be presented as real employee activity.

### Extension security note

`SHADOW_INGEST_TOKEN` is a shared local-demo credential stored in the extension's local storage. Use a strong, separate value, do not commit it, and do not reuse the admin token. A production deployment should replace it with per-install, revocable credentials and authenticated device enrollment.

Supported AI services: ChatGPT, Gemini and Claude only. The catalog is fixed in `database/init.sql`
(a database constraint rejects any other provider; existing volumes are cleaned on start) and the
admin "register a tool" form/endpoint has been removed. Admins can still change each tool's status.

## 6b. Technical Dashboard: Data Intelligence & Investigation Center

**Sensitive Data Intelligence** (`GET /api/admin/intelligence?hours=1|24|168`, trend per 5 min / hour / day): findings grouped into five
categories (Personal, Financial, Credentials, Business, Medical) with counts, percentages, a daily trend
and a per-AI-provider breakdown. Only finding *types and counts* are aggregated; prompts, matched values
and pseudonym mappings are never stored or returned. A table view is available for every chart.

**Incident Investigation Center**: each incident has ID, severity, AI provider, detection category,
policy action, timestamp and investigation status.

| Action | Allowed from | Result |
|---|---|---|
| `ACKNOWLEDGE` | OPEN | ACKNOWLEDGED, assigned to the analyst |
| `INVESTIGATE` | OPEN, ACKNOWLEDGED | INVESTIGATING + full technical analysis |
| `RESOLVE` | OPEN, ACKNOWLEDGED, INVESTIGATING | RESOLVED; requires a resolution category and a reason (≥10 chars) |

- `POST /api/admin/incidents/{id}/actions` — `{action, analyst, note?, resolution_category?}`; invalid transitions return 409.
- `GET /api/admin/incidents/{id}` — incident, technical analysis (findings by category, data exposure,
  provider Shadow-AI status, related incidents ±24h, recommendations) and the activity timeline.
- States and the activity log are stored in PostgreSQL (`incidents.status…`, `incident_activity`);
  existing volumes are upgraded automatically on start.
- Clean scans (ALLOW with no findings) are stored as `AUTO_CLOSED` and are not shown in the queue.
- Set your analyst name in the dashboard's **Settings**; it is recorded on every action.

## 6b2. NexGuard website & login (v1.9.0)

| Address | What | Who |
|---|---|---|
| `http://localhost:8000/` | Public website (product, capabilities, contact) | everyone |
| `http://localhost:8000/login/` | Sign in · Forgot password · Google | everyone |
| `http://localhost:8000/app/` | User Dashboard (Secure AI Chat, extension download) | signed-in users and admins |
| `http://localhost:8000/admin/` | Admin Console | admins only |

**First admin:** set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` (at least 10 characters with upper case, lower case and a number) and start the stack: the account is created on startup.

**Demo account with a simple password (local demos only):**
```
DEMO_USER_EMAIL=test@test.com
DEMO_USER_PASSWORD=test
DEMO_ALLOW_WEAK_PASSWORD=true
```
Only this demo user (role *user*, never admin) may have a password that breaks the rules; the server logs a warning on startup. Remove these lines before the site is reachable by anyone else.

**Registering users (Admin Console → Χρήστες):** enter the email, name and role (User / Administrator) and press *Εγγραφή & πρόσκληση*. The person receives an invitation email (valid 72 hours, single use) and sets their own password at `/login/#invite=…`; nobody else ever sees it. Without SMTP the console shows the invitation link to copy and pass on. From the same table: change role (effective immediately), resend an invitation, disable (signs the user out everywhere) / enable, delete. You cannot remove your own admin access, and at least one active administrator always remains. Every change is recorded in *Ιστορικό λογαριασμών*.

The same from the command line:
```bash
docker compose exec backend python manage_users.py create maria@company.gr --name "Μαρία" --role user
docker compose exec backend python manage_users.py list
docker compose exec backend python manage_users.py set-password maria@company.gr
docker compose exec backend python manage_users.py disable maria@company.gr
```
The Admin Console now works with the admin's session: no admin token in the browser, and every investigation action is recorded under the signed-in admin's name. `ADMIN_API_TOKEN` still works for scripts/API (`X-Admin-Token` header).

**Forgot password:** the login page sends a single-use link valid for 30 minutes. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (e.g. a Gmail/Microsoft 365 account with an app password). Without SMTP no email is sent; with `DEBUG=true` the link is printed in `docker compose logs backend` for local testing. The answer is the same whether or not the email exists.

**Sign in with Google:**
1. Google Cloud Console → APIs & Services → Credentials → *Create credentials* → *OAuth client ID* → *Web application*.
2. Authorized redirect URI: `http://localhost:8000/api/auth/google/callback` (or `PUBLIC_BASE_URL` + `/api/auth/google/callback`).
3. Put the values in `.env`: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and optionally `GOOGLE_ALLOWED_DOMAINS=company.gr`.
4. `docker compose up -d --build`.

A Google account can sign in if an account with the same (verified) email exists, or if its domain is in `GOOGLE_ALLOWED_DOMAINS` (a *user* account is then created; admins are only made with `manage_users.py`).

**Security:** scrypt password hashes; sessions in an HttpOnly, SameSite=Lax cookie (8 hours, or 30 days with "remember me"), stored only as SHA-256; server-side logout; 5 wrong passwords lock the account for 15 minutes; CSRF origin check; no open redirects; OAuth 2.0 with PKCE, state and nonce. Behind HTTPS set `COOKIE_SECURE=true` and `PUBLIC_BASE_URL=https://…`.

## 6c. PDF attachments (v1.8.0, extension 1.5.0)

When a user attaches a PDF on ChatGPT, Gemini or Claude (file picker, drag & drop or paste), the extension holds it back and sends it **only to the local AI Shield backend** (`POST /api/shadow/scan-file`, extension token). The backend reads the text in memory with `pypdf` and applies **the same DLP policy as typed prompts**:

| Policy | What happens to the PDF |
|---|---|
| BLOCK (passwords, keys, cards…) | Not attached. The user sees why. |
| WARN (health, contracts…) | The user must confirm; then the original PDF is attached. |
| REDACT / WARN_REDACT (AFM, IBAN, email…) | The PDF is **not** attached. Its text is put in the message with consistent pseudonyms (`[AFM_001]`), and the AI's answer shows the real values only on the user's screen. |
| ALLOW | The original PDF is attached. |

Fail closed: encrypted PDFs, files over 10 MB / 200 pages / 60,000 characters, or an unreachable backend → not attached. Image-only (scanned) PDFs have no text to check → WARN. Other file types are not affected.
Privacy: the file, its text and its **name** are never stored or logged; incidents record only finding types/counts plus `content_type = 'pdf'`, shown as a **PDF** tag in the Technical Dashboard. New dependency: `pypdf` (in `backend/requirements.txt`).

## 6d. Security hardening (v1.7.5)

- **No third-party requests:** the dashboards' fonts (Poppins, DM Sans, SIL OFL) are bundled in `frontend/*/fonts/`; nothing is loaded from Google or any CDN.
- **Security headers** on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`; the dashboards also get a strict `Content-Security-Policy` (`script-src 'self'`, `font-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`).
- **Authentication first:** admin and extension endpoints authenticate through FastAPI dependencies (`require_admin`, `require_discovery`), so an unauthenticated request always gets `401` and never the request schema.
- **Extension 1.4.2:** before every send it waits for the page's editor state to settle and verifies that exactly the scanned text is in the composer; if the text changed after the scan, nothing is sent.

## 7. Important limitations before production

This is a hackathon/demo baseline, not a certified DLP product. Regex scanning can produce false positives and miss sensitive data. The current `AMKA` and `AFM` patterns are format-based and do not validate checksum/identity. Prompt-injection detection is not a guarantee and must be implemented as a separate layered control. Add authentication and per-user authorization, HTTPS, strict CORS, rate limiting, request-size limits, secret manager integration, retention/deletion controls, dependency scanning, and security tests before production. Do not treat user confirmation as proof that data is safe to disclose.

Audit records store metadata/findings only, not raw prompts, replies, or API keys. Shadow Radar stores AI domain, event time, coarse team label, pseudonymous install hash, source, and the policy status at the time of the event.


## Shadow Radar Prompt Guard (v1.1)
See `browser-extension/README.md` for setup. Domain discovery is separate from optional pre-send prompt scanning.


## Troubleshooting: API CONNECTION / CORS

Open the admin dashboard through the backend, preferably at `http://localhost:8000/admin/` (not by opening the HTML file and not by mixing `localhost` with `127.0.0.1`). The technical dashboard now uses same-origin relative API requests when served by FastAPI, so an old API Base URL saved in browser local storage cannot redirect it to a different origin. The backend also accepts localhost/127.0.0.1 development origins and the browser-extension origins used by the opt-in extension.

After updating, rebuild/recreate the backend with `sudo docker compose up --build -d --force-recreate backend`. Do not run `docker compose down -v`; that would delete the PostgreSQL volume. If API CONNECTION then shows `401 Unauthorized`, the CORS connection is fixed and the remaining issue is the Admin API Token configured in the dashboard.


## Firefox Prompt Guard — local-only mode

For the single-user Docker setup, the Prompt Guard sends the prompt only to the local backend at `http://localhost:8000/api/shadow/scan-prompt`. It does not call the OpenAI API and does not need an OpenAI API key. The user continues using their normal ChatGPT.com login/session. Follow `browser-extension/README.md` for the Firefox install and policy behavior.

The Docker host port is bound to `127.0.0.1:8000` so this local demo is not exposed to the LAN. The extension's `SHADOW_INGEST_TOKEN` is a shared secret for authenticating to the local scanner; it is not a provider API key. Keep it private.

The scanner now includes deterministic phrase heuristics for a small set of prompt-injection patterns. These heuristics are not a complete prompt-injection detector. In the selected WARN failure mode, if the local scanner is unavailable, the extension displays an explicit confirmation dialog before sending an unscanned prompt; cancelling keeps the prompt unsent. Secrets matching configured patterns remain BLOCKed and detected PII is redacted.

This extension is a best-effort browser UI control, not a network-level enforcement boundary. A user can disable it, providers can change their page DOM, and other send paths/devices/API clients are outside its coverage. Do not describe it as guaranteed DLP enforcement.

# AI Shield — Shadow Radar + Prompt Guard (Firefox)

## What the Firefox Prompt Guard does

When enabled, Prompt Guard pauses a supported chat site's Send/Enter action, sends the prompt to the **local AI Shield backend** for deterministic scanning, and resumes only according to the backend policy. It does not call OpenAI, Gemini, or any other model API to scan a ChatGPT.com prompt. The user remains signed in to ChatGPT.com with their normal browser session.

- `ALLOW`: resumes the original prompt.
- DLP policy matrix (decided by the backend, strictest wins: BLOCK > WARN > REDACT > ALLOW):
  - `BLOCK` – API keys, passwords, private keys, JWT, connection strings, card PAN / CVV / expiry: nothing is sent.
  - `WARN` – health & biometric data, NDAs / contracts, internal e-mails, confidential material: the user must confirm; then it is sent as it is.
  - `WARN` + `REDACT` – IBAN, BIC/SWIFT, account numbers, payroll / invoices: confirm, then these values are sent as pseudonyms.
  - `REDACT` – ΑΦΜ, ΑΜΚΑ, ID cards, passports, Π.Α., e-mail, mobile: replaced with reversible pseudonyms (`[AFM_001]`) and restored only in your browser.
  - `ALLOW` – full names and addresses: sent as they are.
- `WARN`: asks the user; after approval, asks the backend to record the confirmation before resuming.
- `BLOCK`: does not send.
- Scanner/network/settings/pseudonymization failure: **fail closed** — an unscanned prompt is never sent.

### Settings page (about:addons → AI Shield → Options)

- Live status: backend online + latency, extension token valid (checked against the backend), Prompt Guard on/off, vault size.
- Connection test, team quick-picks, show/hide token, unsaved-changes bar.
- **Policy test**: type any text and see the DLP action and exactly what the AI would receive. It is a dry run
  (`POST /api/shadow/policy-preview`): nothing is sent to an AI provider and no incident is stored.
- The DLP matrix in force (`GET /api/shadow/policy`), and the vault (pseudonyms only, never the real values).

### Reversible Privacy Engine

```
You type:      Prepare an email for client John Smith. His AFM is 123456789. His account number is 987654321.
AI receives:   Prepare an email for client [PERSON_001]. His AFM is [AFM_001]. His account number is [ACCOUNT_001].
AI answers:    Dear [PERSON_001], ...
You see:       Dear John Smith, ...
```

- The backend returns only the *positions* and types of sensitive values (`entities`), never the values; the extension builds the mapping itself.
- The mapping (`[PERSON_001]` ↔ `John Smith`) lives only in `storage.session` of the extension background: RAM only, wiped when the browser closes, never sent to the backend or the AI provider. It can be cleared from the options page.
- Same value → same pseudonym for the whole browser session, so the model can still tell people apart and follow-up prompts stay consistent. A value already in the vault is pseudonymized even if a later prompt mentions it without a label ("make it shorter for John Smith").
- De-anonymization edits page text nodes in place and never touches the composer or other editable fields, so real values are not re-sent. It can be turned off in the options.
- Limitations: the site's own "Copy" button copies the text with pseudonyms; if the model rewrites a token (e.g. `Person 1`), it is not restored; the provider's page scripts can read the restored text that is displayed on the page.

The local scanner uses regular expressions and conservative phrase heuristics. It is useful as a first security layer, but it cannot guarantee detection of every secret, personal-data format, prompt injection, or other unsafe content. False positives and false negatives are possible.

## Firefox setup

1. Copy `.env.example` to `.env` in the project root.
2. Set strong random values for `POSTGRES_PASSWORD`, `ADMIN_API_TOKEN`, and `SHADOW_INGEST_TOKEN`. For example, generate values with `openssl rand -hex 32`. Do not paste these values into support chats or commit `.env`.
3. Start the stack from the project directory: `docker compose up --build -d`.
4. Verify `http://localhost:8000/health` returns `status: ok`, then open `http://localhost:8000/app/`.
5. Open `about:debugging#/runtime/this-firefox`.
6. Choose **This Firefox** → **Load Temporary Add-on…** and select `browser-extension/firefox/manifest.json`.
7. Open the extension's options page. Set API URL to `http://localhost:8000`, paste the value of `SHADOW_INGEST_TOKEN`, choose a team label, and enable Prompt Guard.
8. Reload any already-open ChatGPT.com tab after enabling the extension.

## Privacy and network behavior

- The prompt is sent to the configured AI Shield backend only at the moment the user presses Send/Enter.
- With this Docker configuration, the backend port is bound to `127.0.0.1` and is not exposed on the LAN.
- Prompt contents and matched values are processed in memory. Incident records contain provider, team label, policy action/risk and finding types/counts, not raw prompt text.
- The extension stores its local settings and shared local-backend token in Firefox extension storage.
- The Gemini API key is optional for this ChatGPT.com workflow. It is used only by the separate User Dashboard's Gemini chat.

## Important limitations

This is a browser-extension UI interception layer, not a network proxy or a browser-enforced enterprise DLP boundary. ChatGPT and other providers can change their page DOM, which can break selectors; other send paths, other browsers/devices, direct API clients, or a disabled/uninstalled extension are outside its coverage. A user with control of the browser can disable or bypass the extension. For stronger organizational enforcement, use managed browsers and an approved network/DLP control in addition to this extension.

Gemini note: Gemini has no `<form>` around its composer and a localized send button ("Αποστολή μηνύματος"); the guard finds the send button from the composer's containers and by its Material `send` icon, so both Enter and click are intercepted.

Claude note: claude.ai (React + ProseMirror) sends from its own state, not from the DOM. After the pseudonymized text is written, the guard waits for the editor-to-React update to commit before pressing Send again, so the original text is never the one sent.

Supported AI services: **ChatGPT** (chatgpt.com, chat.openai.com), **Gemini** (gemini.google.com) and **Claude** (claude.ai) only.

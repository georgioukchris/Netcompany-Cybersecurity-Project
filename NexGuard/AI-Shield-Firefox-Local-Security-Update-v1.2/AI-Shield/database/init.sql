-- AI Shield schema. Safe to run on every startup; existing volumes are upgraded.
CREATE TABLE IF NOT EXISTS incidents (
    id          BIGSERIAL PRIMARY KEY,
    user_id     VARCHAR(100) NOT NULL,
    tool_name   VARCHAR(100) NOT NULL,
    action      VARCHAR(16)  NOT NULL CHECK (action IN ('ALLOW', 'REDACT', 'PSEUDONYMIZE', 'WARN', 'BLOCK')),
    risk        VARCHAR(10)  NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    findings    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);

-- Upgrade existing volumes: allow the PSEUDONYMIZE action (reversible privacy engine).
ALTER TABLE incidents ALTER COLUMN action TYPE VARCHAR(16);
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_action_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_action_check
    CHECK (action IN ('ALLOW', 'REDACT', 'PSEUDONYMIZE', 'WARN', 'BLOCK'));

-- Incident Investigation Center: workflow state per incident + activity log.
-- AUTO_CLOSED = a clean ALLOW scan with no findings (nothing to investigate).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'OPEN';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(60);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution_category VARCHAR(40);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution_note VARCHAR(1000);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ;
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_status_check
    CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'AUTO_CLOSED'));
UPDATE incidents SET status = 'AUTO_CLOSED'
    WHERE status = 'OPEN' AND action = 'ALLOW' AND findings = '[]'::jsonb;
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status, created_at DESC);

-- DLP WARN: the user confirmed the warning and the prompt was sent (NULL = not applicable / not confirmed).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS user_confirmed_at TIMESTAMPTZ;
-- What was inspected: a typed prompt ('text') or an attached PDF ('pdf'). Never the file name or content.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS content_type VARCHAR(8) NOT NULL DEFAULT 'text';
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_content_type_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_content_type_check CHECK (content_type IN ('text', 'pdf'));
-- Clean or low-risk scans (ALLOW) need no investigation.
UPDATE incidents SET status = 'AUTO_CLOSED' WHERE status = 'OPEN' AND action = 'ALLOW';

-- Who changed what and why. Never contains prompt text or matched values.
CREATE TABLE IF NOT EXISTS incident_activity (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  BIGINT       NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action       VARCHAR(16)  NOT NULL CHECK (action IN ('ACKNOWLEDGE', 'INVESTIGATE', 'RESOLVE')),
    analyst      VARCHAR(60)  NOT NULL,
    from_status  VARCHAR(16)  NOT NULL,
    to_status    VARCHAR(16)  NOT NULL,
    note         VARCHAR(1000),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_activity_incident ON incident_activity (incident_id, created_at);

-- Shadow AI registry. Status values are company policy decisions, not vendor trust claims.
CREATE TABLE IF NOT EXISTS shadow_ai_tools (
    id              BIGSERIAL PRIMARY KEY,
    provider_key    VARCHAR(80) NOT NULL,
    provider_name   VARCHAR(120) NOT NULL,
    domain          VARCHAR(255) NOT NULL UNIQUE,
    category        VARCHAR(80) NOT NULL DEFAULT 'AI assistant',
    status          VARCHAR(12) NOT NULL DEFAULT 'UNAPPROVED'
                    CHECK (status IN ('APPROVED', 'UNAPPROVED', 'REVIEW')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_tools_provider ON shadow_ai_tools(provider_key);

-- Privacy-minimised events: domain and team code only. No URL path, page title,
-- prompt text, form contents, cookies, or employee identity are stored.
CREATE TABLE IF NOT EXISTS shadow_ai_events (
    id                  BIGSERIAL PRIMARY KEY,
    tool_id             BIGINT NOT NULL REFERENCES shadow_ai_tools(id) ON DELETE RESTRICT,
    event_type          VARCHAR(30) NOT NULL DEFAULT 'domain_visit',
    source              VARCHAR(30) NOT NULL DEFAULT 'browser-extension',
    install_id_hash     CHAR(64) NOT NULL,
    team_label          VARCHAR(40) NOT NULL DEFAULT 'Unassigned',
    status_at_time      VARCHAR(12) NOT NULL
                        CHECK (status_at_time IN ('APPROVED', 'UNAPPROVED', 'REVIEW')),
    observed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_events_observed ON shadow_ai_events(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_events_install ON shadow_ai_events(install_id_hash, observed_at DESC);

-- Starter catalog for the hackathon demo. Adjust these statuses to match the
-- organisation's actual AI policy before any real deployment.
-- Supported AI services: ChatGPT, Gemini, Claude only.
-- Upgrade existing volumes: remove any other provider (and its discovery events) first.
DELETE FROM shadow_ai_events WHERE tool_id IN
    (SELECT id FROM shadow_ai_tools WHERE provider_key NOT IN ('chatgpt', 'gemini', 'claude'));
DELETE FROM shadow_ai_tools WHERE provider_key NOT IN ('chatgpt', 'gemini', 'claude');
ALTER TABLE shadow_ai_tools DROP CONSTRAINT IF EXISTS shadow_ai_tools_provider_check;
ALTER TABLE shadow_ai_tools ADD CONSTRAINT shadow_ai_tools_provider_check
    CHECK (provider_key IN ('chatgpt', 'gemini', 'claude'));

INSERT INTO shadow_ai_tools (provider_key, provider_name, domain, category, status) VALUES
 ('chatgpt', 'ChatGPT', 'chatgpt.com', 'General-purpose assistant', 'APPROVED'),
 ('chatgpt', 'ChatGPT', 'chat.openai.com', 'General-purpose assistant', 'APPROVED'),
 ('gemini', 'Google Gemini', 'gemini.google.com', 'General-purpose assistant', 'APPROVED'),
 ('claude', 'Claude', 'claude.ai', 'General-purpose assistant', 'REVIEW')
ON CONFLICT (domain) DO NOTHING;

-- ============================ NexGuard accounts ============================
-- Users sign in at /login (password or Google). Passwords are stored only as scrypt hashes;
-- session, reset and OAuth tokens only as SHA-256 hashes (a database leak reveals no usable token).
CREATE TABLE IF NOT EXISTS app_users (
    id             BIGSERIAL PRIMARY KEY,
    email          VARCHAR(254) NOT NULL UNIQUE,
    display_name   VARCHAR(80)  NOT NULL,
    role           VARCHAR(10)  NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    password_hash  VARCHAR(255),
    google_sub     VARCHAR(255) UNIQUE,
    disabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at  TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS user_sessions (
    id            BIGSERIAL PRIMARY KEY,
    token_hash    CHAR(64)     NOT NULL UNIQUE,
    user_id       BIGINT       NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ  NOT NULL,
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions (user_id);
CREATE TABLE IF NOT EXISTS password_resets (
    id          BIGSERIAL PRIMARY KEY,
    token_hash  CHAR(64)     NOT NULL UNIQUE,
    user_id     BIGINT       NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash     CHAR(64)     PRIMARY KEY,
    code_verifier  VARCHAR(128) NOT NULL,
    nonce          VARCHAR(64)  NOT NULL,
    next_path      VARCHAR(200) NOT NULL DEFAULT '/',
    expires_at     TIMESTAMPTZ  NOT NULL
);

-- Upgrade account tables created by older versions (CREATE TABLE IF NOT EXISTS never adds columns;
-- a missing column made /login answer 500).
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS display_name  VARCHAR(80)  NOT NULL DEFAULT '';
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role          VARCHAR(10)  NOT NULL DEFAULT 'user';
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS google_sub    VARCHAR(255);
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS disabled      BOOLEAN      NOT NULL DEFAULT FALSE;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW();
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE app_users ALTER COLUMN password_hash DROP NOT NULL;   -- invited users have no password yet
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS used_at    TIMESTAMPTZ;

-- Invitations from the Admin Console use one-time activation links.
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS purpose VARCHAR(8) NOT NULL DEFAULT 'reset';
ALTER TABLE password_resets DROP CONSTRAINT IF EXISTS password_resets_purpose_check;
ALTER TABLE password_resets ADD CONSTRAINT password_resets_purpose_check CHECK (purpose IN ('reset', 'invite'));

-- Who created, invited, changed or removed which account (Admin Console → Χρήστες).
CREATE TABLE IF NOT EXISTS account_activity (
    id            BIGSERIAL PRIMARY KEY,
    actor         VARCHAR(254) NOT NULL,
    action        VARCHAR(16)  NOT NULL CHECK (action IN ('CREATE', 'INVITE', 'ACTIVATE', 'ROLE', 'DISABLE', 'ENABLE', 'DELETE', 'RENAME')),
    target_email  VARCHAR(254) NOT NULL,
    detail        VARCHAR(200),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_account_activity_time ON account_activity (created_at DESC);

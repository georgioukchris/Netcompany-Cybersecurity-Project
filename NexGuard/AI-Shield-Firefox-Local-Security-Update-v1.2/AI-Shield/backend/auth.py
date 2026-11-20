"""NexGuard accounts: password login, sessions, password reset by email, Google sign-in.

Security notes
- Passwords: scrypt (N=2^14, r=8, p=1) with a per-user salt; compared in constant time.
- Session / reset / OAuth-state tokens: 256-bit random; only their SHA-256 is stored.
- Session cookie: HttpOnly, SameSite=Lax, Secure on HTTPS. Sessions are revoked on logout
  and on password reset.
- Login and reset requests are rate-limited; responses never reveal whether an email exists.
- Google: OAuth 2.0 authorization-code flow with PKCE (S256), state and nonce. The ID token
  is received directly from Google's token endpoint over TLS (OIDC Core 3.1.3.7), and its
  issuer, audience, expiry, nonce and email_verified claims are validated.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

from database import get_connection

logger = logging.getLogger("nexguard.auth")

SESSION_COOKIE = "ng_session"
SESSION_HOURS = 8
REMEMBER_DAYS = 30
RESET_MINUTES = 30
INVITE_HOURS = 72
OAUTH_STATE_MINUTES = 10
PASSWORD_MIN = 10
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,63}$")


# ------------------------------------------------------------------ helpers
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email)) and len(email) <= 254


def password_problem(password: str) -> str | None:
    if len(password) < PASSWORD_MIN:
        return f"Ο κωδικός πρέπει να έχει τουλάχιστον {PASSWORD_MIN} χαρακτήρες."
    if len(password) > 200:
        return "Ο κωδικός είναι πολύ μεγάλος."
    if password.lower() == password or password.upper() == password or not re.search(r"\d", password):
        return "Ο κωδικός πρέπει να έχει κεφαλαία, πεζά και τουλάχιστον έναν αριθμό."
    return None


# ------------------------------------------------------------------ passwords
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str | None) -> bool:
    try:
        scheme, n, r, p, salt, dk = (stored or _DUMMY_HASH).split("$")
        if scheme != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, _unb64(dk)) and stored is not None
    except Exception:
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))  # same work when the user does not exist


# ------------------------------------------------------------------ users
USER_COLS = "id, email, display_name, role, disabled, password_hash IS NOT NULL AS has_password, google_sub IS NOT NULL AS has_google"


def public_user(u: dict) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["display_name"], "role": u["role"]}


def get_user_by_email(email: str) -> dict | None:
    with get_connection() as conn:
        return conn.execute(f"SELECT {USER_COLS}, password_hash FROM app_users WHERE email = %s",
                            (normalize_email(email),)).fetchone()


def get_user_by_google(sub: str) -> dict | None:
    with get_connection() as conn:
        return conn.execute(f"SELECT {USER_COLS} FROM app_users WHERE google_sub = %s", (sub,)).fetchone()


def create_user(email: str, name: str, role: str = "user", password: str | None = None,
                google_sub: str | None = None, enforce_policy: bool = True) -> dict:
    email = normalize_email(email)
    if not valid_email(email):
        raise ValueError("Μη έγκυρο email.")
    if role not in ("user", "admin"):
        raise ValueError("Ο ρόλος πρέπει να είναι user ή admin.")
    if password is not None and enforce_policy and (msg := password_problem(password)):
        raise ValueError(msg)
    with get_connection() as conn:
        return conn.execute(
            f"""INSERT INTO app_users (email, display_name, role, password_hash, google_sub)
                VALUES (%s, %s, %s, %s, %s) RETURNING {USER_COLS}""",
            (email, (name or email.split("@")[0])[:80], role,
             hash_password(password) if password else None, google_sub)).fetchone()


def set_password(user_id: int, password: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE app_users SET password_hash = %s WHERE id = %s", (hash_password(password), user_id))


def link_google(user_id: int, sub: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE app_users SET google_sub = %s WHERE id = %s AND google_sub IS NULL", (sub, user_id))


def touch_login(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE app_users SET last_login_at = NOW() WHERE id = %s", (user_id,))


def bootstrap_users() -> None:
    """Create the demo user and the first admin from the environment, then make sure there is an
    administrator. Passwords of existing accounts are never overwritten."""
    # Demo user first: ADMIN_EMAIL may point at the demo account (e.g. ADMIN_EMAIL=test@test.com).
    for prefix, role in (("DEMO_USER", "user"), ("ADMIN", "admin")):
        email = normalize_email(os.getenv(f"{prefix}_EMAIL", ""))
        password = os.getenv(f"{prefix}_PASSWORD", "")
        if not email:
            continue
        try:
            if get_user_by_email(email):
                continue
            if not password:
                logger.warning("%s_EMAIL is set but %s_PASSWORD is empty: the %s account was not created.", prefix, prefix, role)
                continue
            # Demo only: DEMO_ALLOW_WEAK_PASSWORD=true lets the demo user (never the admin) keep a
            # short password such as "test". Every other account still follows the password rules.
            weak_ok = prefix == "DEMO_USER" and os.getenv("DEMO_ALLOW_WEAK_PASSWORD", "").lower() == "true"
            create_user(email, os.getenv(f"{prefix}_NAME", "") or email.split("@")[0], role, password,
                        enforce_policy=not weak_ok)
            logger.info("Created %s account %s", role, email)
            if weak_ok and password_problem(password):
                logger.warning("DEMO account %s has a WEAK password (DEMO_ALLOW_WEAK_PASSWORD=true). "
                               "Use it only for local demos, never on a server reachable by others.", email)
        except Exception as exc:
            logger.warning("Could not create %s account from .env: %s", role, exc)
    try:
        ensure_first_admin()
    except Exception as exc:
        logger.warning("Could not set the first admin from ADMIN_EMAIL: %s", exc)


def ensure_first_admin() -> None:
    """While there is no active administrator, the existing account named in ADMIN_EMAIL is made
    admin (role only; the password is not touched). Once an admin exists nothing is changed, so a
    role later changed in the Admin Console is not undone on restart."""
    email = normalize_email(os.getenv("ADMIN_EMAIL", ""))
    if not email:
        return
    user = get_user_by_email(email)
    if user is None or user["role"] == "admin" or user["disabled"]:
        return
    if active_admins_except(user["id"]) > 0:
        return
    update_user(user["id"], role="admin")
    log_activity("system", "ROLE", email, "admin από ADMIN_EMAIL (.env), πρώτη εκκίνηση")
    logger.info("Account %s is now admin (ADMIN_EMAIL, no administrator existed).", email)
    if email == normalize_email(os.getenv("DEMO_USER_EMAIL", "")) and password_problem(os.getenv("DEMO_USER_PASSWORD", "")):
        logger.warning("ADMIN account %s has a WEAK demo password. Use it only for local demos.", email)


# ------------------------------------------------------------------ sessions
def create_session(user_id: int, remember: bool) -> tuple[str, int]:
    token = new_token()
    max_age = REMEMBER_DAYS * 86400 if remember else SESSION_HOURS * 3600
    with get_connection() as conn:
        conn.execute("""INSERT INTO user_sessions (token_hash, user_id, expires_at)
                        VALUES (%s, %s, NOW() + make_interval(secs => %s))""", (token_hash(token), user_id, max_age))
        # housekeeping: drop expired sessions / resets / oauth states
        conn.execute("DELETE FROM user_sessions WHERE expires_at < NOW()")
    touch_login(user_id)
    return token, max_age


def session_user(token: str | None) -> dict | None:
    if not token or len(token) > 100:
        return None
    with get_connection() as conn:
        return conn.execute(
            f"""UPDATE user_sessions s SET last_seen_at = NOW()
                FROM app_users u
                WHERE s.token_hash = %s AND s.user_id = u.id AND s.expires_at > NOW() AND NOT u.disabled
                RETURNING u.id, u.email, u.display_name, u.role""", (token_hash(token),)).fetchone()


def delete_session(token: str | None) -> None:
    if token:
        with get_connection() as conn:
            conn.execute("DELETE FROM user_sessions WHERE token_hash = %s", (token_hash(token),))


def delete_user_sessions(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = %s", (user_id,))


# ------------------------------------------------------------------ password reset
def create_reset(user_id: int, purpose: str = "reset") -> str:
    """One-time link: 'reset' (forgot password, 30 min) or 'invite' (new account, 72 h).
    Any earlier unused link of the same user stops working."""
    token = new_token()
    minutes = INVITE_HOURS * 60 if purpose == "invite" else RESET_MINUTES
    with get_connection() as conn:
        conn.execute("DELETE FROM password_resets WHERE expires_at < NOW() OR (user_id = %s AND used_at IS NULL)", (user_id,))
        conn.execute("""INSERT INTO password_resets (token_hash, user_id, expires_at, purpose)
                        VALUES (%s, %s, NOW() + make_interval(mins => %s), %s)""", (token_hash(token), user_id, minutes, purpose))
    return token


def consume_reset(token: str) -> dict | None:
    """Single use: atomically marks the token used; returns {user_id, purpose} or None."""
    if not token or len(token) > 100:
        return None
    with get_connection() as conn:
        return conn.execute("""UPDATE password_resets SET used_at = NOW()
                               WHERE token_hash = %s AND used_at IS NULL AND expires_at > NOW()
                               RETURNING user_id, purpose""", (token_hash(token),)).fetchone()


# ------------------------------------------------------------------ user management (Admin Console)
def log_activity(actor: str, action: str, target_email: str, detail: str | None = None) -> None:
    with get_connection() as conn:
        conn.execute("INSERT INTO account_activity (actor, action, target_email, detail) VALUES (%s, %s, %s, %s)",
                     (actor[:254], action, target_email[:254], (detail or None) and detail[:200]))


def list_users() -> list[dict]:
    with get_connection() as conn:
        return conn.execute("""
            SELECT u.id, u.email, u.display_name AS name, u.role, u.disabled, u.created_at, u.last_login_at,
                   u.password_hash IS NOT NULL AS has_password, u.google_sub IS NOT NULL AS has_google,
                   (SELECT MAX(r.expires_at) FROM password_resets r
                     WHERE r.user_id = u.id AND r.purpose = 'invite' AND r.used_at IS NULL) AS invite_expires_at,
                   (SELECT COUNT(*) FROM user_sessions s WHERE s.user_id = u.id AND s.expires_at > NOW()) AS active_sessions
            FROM app_users u ORDER BY u.created_at DESC, u.id DESC""").fetchall()


def recent_activity(limit: int = 30) -> list[dict]:
    with get_connection() as conn:
        return conn.execute("""SELECT actor, action, target_email, detail, created_at FROM account_activity
                               ORDER BY id DESC LIMIT %s""", (limit,)).fetchall()


def get_user(user_id: int) -> dict | None:
    with get_connection() as conn:
        return conn.execute(f"SELECT {USER_COLS} FROM app_users WHERE id = %s", (user_id,)).fetchone()


def active_admins_except(user_id: int) -> int:
    with get_connection() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM app_users WHERE role = 'admin' AND NOT disabled AND id <> %s",
                                (user_id,)).fetchone()["n"])


def update_user(user_id: int, role: str | None = None, disabled: bool | None = None, name: str | None = None) -> None:
    with get_connection() as conn:
        if role is not None:
            conn.execute("UPDATE app_users SET role = %s WHERE id = %s", (role, user_id))
        if disabled is not None:
            conn.execute("UPDATE app_users SET disabled = %s WHERE id = %s", (disabled, user_id))
        if name is not None:
            conn.execute("UPDATE app_users SET display_name = %s WHERE id = %s", (name, user_id))


def delete_user(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM app_users WHERE id = %s", (user_id,))


# ------------------------------------------------------------------ rate limiting (per process)
class RateLimiter:
    def __init__(self, limit: int, window_s: int):
        self.limit, self.window, self.hits, self.lock = limit, window_s, {}, threading.Lock()

    def _recent(self, key):
        now = time.monotonic()
        self.hits[key] = [t for t in self.hits.get(key, []) if now - t < self.window]
        return self.hits[key]

    def blocked(self, key) -> bool:
        with self.lock:
            return len(self._recent(key)) >= self.limit

    def hit(self, key) -> None:
        with self.lock:
            self._recent(key).append(time.monotonic())

    def clear(self, key) -> None:
        with self.lock:
            self.hits.pop(key, None)


login_by_email = RateLimiter(5, 15 * 60)     # 5 wrong passwords per account / 15 min
login_by_ip = RateLimiter(30, 15 * 60)
reset_by_email = RateLimiter(5, 15 * 60)   # reset emails per account / 15 min
reset_by_ip = RateLimiter(20, 15 * 60)


# ------------------------------------------------------------------ email
def mail_configured() -> bool:
    return bool(os.getenv("SMTP_HOST"))


def send_mail(to: str, subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER") or "nexguard@localhost"
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    port = int(os.getenv("SMTP_PORT", "587"))
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            if os.getenv("SMTP_STARTTLS", "true").lower() != "false":
                server.starttls(context=ssl.create_default_context())
        with server:
            if os.getenv("SMTP_USER"):
                server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("Password reset email could not be sent: %s", type(exc).__name__)
        return False


# ------------------------------------------------------------------ Google sign-in
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}


def google_config() -> dict | None:
    cid, secret = os.getenv("GOOGLE_CLIENT_ID", "").strip(), os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    if not cid or not secret:
        return None
    return {
        "client_id": cid, "client_secret": secret,
        "auth_url": os.getenv("GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth"),
        "token_url": os.getenv("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token"),
        "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI", "").strip(),
        "allowed_domains": [d.strip().lower().lstrip("@") for d in os.getenv("GOOGLE_ALLOWED_DOMAINS", "").split(",") if d.strip()],
    }


def create_oauth_state(next_path: str) -> tuple[str, str, str]:
    state, verifier, nonce = new_token(), secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    with get_connection() as conn:
        conn.execute("DELETE FROM oauth_states WHERE expires_at < NOW()")
        conn.execute("""INSERT INTO oauth_states (state_hash, code_verifier, nonce, next_path, expires_at)
                        VALUES (%s, %s, %s, %s, NOW() + make_interval(mins => %s))""",
                     (token_hash(state), verifier, nonce, next_path, OAUTH_STATE_MINUTES))
    return state, verifier, nonce


def consume_oauth_state(state: str) -> dict | None:
    if not state or len(state) > 100:
        return None
    with get_connection() as conn:
        return conn.execute("""DELETE FROM oauth_states WHERE state_hash = %s AND expires_at > NOW()
                               RETURNING code_verifier, nonce, next_path""", (token_hash(state),)).fetchone()


def google_auth_url(cfg: dict, redirect_uri: str, state: str, verifier: str, nonce: str) -> str:
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    params = {"client_id": cfg["client_id"], "redirect_uri": redirect_uri, "response_type": "code",
              "scope": "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"}
    if len(cfg["allowed_domains"]) == 1:
        params["hd"] = cfg["allowed_domains"][0]
    return cfg["auth_url"] + "?" + urllib.parse.urlencode(params)


class GoogleError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def google_exchange(cfg: dict, code: str, verifier: str, redirect_uri: str, nonce: str) -> dict:
    body = urllib.parse.urlencode({"code": code, "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
                                   "redirect_uri": redirect_uri, "grant_type": "authorization_code",
                                   "code_verifier": verifier}).encode()
    req = urllib.request.Request(cfg["token_url"], data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        _, payload, _ = data["id_token"].split(".")
        claims = json.loads(_unb64(payload))
    except Exception as exc:
        logger.warning("Google token exchange failed: %s", type(exc).__name__)
        raise GoogleError("google_failed") from exc
    if (claims.get("iss") not in GOOGLE_ISSUERS or claims.get("aud") != cfg["client_id"]
            or int(claims.get("exp", 0)) < time.time() or not hmac.compare_digest(str(claims.get("nonce", "")), nonce)
            or not claims.get("sub")):
        raise GoogleError("google_failed")
    if claims.get("email_verified") is not True or not claims.get("email"):
        raise GoogleError("google_unverified")
    return claims


def google_user(cfg: dict, claims: dict) -> dict:
    """Existing account (by Google id, then by verified email) or, for an allowed domain, a new user."""
    sub, email = str(claims["sub"]), normalize_email(claims["email"])
    user = get_user_by_google(sub)
    if user is None:
        user = get_user_by_email(email)
        if user is not None:
            link_google(user["id"], sub)
    if user is None:
        domain = email.rsplit("@", 1)[-1]
        if domain not in cfg["allowed_domains"]:
            raise GoogleError("account_not_allowed")
        user = create_user(email, str(claims.get("name") or "")[:80], "user", None, sub)
    if user["disabled"]:
        raise GoogleError("account_disabled")
    return user

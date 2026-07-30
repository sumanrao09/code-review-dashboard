"""SonarQube token management.

The scanner and the issues API need a user token. Instead of making the user
create one by hand, we provision it through SonarQube's own API
(/api/user_tokens/generate) using the documented default credentials of a
fresh install (admin/admin) — which is exactly what the bundled Docker
service ships with. Resolution order for a working token:

1. SONAR_TOKEN env var — explicit user config, never overridden
2. token stored in the settings DB — pasted in Settings or auto-provisioned
3. auto-provision via the API with admin/admin (fresh installs)
"""
import os

import httpx

from app import db, token_store

SONAR_URL = os.environ.get("SONAR_URL", "http://localhost:9000")
TOKEN_NAME = "secure-review-dashboard"
_SETTING_KEY = "sonar_token"

# SonarQube's documented factory credentials. Auto-provisioning only works
# while a fresh local install still has them; once the admin password is
# changed the user supplies a token via Settings or SONAR_TOKEN instead.
_DEFAULT_LOGIN = "admin"
_DEFAULT_PASSWORD = "admin"


def validate_token(token: str) -> bool:
    """True if the token authenticates against the server."""
    try:
        r = httpx.get(f"{SONAR_URL}/api/authentication/validate",
                      auth=(token, ""), timeout=10)
        return r.status_code == 200 and r.json().get("valid") is True
    except Exception:
        return False


def generate_token(login: str | None = None,
                   password: str | None = None) -> str:
    """Create (or recreate) our named user token via the SonarQube API."""
    login = login or _DEFAULT_LOGIN
    password = password or _DEFAULT_PASSWORD

    def _post(action: str, **data):
        return httpx.post(f"{SONAR_URL}/api/user_tokens/{action}",
                          data=data, auth=(login, password), timeout=15)

    resp = _post("generate", name=TOKEN_NAME)
    if resp.status_code == 400:  # token name already exists — recreate it
        _post("revoke", name=TOKEN_NAME)
        resp = _post("generate", name=TOKEN_NAME)
    if resp.status_code != 200:
        raise RuntimeError(
            f"SonarQube refused token generation (HTTP {resp.status_code}) — "
            f"has the admin password been changed?")
    return resp.json()["token"]


def stored_token(conn) -> str | None:
    return db.get_setting(conn, _SETTING_KEY)


def store_token(conn, token: str) -> None:
    db.set_setting(conn, _SETTING_KEY, token)


def resolve_token() -> str:
    """Best available token for a scan run (no provisioning attempts here)."""
    return token_store.resolve("SONAR_TOKEN", _SETTING_KEY) or "admin"


def ensure_token(conn) -> list:
    """Pre-scan hook: make sure a working token exists, auto-provisioning one
    from a default-credential server if needed. Returns preflight warnings."""
    if os.environ.get("SONAR_TOKEN"):
        return []  # explicit config wins; the user manages it
    tok = stored_token(conn)
    if tok and validate_token(tok):
        return []
    try:
        store_token(conn, generate_token())
        return []
    except Exception as exc:
        if tok:  # keep the stored token — the server may just be down
            return [f"sonarqube: stored token could not be validated and "
                    f"auto-provisioning failed ({exc})."]
        return [f"sonarqube: no token available and auto-provisioning with "
                f"default credentials failed ({exc}). Paste a token in "
                f"Settings or set SONAR_TOKEN."]

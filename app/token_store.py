"""Scanner-token resolution shared by the runners.

Resolution order: explicit env var (never overridden) → token stored in the
settings DB (pasted in the Settings dialog or auto-provisioned) → None.
"""
import os

from app import db
from app.config import DB_PATH


def resolve(env_var: str, setting_key: str) -> str | None:
    env = os.environ.get(env_var)
    if env:
        return env
    try:
        conn = db.connect(DB_PATH)
        tok = db.get_setting(conn, setting_key)
        conn.close()
        return tok or None
    except Exception:
        return None

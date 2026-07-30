"""Tests for SonarQube token auto-provisioning."""
import pytest

from app import db, token_store
from app.runners import sonar_auth


class _Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body


def _conn(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    return db.connect(dbp)


# ---------- generate_token ----------
def test_generate_token_success(monkeypatch):
    monkeypatch.setattr(sonar_auth.httpx, "post",
                        lambda *a, **k: _Resp(200, {"token": "squ_abc"}))
    assert sonar_auth.generate_token() == "squ_abc"


def test_generate_token_recreates_existing(monkeypatch):
    seq = [_Resp(400), _Resp(200), _Resp(200, {"token": "squ_new"})]
    monkeypatch.setattr(sonar_auth.httpx, "post",
                        lambda *a, **k: seq.pop(0))
    assert sonar_auth.generate_token() == "squ_new"


def test_generate_token_auth_failure_raises(monkeypatch):
    monkeypatch.setattr(sonar_auth.httpx, "post", lambda *a, **k: _Resp(401))
    with pytest.raises(RuntimeError, match="password"):
        sonar_auth.generate_token()


# ---------- ensure_token ----------
def test_ensure_token_env_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("SONAR_TOKEN", "envtok")
    assert sonar_auth.ensure_token(_conn(tmp_path)) == []


def test_ensure_token_autoprovisions_and_stores(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    monkeypatch.setattr(sonar_auth, "generate_token", lambda: "squ_auto")
    conn = _conn(tmp_path)
    assert sonar_auth.ensure_token(conn) == []
    assert sonar_auth.stored_token(conn) == "squ_auto"


def test_ensure_token_keeps_valid_stored_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    conn = _conn(tmp_path)
    sonar_auth.store_token(conn, "squ_ok")
    monkeypatch.setattr(sonar_auth, "validate_token", lambda t: True)

    def never():
        raise AssertionError("should not regenerate a valid token")
    monkeypatch.setattr(sonar_auth, "generate_token", never)
    assert sonar_auth.ensure_token(conn) == []


def test_ensure_token_warns_when_provisioning_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)

    def boom():
        raise RuntimeError("HTTP 401")
    monkeypatch.setattr(sonar_auth, "generate_token", boom)
    warnings = sonar_auth.ensure_token(_conn(tmp_path))
    assert len(warnings) == 1
    assert "Settings" in warnings[0]


def test_ensure_token_keeps_stored_when_server_down(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    conn = _conn(tmp_path)
    sonar_auth.store_token(conn, "squ_user_pasted")
    monkeypatch.setattr(sonar_auth, "validate_token", lambda t: False)

    def down():
        raise RuntimeError("connection refused")
    monkeypatch.setattr(sonar_auth, "generate_token", down)
    warnings = sonar_auth.ensure_token(conn)
    assert len(warnings) == 1
    assert sonar_auth.stored_token(conn) == "squ_user_pasted"  # not clobbered


# ---------- resolve_token ----------
def test_resolve_token_env_first(monkeypatch):
    monkeypatch.setenv("SONAR_TOKEN", "envtok")
    assert sonar_auth.resolve_token() == "envtok"


def test_resolve_token_from_db(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    db.set_setting(conn, "sonar_token", "squ_db")
    conn.close()
    monkeypatch.setattr(token_store, "DB_PATH", dbp)
    assert sonar_auth.resolve_token() == "squ_db"


def test_resolve_token_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    monkeypatch.setattr(token_store, "DB_PATH", tmp_path / "missing.db")
    assert sonar_auth.resolve_token() == "admin"

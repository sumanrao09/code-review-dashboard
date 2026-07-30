from app import db, settings


def _conn(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    return db.connect(dbp)


def test_save_and_get(tmp_path):
    conn = _conn(tmp_path)
    settings.save_provider_config(conn, "anthropic", {"anthropic": "sk-ant-123"})
    cfg = settings.get_provider_config(conn)
    assert cfg["provider"] == "anthropic"
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["openai_key"] is None


def test_empty_key_does_not_overwrite(tmp_path):
    conn = _conn(tmp_path)
    settings.save_provider_config(conn, "anthropic", {"anthropic": "sk-ant-123"})
    settings.save_provider_config(conn, "openai", {"anthropic": "", "openai": ""})
    cfg = settings.get_provider_config(conn)
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["provider"] == "openai"


def test_new_provider_keys_roundtrip(tmp_path):
    conn = _conn(tmp_path)
    settings.save_provider_config(conn, "gemini", {
        "gemini": "g-1", "deepseek": "d-1", "grok": "x-1"})
    cfg = settings.get_provider_config(conn)
    assert cfg["gemini_key"] == "g-1"
    assert cfg["deepseek_key"] == "d-1"
    assert cfg["grok_key"] == "x-1"


def test_keyless_provider_selectable(tmp_path):
    conn = _conn(tmp_path)
    settings.save_provider_config(conn, "ollama", {})
    assert settings.get_provider_config(conn)["provider"] == "ollama"


def test_unknown_key_names_ignored(tmp_path):
    conn = _conn(tmp_path)
    settings.save_provider_config(conn, "anthropic", {"evil": "x"})
    assert db.get_setting(conn, "evil_key") is None


def test_settings_endpoint_scanner_tokens(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main

    dbp = tmp_path / "app.db"
    monkeypatch.setattr(main, "DB_PATH", dbp)
    db.init_db(dbp)
    client = TestClient(main.app)

    cfg = client.get("/api/settings").json()
    assert cfg["sonar_token"] == "unset"
    assert cfg["snyk_token"] == "unset"

    client.post("/api/settings",
                json={"sonar_token": "sq-1", "snyk_token": "st-1"})
    cfg = client.get("/api/settings").json()
    assert cfg["sonar_token"] == "set"
    assert cfg["snyk_token"] == "set"

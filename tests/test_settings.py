from app import db, settings


def test_save_and_get(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    settings.save_provider_config(conn, "anthropic", "sk-ant-123", "")
    cfg = settings.get_provider_config(conn)
    assert cfg["provider"] == "anthropic"
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["openai_key"] is None


def test_empty_key_does_not_overwrite(tmp_path):
    dbp = tmp_path / "app.db"
    db.init_db(dbp)
    conn = db.connect(dbp)
    settings.save_provider_config(conn, "anthropic", "sk-ant-123", "")
    settings.save_provider_config(conn, "openai", "", "")
    cfg = settings.get_provider_config(conn)
    assert cfg["anthropic_key"] == "sk-ant-123"
    assert cfg["provider"] == "openai"

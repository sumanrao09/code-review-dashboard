from app import db


def get_provider_config(conn) -> dict:
    return {
        "provider": db.get_setting(conn, "provider"),
        "anthropic_key": db.get_setting(conn, "anthropic_key"),
        "openai_key": db.get_setting(conn, "openai_key"),
    }


def save_provider_config(conn, provider: str, anthropic_key: str,
                         openai_key: str) -> None:
    if provider:
        db.set_setting(conn, "provider", provider)
    if anthropic_key:
        db.set_setting(conn, "anthropic_key", anthropic_key)
    if openai_key:
        db.set_setting(conn, "openai_key", openai_key)

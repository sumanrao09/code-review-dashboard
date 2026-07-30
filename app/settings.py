from app import db

# Providers that authenticate with an API key stored in Settings.
KEYED_PROVIDERS = ["anthropic", "openai", "gemini", "deepseek", "grok"]
# Providers that need no key (Ollama runs locally).
KEYLESS_PROVIDERS = ["ollama"]
PROVIDERS = KEYED_PROVIDERS + KEYLESS_PROVIDERS


def get_provider_config(conn) -> dict:
    cfg = {"provider": db.get_setting(conn, "provider")}
    for p in KEYED_PROVIDERS:
        cfg[f"{p}_key"] = db.get_setting(conn, f"{p}_key")
    return cfg


def save_provider_config(conn, provider: str, keys: dict) -> None:
    """Persist the active provider and any non-empty keys.

    Empty values never overwrite a stored key, so the UI can send blank
    fields for keys the user wants to keep.
    """
    if provider:
        db.set_setting(conn, "provider", provider)
    for name, value in (keys or {}).items():
        if name in KEYED_PROVIDERS and value:
            db.set_setting(conn, f"{name}_key", value)

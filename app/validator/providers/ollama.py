"""Local models via Ollama's OpenAI-compatible endpoint. No API key needed —
override the model/URL with the OLLAMA_MODEL / OLLAMA_URL env vars."""
import os

from app.validator.base import Verdict
from app.validator.providers.openai_compat import validate_via

DEFAULT_MODEL = "llama3.1"
DEFAULT_URL = "http://localhost:11434/v1"


def validate(prompt: str, api_key: str) -> Verdict:
    model = os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
    base_url = os.environ.get("OLLAMA_URL", DEFAULT_URL)
    # Ollama ignores the key but the OpenAI client requires a non-empty one.
    return validate_via(base_url, model, prompt, api_key or "ollama")

from app.validator.base import Verdict
from app.validator.providers.openai_compat import validate_via

MODEL = "grok-3"
BASE_URL = "https://api.x.ai/v1"


def validate(prompt: str, api_key: str) -> Verdict:
    return validate_via(BASE_URL, MODEL, prompt, api_key)

from app.validator.base import Verdict
from app.validator.providers.openai_compat import validate_via

MODEL = "deepseek-chat"
BASE_URL = "https://api.deepseek.com"


def validate(prompt: str, api_key: str) -> Verdict:
    return validate_via(BASE_URL, MODEL, prompt, api_key)

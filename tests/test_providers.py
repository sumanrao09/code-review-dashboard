import json

import pytest

from app.validator.providers import anthropic as anth
from app.validator.providers import deepseek, gemini, grok, ollama
from app.validator.providers import openai as oai
from app.validator.providers import openai_compat


def test_anthropic_verdict_from_json():
    data = {"verdict": "confirmed", "confidence": "high", "verdict_note": "n",
            "impact_text": "i", "recommendation": "r", "cwe": "CWE-89"}
    v = anth._verdict_from_json(data)
    assert v.verdict == "confirmed"
    assert v.cwe == "CWE-89"


def test_openai_verdict_from_json_null_cwe():
    data = {"verdict": "false_positive", "confidence": "medium",
            "verdict_note": "n", "impact_text": "i", "recommendation": "r",
            "cwe": None}
    v = oai._verdict_from_json(data)
    assert v.verdict == "false_positive"
    assert v.cwe is None


def test_anthropic_refusal_helper():
    v = anth._refusal_verdict()
    assert v.verdict == "inconclusive"
    assert v.confidence == "low"


# ---------- Gemini ----------
class _FakeResp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


def test_gemini_validate_parses_response(monkeypatch):
    verdict_json = {"verdict": "confirmed", "confidence": "high",
                    "verdict_note": "n", "impact_text": "i",
                    "recommendation": "r", "cwe": "CWE-79"}
    body = {"candidates": [{"content": {"parts": [
        {"text": json.dumps(verdict_json)}]}}]}
    monkeypatch.setattr(gemini.httpx, "post", lambda *a, **k: _FakeResp(body))
    v = gemini.validate("prompt", "key")
    assert v.verdict == "confirmed"
    assert v.cwe == "CWE-79"


def test_gemini_safety_block_is_inconclusive(monkeypatch):
    body = {"candidates": [{"finishReason": "SAFETY"}]}
    monkeypatch.setattr(gemini.httpx, "post", lambda *a, **k: _FakeResp(body))
    v = gemini.validate("prompt", "key")
    assert v.verdict == "inconclusive"


def test_gemini_empty_candidates_is_inconclusive(monkeypatch):
    monkeypatch.setattr(gemini.httpx, "post",
                        lambda *a, **k: _FakeResp({"candidates": []}))
    assert gemini.validate("prompt", "key").verdict == "inconclusive"


# ---------- OpenAI-compatible helper (DeepSeek / Grok / Ollama) ----------
def test_extract_json_plain():
    data = openai_compat._extract_json('{"verdict": "confirmed"}')
    assert data["verdict"] == "confirmed"


def test_extract_json_code_fenced_with_prose():
    text = 'Here you go:\n```json\n{"verdict": "false_positive", "cwe": null}\n```'
    data = openai_compat._extract_json(text)
    assert data["verdict"] == "false_positive"
    assert data["cwe"] is None


def test_extract_json_rejects_non_json():
    with pytest.raises(ValueError):
        openai_compat._extract_json("I cannot answer that.")


def test_compat_providers_use_expected_endpoints():
    assert deepseek.BASE_URL == "https://api.deepseek.com"
    assert grok.BASE_URL == "https://api.x.ai/v1"
    assert ollama.DEFAULT_URL.startswith("http://localhost:11434")


def test_service_registry_has_all_providers():
    from app.validator import service
    assert set(service.PROVIDERS) == {"anthropic", "openai", "gemini",
                                      "deepseek", "grok", "ollama"}

from app.validator.providers import anthropic as anth
from app.validator.providers import openai as oai


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

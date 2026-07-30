import json

import httpx

from app.validator.base import Verdict

MODEL = "gemini-2.5-flash"
BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

# Gemini's responseSchema is an OpenAPI-style subset (no additionalProperties,
# uppercase types, nullable flag), so it gets its own schema rather than
# reusing VERDICT_SCHEMA.
_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "verdict": {"type": "STRING",
                    "enum": ["confirmed", "partially_true", "false_positive"]},
        "confidence": {"type": "STRING", "enum": ["high", "medium", "low"]},
        "verdict_note": {"type": "STRING"},
        "impact_text": {"type": "STRING"},
        "recommendation": {"type": "STRING"},
        "cwe": {"type": "STRING", "nullable": True},
    },
    "required": ["verdict", "confidence", "verdict_note", "impact_text",
                 "recommendation"],
}


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def _refusal_verdict() -> Verdict:
    return Verdict(verdict="inconclusive", confidence="low",
                   verdict_note="Model declined to assess this finding.",
                   impact_text="", recommendation="", cwe=None)


def validate(prompt: str, api_key: str) -> Verdict:
    resp = httpx.post(
        f"{BASE_URL}/{MODEL}:generateContent",
        headers={"x-goog-api-key": api_key},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": _SCHEMA,
            },
        },
        timeout=120,
    )
    resp.raise_for_status()
    body = resp.json()
    candidates = body.get("candidates") or []
    if not candidates or candidates[0].get("finishReason") == "SAFETY":
        return _refusal_verdict()
    parts = candidates[0].get("content", {}).get("parts", [])
    text = next((p["text"] for p in parts if "text" in p), "{}")
    return _verdict_from_json(json.loads(text))

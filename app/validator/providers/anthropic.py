import json

import anthropic

from app.validator.base import VERDICT_SCHEMA, Verdict

MODEL = "claude-opus-4-8"


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
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.beta.messages.create(
        model=MODEL,
        max_tokens=1024,
        betas=["server-side-fallback-2026-06-01"],
        fallbacks=[{"model": "claude-opus-4-8"}],
        output_config={"format": {"type": "json_schema",
                                  "schema": VERDICT_SCHEMA}},
        messages=[{"role": "user", "content": prompt}],
    )
    if resp.stop_reason == "refusal":
        return _refusal_verdict()
    text = next((b.text for b in resp.content if b.type == "text"), "{}")
    return _verdict_from_json(json.loads(text))

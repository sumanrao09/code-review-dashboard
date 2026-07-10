import json

from openai import OpenAI

from app.validator.base import VERDICT_SCHEMA, Verdict

MODEL = "gpt-4o"


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def validate(prompt: str, api_key: str) -> Verdict:
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "verdict", "strict": True,
                            "schema": VERDICT_SCHEMA},
        },
    )
    data = json.loads(resp.choices[0].message.content)
    return _verdict_from_json(data)

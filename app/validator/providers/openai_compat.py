"""Shared validate() plumbing for OpenAI-compatible APIs.

DeepSeek, xAI (Grok) and Ollama all speak the OpenAI chat-completions
protocol, so each provider module is a thin wrapper around validate_via().
Strict json_schema mode isn't uniformly supported across these servers, so we
request json_object mode (falling back to plain text) and parse leniently.
"""
import json
import re

from openai import BadRequestError, OpenAI

from app.validator.base import Verdict


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def _extract_json(text: str) -> dict:
    """Parse a JSON object out of a model reply, tolerating code fences."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text, flags=re.S)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"No JSON object in model response: {text[:200]!r}")
    return json.loads(text[start:end + 1])


def validate_via(base_url: str, model: str, prompt: str,
                 api_key: str) -> Verdict:
    client = OpenAI(api_key=api_key, base_url=base_url)
    kwargs = {"model": model,
              "messages": [{"role": "user", "content": prompt}]}
    try:
        resp = client.chat.completions.create(
            **kwargs, response_format={"type": "json_object"})
    except BadRequestError:
        # Server doesn't support response_format — rely on the prompt's
        # "return JSON" instruction and lenient parsing instead.
        resp = client.chat.completions.create(**kwargs)
    data = _extract_json(resp.choices[0].message.content)
    return _verdict_from_json(data)

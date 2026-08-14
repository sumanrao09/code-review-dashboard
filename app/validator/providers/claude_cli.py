"""Validate findings through the local Claude CLI (Claude Code) in headless
mode, instead of the Anthropic API.

This uses whatever the CLI is logged into — including a Claude Pro/Max
*subscription* — so it needs no API key. It shells out exactly like the
scanner runners do:

    claude -p --output-format json      (prompt on stdin)

`--output-format json` wraps the model reply in an envelope
(``{"result": "<text>", "is_error": false, ...}``); we pull ``result`` out
and parse the verdict JSON from it. Point at a specific binary with the
CLAUDE_CLI env var if `claude` isn't on PATH.
"""
import json
import os
import re
import shutil
import subprocess

from app.validator.base import Verdict

NAME = "claude_cli"

# Steer the CLI to answer directly from the prompt and emit only JSON, so a
# print-mode agent session doesn't wander off into tool use or prose.
_JSON_ONLY = (
    "\n\nImportant: Answer only from the context above — do not use any tools, "
    "read files, or run commands. Respond with ONLY the JSON object described, "
    "with no prose and no markdown code fences."
)

_TIMEOUT_SECONDS = 180


def _resolve_exe() -> str | None:
    return (os.environ.get("CLAUDE_CLI")
            or shutil.which("claude")
            or shutil.which("claude.cmd"))


def _cli_argv(exe: str) -> list:
    # A .cmd/.bat shim can't be launched by bare name on Windows — go via cmd /c.
    if exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe]
    return [exe]


def _model_text(stdout: str) -> str:
    """Unwrap the CLI's JSON envelope to the model's reply text.

    `--output-format json` wraps the reply as ``{"type": "result",
    "result": "<text>", ...}``. Older builds may emit the reply directly, so
    only dicts that actually look like the envelope are unwrapped — anything
    else (e.g. the verdict JSON itself) is passed through untouched.
    """
    stdout = (stdout or "").strip()
    try:
        env = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout  # older CLI / plain output — treat as the reply itself
    is_envelope = isinstance(env, dict) and ("result" in env
                                             or env.get("type") == "result")
    if is_envelope:
        if env.get("is_error"):
            raise RuntimeError(env.get("result") or "Claude CLI reported an error")
        return env.get("result") or ""
    return stdout  # not an envelope — hand the raw text to _extract_json


def _extract_json(text: str) -> dict:
    """Parse a JSON object out of a reply, tolerating code fences and prose."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text, flags=re.S)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"No JSON object in Claude CLI response: {text[:200]!r}")
    return json.loads(text[start:end + 1])


def _verdict_from_json(data: dict) -> Verdict:
    return Verdict(
        verdict=data["verdict"], confidence=data["confidence"],
        verdict_note=data["verdict_note"], impact_text=data["impact_text"],
        recommendation=data["recommendation"], cwe=data.get("cwe"),
    )


def validate(prompt: str, api_key: str = "") -> Verdict:
    exe = _resolve_exe()
    if not exe:
        raise RuntimeError(
            "Claude CLI not found. Install Claude Code and make sure 'claude' is "
            "on your PATH (or set the CLAUDE_CLI env var to its full path), then "
            "sign in with your subscription via `claude`.")
    cmd = _cli_argv(exe) + ["-p", "--output-format", "json"]
    try:
        proc = subprocess.run(
            cmd, input=prompt + _JSON_ONLY, capture_output=True,
            text=True, encoding="utf-8", timeout=_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Claude CLI timed out after {_TIMEOUT_SECONDS}s.")
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(
            f"Claude CLI exited {proc.returncode}: {msg[:300] or 'no output'}")
    return _verdict_from_json(_extract_json(_model_text(proc.stdout)))
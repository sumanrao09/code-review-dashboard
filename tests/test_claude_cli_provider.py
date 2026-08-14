import json

import pytest

from app.validator.providers import claude_cli


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_VERDICT = {
    "verdict": "confirmed", "confidence": "high",
    "verdict_note": "user input reaches os.system",
    "impact_text": "remote command execution",
    "recommendation": "use subprocess with a list", "cwe": "CWE-78",
}


def _patch(monkeypatch, proc):
    monkeypatch.setattr(claude_cli, "_resolve_exe", lambda: "claude")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        return proc

    monkeypatch.setattr(claude_cli.subprocess, "run", fake_run)
    return captured


def test_validate_parses_json_envelope(monkeypatch):
    envelope = {"type": "result", "is_error": False,
                "result": json.dumps(_VERDICT)}
    cap = _patch(monkeypatch, _Proc(stdout=json.dumps(envelope)))

    v = claude_cli.validate("check this finding", api_key="")
    assert v.verdict == "confirmed"
    assert v.cwe == "CWE-78"
    # runs headless with JSON output, prompt piped on stdin
    assert "-p" in cap["cmd"] and "--output-format" in cap["cmd"]
    assert "check this finding" in cap["input"]


def test_validate_tolerates_code_fences_in_result(monkeypatch):
    fenced = "```json\n" + json.dumps(_VERDICT) + "\n```"
    envelope = {"result": fenced, "is_error": False}
    _patch(monkeypatch, _Proc(stdout=json.dumps(envelope)))
    assert claude_cli.validate("x").verdict == "confirmed"


def test_validate_accepts_unwrapped_output(monkeypatch):
    # Older CLI without the JSON envelope: stdout is the reply itself.
    _patch(monkeypatch, _Proc(stdout=json.dumps(_VERDICT)))
    assert claude_cli.validate("x").confidence == "high"


def test_validate_raises_on_cli_error_envelope(monkeypatch):
    envelope = {"is_error": True, "result": "usage limit reached"}
    _patch(monkeypatch, _Proc(stdout=json.dumps(envelope)))
    with pytest.raises(Exception) as e:
        claude_cli.validate("x")
    assert "usage limit" in str(e.value)


def test_validate_raises_on_nonzero_exit(monkeypatch):
    _patch(monkeypatch, _Proc(returncode=1, stderr="boom"))
    with pytest.raises(RuntimeError) as e:
        claude_cli.validate("x")
    assert "boom" in str(e.value)


def test_validate_raises_when_cli_missing(monkeypatch):
    monkeypatch.setattr(claude_cli, "_resolve_exe", lambda: None)
    with pytest.raises(RuntimeError) as e:
        claude_cli.validate("x")
    assert "not found" in str(e.value).lower()


def test_windows_cmd_shim_wrapped(monkeypatch):
    assert claude_cli._cli_argv("C:/n/claude.cmd")[:2] == ["cmd", "/c"]
    assert claude_cli._cli_argv("/usr/bin/claude") == ["/usr/bin/claude"]


def test_registered_as_keyless_provider():
    from app import settings as settings_mod
    from app.validator import service
    assert "claude_cli" in settings_mod.KEYLESS_PROVIDERS
    assert "claude_cli" in service.PROVIDERS
    assert "claude_cli" not in settings_mod.KEYED_PROVIDERS

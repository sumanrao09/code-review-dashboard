from concurrent.futures import ThreadPoolExecutor

from app import db
from app.validator import base
from app.validator.base import Verdict
from app.validator.providers import anthropic as anthropic_provider
from app.validator.providers import claude_cli as claude_cli_provider
from app.validator.providers import deepseek as deepseek_provider
from app.validator.providers import gemini as gemini_provider
from app.validator.providers import grok as grok_provider
from app.validator.providers import ollama as ollama_provider
from app.validator.providers import openai as openai_provider

PROVIDERS = {
    "anthropic": anthropic_provider.validate,
    "openai": openai_provider.validate,
    "gemini": gemini_provider.validate,
    "deepseek": deepseek_provider.validate,
    "grok": grok_provider.validate,
    "ollama": ollama_provider.validate,
    "claude_cli": claude_cli_provider.validate,
}


def _validate_one(finding, project_path, provider_fn, api_key) -> Verdict:
    ctx = base.build_code_context(project_path, finding.file, finding.line)
    prompt = base.build_prompt(finding, ctx)
    try:
        return provider_fn(prompt, api_key)
    except Exception as exc:  # provider error must not abort the batch
        return Verdict("inconclusive", "low", f"Validation error: {exc}",
                       "", "", None)


def validate_finding(conn, finding, project_path: str, provider_fn,
                     api_key: str) -> Verdict:
    """Validate a single finding and persist its verdict."""
    v = _validate_one(finding, project_path, provider_fn, api_key)
    db.update_finding_verdict(conn, finding.id, v.verdict, v.confidence,
                              v.verdict_note, v.impact_text,
                              v.recommendation, v.cwe)
    return v


def validate_scan(conn, scan_id: int, project_path: str, provider_fn,
                  api_key: str, concurrency: int = 5) -> dict:
    findings = db.get_findings(conn, scan_id)
    verdicts = {}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(_validate_one, f, project_path, provider_fn, api_key): f
                for f in findings}
        for fut, f in futs.items():
            v = fut.result()
            db.update_finding_verdict(conn, f.id, v.verdict, v.confidence,
                                      v.verdict_note, v.impact_text,
                                      v.recommendation, v.cwe)
            verdicts[f.id] = v.verdict
    return {"validated": len(findings), "verdicts": verdicts}

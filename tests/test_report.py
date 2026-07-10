from app.report import generator
from app.models import Finding


def _findings():
    return [
        Finding(tool="semgrep", severity="high", rule_id="r1", title="SQLi",
                description="d", file="a.py", line=5, cwe="CWE-89",
                verdict="confirmed", confidence="high", verdict_note="n",
                impact_text="i", recommendation="fix"),
        Finding(tool="semgrep", severity="low", rule_id="r2", title="Noise",
                description="d", file="b.py", line=2, verdict="false_positive"),
    ]


def test_build_data_default_excludes_false_positives():
    data = generator.build_data(_findings(), {}, include_false_positives=False)
    assert len(data["F"]) == 1
    entry = data["F"][0]
    assert entry["title"] == "SQLi"
    assert entry["risk"] == "High"
    assert entry["location"] == "a.py"
    assert entry["verdict"] == "CONFIRMED"
    assert data["CWE"]["SQLi"] == "CWE-89"


def test_build_data_include_false_positives():
    data = generator.build_data(_findings(), {}, include_false_positives=True)
    assert len(data["F"]) == 2


def test_render_report_embeds_data_and_meta(tmp_path, monkeypatch):
    # minimal template so the test doesn't depend on the 188KB reference
    tpl = tmp_path / "template.html"
    tpl.write_text("<h1>{{ meta.client }}</h1>"
                   "<script>const DATA = {{ data_json | safe }};</script>")
    monkeypatch.setattr(generator, "TEMPLATE_PATH", tpl)
    html = generator.render_report({"F": [], "CWE": {}, "LOCS": {}, "VERDICTS": {}},
                                   {"client": "AcmeCorp"})
    assert "AcmeCorp" in html
    assert '"F":' in html or '"F": []' in html


def test_render_report_real_template_verdicts_and_data():
    """C1+C2: real template must embed VERDICTS key and use capitalized tokens."""
    findings = [
        Finding(tool="semgrep", severity="critical", rule_id="r1",
                title="Critical SQLi", description="desc", file="app.py",
                line=10, cwe="CWE-89", verdict="confirmed",
                confidence="high", verdict_note="verified", impact_text="i",
                recommendation="fix"),
        Finding(tool="snyk", severity="high", rule_id="r2",
                title="High XSS", description="desc2", file="views.py",
                line=20, cwe="CWE-79", verdict="partially_true",
                confidence="medium", verdict_note="partial", impact_text="i2",
                recommendation="fix2"),
        Finding(tool="semgrep", severity="medium", rule_id="r3",
                title="Medium Issue", description="desc3", file="utils.py",
                line=30, cwe=None, verdict="false_positive",
                confidence=None, verdict_note=None, impact_text=None,
                recommendation=None),
        Finding(tool="semgrep", severity="low", rule_id="r4",
                title="Low Info", description="desc4", file="config.py",
                line=40, cwe=None, verdict=None,
                confidence=None, verdict_note=None, impact_text=None,
                recommendation=None),
    ]
    meta = {"client": "TestCorp", "assessment_type": "White-box",
            "repos": "test-repo", "report_date": "2026-01-01"}
    data = generator.build_data(findings, meta, include_false_positives=True)
    html = generator.render_report(data, meta)

    # (a) a finding's title appears in the rendered HTML
    assert "Critical SQLi" in html

    # (b) VERDICTS key is present in the embedded data
    assert '"VERDICTS"' in html

    # (c) severity tokens are capitalized (template-expected)
    assert '"Critical"' in html
    assert '"High"' in html
    # low severity finding (unvalidated) should be present
    assert '"Low"' in html
    # no lowercase severity tokens in the data section
    assert '"risk": "high"' not in html
    assert '"risk": "critical"' not in html

    # (c) verdict tokens use template-expected uppercase strings
    assert '"CONFIRMED"' in html
    assert '"PARTIALLY TRUE"' in html
    assert '"FALSE POSITIVE"' in html


def test_render_report_xss_meta_escaped():
    """I3(a): meta fields must be HTML-escaped; JSON data must break </script>."""
    xss_title = "</script><img src=x onerror=alert(1)>"
    xss_client = "<script>alert(2)</script>"
    findings = [
        Finding(tool="semgrep", severity="high", rule_id="r1",
                title=xss_title, description="d", file="a.py",
                line=1, cwe=None, verdict="confirmed",
                confidence="high", verdict_note="n", impact_text="i",
                recommendation="fix"),
    ]
    meta = {"client": xss_client, "assessment_type": "White-box",
            "repos": "repo", "report_date": "2026-01-01"}
    data = generator.build_data(findings, meta, include_false_positives=False)
    html = generator.render_report(data, meta)

    # The meta script tag must be HTML-escaped (not appear raw)
    assert "<script>alert(2)</script>" not in html
    assert "&lt;script&gt;alert(2)" in html

    # The finding's </script> in the JSON data must be broken (can't close the tag)
    assert "</script><img" not in html
    # The escaped form should appear
    assert "<\\/script>" in html


def test_report_template_escapes_all_finding_innerhtml_sinks():
    """Regression guard for DOM-XSS in the report template.

    Finding text derives from tools scanning untrusted code. The template
    renders findings client-side; any finding-derived value written into an
    innerHTML sink must go through esc(). This asserts (a) the esc() helper
    exists and (b) no finding field is interpolated raw into template-literal
    HTML. (The runtime DOM safety itself is enforced by esc() in the browser,
    which pytest cannot execute — this locks the source-level invariant.)
    """
    from pathlib import Path
    tpl = Path("app/report/template.html").read_text()

    assert "function esc(" in tpl, "esc() HTML-escape helper missing from template"

    # These finding fields must never appear as a bare ${f.X} interpolation
    # (they must be wrapped as ${esc(f.X)}). Property/textContent uses don't
    # use the ${...} form, so they won't match.
    forbidden = [
        "${f.title}", "${f.component}", "${f.category}",
        "${f.impact}", "${f.location}", "${f.location||",
        "${f.parameter}", "${f.parameter||", "${f.exploitability}",
        "${f.exploitability||", "${f.impact||", "${cweFull}", "${imgSrc}",
    ]
    leaks = [p for p in forbidden if p in tpl]
    assert not leaks, f"unescaped finding-derived innerHTML sink(s) in template: {leaks}"

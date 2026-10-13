import json
import shutil
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_ai import report
from appsec_ai.engines.ai_security import AISecurityEngine
from appsec_ai.models import Category, Finding, Severity, Verdict
from appsec_ai.scanner import scan
from appsec_ai.triage import Triager

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"


def ai_rules(target: Path) -> set[tuple[str, int, str]]:
    return {(f.file, f.line, f.rule_id) for f in AISecurityEngine().run(target)}


def test_detects_llm_risks_in_python():
    rules = {(file, rule) for file, _, rule in ai_rules(FIXTURE) if file == "app.py"}
    assert rules == {
        ("app.py", "llm05-llm-output-to-code-exec"),     # eval(answer)
        ("app.py", "llm05-llm-output-to-sql"),           # DB.execute(query)
        ("app.py", "llm05-llm-output-to-html"),          # f"<div>{...}</div>"
        ("app.py", "llm06-excessive-agency-tool"),       # run_shell / delete_user
        ("app.py", "llm01-prompt-concatenation"),        # f"... {question}"
        ("app.py", "llm01-indirect-prompt-injection"),   # contenido de una URL
        ("app.py", "llm02-llm-io-logged"),               # print(answer)
    }


def test_detects_llm_risks_in_typescript():
    rules = {rule for file, _, rule in ai_rules(FIXTURE) if file == "agent.ts"}
    assert rules == {
        "llm05-llm-output-to-code-exec",
        "llm05-llm-output-to-html",
        "llm01-untrusted-input-in-system-prompt",
    }


def test_ai_inventory():
    engine = AISecurityEngine()
    engine.run(FIXTURE)
    inv = {(c.kind, c.name) for c in engine.inventory}
    assert ("llm_sdk", "Anthropic") in inv
    assert ("llm_sdk", "OpenAI") in inv
    assert ("framework", "LangChain") in inv
    assert ("agent_tool", "run_shell") in inv
    assert ("model", "gpt-4o") in inv


def test_safe_llm_code_has_no_findings(tmp_path):
    (tmp_path / "safe.py").write_text(textwrap.dedent('''
        import anthropic
        from flask import Flask, request
        from markupsafe import escape

        app = Flask(__name__)
        client = anthropic.Anthropic()
        SYSTEM = "Eres un asistente. Responde solo sobre nuestros productos."

        @app.route("/ask")
        def ask():
            question = request.args.get("q", "")
            msg = client.messages.create(
                model="claude-opus-5-5",
                max_tokens=1024,
                system=SYSTEM,
                messages=[{"role": "user", "content": question}],
            )
            answer = msg.content[0].text
            return {"answer": answer}
    '''))
    assert AISecurityEngine().run(tmp_path) == []


def test_ignores_vendored_and_invalid_files(tmp_path):
    (tmp_path / "node_modules").mkdir()
    shutil.copy(FIXTURE / "app.py", tmp_path / "node_modules" / "app.py")
    (tmp_path / "broken.py").write_text("def (:\n")
    assert AISecurityEngine().run(tmp_path) == []


# --- Triage con un cliente de Claude simulado --------------------------------------

class FakeMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0)
        if "output_config" in kwargs and "format" in kwargs["output_config"]:
            n = kwargs["messages"][0]["content"].count('"id":')
            results = [{
                "id": i, "verdict": "false_positive" if i == 0 else "true_positive",
                "severity": "critical", "confidence": 0.9, "explanation": "Explicación",
                "exploit_scenario": "Escenario", "fix": "Corrección", "fixed_code": "safe()",
            } for i in range(n)]
            text = json.dumps({"results": results})
        else:
            text = "Resumen ejecutivo"
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)],
                               usage=usage, stop_reason="end_turn")


def fake_client():
    return SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages()))


def test_triage_one_request_per_file_and_suppresses_false_positives(tmp_path):
    client = fake_client()
    triager = Triager(client=client, cache_dir=tmp_path / "cache")
    result = scan(FIXTURE, engines=["ai-security"], triager=triager)

    calls = client.beta.messages.calls
    files = {f.file for f in result.findings}
    assert len(calls) == len(files) + 1  # + resumen ejecutivo
    first = calls[0]
    assert first["model"] == "claude-opus-5-5"
    assert first["fallbacks"] == "default"
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert all(f.triage for f in result.findings)
    assert sum(f.is_suppressed for f in result.findings) == len(files)
    assert result.ai_summary == "Resumen ejecutivo"
    assert result.llm_usage["requests"] == len(calls)

    # Segundo escaneo: todo sale de la caché local salvo el resumen.
    client2 = fake_client()
    scan(FIXTURE, engines=["ai-security"], triager=Triager(client=client2, cache_dir=tmp_path / "cache"))
    assert len(client2.beta.messages.calls) == 1


def test_triage_respects_budget():
    client = fake_client()
    triager = Triager(client=client, max_requests=1)
    findings = AISecurityEngine().run(FIXTURE)
    warnings = triager.triage(FIXTURE, findings)
    assert len(client.beta.messages.calls) == 1
    assert any("Presupuesto" in w for w in warnings)


def test_triage_untrusted_code_is_marked_as_data():
    client = fake_client()
    Triager(client=client).triage(FIXTURE, AISecurityEngine().run(FIXTURE)[:1])
    call = client.beta.messages.calls[0]
    assert "DATOS NO CONFIABLES" in call["system"][0]["text"]
    assert "<codigo>" in call["messages"][0]["content"]


# --- Informes ----------------------------------------------------------------------

def test_sarif_and_markdown():
    result = scan(FIXTURE, engines=["ai-security"])
    sarif = report.to_sarif(result)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == len(result.findings)
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results)
    md = report.to_markdown(result)
    assert "Inventario de IA" in md and "CRITICAL" in md


def test_severity_parsing():
    assert Severity.parse("ERROR") == Severity.HIGH
    assert Severity.parse(None) == Severity.MEDIUM
    assert Severity.parse("Critical") == Severity.CRITICAL


def test_fingerprint_ignores_line_numbers():
    a = Finding(engine="e", rule_id="r", category=Category.SAST, severity=Severity.LOW, title="t",
                file="a.py", line=1, snippet="x()")
    b = a.model_copy(update={"line": 50})
    assert a.fingerprint == b.fingerprint


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks no instalado")
def test_gitleaks_redacts_secrets():
    result = scan(FIXTURE, engines=["gitleaks"])
    secrets = [f for f in result.findings if f.category == Category.SECRETS]
    assert secrets and all("REDACTED" in f.snippet for f in secrets)


def test_cli_fail_on(tmp_path):
    from appsec_ai.cli import main

    out = tmp_path / "r.sarif"
    assert main(["scan", str(FIXTURE), "--engines", "ai-security", "--format", "sarif",
                 "-o", str(out), "--fail-on", "critical"]) == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert main(["scan", str(tmp_path), "--engines", "ai-security", "--fail-on", "low"]) == 0

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
        ("app.py", "llm10-no-rate-limit"),               # /ask llama al LLM y no hay rate limiting
    }


def test_detects_llm_risks_in_typescript():
    rules = {rule for file, _, rule in ai_rules(FIXTURE) if file == "agent.ts"}
    assert rules == {
        "llm05-llm-output-to-code-exec",
        "llm05-llm-output-to-html",
        "llm01-untrusted-input-in-system-prompt",
        "llm10-no-output-limit",
        "llm10-no-rate-limit",
    }


AGENTS = Path(__file__).parent / "fixtures" / "ai_agents"


def test_agents_mcp_and_new_rules():
    assert ai_rules(AGENTS) == {
        # Python: FastMCP, LangChain, OpenAI
        ("agents.py", 20, "llm06-excessive-agency-tool"),        # @mcp.tool que borra ficheros
        ("agents.py", 33, "llm07-secret-in-system-prompt"),      # contraseña en el prompt de sistema
        ("agents.py", 33, "llm10-no-output-limit"),              # chat.completions sin max_tokens
        ("agents.py", 41, "llm05-llm-output-selects-function"),  # getattr(tools, salida)
        ("agents.py", 42, "llm05-llm-output-to-request"),        # requests.get(salida)
        ("agents.py", 44, "llm05-llm-output-to-filesystem"),     # open(salida)
        ("agents.py", 49, "llm10-unbounded-agent-loop"),         # max_iterations=None
        ("agents.py", 53, "llm06-mcp-http-without-auth"),        # mcp.run(transport="http") sin auth
        # TypeScript: Vercel AI SDK y MCP SDK
        ("agent_tools.ts", 14, "llm06-excessive-agency-tool"),   # tool() con execSync
        ("agent_tools.ts", 27, "llm07-secret-in-system-prompt"),
        ("agent_tools.ts", 27, "llm10-no-output-limit"),
        ("agent_tools.ts", 33, "llm05-llm-output-selects-function"),  # handlers[text]()
        ("agent_tools.ts", 34, "llm05-llm-output-to-request"),   # fetch(text)
        ("agent_tools.ts", 35, "llm05-llm-output-to-filesystem"),
        ("agent_tools.ts", 36, "llm02-llm-io-logged"),
        ("agent_tools.ts", 39, "llm01-indirect-prompt-injection"),  # documento descargado en el prompt
        ("agent_tools.ts", 48, "llm06-excessive-agency-tool"),   # server.tool que borra ficheros
        ("agent_tools.ts", 52, "llm06-mcp-http-without-auth"),
    }


def test_rag_access_control_and_authorization_in_prompt():
    assert ai_rules(Path(__file__).parent / "fixtures" / "rag") == {
        ("rag.py", 19, "llm08-rag-without-access-filter"),   # similarity_search sin filter
        ("rag.py", 20, "llm08-rag-without-access-filter"),   # as_retriever() sin filtro + invoke
        ("rag.py", 21, "llm08-rag-without-access-filter"),   # Chroma collection.query sin where
        ("rag.py", 22, "llm07-authorization-in-prompt"),     # "Solo puedes mostrar las nóminas del usuario..."
        ("rag.ts", 13, "llm08-rag-without-access-filter"),   # similaritySearch(question, 4)
        ("rag.ts", 14, "llm08-rag-without-access-filter"),   # Pinecone query sin filter
        ("rag.ts", 18, "llm08-rag-without-access-filter"),   # asRetriever sin filtro + invoke
        ("rag.ts", 21, "llm07-authorization-in-prompt"),     # "You must only show invoices..."
        ("rag.py", 22, "llm10-no-rate-limit"),               # sin rate limiting en el repositorio
        ("rag.ts", 21, "llm10-no-rate-limit"),
    }


@pytest.mark.parametrize("text, expected", [
    ("Solo puedes mostrar los pedidos del usuario actual.", True),
    ("No reveles información de otros clientes.", True),
    ("Si el usuario es administrador, puede ver todo.", True),
    ("Never reveal data from other customers.", True),
    ("Solo puedes responder preguntas sobre nuestros productos.", False),
    ("Responde al usuario en español.", False),
    ("Only answer questions about cooking.", False),
])
def test_authorization_in_prompt_patterns(text, expected):
    from appsec_ai.engines.ai_common import AUTHZ_IN_PROMPT
    assert bool(AUTHZ_IN_PROMPT.search(text)) is expected


@pytest.mark.parametrize("text, expected", [
    ("Usa la clave sk_" "live_51HxQe2LkT9vRmW3pZaB7cD8 para la API", True),   # Stripe (partida para push protection)
    ("La clave de acceso es Abc12345xyz", True),
    ("La palabra clave es importante para el SEO", False),
    ("Tu token tiene este formato: token = 'YOUR_API_TOKEN_HERE'", False),
])
def test_secret_in_prompt_patterns(text, expected):
    from appsec_ai.engines.ai_common import SECRET_IN_TEXT
    assert bool(SECRET_IN_TEXT.search(text)) is expected


def test_agents_inventory_names_tools():
    engine = AISecurityEngine()
    engine.run(AGENTS)
    inv = {(c.kind, c.name) for c in engine.inventory}
    assert {("agent_tool", "shell"), ("agent_tool", "weather"), ("mcp_tool", "delete_file"),
            ("mcp_tool", "count_users"), ("mcp_server", "mcp"), ("framework", "Vercel AI SDK")} <= inv


def test_safe_typescript_has_no_findings():
    assert not [f for f in AISecurityEngine().run(AGENTS) if f.file == "safe.tsx"]


def test_ai_inventory():
    engine = AISecurityEngine()
    engine.run(FIXTURE)
    inv = {(c.kind, c.name) for c in engine.inventory}
    assert ("llm_sdk", "Anthropic") in inv
    assert ("llm_sdk", "OpenAI") in inv
    assert ("framework", "LangChain") in inv
    assert ("agent_tool", "run_shell") in inv
    assert ("model", "gpt-4o") in inv


def test_rate_limit_rule_is_silenced_by_any_rate_limiting_signal(tmp_path):
    shutil.copytree(FIXTURE, tmp_path / "app")
    assert any(f.rule_id == "llm10-no-rate-limit" for f in AISecurityEngine().run(tmp_path / "app"))
    (tmp_path / "app" / "requirements.txt").write_text("flask\nslowapi==0.1.9\n")
    assert not any(f.rule_id == "llm10-no-rate-limit" for f in AISecurityEngine().run(tmp_path / "app"))


def test_safe_llm_code_has_no_findings(tmp_path):
    (tmp_path / "safe.py").write_text(textwrap.dedent('''
        import anthropic
        from flask import Flask, request
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        from markupsafe import escape

        app = Flask(__name__)
        limiter = Limiter(get_remote_address, app=app)
        client = anthropic.Anthropic()
        SYSTEM = "Eres un asistente. Responde solo sobre nuestros productos."

        @app.route("/ask")
        @limiter.limit("10 per minute")
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


def test_triage_llm_errors_become_warnings_not_crashes():
    client = fake_client()
    create = client.beta.messages.create

    def refuse_summary(**kwargs):
        response = create(**kwargs)
        if "format" not in kwargs["output_config"]:
            response.stop_reason = "refusal"
        return response

    client.beta.messages.create = refuse_summary
    result = scan(FIXTURE, engines=["ai-security"], triager=Triager(client=client))
    assert all(f.triage for f in result.findings)
    assert result.ai_summary == ""
    assert any(e.engine == "triage" and "resumen" in e.detail for e in result.engines)


def test_cli_ai_triage_without_credentials_fails_cleanly(monkeypatch, capsys, tmp_path):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_CONFIG_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    from appsec_ai.cli import main

    with pytest.raises(SystemExit) as e:
        main(["scan", str(FIXTURE), "--engines", "ai-security", "--ai-triage"])
    assert e.value.code == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_triage_untrusted_code_is_marked_as_data():
    client = fake_client()
    Triager(client=client).triage(FIXTURE, AISecurityEngine().run(FIXTURE)[:1])
    call = client.beta.messages.calls[0]
    assert "DATOS NO CONFIABLES" in call["system"][0]["text"]
    assert "<codigo>" in call["messages"][0]["content"]


# --- Informes ----------------------------------------------------------------------

def test_every_ai_rule_has_a_compliance_mapping():
    from appsec_ai import compliance
    from appsec_ai.engines.ai_common import RULES

    assert set(compliance.RULES) == set(RULES)
    for m in compliance.RULES.values():
        assert set(m.atlas) <= set(compliance.ATLAS) and m.atlas
        assert set(m.nist) <= set(compliance.NIST)
        assert set(m.iso42001) <= set(compliance.ISO42001)
        assert set(m.eu_ai_act) <= set(compliance.EU_AI_ACT)


def test_report_includes_compliance_mapping():
    result = scan(FIXTURE, engines=["ai-security"])
    md = report.to_markdown(result)
    assert "## Mapeo a marcos de IA" in md
    assert "AML.T0050 Command and Scripting Interpreter" in md  # eval de la salida del LLM
    assert any("MITRE-ATLAS AML.T0051" in x for f in result.findings for x in f.frameworks)


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


def test_cross_engine_findings_are_merged():
    from appsec_ai.scanner import dedupe

    def mk(engine, rule, cwe, sev=Severity.HIGH):
        category = Category.AI if rule.startswith("llm") else Category.SAST
        return Finding(engine=engine, rule_id=rule, category=category, severity=sev, title=rule,
                       file="app.py", line=10, snippet=rule, frameworks=[cwe])

    merged = dedupe([mk("opengrep", "python-code-injection", "CWE-95", Severity.CRITICAL),
                     mk("ai-security", "llm05-llm-output-to-code-exec", "CWE-94"),
                     mk("opengrep", "python-ssrf", "CWE-918")])
    assert [f.rule_id for f in merged] == ["llm05-llm-output-to-code-exec", "python-ssrf"]
    assert "opengrep:python-code-injection" in merged[0].frameworks


RULES_DIR = Path(__file__).parent.parent / "src" / "appsec_ai" / "rules" / "sast"
RULE_TESTS = Path(__file__).parent / "rules"


@pytest.mark.skipif(not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep no instalado")
@pytest.mark.parametrize("lang", ["java", "go"])
def test_ai_rules_for_java_and_go(lang):
    """Reglas de IA en YAML (rules/ai): casos ruleid/ok en tests/rules/ai/."""
    import subprocess

    binary = shutil.which("opengrep") or shutil.which("semgrep")
    target = next((RULE_TESTS / "ai").glob(f"{lang}.*"))
    config = RULES_DIR.parent / "ai" / f"{lang}.yaml"
    proc = subprocess.run([binary, "--test", "--metrics=off", "--config", str(config), str(target)],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]


@pytest.mark.skipif(not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep no instalado")
def test_java_and_go_ai_findings_are_ai_category_with_atlas(tmp_path):
    shutil.copy(RULE_TESTS / "ai" / "go.go", tmp_path / "main.go")
    result = scan(tmp_path, engines=["opengrep"])
    ai = [f for f in result.findings if f.rule_id == "llm05-llm-output-to-code-exec"]
    assert ai and ai[0].category == Category.AI and ai[0].severity == Severity.CRITICAL
    assert "MITRE-ATLAS AML.T0050" in ai[0].frameworks


@pytest.mark.skipif(not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep no instalado")
@pytest.mark.parametrize("lang", ["python", "javascript", "java", "go"])
def test_sast_rules(lang):
    """Cada regla tiene casos positivos (ruleid) y negativos (ok) en tests/rules/."""
    import subprocess

    binary = shutil.which("opengrep") or shutil.which("semgrep")
    target = next(RULE_TESTS.glob(f"{lang}.*"))
    proc = subprocess.run([binary, "--test", "--metrics=off", "--config", str(RULES_DIR / f"{lang}.yaml"), str(target)],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]


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


def test_inline_suppressions(tmp_path):
    (tmp_path / "a.py").write_text(
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def f():\n"
        "    r = client.messages.create(model='m', max_tokens=10, messages=[])\n"
        "    eval(r.content[0].text)  # appsec-ai: ignore\n"
        "    # nosec\n"
        "    exec(r.content[0].text)\n"
        "    print(r)\n"
    )
    result = scan(tmp_path, engines=["ai-security"])
    assert [f.rule_id for f in result.findings] == ["llm02-llm-io-logged"]
    assert result.suppressed_inline == 2

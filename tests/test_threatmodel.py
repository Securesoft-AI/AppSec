"""RF-2.6: modelo de amenazas de IA (determinista y enriquecido con Claude)."""
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_ai import threatmodel
from appsec_ai.models import AIComponent, Category, Finding, Severity
from appsec_ai.report import to_markdown
from appsec_ai.scanner import scan
from appsec_ai.triage import Triager

DEMO = Path(__file__).resolve().parents[1] / "web" / "demo-repos"


def fake_client(payload):
    calls = []

    def create(**kw):
        calls.append(kw)
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=1, output_tokens=1, cache_read_input_tokens=0))
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), calls


def test_no_ai_components_no_model():
    assert threatmodel.baseline([], [], "es") is None


def test_baseline_from_demo_repo():
    res = scan(DEMO / "agentes-internos", engines=["ai-security"])
    tm = threatmodel.baseline(res.ai_inventory, res.findings, "es")
    ids = {a.id for a in tm.assets}
    assert {"user", "llm"} <= ids and any(i.startswith("tool_") for i in ids)
    by = {t.owasp: t for t in tm.threats}
    assert by["LLM06"].status == "confirmed" and by["LLM06"].findings
    assert all(t.attack_path and t.mitigations for t in tm.threats)
    # Las confirmadas van primero.
    statuses = [t.status for t in tm.threats]
    assert statuses == sorted(statuses, key=lambda s: s != "confirmed")
    # El usuario siempre entra por una frontera de confianza.
    assert any(f.source == "user" and f.untrusted for f in tm.flows)


def test_potential_threats_from_architecture_only():
    inv = [AIComponent(kind="model", name="gpt", file="a.py", line=1),
           AIComponent(kind="agent_tool", name="send_email", file="a.py", line=5)]
    tm = threatmodel.baseline(inv, [], "en")
    by = {t.owasp: t for t in tm.threats}
    assert by["LLM06"].status == "potential" and by["LLM06"].title == "Excessive tool agency"
    assert "tool_send_email" in by["LLM06"].assets


def test_mermaid_escapes_labels():
    inv = [AIComponent(kind="agent_tool", name='x"] --> evil["', file="a.py", line=1)]
    tm = threatmodel.baseline(inv, [], "es")
    diagram = threatmodel.mermaid(tm)
    line = next(x for x in diagram.splitlines() if x.strip().startswith("tool_") and "[" in x)
    assert diagram.startswith("flowchart LR") and line.count('"') == 2 and line.count("[") == 1


def test_enrich_with_claude(tmp_path):
    (tmp_path / "app.py").write_text("def run(q):\n    return llm.invoke(q)\n")
    inv = [AIComponent(kind="llm_entrypoint", name="invoke", file="app.py", line=2),
           AIComponent(kind="agent_tool", name="shell", file="app.py", line=1)]
    f = Finding(engine="ai-security", rule_id="llm06-excessive-agency-tool", category=Category.AI,
                severity=Severity.HIGH, title="t", file="app.py", line=1, frameworks=["OWASP-LLM06:2025 Excessive Agency"])
    base = threatmodel.baseline(inv, [f], "es")
    client, calls = fake_client({
        "summary": "Un agente con shell.",
        "threats": [{"title": "RCE vía la herramienta shell", "owasp": "LLM06", "severity": "critical",
                     "status": "confirmed", "assets": ["llm", "tool_shell", "inventado"],
                     "attack_path": ["a", "b"], "mitigations": ["m"], "related_rules": ["llm06-excessive-agency-tool"]}],
        "flows": [{"source": "tool_shell", "target": "user", "label": "salida", "untrusted": False},
                  {"source": "x", "target": "y", "label": "", "untrusted": True}]})
    triager = Triager(client=client, max_requests=5)
    tm = threatmodel.enrich(triager, tmp_path, base, inv, [f], "es")
    assert tm.generated_by == "ai" and tm.summary == "Un agente con shell."
    th = tm.threats[0]
    assert th.severity == Severity.CRITICAL and th.assets == ["llm", "tool_shell"] and th.findings == [f.fingerprint]
    assert len(tm.flows) == len(base.flows) + 1          # el flujo con ids inexistentes se descarta
    prompt = calls[0]["messages"][0]["content"]
    assert "llm.invoke(q)" in prompt and "<codigo>" in prompt   # el código va como dato delimitado


def test_enrich_failure_keeps_baseline(tmp_path):
    inv = [AIComponent(kind="model", name="gpt", file="a.py", line=1)]
    base = threatmodel.baseline(inv, [], "es")
    client, _ = fake_client("no es json")
    triager = Triager(client=client, max_requests=5)
    assert threatmodel.enrich(triager, tmp_path, base, inv, [], "es") == base
    assert any("modelo de amenazas" in w for w in triager.warnings)


def test_code_excerpts_stay_inside_the_repo(tmp_path):
    outside = tmp_path / "secreto.py"
    outside.write_text("CLAVE = 1\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    inv = [AIComponent(kind="llm_entrypoint", name="x", file="../secreto.py", line=1)]
    assert threatmodel.code_excerpts(repo, inv) == ""


def test_report_includes_threat_model():
    res = scan(DEMO / "asistente-rrhh", engines=["ai-security"])
    res.threat_model = threatmodel.baseline(res.ai_inventory, res.findings, "en")
    md = to_markdown(res, lang="en")
    assert "## AI threat model" in md and "```mermaid" in md and "Attack path" in md

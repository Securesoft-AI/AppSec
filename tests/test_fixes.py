import json
from types import SimpleNamespace

import pytest

from appsec_ai.fixes import Edit, FixError, apply_edits, build_fix, check_syntax, files_to_fix
from appsec_ai.models import Category, Finding, Severity, Triage, Verdict
from appsec_ai.triage import Triager


def finding(file="app.py", line=3, verdict=Verdict.TRUE_POSITIVE, severity=Severity.HIGH, rule="r1"):
    f = Finding(engine="ai-security", rule_id=rule, category=Category.AI, severity=severity, title="t",
                message="m", file=file, line=line)
    if verdict:
        f.triage = Triage(verdict=verdict, severity=severity, confidence=0.9, explanation="e", fix="usa x")
    return f


def test_apply_edits_requires_exactly_one_match():
    text = "a = 1\nb = eval(x)\nc = eval(x)\n"
    with pytest.raises(FixError, match="2 veces"):
        apply_edits(text, [Edit("eval(x)", "x")])
    with pytest.raises(FixError, match="0 veces"):
        apply_edits(text, [Edit("exec(x)", "x")])
    with pytest.raises(FixError, match="vacío"):
        apply_edits(text, [Edit("", "x")])
    assert apply_edits(text, [Edit("b = eval(x)", "b = x")]) == "a = 1\nb = x\nc = eval(x)\n"


def test_syntax_check_rejects_broken_fixes():
    check_syntax("ok.py", "x = 1\n")
    check_syntax("ok.ts", "const x: number = 1;\n")
    with pytest.raises(FixError, match="Python"):
        check_syntax("bad.py", "def f(:\n")
    with pytest.raises(FixError, match="JavaScript"):
        check_syntax("bad.ts", "const x = ;\n")
    check_syntax("README.md", "{{ no se valida }}")


def test_build_fix_rejects_noop():
    with pytest.raises(FixError, match="no cambia"):
        build_fix("a.py", "x = 1\n", [Edit("x = 1", "x = 1")], "", [])


def test_only_confirmed_findings_are_fixed_most_severe_files_first():
    findings = [finding("low.py", severity=Severity.LOW), finding("crit.py", severity=Severity.CRITICAL),
                finding("fp.py", verdict=Verdict.FALSE_POSITIVE), finding("review.py", verdict=Verdict.NEEDS_REVIEW),
                finding("untriaged.py", verdict=None), finding("crit.py", line=9, severity=Severity.HIGH)]
    targets = files_to_fix(findings, limit=1)
    assert list(targets) == ["crit.py"] and len(targets["crit.py"]) == 2
    assert set(files_to_fix(findings)) == {"crit.py", "low.py"}


def fix_client(edits, summary="Se elimina eval."):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        text = json.dumps({"edits": edits, "summary": summary})
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=1, output_tokens=1, cache_read_input_tokens=0))
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), calls


def test_propose_fix_applies_validated_edits(tmp_path):
    (tmp_path / "app.py").write_text("import os\n\ndef run(answer):\n    return eval(answer)\n")
    client, calls = fix_client([{"find": "    return eval(answer)", "replace": "    return answer"}])
    fx = Triager(client=client).propose_fix(tmp_path, "app.py", [finding(line=4)])
    assert fx.fixed.endswith("    return answer\n") and fx.summary == "Se elimina eval."
    assert "DATOS NO CONFIABLES" in calls[0]["system"][0]["text"]
    assert calls[0]["output_config"]["format"]["type"] == "json_schema"


@pytest.mark.parametrize("edits, error", [
    ([{"find": "no existe", "replace": "x"}], "0 veces"),
    ([{"find": "    return eval(answer)", "replace": "    return (("}], "sintaxis"),
])
def test_propose_fix_never_returns_unsafe_edits(tmp_path, edits, error):
    (tmp_path / "app.py").write_text("def run(answer):\n    return eval(answer)\n")
    client, _ = fix_client(edits)
    with pytest.raises(FixError, match=error):
        Triager(client=client).propose_fix(tmp_path, "app.py", [finding()])


def test_propose_fix_refuses_symlinks(tmp_path):
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    client, calls = fix_client([])
    with pytest.raises(FixError, match="no disponible"):
        Triager(client=client).propose_fix(tmp_path, "link.py", [finding(file="link.py")])
    assert not calls

"""Escaneo incremental en PRs (RF-1.8)."""
import shutil
from pathlib import Path

import pytest

from appsec_ai.engines.base import staged
from appsec_ai.engines.opensource import OSVEngine
from appsec_ai.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"


def test_only_changed_files_are_analysed():
    full = scan(FIXTURE, engines=["ai-security"])
    inc = scan(FIXTURE, engines=["ai-security"], only_files={"app.py"})
    assert {f.file for f in full.findings} == {"app.py", "agent.ts"}
    assert {f.file for f in inc.findings} == {"app.py"}
    assert {f.rule_id for f in inc.findings} == {f.rule_id for f in full.findings if f.file == "app.py"}
    assert inc.engines[0].detail == "incremental: 1 ficheros"


def test_staged_copy_skips_symlinks_and_paths_outside_the_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "secreto.txt").write_text("no")
    (repo / "link.py").symlink_to(tmp_path / "secreto.txt")
    with staged(repo, {"src/a.py", "link.py", "../secreto.txt", "no-existe.py"}) as root:
        files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert files == ["src/a.py"]


def test_dependency_scan_only_when_a_manifest_changes(tmp_path):
    engine = OSVEngine()
    engine.find_binary = lambda: pytest.fail("no debería ejecutar osv-scanner")
    assert engine.run(tmp_path, only={"app.py", "src/x.ts"}) == []


def test_sandboxed_incremental_scan(tmp_path):
    from appsec_ai.service.sandbox import sandboxed_scan

    src = tmp_path / "src"
    shutil.copytree(FIXTURE, src)
    result = sandboxed_scan(src, timeout=120, only_files={"agent.ts"})
    assert {f.file for f in result.findings} == {"agent.ts"}
    assert not (src / "appsec-ai-files.txt").exists()  # la lista queda fuera del repositorio


@pytest.mark.skipif(not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep no instalado")
def test_opengrep_incremental(tmp_path):
    shutil.copy(Path(__file__).parent / "rules" / "ai" / "go.go", tmp_path / "main.go")
    (tmp_path / "other.go").write_text((tmp_path / "main.go").read_text())
    result = scan(tmp_path, engines=["opengrep"], only_files={"main.go"})
    assert result.findings and {f.file for f in result.findings} == {"main.go"}

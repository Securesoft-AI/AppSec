import json
import os
import sys
import time
from pathlib import Path

import pytest

from appsec_ai.service.sandbox import SandboxError, build_command, sandboxed_scan

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"


def test_sandboxed_scan_matches_in_process_scan_and_hides_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secreto")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:clave@db/x")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text((FIXTURE / "app.py").read_text())
    result = sandboxed_scan(src, timeout=120)
    assert any(f.rule_id == "llm05-llm-output-to-code-exec" for f in result.findings)

    # Un "motor" malicioso que vuelca su entorno no ve ningún secreto.
    spy = tmp_path / "spy.py"
    spy.write_text("import json, os, sys; json.dump(dict(os.environ), open(sys.argv[1], 'w'))")
    dump = tmp_path / "env.json"
    with pytest.raises(SandboxError):  # el envoltorio no ejecuta el escaneo, así que la salida no es JSON
        sandboxed_scan(src, wrapper=f"{sys.executable} {spy} {dump} --", timeout=60)
    env = json.loads(dump.read_text())
    assert not {"ANTHROPIC_API_KEY", "GITHUB_APP_PRIVATE_KEY", "DATABASE_URL"} & set(env)
    assert "PATH" in env


def test_wrapper_can_reference_scan_directory():
    cmd = build_command(Path("/work/src"), "bwrap --ro-bind / / --bind {src} {src}")
    assert cmd[:5] == ["bwrap", "--ro-bind", "/", "/", "--bind"] and cmd[5:7] == ["/work/src", "/work/src"]
    assert cmd[-4:] == ["scan", "/work/src", "--format", "json"]


def test_timeout_kills_the_whole_process_group(tmp_path):
    script = tmp_path / "slow.py"
    pidfile = tmp_path / "child.pid"
    script.write_text(
        "import os, subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(60)\n")
    with pytest.raises(SandboxError, match="tiempo máximo"):
        sandboxed_scan(tmp_path, wrapper=f"{sys.executable} {script} --", timeout=2)
    child = int(pidfile.read_text())
    for _ in range(50):  # el hijo huérfano tarda un instante en desaparecer
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    pytest.fail("el proceso hijo sigue vivo")


def test_repository_code_is_never_imported(tmp_path):
    src = tmp_path / "src"
    (src / "appsec_ai").mkdir(parents=True)
    marker = tmp_path / "pwned"
    for name in ("appsec_ai/__init__.py", "json.py", "pydantic.py"):
        (src / name).write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    sandboxed_scan(src, timeout=120)
    assert not marker.exists()

"""Contenedor efímero por escaneo (RF-4.4): SCAN_RUNNER ejecuta el escaneo fuera del worker.

Aquí el "contenedor" es un script local que recibe los mismos marcadores que recibiría `docker run`
(o un Job de gVisor): comprueba que se le pasa el directorio de solo lectura, el fichero de salida y, en
los escaneos incrementales, la lista de ficheros; luego llama a nuestro propio escáner y deja el JSON.
"""
import os
import stat
import textwrap
from pathlib import Path

import pytest

from appsec_ai.models import ScanResult
from appsec_ai.service.sandbox import SandboxError, runner_scan


def write_app(tmp_path: Path) -> Path:
    src = tmp_path / "repo"
    src.mkdir()
    (src / "app.py").write_text("import os\nos.system('echo ' + input())\n")  # command injection
    (src / "ok.py").write_text("x = 1\n")
    return src


def fake_container(tmp_path: Path, extra: str = "") -> str:
    """Un 'contenedor' de pega: valida los marcadores y corre appsec-ai sobre {src}."""
    script = tmp_path / "runner.sh"
    script.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        SRC="$1"; OUT="$2"; FILES="${{3:-}}"; ENGINES="${{4:-}}"
        test -d "$SRC"                      # el repositorio está montado
        {extra}
        args=(scan "$SRC" --format json)
        [ -n "$FILES" ] && args+=(--files-from "$FILES")
        [ -n "$ENGINES" ] && args+=(--engines "$ENGINES")
        appsec-ai "${{args[@]}}" > "$OUT"
    """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    # 4 argumentos posicionales: {src} {out} {files_from} {engines}
    return f'{script} {{src}} {{out}} "{{files_from}}" "{{engines}}"'


def test_runner_produces_a_scan_result(tmp_path):
    src = write_app(tmp_path)
    result = runner_scan(src, fake_container(tmp_path), engines=["ai-security", "opengrep"])
    assert isinstance(result, ScanResult)
    assert any("app.py" in f.file for f in result.findings)


def test_runner_passes_the_incremental_file_list(tmp_path):
    src = write_app(tmp_path)
    # El 'contenedor' exige que la lista de ficheros exista y la vuelca a un testigo.
    probe = tmp_path / "seen.txt"
    runner = fake_container(tmp_path, extra=f'test -f "$FILES"; cp "$FILES" {probe}')
    runner_scan(src, runner, only_files={"app.py"}, engines=["opengrep"])
    assert probe.read_text().strip() == "app.py"


def test_runner_failure_is_reported(tmp_path):
    src = write_app(tmp_path)
    bad = tmp_path / "bad.sh"
    bad.write_text("#!/usr/bin/env bash\nexit 7\n")
    bad.chmod(bad.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(SandboxError):
        runner_scan(src, f"{bad} {{src}} {{out}}")


def test_runner_without_valid_output_is_reported(tmp_path):
    src = write_app(tmp_path)
    silent = tmp_path / "silent.sh"
    silent.write_text("#!/usr/bin/env bash\nexit 0\n")  # no escribe {out}
    silent.chmod(silent.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(SandboxError):
        runner_scan(src, f"{silent} {{src}} {{out}}")


def test_runner_leaves_no_temp_files_behind(tmp_path):
    src = write_app(tmp_path)
    runner = fake_container(tmp_path)
    before = set(os.listdir(src.parent))
    runner_scan(src, runner, engines=["opengrep"])
    # Ni el fichero de salida ni la lista incremental quedan junto al repositorio.
    assert set(os.listdir(src.parent)) - before == set()

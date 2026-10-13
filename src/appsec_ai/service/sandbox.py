"""Ejecución aislada del escaneo: el código del cliente no se analiza dentro del proceso del worker.

El worker tiene en memoria y en su entorno las claves de la GitHub App, de Anthropic y de la base de
datos. Los motores (Semgrep, Gitleaks, OSV, Checkov y los nuestros) procesan código no confiable, así
que se ejecutan en un subproceso:

- sin secretos en el entorno (solo PATH, proxy, certificados...);
- en su propia sesión de procesos, que se mata entera si se pasa de tiempo;
- con límites de CPU, tamaño de fichero, descriptores y sin volcados de memoria;
- opcionalmente envuelto en un sandbox del sistema (SCAN_SANDBOX_CMD), p. ej. bubblewrap.

El triage con Claude se hace después, en el worker, y solo lee ficheros.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path

from appsec_ai.engines.base import safe_env
from appsec_ai.models import ScanResult


class SandboxError(RuntimeError):
    pass


def _limits(cpu_seconds: int, max_file_mb: int):
    def apply():
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_mb * 1_048_576,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def build_command(src: Path, wrapper: str = "", files_from: Path | None = None) -> list[str]:
    """`wrapper` admite {src} para montar solo el directorio del escaneo (bubblewrap, firejail...)."""
    # -I: modo aislado de Python. Sin él, un `json.py` o un paquete `appsec_ai/` en el repositorio del
    # cliente se importaría en lugar del nuestro (el directorio actual entra en sys.path con -m).
    scan = [sys.executable, "-I", "-m", "appsec_ai.cli", "scan", str(src), "--format", "json"]
    if files_from is not None:
        scan += ["--files-from", str(files_from)]
    return [part.replace("{src}", str(src)) for part in shlex.split(wrapper)] + scan


def sandboxed_scan(src: Path, wrapper: str = "", timeout: int = 900, max_file_mb: int = 512,
                   only_files: set[str] | None = None) -> ScanResult:
    files_from = None
    if only_files is not None:
        # Fuera del directorio del repositorio, para que el código del cliente no lo pueda alterar.
        files_from = src.parent / "appsec-ai-files.txt"
        files_from.write_text("\n".join(sorted(only_files)))
    proc = subprocess.Popen(
        build_command(src, wrapper, files_from), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=safe_env(SEMGREP_SEND_METRICS="off", PYTHONDONTWRITEBYTECODE="1"), cwd=src.parent,
        start_new_session=True, preexec_fn=_limits(timeout, max_file_mb),
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)  # también los motores que haya lanzado
        proc.communicate()
        raise SandboxError(f"el escaneo superó el tiempo máximo ({timeout} s)") from None
    if proc.returncode != 0:
        raise SandboxError(f"el escaneo aislado falló ({proc.returncode}): {err.strip()[-500:]}")
    try:
        return ScanResult.model_validate_json(out)
    except ValueError as e:
        raise SandboxError(f"salida no válida del escaneo aislado: {e}") from None

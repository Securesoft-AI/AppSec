"""Ejecución aislada del escaneo: el código del cliente no se analiza dentro del proceso del worker.

El worker tiene en memoria y en su entorno las claves de la GitHub App, de Anthropic y de la base de
datos. Los motores (Semgrep, Gitleaks, OSV, Checkov y los nuestros) procesan código no confiable, así
que se ejecutan en un subproceso:

- sin secretos en el entorno (solo PATH, proxy, certificados...);
- en su propia sesión de procesos, que se mata entera si se pasa de tiempo;
- con límites de CPU, tamaño de fichero, descriptores y sin volcados de memoria;
- opcionalmente envuelto en un sandbox del sistema (SCAN_SANDBOX_CMD), p. ej. bubblewrap.

Para aislar de verdad cada escaneo (RF-4.4), SCAN_RUNNER ejecuta el escaneo en su propio contenedor
efímero (gVisor/Firecracker, un Job de Kubernetes o `docker run`): ver `runner_scan`.

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


def build_command(src: Path, wrapper: str = "", files_from: Path | None = None,
                  engines: list[str] | None = None) -> list[str]:
    """`wrapper` admite {src} para montar solo el directorio del escaneo (bubblewrap, firejail...)."""
    # -I: modo aislado de Python. Sin él, un `json.py` o un paquete `appsec_ai/` en el repositorio del
    # cliente se importaría en lugar del nuestro (el directorio actual entra en sys.path con -m).
    scan = [sys.executable, "-I", "-m", "appsec_ai.cli", "scan", str(src), "--format", "json"]
    if files_from is not None:
        scan += ["--files-from", str(files_from)]
    if engines:
        scan += ["--engines", ",".join(engines)]
    return [part.replace("{src}", str(src)) for part in shlex.split(wrapper)] + scan


def sandboxed_scan(src: Path, wrapper: str = "", timeout: int = 900, max_file_mb: int = 512,
                   only_files: set[str] | None = None, engines: list[str] | None = None) -> ScanResult:
    files_from = None
    if only_files is not None:
        # Fuera del directorio del repositorio, para que el código del cliente no lo pueda alterar.
        files_from = src.parent / "appsec-ai-files.txt"
        files_from.write_text("\n".join(sorted(only_files)))
    proc = subprocess.Popen(
        build_command(src, wrapper, files_from, engines), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
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


def runner_scan(src: Path, runner: str, timeout: int = 900, only_files: set[str] | None = None,
                engines: list[str] | None = None) -> ScanResult:
    """Ejecuta el escaneo en un contenedor efímero descrito por `runner` (RF-4.4).

    `runner` es una plantilla de orden con marcadores que se sustituyen:
      {src}         directorio del repositorio a montar de solo lectura;
      {out}         fichero donde el contenedor debe escribir el resultado JSON (lo leemos aquí);
      {files_from}  fichero con las rutas a analizar (escaneo incremental; vacío si es completo);
      {engines}     motores separados por comas (vacío = todos).
    El contenedor es responsable de montar {src} de solo lectura, sin red y sin secretos, y de correr
    `appsec-ai scan` dentro. Ejemplo con gVisor:
      docker run --rm --runtime=runsc --network=none --read-only -v {src}:/src:ro -v {out}:/out.json \
                 appsec-ai-scanner scan /src --format json {engines_opt} > /out.json
    """
    import tempfile

    staged = None
    if only_files is not None:
        staged = src.parent / "appsec-ai-files.txt"  # fuera del repo: el cliente no puede alterarlo
        staged.write_text("\n".join(sorted(only_files)))
    out_file = Path(tempfile.mkstemp(prefix="appsec-ai-out-", suffix=".json", dir=src.parent)[1])
    try:
        values = {"src": str(src), "out": str(out_file), "files_from": str(staged) if staged else "",
                  "engines": ",".join(engines) if engines else ""}
        # No se descartan los marcadores vacíos: son posicionales y el contenedor espera "" como "sin valor".
        cmd = [_fill(part, values) for part in shlex.split(runner)]
        if not cmd:
            raise SandboxError("SCAN_RUNNER está vacío")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=safe_env(), cwd=src.parent, start_new_session=True)
        try:
            _, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise SandboxError(f"el escaneo en contenedor superó el tiempo máximo ({timeout} s)") from None
        if proc.returncode != 0:
            raise SandboxError(f"el contenedor de escaneo falló ({proc.returncode}): {err.strip()[-500:]}")
        try:
            return ScanResult.model_validate_json(out_file.read_text())
        except (ValueError, OSError) as e:
            raise SandboxError(f"el contenedor no dejó un resultado válido en {{out}}: {e}") from None
    finally:
        out_file.unlink(missing_ok=True)
        if staged is not None:
            staged.unlink(missing_ok=True)


def _fill(part: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        part = part.replace("{" + key + "}", value)
    return part

from __future__ import annotations

import json
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from appsec_ai.models import Finding

# Directorios que ningún motor debería analizar.
IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", ".appsec-ai-cache", "vendor",
}


class EngineError(RuntimeError):
    pass


class Engine(ABC):
    name: str = ""
    binary: str | None = None

    def available(self) -> bool:
        return self.binary is None or self.find_binary() is not None

    def find_binary(self) -> str | None:
        if self.binary is None:
            return None
        found = shutil.which(self.binary)
        if found:
            return found
        # Binarios instalados en el mismo entorno virtual que este paquete.
        import sys

        candidate = Path(sys.executable).parent / self.binary
        return str(candidate) if candidate.exists() else None

    @abstractmethod
    def run(self, target: Path) -> list[Finding]:
        ...


def run_json(cmd: list[str], ok_codes: tuple[int, ...] = (0, 1), timeout: int = 900) -> object:
    """Ejecuta un motor y devuelve su salida JSON. Muchos motores salen con 1 si hay hallazgos."""
    env = {**os.environ, "NO_COLOR": "1"}
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode not in ok_codes:
        raise EngineError(f"{cmd[0]} salió con {proc.returncode}: {proc.stderr.strip()[-500:]}")
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise EngineError(f"{cmd[0]} devolvió JSON no válido: {e}") from e


def read_lines(target: Path, rel: str, start: int, end: int | None = None, context: int = 0) -> str:
    path = (target / rel) if not Path(rel).is_absolute() else Path(rel)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if start <= 0:
        return ""
    end = end or start
    lo = max(0, start - 1 - context)
    hi = min(len(lines), end + context)
    return "\n".join(lines[lo:hi])


def relpath(target: Path, p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(target.resolve()))
    except ValueError:
        return p.lstrip("/")

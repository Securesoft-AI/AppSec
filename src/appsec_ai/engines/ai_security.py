"""Motor propio de seguridad de IA: inventario de uso de LLMs y riesgos del OWASP Top 10 para LLM.

- Python: análisis de flujo sobre el AST (`ai_python`).
- JavaScript/TypeScript: análisis de flujo sobre el árbol de tree-sitter (`ai_js`).

Ambos producen candidatos que después el triage con Claude confirma o descarta.
"""

from __future__ import annotations

from pathlib import Path

from appsec_ai.engines.ai_common import RATE_LIMIT_SIGNAL, FindingSink
from appsec_ai.engines.ai_js import analyze_js
from appsec_ai.engines.ai_python import analyze_python
from appsec_ai.engines.base import Engine, iter_source_files
from appsec_ai.models import AIComponent, Finding

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
# Dónde buscar señales de rate limiting: código y manifiestos de dependencias de cualquier lenguaje.
RATE_LIMIT_FILES = PY_EXT | JS_EXT | {".go", ".java", ".kt", ".toml", ".txt", ".json", ".mod", ".xml", ".gradle",
                                      ".kts", ".yaml", ".yml", ".conf", ".cfg"}


class AISecurityEngine(Engine):
    name = "ai-security"

    def __init__(self):
        self.inventory: list[AIComponent] = []

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        inventory: list[AIComponent] = []
        for path in iter_source_files(target, PY_EXT | JS_EXT):
            rel = str(path.relative_to(target))
            if path.suffix in PY_EXT:
                f, inv = analyze_python(rel, path.read_text(errors="replace"))
            elif path.name.endswith(".d.ts"):
                continue
            else:
                f, inv = analyze_js(rel, path.read_bytes(), path.suffix)
            findings += f
            inventory += inv
        self.inventory = _dedupe_inventory(inventory)
        findings += _rate_limit_findings(target, self.inventory)
        return findings


def _rate_limit_findings(target: Path, inventory: list[AIComponent]) -> list[Finding]:
    """Un aviso por fichero con llamadas al LLM disparables por el usuario, si no hay rate limiting en ningún sitio."""
    entrypoints: dict[str, int] = {}
    for c in inventory:
        if c.kind == "llm_entrypoint":
            entrypoints[c.file] = min(c.line, entrypoints.get(c.file, c.line))
    if not entrypoints or _has_rate_limit(target):
        return []
    findings = []
    for rel, line in sorted(entrypoints.items()):
        lines = (target / rel).read_text(errors="replace").splitlines()
        sink = FindingSink("ai-security", rel, lines)
        sink.add("llm10-no-rate-limit", line)
        findings += sink.findings
    return findings


def _has_rate_limit(target: Path) -> bool:
    for path in iter_source_files(target, RATE_LIMIT_FILES):
        if RATE_LIMIT_SIGNAL.search(path.read_text(errors="replace")):
            return True
    return False


def _dedupe_inventory(items: list[AIComponent]) -> list[AIComponent]:
    seen, out = set(), []
    for c in items:
        key = (c.kind, c.name, c.file)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out

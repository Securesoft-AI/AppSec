"""Motor propio de seguridad de IA: inventario de uso de LLMs y riesgos del OWASP Top 10 para LLM.

- Python: análisis de flujo sobre el AST (`ai_python`).
- JavaScript/TypeScript: análisis de flujo sobre el árbol de tree-sitter (`ai_js`).

Ambos producen candidatos que después el triage con Claude confirma o descarta.
"""

from __future__ import annotations

from pathlib import Path

from appsec_ai.engines.ai_js import analyze_js
from appsec_ai.engines.ai_python import analyze_python
from appsec_ai.engines.base import Engine, iter_source_files
from appsec_ai.models import AIComponent, Finding

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


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
        return findings


def _dedupe_inventory(items: list[AIComponent]) -> list[AIComponent]:
    seen, out = set(), []
    for c in items:
        key = (c.kind, c.name, c.file)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out

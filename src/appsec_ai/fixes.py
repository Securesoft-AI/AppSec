"""Correcciones automáticas: aplicar y validar las ediciones que propone el modelo.

El modelo devuelve ediciones "buscar → reemplazar" sobre el fichero. Nada se aplica a ciegas:
cada texto buscado debe aparecer exactamente una vez, y el fichero resultante debe seguir
siendo sintácticamente válido. Si algo falla, no se propone la corrección.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from appsec_ai.models import Finding, Verdict

MAX_FILES_PER_PR = 5
MAX_FILE_BYTES = 200_000


class FixError(ValueError):
    pass


@dataclass
class Edit:
    find: str
    replace: str


@dataclass
class FileFix:
    path: str
    original: str
    fixed: str
    summary: str
    findings: list[Finding] = field(default_factory=list)


def apply_edits(text: str, edits: list[Edit]) -> str:
    if not edits:
        raise FixError("sin ediciones")
    for e in edits:
        if not e.find:
            raise FixError("edición con texto de búsqueda vacío")
        n = text.count(e.find)
        if n != 1:
            raise FixError(f"el texto a reemplazar aparece {n} veces (debe aparecer una): {e.find[:80]!r}")
        text = text.replace(e.find, e.replace, 1)
    return text


def check_syntax(path: str, text: str):
    """Rechaza correcciones que rompen el fichero. Solo se valida lo que se sabe parsear."""
    suffix = Path(path).suffix
    if suffix == ".py":
        try:
            ast.parse(text)
        except SyntaxError as e:
            raise FixError(f"la corrección rompe la sintaxis de Python: {e.msg} (línea {e.lineno})") from None
    elif suffix in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"):
        from appsec_ai.engines.ai_js import parser_for

        tree = parser_for(".tsx" if suffix == ".tsx" else ".ts" if suffix.endswith("ts") else ".js").parse(text.encode())
        if tree.root_node.has_error:
            raise FixError("la corrección rompe la sintaxis de JavaScript/TypeScript")


def build_fix(path: str, original: str, edits: list[Edit], summary: str, findings: list[Finding]) -> FileFix:
    fixed = apply_edits(original, edits)
    if fixed == original:
        raise FixError("la corrección no cambia el fichero")
    check_syntax(path, fixed)
    return FileFix(path=path, original=original, fixed=fixed, summary=summary.strip(), findings=findings)


def fixable(findings: list[Finding]) -> list[Finding]:
    """Problemas confirmados por el triage, en ficheros de código: los únicos que se corrigen solos."""
    return [f for f in findings
            if f.triage and f.triage.verdict == Verdict.TRUE_POSITIVE and f.file and f.line]


def files_to_fix(findings: list[Finding], limit: int = MAX_FILES_PER_PR) -> dict[str, list[Finding]]:
    """Agrupa por fichero, empezando por los hallazgos más graves."""
    by_file: dict[str, list[Finding]] = {}
    for f in sorted(fixable(findings), key=lambda f: -f.effective_severity.rank):
        if f.file in by_file or len(by_file) < limit:
            by_file.setdefault(f.file, []).append(f)
    return by_file

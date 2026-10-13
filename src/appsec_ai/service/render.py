"""Presentación de resultados en GitHub: check run con anotaciones y comentario del PR."""

from __future__ import annotations

from collections import Counter

from appsec_ai.fixes import FileFix, fixable
from appsec_ai.models import Finding, ScanResult, Severity
from appsec_ai.report import CATEGORY_LABEL, SEV_ICON

CHECK_NAME = "appsec-ai"
COMMENT_MARKER = "<!-- appsec-ai:pr-comment -->"
FIX_MARKER = "<!-- appsec-ai:fix-comment -->"
ANNOTATION_LEVEL = {"critical": "failure", "high": "failure", "medium": "warning", "low": "notice", "info": "notice"}
MAX_ANNOTATIONS = 200
MAX_COMMENT_FINDINGS = 15


def visible(result: ScanResult) -> list[Finding]:
    return [f for f in result.findings if not f.is_suppressed]


def counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.effective_severity.value for f in findings)
    return {s.value: c.get(s.value, 0) for s in Severity}


def conclusion(findings: list[Finding], fail_on: str) -> str:
    threshold = Severity(fail_on).rank
    return "failure" if any(f.effective_severity.rank >= threshold for f in findings) else "success"


def explanation(f: Finding) -> str:
    if f.triage:
        text = f.triage.explanation
        if f.triage.fix:
            text += f"\n\nCorrección: {f.triage.fix}"
        return text
    return f.message or f.title


def annotations(findings: list[Finding]) -> list[dict]:
    out = []
    for f in findings[:MAX_ANNOTATIONS]:
        if not f.file:
            continue
        start = max(1, f.line or 1)
        end = max(start, f.end_line or start)
        out.append({
            "path": f.file,
            "start_line": start,
            "end_line": end,
            "annotation_level": ANNOTATION_LEVEL[f.effective_severity.value],
            "title": f"[{f.effective_severity.value.upper()}] {f.title}"[:255],
            "message": explanation(f)[:64000],
            "raw_details": f"{f.engine}/{f.rule_id} · {', '.join(f.frameworks[:4])}"[:64000],
        })
    return out


def summary_table(findings: list[Finding]) -> str:
    c = counts(findings)
    rows = " | ".join(f"{SEV_ICON[s]} {s}: **{n}**" for s, n in c.items() if n)
    return rows or "Sin hallazgos 🎉"


def check_output(result: ScanResult, scope_note: str) -> tuple[str, str, str]:
    findings = visible(result)
    total = len(findings)
    title = f"{total} hallazgo{'s' if total != 1 else ''} de seguridad" if total else "Sin hallazgos de seguridad"
    by_cat = Counter(CATEGORY_LABEL[f.category.value] for f in findings)
    summary = "\n".join([
        summary_table(findings),
        "",
        scope_note,
        "",
        " · ".join(f"{cat}: {n}" for cat, n in by_cat.most_common()) if by_cat else "",
    ]).strip()
    text_parts = []
    if result.ai_summary:
        text_parts += ["## Resumen de seguridad de IA", "", result.ai_summary, ""]
    if result.ai_inventory:
        text_parts += ["## Inventario de IA", "", "| Tipo | Componente | Ubicación |", "|---|---|---|"]
        text_parts += [f"| {c.kind} | {c.name} | `{c.file}:{c.line}` |" for c in result.ai_inventory[:50]]
    return title, summary, "\n".join(text_parts)


def pr_comment(result: ScanResult, details_url: str = "") -> str:
    findings = visible(result)
    lines = [COMMENT_MARKER, "### 🛡️ appsec-ai", "", summary_table(findings), ""]
    if not findings:
        lines += ["No se han encontrado problemas de seguridad en los ficheros modificados."]
    else:
        lines += ["| Severidad | Problema | Ubicación |", "|---|---|---|"]
        for f in findings[:MAX_COMMENT_FINDINGS]:
            sev = f.effective_severity.value
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            lines.append(f"| {SEV_ICON[sev]} {sev} | {f.title.replace('|', '/')} | {loc} |")
        if len(findings) > MAX_COMMENT_FINDINGS:
            lines.append(f"\n…y {len(findings) - MAX_COMMENT_FINDINGS} más.")
        lines += ["", "Cada hallazgo aparece anotado en la pestaña **Files changed** con la explicación y la corrección."]
    if details_url:
        lines += ["", f"[Ver el informe completo]({details_url})"]
    if result.suppressed_inline:
        lines += ["", f"_{result.suppressed_inline} hallazgos silenciados con `appsec-ai: ignore` / `nosec`._"]
    return "\n".join(lines)


# -- correcciones ---------------------------------------------------------------------------

def fix_actions(result: ScanResult) -> list[dict]:
    """Botón del check para abrir un PR con las correcciones, si hay problemas confirmados por la IA."""
    if not fixable(visible(result)):
        return []
    # GitHub limita la etiqueta a 20 caracteres y la descripción a 40.
    return [{"label": "Abrir PR con fixes", "description": "Corrige con IA los problemas confirmados",
             "identifier": "open_fix_pr"}]


def fix_pr_title(fixes: list[FileFix]) -> str:
    n = sum(len(f.findings) for f in fixes)
    return f"appsec-ai: corrige {n} problema{'s' if n != 1 else ''} de seguridad"


def fix_pr_body(fixes: list[FileFix], skipped: dict[str, str], source: str) -> str:
    lines = ["### 🛡️ Correcciones de seguridad propuestas por appsec-ai", "",
             f"Generadas con IA a partir de {source}. **Revísalas antes de fusionar**: comprueba que el "
             "comportamiento sigue siendo el esperado y que pasan los tests.", ""]
    for fx in fixes:
        lines += [f"#### `{fx.path}`", ""]
        for f in fx.findings:
            sev = f.effective_severity.value
            lines.append(f"- {SEV_ICON[sev]} **{f.title}** (línea {f.line}, `{f.rule_id}`)")
        if fx.summary:
            lines += ["", fx.summary]
        lines.append("")
    if skipped:
        lines += ["#### Sin corrección automática", ""]
        lines += [f"- `{path}`: {reason}" for path, reason in skipped.items()]
        lines.append("")
    return "\n".join(lines)


def fix_comment(pr_url: str, n_files: int) -> str:
    return (f"{FIX_MARKER}\n🛠️ He abierto {pr_url} con las correcciones de seguridad para {n_files} "
            f"fichero{'s' if n_files != 1 else ''}. Revísalo antes de fusionarlo.")


def fix_failed_comment(skipped: dict[str, str]) -> str:
    lines = [FIX_MARKER, "🛠️ No he podido generar una corrección automática segura:", ""]
    lines += [f"- `{path}`: {reason}" for path, reason in skipped.items()]
    lines += ["", "Las anotaciones del check explican cómo corregir cada problema a mano."]
    return "\n".join(lines)


FIX_PERMISSION_COMMENT = (
    f"{FIX_MARKER}\n🛠️ Para abrir PRs con correcciones, appsec-ai necesita permiso de escritura en el contenido "
    "del repositorio (Contents: Read & write). Un administrador puede concederlo en la configuración de la "
    "instalación de la GitHub App."
)

"""Presentación de resultados en GitHub: check run con anotaciones y comentario del PR."""

from __future__ import annotations

from collections import Counter

from appsec_ai.fixes import FileFix, fixable
from appsec_ai.i18n import localize, ui
from appsec_ai.models import Finding, ScanResult, Severity
from appsec_ai.report import SEV_ICON, category_label

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


def explanation(f: Finding, lang: str = "es") -> str:
    if f.triage:
        text = f.triage.explanation
        if f.triage.fix:
            text += f"\n\n{ui(lang, 'fix')}: {f.triage.fix}"
        return text
    title, message = localize(f, lang)
    return message or title


def annotations(findings: list[Finding], lang: str = "es") -> list[dict]:
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
            "title": f"[{f.effective_severity.value.upper()}] {localize(f, lang)[0]}"[:255],
            "message": explanation(f, lang)[:64000],
            "raw_details": f"{f.engine}/{f.rule_id} · {', '.join(f.frameworks[:4])}"[:64000],
        })
    return out


def summary_table(findings: list[Finding], lang: str = "es") -> str:
    c = counts(findings)
    rows = " | ".join(f"{SEV_ICON[s]} {s}: **{n}**" for s, n in c.items() if n)
    return rows or ui(lang, "no_findings")


def check_output(result: ScanResult, full_scan: bool, lang: str = "es") -> tuple[str, str, str]:
    findings = visible(result)
    total = len(findings)
    title = ui(lang, "findings_title", n=total) if total else ui(lang, "no_findings_title")
    by_cat = Counter(category_label(f.category.value, lang) for f in findings)
    summary = "\n".join([
        summary_table(findings, lang),
        "",
        ui(lang, "scope_full" if full_scan else "scope_pr"),
        "",
        " · ".join(f"{cat}: {n}" for cat, n in by_cat.most_common()) if by_cat else "",
    ]).strip()
    text_parts = []
    if result.ai_summary:
        text_parts += [f"## {ui(lang, 'ai_summary')}", "", result.ai_summary, ""]
    inventory = [c for c in result.ai_inventory if c.kind != "llm_entrypoint"]
    if inventory:
        text_parts += [f"## {ui(lang, 'ai_inventory')}", "",
                       f"| {ui(lang, 'kind')} | {ui(lang, 'component')} | {ui(lang, 'location')} |", "|---|---|---|"]
        text_parts += [f"| {c.kind} | {c.name} | `{c.file}:{c.line}` |" for c in inventory[:50]]
    return title, summary, "\n".join(text_parts)


def pr_comment(result: ScanResult, details_url: str = "", lang: str = "es") -> str:
    findings = visible(result)
    lines = [COMMENT_MARKER, "### 🛡️ appsec-ai", "", summary_table(findings, lang), ""]
    if not findings:
        lines += [ui(lang, "pr_clean")]
    else:
        lines += [f"| {ui(lang, 'severity')} | {ui(lang, 'problem')} | {ui(lang, 'location')} |", "|---|---|---|"]
        for f in findings[:MAX_COMMENT_FINDINGS]:
            sev = f.effective_severity.value
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            lines.append(f"| {SEV_ICON[sev]} {sev} | {localize(f, lang)[0].replace('|', '/')} | {loc} |")
        if len(findings) > MAX_COMMENT_FINDINGS:
            lines.append("\n" + ui(lang, "and_more", n=len(findings) - MAX_COMMENT_FINDINGS))
        lines += ["", ui(lang, "annotated")]
    if details_url:
        lines += ["", f"[{ui(lang, 'full_report')}]({details_url})"]
    if result.suppressed_inline:
        lines += ["", f"_{ui(lang, 'silenced', n=result.suppressed_inline)}_"]
    return "\n".join(lines)


# -- correcciones ---------------------------------------------------------------------------

def fix_actions(result: ScanResult, lang: str = "es") -> list[dict]:
    """Botón del check para abrir un PR con las correcciones, si hay problemas confirmados por la IA."""
    if not fixable(visible(result)):
        return []
    # GitHub limita la etiqueta a 20 caracteres y la descripción a 40.
    return [{"label": ui(lang, "fix_label")[:20], "description": ui(lang, "fix_desc")[:40], "identifier": "open_fix_pr"}]


def fix_pr_title(fixes: list[FileFix], lang: str = "es") -> str:
    return ui(lang, "fix_title", n=sum(len(f.findings) for f in fixes))


def fix_source(pr_number: int | None, sha: str, lang: str = "es") -> str:
    return ui(lang, "fix_source_pr", n=pr_number) if pr_number else ui(lang, "fix_source_commit", sha=sha[:7])


def fix_pr_body(fixes: list[FileFix], skipped: dict[str, str], source: str, lang: str = "es") -> str:
    lines = [f"### 🛡️ {ui(lang, 'fix_heading')}", "", ui(lang, "fix_intro", source=source), ""]
    for fx in fixes:
        lines += [f"#### `{fx.path}`", ""]
        for f in fx.findings:
            sev = f.effective_severity.value
            lines.append(f"- {SEV_ICON[sev]} **{localize(f, lang)[0]}** ({ui(lang, 'line')} {f.line}, `{f.rule_id}`)")
        if fx.summary:
            lines += ["", fx.summary]
        lines.append("")
    if skipped:
        lines += [f"#### {ui(lang, 'fix_skipped')}", ""]
        lines += [f"- `{path}`: {reason}" for path, reason in skipped.items()]
        lines.append("")
    return "\n".join(lines)


def fix_comment(pr_url: str, n_files: int, lang: str = "es") -> str:
    return f"{FIX_MARKER}\n" + ui(lang, "fix_done", url=pr_url, n=n_files)


def fix_failed_comment(skipped: dict[str, str], lang: str = "es") -> str:
    lines = [FIX_MARKER, ui(lang, "fix_failed"), ""]
    lines += [f"- `{path}`: {reason}" for path, reason in skipped.items()]
    lines += ["", ui(lang, "fix_failed_hint")]
    return "\n".join(lines)


def fix_permission_comment(lang: str = "es") -> str:
    return f"{FIX_MARKER}\n" + ui(lang, "fix_permission")

"""Informe PDF para cuestionarios de seguridad de clientes (RF-4.7), en español o inglés.

Incluye: resumen por severidad, metodología, mapeo de las reglas de IA a marcos (ATLAS, NIST AI RMF,
ISO/IEC 42001, EU AI Act), inventario de IA y el detalle de cada hallazgo abierto.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from appsec_ai import compliance
from appsec_ai.i18n import localize
from appsec_ai.models import ScanResult, Severity

INK = colors.HexColor("#12232a")
MUTED = colors.HexColor("#55666c")
LINE = colors.HexColor("#d5dddb")
ACCENT = colors.HexColor("#0d5f5c")
SEV_COLOR = {"critical": "#b4321f", "high": "#b4321f", "medium": "#9a5b00", "low": "#55666c", "info": "#55666c"}
MAX_FINDINGS = 200

TEXT = {
    "es": {
        "title": "Informe de seguridad", "generated": "Generado", "commit": "Commit", "summary": "Resumen",
        "severity": "Severidad", "findings": "Hallazgos", "total": "Total", "suppressed": "descartados como falsos positivos por el triage con IA",
        "methodology": "Metodología", "method_text": (
            "Análisis estático del código fuente con motores open source (Semgrep/Opengrep, Gitleaks, OSV-Scanner, "
            "Checkov) y un motor propio de seguridad de IA alineado con el OWASP Top 10 para aplicaciones LLM. Cuando "
            "está activado, cada hallazgo lo revisa un modelo de IA que confirma o descarta el problema, ajusta la "
            "severidad al contexto y propone la corrección. Las conclusiones automáticas deben revisarse por una persona."),
        "engines": "Motores", "mapping": "Mapeo a marcos de IA", "mapping_note": (
            "Orientativo: qué técnica de ataque, control o requisito toca cada tipo de hallazgo. No es una evaluación "
            "de conformidad. Los artículos del EU AI Act citados obligan a los sistemas de alto riesgo."),
        "rule": "Regla", "inventory": "Inventario de IA", "kind": "Tipo", "component": "Componente", "where": "Ubicación",
        "detail": "Detalle de los hallazgos", "location": "Ubicación", "references": "Referencias", "fix": "Corrección",
        "attack": "Escenario de ataque", "verdict": "Veredicto IA", "none": "Sin hallazgos abiertos.", "page": "Página",
        "truncated": "Se muestran los {n} hallazgos más graves de {total}.",
        "critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa",
    },
    "en": {
        "title": "Security report", "generated": "Generated", "commit": "Commit", "summary": "Summary",
        "severity": "Severity", "findings": "Findings", "total": "Total", "suppressed": "dismissed as false positives by AI triage",
        "methodology": "Methodology", "method_text": (
            "Static analysis of the source code with open-source engines (Semgrep/Opengrep, Gitleaks, OSV-Scanner, "
            "Checkov) and a proprietary AI-security engine aligned with the OWASP Top 10 for LLM applications. When "
            "enabled, an AI model reviews each finding, confirms or dismisses it, adjusts severity to context and "
            "proposes a fix. Automated conclusions should be reviewed by a person."),
        "engines": "Engines", "mapping": "AI framework mapping", "mapping_note": (
            "Indicative: which attack technique, control or requirement each kind of finding relates to. This is not "
            "a conformity assessment. The EU AI Act articles cited apply to high-risk systems."),
        "rule": "Rule", "inventory": "AI inventory", "kind": "Type", "component": "Component", "where": "Location",
        "detail": "Findings in detail", "location": "Location", "references": "References", "fix": "Fix",
        "attack": "Attack scenario", "verdict": "AI verdict", "none": "No open findings.", "page": "Page",
        "truncated": "Showing the {n} most severe of {total} findings.",
        "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational",
    },
}


def to_pdf(result: ScanResult, lang: str = "es", target: str = "", commit: str = "",
           generated: dt.datetime | None = None, include_compliance: bool = True) -> bytes:
    T = TEXT["en" if lang == "en" else "es"]
    generated = generated or dt.datetime.now(dt.timezone.utc)
    st = _styles()
    findings = sorted((f for f in result.findings if not f.is_suppressed),
                      key=lambda f: (-f.effective_severity.rank, f.file, f.line))
    suppressed = sum(f.is_suppressed for f in result.findings)
    counts = Counter(f.effective_severity.value for f in findings)
    name = target or result.target

    story = [Paragraph(T["title"], st["title"]),
             Paragraph(f"<b>{_e(name)}</b>", st["subtitle"]),
             Paragraph(f'{T["generated"]}: {generated:%Y-%m-%d %H:%M} UTC'
                       + (f' · {T["commit"]} <font face="Courier">{_e(commit[:12])}</font>' if commit else ""), st["muted"]),
             Spacer(1, 8 * mm), Paragraph(T["summary"], st["h2"])]
    rows = [[T["severity"], T["findings"]]]
    rows += [[Paragraph(f'<font color="{SEV_COLOR[s.value]}"><b>■</b></font> {T[s.value]}', st["cell"]),
              str(counts.get(s.value, 0))] for s in Severity]
    rows.append([Paragraph(f"<b>{T['total']}</b>", st["cell"]), str(len(findings))])
    story.append(_table(rows, [80 * mm, 30 * mm], align_right=[1]))
    if suppressed:
        story.append(Paragraph(f"{suppressed} {T['suppressed']}.", st["muted"]))
    if result.ai_summary:
        story += [Spacer(1, 4 * mm), Paragraph(_e(result.ai_summary).replace("\n", "<br/>"), st["body"])]

    story += [Paragraph(T["methodology"], st["h2"]), Paragraph(T["method_text"], st["body"])]
    engines = ", ".join(f"{e.engine} ({e.status})" for e in result.engines if e.engine != "triage")
    if engines:
        story.append(Paragraph(f"<b>{T['engines']}:</b> {_e(engines)}", st["muted"]))

    mapping = compliance.summary(findings) if include_compliance else []
    if mapping:
        story += [Paragraph(T["mapping"], st["h2"]), Paragraph(T["mapping_note"], st["muted"]), Spacer(1, 2 * mm)]
        rows = [[T["rule"], "#", "MITRE ATLAS", "NIST AI RMF", "ISO/IEC 42001", "EU AI Act"]]
        for rule, n, m in mapping:
            rows.append([Paragraph(f'<font face="Courier" size="7">{_e(rule)}</font>', st["small"]), str(n),
                         Paragraph("<br/>".join(m.atlas), st["small"]), Paragraph("<br/>".join(m.nist), st["small"]),
                         Paragraph("<br/>".join(m.iso42001) or "—", st["small"]),
                         Paragraph("<br/>".join(m.eu_ai_act) or "—", st["small"])])
        story.append(_table(rows, [46 * mm, 8 * mm, 30 * mm, 38 * mm, 24 * mm, 20 * mm], align_right=[1]))

    inventory = [c for c in result.ai_inventory if c.kind != "llm_entrypoint"]
    if inventory:
        story += [Paragraph(T["inventory"], st["h2"])]
        rows = [[T["kind"], T["component"], T["where"]]]
        rows += [[_e(c.kind), Paragraph(_e(c.name), st["cell"]),
                  Paragraph(f'<font face="Courier" size="7">{_e(c.file)}:{c.line}</font>', st["cell"])] for c in inventory[:100]]
        story.append(_table(rows, [30 * mm, 55 * mm, 81 * mm]))

    story.append(Paragraph(T["detail"], st["h2"]))
    if not findings:
        story.append(Paragraph(T["none"], st["body"]))
    if len(findings) > MAX_FINDINGS:
        story.append(Paragraph(T["truncated"].format(n=MAX_FINDINGS, total=len(findings)), st["muted"]))
    for i, f in enumerate(findings[:MAX_FINDINGS], 1):
        sev = f.effective_severity.value
        title, message = localize(f, lang)
        block = [Paragraph(f'{i}. <font color="{SEV_COLOR[sev]}"><b>[{T[sev].upper()}]</b></font> {_e(title)}', st["h3"]),
                 Paragraph(f'<b>{T["location"]}:</b> <font face="Courier">{_e(f.file)}:{f.line}</font> · '
                           f'<font face="Courier">{_e(f.rule_id)}</font>', st["muted"])]
        if f.frameworks:
            block.append(Paragraph(f'<b>{T["references"]}:</b> {_e(", ".join(f.frameworks[:6]))}', st["muted"]))
        t = f.triage
        if t:
            block.append(Paragraph(f'<b>{T["verdict"]}:</b> {t.verdict.value} ({t.confidence:.0%})', st["muted"]))
        block.append(Paragraph(_e(t.explanation if t else message), st["body"]))
        if t and t.exploit_scenario:
            block.append(Paragraph(f'<b>{T["attack"]}:</b> {_e(t.exploit_scenario)}', st["body"]))
        if t and t.fix:
            block.append(Paragraph(f'<b>{T["fix"]}:</b> {_e(t.fix)}', st["body"]))
        if f.snippet:
            block.append(Preformatted(_clip(f.snippet), st["code"]))
        story.append(KeepTogether(block))

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=f"{T['title']} — {name}", author="Atalaya")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"Atalaya · {name}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"{T['page']} {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def _e(text: str) -> str:
    """El contenido viene del código del cliente: se escapa para el mini-HTML de ReportLab."""
    return escape(str(text or ""))


def _clip(snippet: str, max_lines: int = 15, width: int = 110) -> str:
    lines = snippet.strip("\n").splitlines()[:max_lines]
    return "\n".join(line if len(line) <= width else line[: width - 1] + "…" for line in lines)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["BodyText"]
    mk = lambda name, **kw: ParagraphStyle(name, parent=base, **{"textColor": INK, "alignment": TA_LEFT, **kw})  # noqa: E731
    return {
        "title": mk("title", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=ACCENT),
        "subtitle": mk("subtitle", fontSize=12, leading=16),
        "h2": mk("h2", fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=10, spaceAfter=4, keepWithNext=1),
        "h3": mk("h3", fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=8),
        "body": mk("body", fontSize=9, leading=12.5),
        "cell": mk("cell", fontSize=8.5, leading=11),
        "small": mk("small", fontSize=7, leading=9),
        "muted": mk("muted", fontSize=8, leading=11, textColor=MUTED),
        "code": ParagraphStyle("code", fontName="Courier", fontSize=7, leading=9, textColor=INK,
                               backColor=colors.HexColor("#f7f9f8"), borderColor=LINE, borderWidth=0.5,
                               borderPadding=4, spaceBefore=4, spaceAfter=4),
    }


def _table(rows: list[list], widths: list[float], align_right: list[int] | None = None) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8), ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
             ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for col in align_right or []:
        style.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    table.setStyle(TableStyle(style))
    return table

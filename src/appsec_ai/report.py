from __future__ import annotations

from collections import Counter

from appsec_ai import __version__
from appsec_ai.models import Finding, ScanResult, Severity

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
CATEGORY_LABEL = {"ai": "Seguridad de IA", "sast": "Código (SAST)", "secrets": "Secretos",
                  "sca": "Dependencias", "iac": "Infraestructura (IaC)"}


def visible(result: ScanResult, include_suppressed: bool = False) -> list[Finding]:
    return [f for f in result.findings if include_suppressed or not f.is_suppressed]


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_markdown(result: ScanResult, include_suppressed: bool = False) -> str:
    findings = visible(result, include_suppressed)
    suppressed = sum(1 for f in result.findings if f.is_suppressed)
    counts = Counter(f.effective_severity.value for f in findings)
    out = [f"# Informe de seguridad — `{result.target}`", ""]

    out += ["## Resumen", "", "| Severidad | Hallazgos |", "|---|---|"]
    for sev in Severity:
        out.append(f"| {SEV_ICON[sev.value]} {sev.value} | {counts.get(sev.value, 0)} |")
    out.append("")
    if suppressed:
        out += [f"_{suppressed} hallazgos descartados como falsos positivos por el triage con IA._", ""]

    by_cat = Counter(f.category.value for f in findings)
    out += ["| Área | Hallazgos |", "|---|---|"]
    out += [f"| {CATEGORY_LABEL[c]} | {n} |" for c, n in by_cat.most_common()]
    out.append("")

    if result.ai_summary:
        out += ["## Resumen ejecutivo de seguridad de IA", "", result.ai_summary, ""]

    if result.ai_inventory:
        out += ["## Inventario de IA", "", "| Tipo | Componente | Ubicación |", "|---|---|---|"]
        for c in result.ai_inventory:
            out.append(f"| {c.kind} | {c.name} | `{c.file}:{c.line}` |")
        out.append("")

    out += ["## Hallazgos", ""]
    if not findings:
        out += ["Sin hallazgos. 🎉", ""]
    for i, f in enumerate(findings, 1):
        sev = f.effective_severity.value
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        out += [f"### {i}. {SEV_ICON[sev]} [{sev.upper()}] {f.title}", "",
                f"- **Ubicación:** {loc}", f"- **Motor / regla:** {f.engine} / `{f.rule_id}`"]
        if f.frameworks:
            out.append(f"- **Referencias:** {', '.join(f.frameworks[:6])}")
        if f.triage:
            t = f.triage
            out.append(f"- **Veredicto IA:** {t.verdict.value} (confianza {t.confidence:.0%})")
            out += ["", t.explanation]
            if t.exploit_scenario:
                out += ["", f"**Escenario de ataque:** {t.exploit_scenario}"]
            if t.fix:
                out += ["", f"**Corrección:** {t.fix}"]
            if t.fixed_code:
                out += ["", "```", t.fixed_code.strip(), "```"]
        else:
            if f.message:
                out += ["", f.message]
        if f.snippet and not (f.triage and f.triage.fixed_code):
            out += ["", "```", f.snippet.strip()[:1500], "```"]
        out.append("")

    out += ["## Motores ejecutados", "", "| Motor | Estado | Detalle |", "|---|---|---|"]
    for e in result.engines:
        detail = f"{e.findings} hallazgos" if e.status == "ok" else e.detail
        out.append(f"| {e.engine} | {e.status} | {detail} |")
    if result.llm_usage:
        u = result.llm_usage
        out += ["", f"_Uso de IA: {u.get('requests', 0)} peticiones, {u.get('input_tokens', 0)} tokens de entrada, "
                    f"{u.get('output_tokens', 0)} de salida, {u.get('cache_read_input_tokens', 0)} leídos de caché._"]
    out.append("")
    return "\n".join(out)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0: lo entienden GitHub Code Scanning, GitLab, Azure DevOps y la mayoría de IDEs."""
    rules: dict[str, dict] = {}
    results = []
    for f in visible(result):
        rid = f"{f.engine}/{f.rule_id}"
        rules.setdefault(rid, {
            "id": rid,
            "name": f.rule_id,
            "shortDescription": {"text": f.title[:200]},
            "properties": {"tags": [f.category.value] + f.frameworks[:5]},
        })
        text = f.triage.explanation if f.triage else (f.message or f.title)
        if f.triage and f.triage.fix:
            text += f"\n\nCorrección: {f.triage.fix}"
        r = {
            "ruleId": rid,
            "level": SARIF_LEVEL[f.effective_severity.value],
            "message": {"text": text},
            "partialFingerprints": {"appsecAi/v1": f.fingerprint},
            "properties": {"severity": f.effective_severity.value},
        }
        if f.file:
            region = {"startLine": max(1, f.line)} if f.line else {"startLine": 1}
            if f.end_line and f.end_line >= region["startLine"]:
                region["endLine"] = f.end_line
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": region}}]
        results.append(r)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "appsec-ai", "version": __version__, "rules": list(rules.values())}},
            "results": results,
        }],
    }

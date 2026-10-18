from __future__ import annotations

from collections import Counter

from appsec_ai import __version__, compliance
from appsec_ai.models import Finding, ScanResult, Severity

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
CATEGORY_LABEL = {"ai": "Seguridad de IA", "sast": "Código (SAST)", "secrets": "Secretos",
                  "sca": "Dependencias", "iac": "Infraestructura (IaC)"}
CATEGORY_LABEL_EN = {"ai": "AI security", "sast": "Code (SAST)", "secrets": "Secrets",
                     "sca": "Dependencies", "iac": "Infrastructure (IaC)"}


def category_label(category: str, lang: str = "es") -> str:
    return (CATEGORY_LABEL_EN if lang == "en" else CATEGORY_LABEL).get(category, category)


def visible(result: ScanResult, include_suppressed: bool = False) -> list[Finding]:
    return [f for f in result.findings if include_suppressed or not f.is_suppressed]


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_markdown(result: ScanResult, include_suppressed: bool = False, lang: str = "es") -> str:
    from appsec_ai.i18n import localize, ui

    findings = visible(result, include_suppressed)
    suppressed = sum(1 for f in result.findings if f.is_suppressed)
    counts = Counter(f.effective_severity.value for f in findings)
    out = [f"# {ui(lang, 'report_title')} — `{result.target}`", ""]

    out += [f"## {ui(lang, 'summary')}", "", f"| {ui(lang, 'severity')} | {ui(lang, 'findings')} |", "|---|---|"]
    for sev in Severity:
        out.append(f"| {SEV_ICON[sev.value]} {sev.value} | {counts.get(sev.value, 0)} |")
    out.append("")
    if suppressed:
        out += [f"_{ui(lang, 'suppressed_ai', n=suppressed)}_", ""]
    if result.suppressed_inline:
        out += [f"_{ui(lang, 'suppressed_inline', n=result.suppressed_inline)}_", ""]

    by_cat = Counter(f.category.value for f in findings)
    out += [f"| {ui(lang, 'area')} | {ui(lang, 'findings')} |", "|---|---|"]
    out += [f"| {category_label(c, lang)} | {n} |" for c, n in by_cat.most_common()]
    out.append("")

    if result.ai_summary:
        out += [f"## {ui(lang, 'exec_summary')}", "", result.ai_summary, ""]

    inventory = [c for c in result.ai_inventory if c.kind != "llm_entrypoint"]
    if inventory:
        out += [f"## {ui(lang, 'ai_inventory')}", "",
                f"| {ui(lang, 'kind')} | {ui(lang, 'component')} | {ui(lang, 'location')} |", "|---|---|---|"]
        for c in inventory:
            out.append(f"| {c.kind} | {c.name} | `{c.file}:{c.line}` |")
        out.append("")

    out += threat_model_markdown(result, lang)
    out += compliance.to_markdown(findings, lang)

    out += [f"## {ui(lang, 'findings')}", ""]
    if not findings:
        out += [ui(lang, "no_findings"), ""]
    for i, f in enumerate(findings, 1):
        sev = f.effective_severity.value
        title, message = localize(f, lang)
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        out += [f"### {i}. {SEV_ICON[sev]} [{sev.upper()}] {title}", "",
                f"- **{ui(lang, 'location')}:** {loc}", f"- **{ui(lang, 'engine_rule')}:** {f.engine} / `{f.rule_id}`"]
        if f.frameworks:
            out.append(f"- **{ui(lang, 'references')}:** {', '.join(f.frameworks[:6])}")
        if f.triage:
            t = f.triage
            out.append(f"- **{ui(lang, 'verdict')}:** {t.verdict.value} ({ui(lang, 'confidence')} {t.confidence:.0%})")
            out += ["", t.explanation]
            if t.exploit_scenario:
                out += ["", f"**{ui(lang, 'attack')}:** {t.exploit_scenario}"]
            if t.fix:
                out += ["", f"**{ui(lang, 'fix')}:** {t.fix}"]
            if t.fixed_code:
                out += ["", "```", t.fixed_code.strip(), "```"]
        elif message:
            out += ["", message]
        if f.snippet and not (f.triage and f.triage.fixed_code):
            out += ["", "```", f.snippet.strip()[:1500], "```"]
        out.append("")

    out += [f"## {ui(lang, 'engines_run')}", "", f"| {ui(lang, 'engine')} | {ui(lang, 'status')} | {ui(lang, 'detail')} |", "|---|---|---|"]
    for e in result.engines:
        detail = ui(lang, "n_findings", n=e.findings) if e.status == "ok" else e.detail
        out.append(f"| {e.engine} | {e.status} | {detail} |")
    if result.llm_usage:
        u = result.llm_usage
        out += ["", "_" + ui(lang, "ai_usage", r=u.get("requests", 0), i=u.get("input_tokens", 0),
                                o=u.get("output_tokens", 0), c=u.get("cache_read_input_tokens", 0)) + "_"]
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


def threat_model_markdown(result: ScanResult, lang: str = "es") -> list[str]:
    """RF-2.6: activos y flujo de datos en Mermaid, y cada amenaza con su camino de ataque y mitigaciones."""
    from appsec_ai.i18n import ui
    from appsec_ai.threatmodel import mermaid

    tm = result.threat_model
    if tm is None or not tm.threats:
        return []
    out = [f"## {ui(lang, 'threat_model')}", "", f"_{ui(lang, 'tm_ai' if tm.generated_by == 'ai' else 'tm_rules')}_", ""]
    if tm.summary:
        out += [tm.summary, ""]
    out += [f"**{ui(lang, 'tm_flow')}**", "", "```mermaid", mermaid(tm), "```", "",
            f"| {ui(lang, 'tm_threat')} | OWASP | {ui(lang, 'severity')} | {ui(lang, 'tm_status')} |", "|---|---|---|---|"]
    out += [f"| {th.title.replace('|', '/')} | {th.owasp} | {SEV_ICON[th.severity.value]} {th.severity.value} | {ui(lang, th.status)} |"
            for th in tm.threats]
    out.append("")
    for th in tm.threats:
        out += [f"### {th.title} ({th.owasp or '—'})", ""]
        if th.findings:
            out += [f"_{ui(lang, 'tm_findings', n=len(th.findings))}_" + (f" · ATLAS {', '.join(th.atlas)}" if th.atlas else ""), ""]
        out += [f"**{ui(lang, 'tm_path')}**", ""] + [f"{i}. {s}" for i, s in enumerate(th.attack_path, 1)] + [""]
        out += [f"**{ui(lang, 'tm_mitigations')}**", ""] + [f"- {s}" for s in th.mitigations] + [""]
    return out

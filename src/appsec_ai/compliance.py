"""Mapeo de las reglas de seguridad de IA a marcos de gestión de riesgos y cumplimiento.

Es orientativo: indica qué técnica de ataque, control o requisito toca cada hallazgo, para preparar
auditorías y cuestionarios de clientes. No es una evaluación de conformidad.

- MITRE ATLAS: IDs comprobados contra ATLAS.yaml v5.6.0 (github.com/mitre-atlas/atlas-data).
- NIST AI RMF 1.0 (AI 100-1) y su perfil de IA generativa (NIST AI 600-1).
- ISO/IEC 42001:2023, controles del anexo A.
- EU AI Act (Reglamento (UE) 2024/1689): los artículos 14 y 15 obligan a los sistemas de alto riesgo.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from appsec_ai.models import Finding

ATLAS = {
    "AML.T0034": "Cost Harvesting",
    "AML.T0034.002": "Agentic Resource Consumption",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0085.000": "Data from AI Services: RAG Databases",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
}

NIST = {
    "MEASURE 2.7": "Se evalúan y documentan la seguridad y la resiliencia del sistema de IA",
    "MEASURE 2.10": "Se examina y documenta el riesgo para la privacidad",
    "MAP 3.5": "Se definen y evalúan los procesos de supervisión humana",
    "600-1: Information Security": "Perfil de IA generativa: seguridad de la información",
    "600-1: Data Privacy": "Perfil de IA generativa: privacidad de los datos",
}

ISO42001 = {
    "A.6.2.4": "Verificación y validación del sistema de IA",
    "A.6.2.6": "Operación y monitorización del sistema de IA",
    "A.6.2.8": "Registro de eventos del sistema de IA",
    "A.9.2": "Procesos para el uso responsable de sistemas de IA",
}

EU_AI_ACT = {
    "Art. 14": "Supervisión humana",
    "Art. 15": "Precisión, solidez y ciberseguridad",
}


@dataclass(frozen=True)
class Mapping:
    atlas: tuple[str, ...]
    nist: tuple[str, ...]
    iso42001: tuple[str, ...]
    eu_ai_act: tuple[str, ...]


_SEC = ("MEASURE 2.7", "600-1: Information Security")
_PRIV = ("MEASURE 2.7", "MEASURE 2.10", "600-1: Information Security", "600-1: Data Privacy")
_AGENCY = ("MEASURE 2.7", "MAP 3.5", "600-1: Information Security")

RULES: dict[str, Mapping] = {
    "llm01-untrusted-input-in-system-prompt": Mapping(("AML.T0051.000",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm01-prompt-concatenation": Mapping(("AML.T0051.000",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm01-indirect-prompt-injection": Mapping(("AML.T0051.001",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm02-llm-io-logged": Mapping(("AML.T0057",), _PRIV, ("A.6.2.8",), ()),
    "llm05-llm-output-to-code-exec": Mapping(("AML.T0051", "AML.T0050"), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm05-llm-output-to-sql": Mapping(("AML.T0051",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm05-llm-output-to-request": Mapping(("AML.T0051",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm05-llm-output-to-filesystem": Mapping(("AML.T0051",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm05-llm-output-to-html": Mapping(("AML.T0051", "AML.T0077"), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm05-llm-output-selects-function": Mapping(("AML.T0051", "AML.T0053"), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm06-excessive-agency-tool": Mapping(("AML.T0053", "AML.T0101"), _AGENCY, ("A.6.2.4", "A.9.2"),
                                          ("Art. 14", "Art. 15")),
    "llm06-mcp-http-without-auth": Mapping(("AML.T0053",), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm07-secret-in-system-prompt": Mapping(("AML.T0056", "AML.T0055"), _SEC, ("A.6.2.4",), ("Art. 15",)),
    "llm07-authorization-in-prompt": Mapping(("AML.T0051", "AML.T0057"), _PRIV, ("A.6.2.4",), ("Art. 15",)),
    "llm08-rag-without-access-filter": Mapping(("AML.T0085.000", "AML.T0057"), _PRIV, ("A.6.2.4",), ("Art. 15",)),
    "llm10-no-output-limit": Mapping(("AML.T0034",), _SEC, ("A.6.2.6",), ()),
    "llm10-unbounded-agent-loop": Mapping(("AML.T0034.002",), _AGENCY, ("A.6.2.6",), ("Art. 14",)),
}


def atlas_refs(rule_id: str) -> list[str]:
    m = RULES.get(rule_id)
    return [f"MITRE-ATLAS {t}" for t in m.atlas] if m else []


def summary(findings: list[Finding]) -> list[tuple[str, int, Mapping]]:
    """(regla, nº de hallazgos, mapeo) de las reglas de IA presentes, de más a menos hallazgos."""
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.rule_id in RULES:
            counts[f.rule_id] += 1
    return [(r, n, RULES[r]) for r, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]


def to_markdown(findings: list[Finding]) -> list[str]:
    rows = summary(findings)
    if not rows:
        return []

    def refs(ids, names):
        return "<br>".join(f"{i} {names[i]}" for i in ids) or "—"
    out = ["## Mapeo a marcos de IA", "",
           "_Orientativo: qué técnica de ataque, control o requisito toca cada tipo de hallazgo. No es una "
           "evaluación de conformidad. Los artículos del EU AI Act citados obligan a los sistemas de alto riesgo._",
           "", "| Regla | Hallazgos | MITRE ATLAS | NIST AI RMF | ISO/IEC 42001 | EU AI Act |",
           "|---|---|---|---|---|---|"]
    for rule, n, m in rows:
        out.append(f"| `{rule}` | {n} | {refs(m.atlas, ATLAS)} | {'<br>'.join(m.nist)} | "
                   f"{refs(m.iso42001, ISO42001)} | {refs(m.eu_ai_act, EU_AI_ACT)} |")
    out.append("")
    return out

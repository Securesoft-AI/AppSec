from __future__ import annotations

import re
from pathlib import Path

from appsec_ai.engines.ai_security import AISecurityEngine
from appsec_ai.engines.base import Engine, EngineError
from appsec_ai.engines.opensource import CheckovEngine, GitleaksEngine, OpengrepEngine, OSVEngine
from appsec_ai.models import Category, EngineRun, Finding, ScanResult
from appsec_ai.triage import Triager

ALL_ENGINES = {
    "ai-security": AISecurityEngine,
    "gitleaks": GitleaksEngine,
    "osv-scanner": OSVEngine,
    "checkov": CheckovEngine,
    "opengrep": OpengrepEngine,
}


def scan(target: Path, engines: list[str] | None = None, triager: Triager | None = None) -> ScanResult:
    target = target.resolve()
    result = ScanResult(target=str(target))
    ai_engine: AISecurityEngine | None = None

    for name in engines or list(ALL_ENGINES):
        engine: Engine = ALL_ENGINES[name]()
        if not engine.available():
            result.engines.append(EngineRun(engine=name, status="skipped", detail="no instalado"))
            continue
        try:
            found = engine.run(target)
        except (EngineError, OSError) as e:
            result.engines.append(EngineRun(engine=name, status="error", detail=str(e)[:300]))
            continue
        result.findings += found
        result.engines.append(EngineRun(engine=name, status="ok", findings=len(found)))
        if isinstance(engine, AISecurityEngine):
            ai_engine = engine

    result.findings, result.suppressed_inline = apply_inline_suppressions(target, dedupe(result.findings))
    if ai_engine:
        result.ai_inventory = ai_engine.inventory

    if triager:
        apply_triage(target, result, triager)

    result.findings.sort(key=lambda f: (-f.effective_severity.rank, f.file, f.line))
    return result


def apply_triage(target: Path, result: ScanResult, triager: Triager):
    """Triage y resumen ejecutivo. Los errores del LLM quedan como avisos, nunca abortan el escaneo."""
    triager.triage(target, result.findings)
    result.ai_summary = triager.summarize(result.ai_inventory, result.findings)
    result.llm_usage = dict(triager.usage)
    for w in triager.warnings:
        result.engines.append(EngineRun(engine="triage", status="error", detail=w))


SUPPRESSION = re.compile(r"(?i)(\bnosec\b|\bnosemgrep\b|appsec-ai:\s*ignore)")


def apply_inline_suppressions(target: Path, findings: list[Finding]) -> tuple[list[Finding], int]:
    """Descarta hallazgos marcados en el código con `nosec`, `nosemgrep` o `appsec-ai: ignore`
    en la propia línea o en la anterior."""
    cache: dict[str, list[str]] = {}
    kept, dropped = [], 0
    for f in findings:
        if f.line and f.file:
            if f.file not in cache:
                try:
                    cache[f.file] = (target / f.file).read_text(errors="replace").splitlines()
                except OSError:
                    cache[f.file] = []
            lines = cache[f.file]
            window = lines[max(0, f.line - 2): min(len(lines), (f.end_line or f.line))]
            if any(SUPPRESSION.search(l) for l in window):
                dropped += 1
                continue
        kept.append(f)
    return kept, dropped


# CWE distintos que describen el mismo problema a efectos de fusionar hallazgos.
CWE_FAMILY = {"CWE-77": "exec", "CWE-78": "exec", "CWE-94": "exec", "CWE-95": "exec"}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Elimina duplicados exactos y fusiona el mismo problema detectado por varios motores.

    Dos hallazgos son el mismo problema si están en la misma línea y comparten CWE. Se conserva
    el del motor de IA (tiene más contexto) o, si no, el más grave; el otro queda como referencia.
    """
    seen: set[str] = set()
    unique = []
    for f in findings:
        key = f"{f.fingerprint}|{f.line}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    def cwes(f: Finding) -> set[str]:
        return {CWE_FAMILY.get(x, x) for x in f.frameworks if x.startswith("CWE-")}

    def priority(f: Finding) -> tuple[int, int]:
        # El hallazgo de IA es el más específico (dice que el origen es el modelo), venga del motor que venga.
        return (1 if f.category == Category.AI else 0, f.severity.rank)

    out: list[Finding] = []
    for f in sorted(unique, key=priority, reverse=True):
        twin = next((o for o in out if f.line and o.file == f.file and o.line == f.line and cwes(o) & cwes(f)), None)
        if twin is None:
            out.append(f)
        else:
            twin.frameworks.append(f"{f.engine}:{f.rule_id}")
    return out

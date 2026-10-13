from __future__ import annotations

from pathlib import Path

from appsec_ai.engines.ai_security import AISecurityEngine
from appsec_ai.engines.base import Engine, EngineError
from appsec_ai.engines.opensource import CheckovEngine, GitleaksEngine, OpengrepEngine, OSVEngine
from appsec_ai.models import EngineRun, Finding, ScanResult
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

    result.findings = dedupe(result.findings)
    if ai_engine:
        result.ai_inventory = ai_engine.inventory

    if triager:
        warnings = triager.triage(target, result.findings)
        result.ai_summary = triager.summarize(result.ai_inventory, result.findings)
        result.llm_usage = dict(triager.usage)
        for w in warnings:
            result.engines.append(EngineRun(engine="triage", status="error", detail=w))

    result.findings.sort(key=lambda f: (-f.effective_severity.rank, f.file, f.line))
    return result


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out = []
    for f in findings:
        key = f"{f.fingerprint}|{f.line}"
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

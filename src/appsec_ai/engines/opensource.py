"""Adaptadores para motores open source con licencia compatible con SaaS.

- Gitleaks (MIT): secretos
- OSV-Scanner (Apache 2.0): dependencias vulnerables
- Checkov (Apache 2.0): infraestructura como código
- Opengrep (LGPL 2.1): SAST genérico. Solo se usan reglas propias, nunca las del
  registro de Semgrep (su licencia prohíbe ofrecerlas en un SaaS).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from appsec_ai.engines.base import Engine, read_lines, relpath, run_json
from appsec_ai.models import Category, Finding, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class GitleaksEngine(Engine):
    name = "gitleaks"
    binary = "gitleaks"

    def run(self, target: Path) -> list[Finding]:
        fd, report = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            run_json(
                [self.find_binary(), "dir", str(target), "--report-format", "json",
                 "--report-path", report, "--no-banner", "--exit-code", "0", "--redact"],
                ok_codes=(0,),
            )
            import json

            data = json.loads(Path(report).read_text() or "[]")
        finally:
            os.unlink(report)
        findings = []
        for leak in data or []:
            rel = relpath(target, leak.get("File", ""))
            findings.append(Finding(
                engine=self.name,
                rule_id=leak.get("RuleID", "secret"),
                category=Category.SECRETS,
                severity=Severity.HIGH,
                title=f"Secreto expuesto: {leak.get('RuleID', '')}",
                message=leak.get("Description", ""),
                file=rel,
                line=leak.get("StartLine", 0),
                end_line=leak.get("EndLine", 0),
                # El valor ya viene redactado: nunca guardamos el secreto.
                snippet=leak.get("Match", ""),
                frameworks=["CWE-798"],
            ))
        return findings


class OSVEngine(Engine):
    name = "osv-scanner"
    binary = "osv-scanner"

    def run(self, target: Path) -> list[Finding]:
        # 0 = sin vulnerabilidades, 1 = hay vulnerabilidades, 128 = no hay ficheros de dependencias.
        data = run_json(
            [self.find_binary(), "scan", "source", "-r", "--format", "json", str(target)],
            ok_codes=(0, 1, 128),
        )
        findings = []
        for result in (data or {}).get("results", []) or []:
            source = relpath(target, result.get("source", {}).get("path", ""))
            for pkg in result.get("packages", []) or []:
                info = pkg.get("package", {})
                vulns = {v["id"]: v for v in pkg.get("vulnerabilities", []) or []}
                # Un "group" agrupa los alias de la misma vulnerabilidad (GHSA, PYSEC, CVE...).
                for group in pkg.get("groups", []) or [{"ids": [i]} for i in vulns]:
                    ids = group.get("ids", [])
                    vuln = next((vulns[i] for i in ids if i in vulns), {})
                    aliases = sorted(set(group.get("aliases", []) or ids))
                    cve = next((a for a in aliases if a.startswith("CVE-")), ids[0] if ids else "")
                    findings.append(Finding(
                        engine=self.name,
                        rule_id=cve,
                        category=Category.SCA,
                        severity=_cvss_to_severity(group.get("max_severity"), vuln),
                        title=f"{info.get('name')} {info.get('version')}: {vuln.get('summary') or cve}",
                        message=(vuln.get("details") or "")[:1500],
                        file=source,
                        snippet=f"{info.get('name')}=={info.get('version')} ({info.get('ecosystem')})",
                        references=[f"https://osv.dev/vulnerability/{i}" for i in ids[:3]],
                        frameworks=aliases + (vuln.get("database_specific", {}) or {}).get("cwe_ids", []),
                    ))
        return findings


def _cvss_to_severity(score: str | None, vuln: dict) -> Severity:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.parse((vuln.get("database_specific", {}) or {}).get("severity"))
    if s >= 9:
        return Severity.CRITICAL
    if s >= 7:
        return Severity.HIGH
    if s >= 4:
        return Severity.MEDIUM
    return Severity.LOW


class CheckovEngine(Engine):
    name = "checkov"
    binary = "checkov"

    def run(self, target: Path) -> list[Finding]:
        data = run_json(
            [self.find_binary(), "-d", str(target), "-o", "json", "--quiet", "--compact",
             "--skip-download", "--framework",
             "terraform,kubernetes,dockerfile,cloudformation,helm,github_actions,arm,bicep"],
            ok_codes=(0, 1),
        )
        reports = data if isinstance(data, list) else [data] if data else []
        findings = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            for chk in report.get("results", {}).get("failed_checks", []) or []:
                rel = chk.get("file_path", "").lstrip("/")
                start, end = (chk.get("file_line_range") or [0, 0])[:2]
                findings.append(Finding(
                    engine=self.name,
                    rule_id=chk.get("check_id", ""),
                    category=Category.IAC,
                    # Checkov sin cuenta de Prisma no da severidad: la decide el triage con IA.
                    severity=Severity.parse(chk.get("severity")),
                    title=chk.get("check_name", ""),
                    message=f"Recurso: {chk.get('resource', '')}",
                    file=rel,
                    line=start,
                    end_line=end,
                    snippet=read_lines(target, rel, start, end),
                    references=[chk["guideline"]] if chk.get("guideline") else [],
                ))
        return findings


class OpengrepEngine(Engine):
    """SAST con Opengrep (o Semgrep CE como alternativa) usando SOLO reglas propias."""

    name = "opengrep"

    def find_binary(self) -> str | None:
        import shutil

        return shutil.which("opengrep") or shutil.which("semgrep")

    def available(self) -> bool:
        return self.find_binary() is not None and (RULES_DIR / "sast").exists()

    def run(self, target: Path) -> list[Finding]:
        data = run_json(
            [self.find_binary(), "scan", "--json", "--quiet", "--metrics=off",
             "--config", str(RULES_DIR / "sast"), str(target)],
            ok_codes=(0, 1),
        )
        findings = []
        for r in (data or {}).get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            rel = relpath(target, r.get("path", ""))
            start, end = r.get("start", {}).get("line", 0), r.get("end", {}).get("line", 0)
            findings.append(Finding(
                engine=self.name,
                rule_id=r.get("check_id", "").split(".")[-1],
                category=Category.SAST,
                severity=Severity.parse(meta.get("severity") or extra.get("severity")),
                title=meta.get("title") or extra.get("message", "")[:120],
                message=extra.get("message", ""),
                file=rel,
                line=start,
                end_line=end,
                snippet=read_lines(target, rel, start, end),
                frameworks=[c.split(":")[0] for c in _as_list(meta.get("cwe"))],
                references=_as_list(meta.get("references")),
            ))
        return findings


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]

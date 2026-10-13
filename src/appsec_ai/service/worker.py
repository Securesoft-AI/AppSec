"""Worker: toma escaneos de la cola, clona el commit, lo analiza y publica el resultado en GitHub."""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path

from appsec_ai.models import Finding, ScanResult
from appsec_ai.scanner import scan as run_scan
from appsec_ai.service import render
from appsec_ai.service.config import Settings
from appsec_ai.service.db import Database, Repository, Scan, ScanKind, ScanStatus, utcnow
from appsec_ai.service.github import GitHubApp

log = logging.getLogger("appsec_ai.worker")
MAX_ATTEMPTS = 3


def dir_size_mb(path: Path) -> float:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()) / 1_048_576


def filter_to_files(result: ScanResult, files: set[str]) -> ScanResult:
    """En un PR solo interesan los hallazgos de los ficheros modificados."""
    kept: list[Finding] = [f for f in result.findings if f.file in files]
    return result.model_copy(update={"findings": kept})


class Worker:
    def __init__(self, settings: Settings, db: Database, github: GitHubApp, scanner=run_scan, triager_factory=None):
        self.settings = settings
        self.db = db
        self.github = github
        self.scanner = scanner
        self.triager_factory = triager_factory or self._default_triager

    def _default_triager(self, max_requests: int):
        if not self.settings.ai_triage:
            return None
        from appsec_ai.triage import Triager

        return Triager(model=self.settings.ai_model, effort=self.settings.ai_effort,
                       language=self.settings.language, max_requests=max_requests)

    def run_forever(self, poll_seconds: float = 2.0):
        log.info("worker iniciado")
        while True:
            if not self.run_once():
                time.sleep(poll_seconds)

    def run_once(self) -> bool:
        scan = self.db.claim_next_scan()
        if scan is None:
            return False
        try:
            self.process(scan.id)
        except Exception as e:  # noqa: BLE001 - un fallo de un escaneo no debe tumbar el worker
            log.exception("escaneo %s falló", scan.id)
            self._fail(scan.id, e)
        return True

    def process(self, scan_id: int):
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            repo = s.get(Repository, scan.repository_id)
            repo_name, installation_id = repo.full_name, repo.installation_id
            kind, sha, pr_number, check_id = scan.kind, scan.head_sha, scan.pr_number, scan.check_run_id

        gh = self.github.installation(installation_id)
        if not check_id:  # en un reintento se reutiliza el check ya creado
            check_id = gh.create_check_run(repo_name, sha, render.CHECK_NAME)
            self._update(scan_id, check_run_id=check_id)

        workdir = Path(tempfile.mkdtemp(prefix="appsec-ai-", dir=self.settings.workdir or None))
        try:
            src = workdir / "src"
            gh.clone(repo_name, sha, src, timeout=self.settings.clone_timeout)
            shutil.rmtree(src / ".git", ignore_errors=True)
            size = dir_size_mb(src)
            if size > self.settings.max_repo_mb:
                raise RuntimeError(f"el repositorio ocupa {size:.0f} MB (máximo {self.settings.max_repo_mb} MB)")

            if kind == ScanKind.PULL_REQUEST.value:
                changed = set(gh.pull_request_files(repo_name, pr_number))
                max_req = self.settings.ai_max_requests_pr
            else:
                changed = None
                max_req = self.settings.ai_max_requests_full

            # El triage con IA solo se aplica a lo que se va a mostrar: primero se escanea sin IA,
            # se filtra por ficheros del PR y después se analiza con IA lo que queda.
            result = self.scanner(src)
            if changed is not None:
                result = filter_to_files(result, changed)
            triager = self.triager_factory(max_req)
            if triager is not None and result.findings:
                triager.triage(src, result.findings)
                result.ai_summary = triager.summarize(result.ai_inventory, result.findings)
                result.llm_usage = dict(triager.usage)
            result.target = repo_name
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        findings = render.visible(result)
        scope = ("Solo se muestran los hallazgos de los ficheros modificados en este PR."
                 if changed is not None else "Escaneo completo de la rama por defecto.")
        title, summary, text = render.check_output(result, scope)
        conclusion = render.conclusion(findings, self.settings.fail_on)
        gh.complete_check_run(repo_name, check_id, conclusion, title, summary, text, render.annotations(findings))
        if pr_number:
            gh.upsert_comment(repo_name, pr_number, render.pr_comment(result), render.COMMENT_MARKER)

        self._update(
            scan_id, status=ScanStatus.COMPLETED.value, finished_at=utcnow(), error="",
            result=result.model_dump(mode="json"),
            summary={"counts": render.counts(findings), "total": len(findings), "conclusion": conclusion,
                     "llm_usage": result.llm_usage, "files_in_scope": len(changed) if changed is not None else None},
        )

    def _update(self, scan_id: int, **values):
        with self.db.session() as s, s.begin():
            scan = s.get(Scan, scan_id)
            for k, v in values.items():
                setattr(scan, k, v)

    def _fail(self, scan_id: int, error: Exception):
        with self.db.session() as s, s.begin():
            scan = s.get(Scan, scan_id)
            retry = scan.attempts < MAX_ATTEMPTS
            scan.status = ScanStatus.QUEUED.value if retry else ScanStatus.FAILED.value
            scan.error = str(error)[:2000]
            scan.finished_at = None if retry else utcnow()
            repo = s.get(Repository, scan.repository_id)
            repo_name, installation_id, check_id = repo.full_name, repo.installation_id, scan.check_run_id
        if not retry and check_id:
            try:
                self.github.installation(installation_id).complete_check_run(
                    repo_name, check_id, "neutral", "No se pudo completar el escaneo",
                    "Ha ocurrido un error interno al analizar este commit. Lo estamos revisando.")
            except Exception:  # noqa: BLE001
                log.exception("no se pudo cerrar el check %s", check_id)

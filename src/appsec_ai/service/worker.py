"""Worker: toma escaneos de la cola, clona el commit, lo analiza y publica el resultado en GitHub."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from pathlib import Path

from appsec_ai.fixes import FileFix, FixError, files_to_fix
from appsec_ai.models import Finding, ScanResult
from appsec_ai.scanner import apply_triage
from appsec_ai.scanner import scan as run_scan
from appsec_ai.service import render
from appsec_ai.service.config import Settings
from appsec_ai.service.crypto import seal, unseal
from appsec_ai.service.db import Database, FixRequest, Repository, Scan, ScanKind, ScanStatus, utcnow
from appsec_ai.service.github import GitHubApp, GitHubError
from appsec_ai.service.sandbox import sandboxed_scan

log = logging.getLogger("appsec_ai.worker")
MAX_ATTEMPTS = 3


def dir_size_mb(path: Path) -> float:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()) / 1_048_576


def filter_to_files(result: ScanResult, files: set[str]) -> ScanResult:
    """En un PR solo interesan los hallazgos de los ficheros modificados."""
    kept: list[Finding] = [f for f in result.findings if f.file in files]
    return result.model_copy(update={"findings": kept})


class Worker:
    def __init__(self, settings: Settings, db: Database, github: GitHubApp, scanner=None, triager_factory=None):
        self.settings = settings
        self.db = db
        self.github = github
        self.scanner = scanner or self._default_scanner
        self.triager_factory = triager_factory or self._default_triager

    def _default_scanner(self, src: Path) -> ScanResult:
        if self.settings.scan_sandbox == "none":
            return run_scan(src)
        return sandboxed_scan(src, self.settings.scan_sandbox_cmd, timeout=self.settings.scan_timeout)

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
        if scan is not None:
            try:
                self.process(scan.id)
            except Exception as e:  # noqa: BLE001 - un fallo de un escaneo no debe tumbar el worker
                log.exception("escaneo %s falló", scan.id)
                self._fail(scan.id, e)
            return True
        fix = self.db.claim_next_fix()
        if fix is not None:
            try:
                self.process_fix(fix.id)
            except Exception as e:  # noqa: BLE001
                log.exception("corrección %s falló", fix.id)
                self._fail_fix(fix.id, e)
            return True
        return False

    def process(self, scan_id: int):
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            repo = s.get(Repository, scan.repository_id)
            repo_id, repo_name, installation_id = repo.id, repo.full_name, repo.installation_id
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
            ai_enabled = triager is not None
            if triager is not None and result.findings:
                if self.settings.ai_cache_dir:
                    # Por repositorio: el triage contiene fragmentos del código del cliente.
                    triager.cache_dir = Path(self.settings.ai_cache_dir) / str(repo_id)
                    triager.cipher = self.db.cipher
                apply_triage(src, result, triager)
            result.target = repo_name
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        findings = render.visible(result)
        scope = ("Solo se muestran los hallazgos de los ficheros modificados en este PR."
                 if changed is not None else "Escaneo completo de la rama por defecto.")
        title, summary, text = render.check_output(result, scope)
        conclusion = render.conclusion(findings, self.settings.fail_on)
        gh.complete_check_run(repo_name, check_id, conclusion, title, summary, text, render.annotations(findings),
                              actions=render.fix_actions(result) if ai_enabled else None)
        if pr_number:
            gh.upsert_comment(repo_name, pr_number, render.pr_comment(result), render.COMMENT_MARKER)

        self._update(
            scan_id, status=ScanStatus.COMPLETED.value, finished_at=utcnow(), error="",
            result=seal(self.db.cipher, result.model_dump(mode="json")),
            summary={"counts": render.counts(findings), "total": len(findings), "conclusion": conclusion,
                     "llm_usage": result.llm_usage, "files_in_scope": len(changed) if changed is not None else None},
        )

    # -- correcciones ("Abrir PR con fixes") ----------------------------------------------------

    def process_fix(self, fix_id: int):
        with self.db.session() as s:
            fix = s.get(FixRequest, fix_id)
            scan = s.get(Scan, fix.scan_id)
            repo = s.get(Repository, scan.repository_id)
            repo_name, installation_id, attempt = repo.full_name, repo.installation_id, fix.attempts
            sha, pr_number = scan.head_sha, scan.pr_number
            base_branch = scan.ref.removeprefix("refs/heads/") if scan.kind == ScanKind.PULL_REQUEST.value \
                else repo.default_branch
            raw = unseal(self.db.cipher, scan.result)
            result = ScanResult.model_validate(raw) if raw else None

        targets = files_to_fix(render.visible(result)) if result else {}
        if not targets:
            return self._finish_fix(fix_id, "No hay problemas confirmados por la IA que corregir.")
        triager = self.triager_factory(len(targets))
        if triager is None:
            return self._finish_fix(fix_id, "El triage con IA está desactivado en este servicio.")

        gh = self.github.installation(installation_id)
        workdir = Path(tempfile.mkdtemp(prefix="appsec-ai-fix-", dir=self.settings.workdir or None))
        fixes: list[FileFix] = []
        skipped: dict[str, str] = {}
        try:
            src = workdir / "src"
            gh.clone(repo_name, sha, src, timeout=self.settings.clone_timeout)
            for rel, findings in targets.items():
                try:
                    fixes.append(triager.propose_fix(src, rel, findings))
                except FixError as e:
                    skipped[rel] = str(e)[:300]
            modes = {fx.path: "100755" if os.access(src / fx.path, os.X_OK) else "100644" for fx in fixes}
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        detail = {"fixed": [fx.path for fx in fixes], "skipped": skipped, "llm_usage": dict(triager.usage)}
        if not fixes:
            if pr_number:
                gh.upsert_comment(repo_name, pr_number, render.fix_failed_comment(skipped), render.FIX_MARKER)
            return self._finish_fix(fix_id, "No se ha podido generar ninguna corrección segura.", detail)

        source = f"el PR #{pr_number}" if pr_number else f"el commit {sha[:7]}"
        try:
            pr = gh.open_fix_pr(
                repo_name, sha, base_branch, f"appsec-ai/fix-{sha[:7]}-{fix_id}-{attempt}",
                [(fx.path, fx.fixed, modes[fx.path]) for fx in fixes],
                render.fix_pr_title(fixes), render.fix_pr_body(fixes, skipped, source),
                message=render.fix_pr_title(fixes))
        except GitHubError as e:
            if " -> 403" in str(e) or " -> 404" in str(e):
                # Sin permiso de escritura en contents: reintentar no sirve.
                if pr_number:
                    gh.upsert_comment(repo_name, pr_number, render.FIX_PERMISSION_COMMENT, render.FIX_MARKER)
                return self._finish_fix(fix_id, f"Sin permiso para crear la rama o el PR: {e}", detail)
            if " -> 422" in str(e):
                # Rama base inexistente (PR desde un fork) o PR ya abierto: tampoco se arregla reintentando.
                return self._finish_fix(fix_id, f"GitHub rechazó la rama o el PR: {e}", detail)
            raise
        # Primero se guarda el PR: si después falla el comentario, un reintento no abriría otro PR.
        with self.db.session() as s, s.begin():
            row = s.get(FixRequest, fix_id)
            row.status, row.finished_at, row.error = ScanStatus.COMPLETED.value, utcnow(), ""
            row.pr_url, row.detail = pr["url"], seal(self.db.cipher, detail)
        if pr_number:
            try:
                gh.upsert_comment(repo_name, pr_number, render.fix_comment(pr["url"], len(fixes)), render.FIX_MARKER)
            except GitHubError:
                log.exception("no se pudo comentar el PR de corrección %s", pr["url"])

    def _finish_fix(self, fix_id: int, error: str, detail: dict | None = None):
        """Fin sin PR: un motivo definitivo, no un error transitorio que merezca reintento."""
        with self.db.session() as s, s.begin():
            row = s.get(FixRequest, fix_id)
            row.status, row.finished_at, row.error = ScanStatus.FAILED.value, utcnow(), error[:2000]
            row.detail = seal(self.db.cipher, detail or {})

    def _fail_fix(self, fix_id: int, error: Exception):
        with self.db.session() as s, s.begin():
            row = s.get(FixRequest, fix_id)
            retry = row.attempts < MAX_ATTEMPTS
            row.status = ScanStatus.QUEUED.value if retry else ScanStatus.FAILED.value
            row.error = str(error)[:2000]
            row.finished_at = None if retry else utcnow()

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

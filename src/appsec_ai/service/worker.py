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
from appsec_ai.service import plans
from appsec_ai.services import categories_for, engines_for
from appsec_ai.service.config import Settings
from appsec_ai.service.crypto import seal, unseal
from appsec_ai.i18n import norm, ui
from appsec_ai.service.db import Database, FixRequest, Installation, Repository, Scan, ScanKind, ScanStatus, utcnow
from appsec_ai.service.github import GitHubApp, GitHubError
from appsec_ai.service.sandbox import runner_scan, sandboxed_scan
from appsec_ai.service import integrations, notify

log = logging.getLogger("appsec_ai.worker")
MAX_ATTEMPTS = 3
MAX_INCREMENTAL_FILES = 3000  # límite de la API de GitHub para los ficheros de un PR


def dir_size_mb(path: Path) -> float:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()) / 1_048_576


def filter_to_categories(result: ScanResult, categories: set[str]) -> ScanResult:
    """Solo los hallazgos de los servicios elegidos (un motor puede servir a varios, como Opengrep)."""
    kept = [f for f in result.findings if f.category.value in categories]
    inventory = result.ai_inventory if "ai" in categories else []
    return result.model_copy(update={"findings": kept, "ai_inventory": inventory})


def filter_to_files(result: ScanResult, files: set[str]) -> ScanResult:
    """En un PR solo interesan los hallazgos de los ficheros modificados."""
    kept: list[Finding] = [f for f in result.findings if f.file in files]
    return result.model_copy(update={"findings": kept})


class Worker:
    def __init__(self, settings: Settings, db: Database, github: GitHubApp, scanner=None, triager_factory=None,
                 notifier=None):
        self.settings = settings
        self.db = db
        self.github = github
        self.scanner = scanner or self._default_scanner
        self.triager_factory = triager_factory or self._default_triager
        self.notifier = notifier if notifier is not None else notify.Slack()

    def _default_scanner(self, src: Path, only_files: set[str] | None = None,
                         engines: list[str] | None = None) -> ScanResult:
        if self.settings.scan_runner:  # un contenedor efímero por escaneo (RF-4.4)
            return runner_scan(src, self.settings.scan_runner, timeout=self.settings.scan_timeout,
                               only_files=only_files, engines=engines)
        if self.settings.scan_sandbox == "none":
            return run_scan(src, engines=engines, only_files=only_files)
        return sandboxed_scan(src, self.settings.scan_sandbox_cmd, timeout=self.settings.scan_timeout,
                              only_files=only_files, engines=engines)

    def _language(self, s, installation_id: int) -> str:
        inst = s.get(Installation, installation_id)
        return norm((inst.language if inst else "") or self.settings.language)

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
        run = self.db.claim_next_redteam()
        if run is not None:
            try:
                self.process_redteam(run.id)
            except Exception as e:  # noqa: BLE001
                log.exception("red team %s falló", run.id)
                self._fail_redteam(run.id, e)
            return True
        return False

    def process(self, scan_id: int):
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            repo = s.get(Repository, scan.repository_id)
            repo_id, repo_name, installation_id = repo.id, repo.full_name, repo.installation_id
            kind, sha, pr_number, check_id = scan.kind, scan.head_sha, scan.pr_number, scan.check_run_id
            lang = self._language(s, installation_id)
            inst = s.get(Installation, installation_id)
            plan = plans.effective_plan(inst)
            ai_left = plans.ai_requests_left(inst, plan)
            # Servicios de este escaneo: los pedidos (o los elegidos para el repositorio) que estén contratados.
            selected = plans.scan_services(plan, scan.services or repo.services)

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
                changed = set(gh.pull_request_files(repo_name, pr_number, limit=MAX_INCREMENTAL_FILES))
                max_req = self.settings.ai_max_requests_pr
            else:
                changed = None
                max_req = self.settings.ai_max_requests_full

            # El triage con IA solo se aplica a lo que se va a mostrar: primero se escanea sin IA,
            # se filtra por ficheros del PR y después se analiza con IA lo que queda.
            # RF-1.8: en un PR los motores solo analizan los ficheros cambiados. Un PR enorme (la API de
            # GitHub no lista más de 3000 ficheros) se escanea entero y se filtra después.
            incremental = changed is not None and len(changed) < MAX_INCREMENTAL_FILES
            result = self.scanner(src, only_files=changed if incremental else None, engines=engines_for(selected))
            result = filter_to_categories(result, categories_for(selected))
            if changed is not None:
                result = filter_to_files(result, changed)
            # El plan decide si hay triage con IA y cuántas peticiones quedan este mes.
            triager = self.triager_factory(min(max_req, ai_left)) if ai_left > 0 else None
            ai_enabled = triager is not None
            if triager is not None:
                triager.language = lang
            if triager is not None and result.findings:
                if self.settings.ai_cache_dir:
                    # Por repositorio: el triage contiene fragmentos del código del cliente.
                    triager.cache_dir = Path(self.settings.ai_cache_dir) / str(repo_id)
                    triager.cipher = self.db.cipher
                apply_triage(src, result, triager)
                self._record_ai_usage(installation_id, triager.requests)
            result.target = repo_name
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        findings = render.visible(result)
        title, summary, text = render.check_output(result, full_scan=changed is None, lang=lang)
        conclusion = render.conclusion(findings, self.settings.fail_on)
        gh.complete_check_run(repo_name, check_id, conclusion, title, summary, text, render.annotations(findings, lang),
                              actions=render.fix_actions(result, lang) if ai_enabled and plan.fix_pr else None)
        if pr_number:
            gh.upsert_comment(repo_name, pr_number, render.pr_comment(result, lang=lang), render.COMMENT_MARKER)

        counts = render.counts(findings)
        self._update(
            scan_id, status=ScanStatus.COMPLETED.value, finished_at=utcnow(), error="",
            result=seal(self.db.cipher, result.model_dump(mode="json")),
            summary={"counts": counts, "total": len(findings), "conclusion": conclusion,
                     "llm_usage": result.llm_usage, "files_in_scope": len(changed) if changed is not None else None},
        )
        # Solo la rama principal y solo si hay algo grave: aviso a Slack y envío automático a Jira/GitLab.
        if kind in (ScanKind.FULL.value, ScanKind.MANUAL.value) and (counts.get("critical") or counts.get("high")):
            self._notify_slack(installation_id, lang, *notify.scan_message(
                repo_name, kind, counts, len(findings), lang, self._panel_url(installation_id)))
            self._auto_export(installation_id, [f.model_dump(mode="json") for f in findings], repo_name, lang)

    def _auto_export(self, installation_id: int, findings: list[dict], repo_name: str, lang: str):
        with self.db.session() as s:
            inst = s.get(Installation, installation_id)
            configs = {p: (unseal(self.db.cipher, getattr(inst, f"{p}_config")) or {}) for p in integrations.PROVIDERS}
        created = integrations.auto_export(self.db, self.db.cipher, installation_id, configs, findings, repo_name, lang)
        for provider, n in created.items():
            self.db.audit(installation_id, "system", f"{provider}.issue_created", "auto", {"count": n})

    def _panel_url(self, installation_id: int) -> str:
        base = (self.settings.public_url or "").rstrip("/")
        return f"{base}/app" if base else ""

    def _notify_slack(self, installation_id: int, lang: str, text: str, blocks: list):
        with self.db.session() as s:
            inst = s.get(Installation, installation_id)
            webhook = (unseal(self.db.cipher, inst.slack_webhook) or {}).get("url", "") if inst else ""
        if webhook:
            self.notifier.post(webhook, text, blocks)

    # -- correcciones ("Abrir PR con fixes") ----------------------------------------------------

    def process_fix(self, fix_id: int):
        with self.db.session() as s:
            fix = s.get(FixRequest, fix_id)
            scan = s.get(Scan, fix.scan_id)
            repo = s.get(Repository, scan.repository_id)
            repo_name, installation_id, attempt = repo.full_name, repo.installation_id, fix.attempts
            lang = self._language(s, installation_id)
            inst = s.get(Installation, installation_id)
            plan = plans.effective_plan(inst)
            ai_left = plans.ai_requests_left(inst, plan)
            sha, pr_number = scan.head_sha, scan.pr_number
            base_branch = scan.ref.removeprefix("refs/heads/") if scan.kind == ScanKind.PULL_REQUEST.value \
                else repo.default_branch
            raw = unseal(self.db.cipher, scan.result)
            result = ScanResult.model_validate(raw) if raw else None

        if not plan.fix_pr:
            return self._finish_fix(fix_id, f"El plan {plan.name} no incluye PRs con correcciones.")
        targets = files_to_fix(render.visible(result)) if result else {}
        if not targets:
            return self._finish_fix(fix_id, "No hay problemas confirmados por la IA que corregir.")
        if ai_left < len(targets):
            return self._finish_fix(fix_id, "Se ha agotado el presupuesto mensual de IA del plan.")
        triager = self.triager_factory(len(targets))
        if triager is None:
            return self._finish_fix(fix_id, "El triage con IA está desactivado en este servicio.")
        triager.language = lang

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

        self._record_ai_usage(installation_id, triager.requests)
        detail = {"fixed": [fx.path for fx in fixes], "skipped": skipped, "llm_usage": dict(triager.usage)}
        if not fixes:
            if pr_number:
                gh.upsert_comment(repo_name, pr_number, render.fix_failed_comment(skipped, lang), render.FIX_MARKER)
            return self._finish_fix(fix_id, "No se ha podido generar ninguna corrección segura.", detail)

        source = render.fix_source(pr_number, sha, lang)
        try:
            pr = gh.open_fix_pr(
                repo_name, sha, base_branch, f"appsec-ai/fix-{sha[:7]}-{fix_id}-{attempt}",
                [(fx.path, fx.fixed, modes[fx.path]) for fx in fixes],
                render.fix_pr_title(fixes, lang), render.fix_pr_body(fixes, skipped, source, lang),
                message=render.fix_pr_title(fixes, lang))
        except GitHubError as e:
            if " -> 403" in str(e) or " -> 404" in str(e):
                # Sin permiso de escritura en contents: reintentar no sirve.
                if pr_number:
                    gh.upsert_comment(repo_name, pr_number, render.fix_permission_comment(lang), render.FIX_MARKER)
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
                gh.upsert_comment(repo_name, pr_number, render.fix_comment(pr["url"], len(fixes), lang), render.FIX_MARKER)
            except GitHubError:
                log.exception("no se pudo comentar el PR de corrección %s", pr["url"])

    def process_redteam(self, run_id: int):
        """Lanza las sondas de red teaming contra el endpoint ya verificado del cliente (RF-2.7)."""
        from appsec_ai import redteam
        from appsec_ai.egress import safe_transport
        from appsec_ai.service.db import RedTeamRun, RedTeamTarget

        with self.db.session() as s:
            run = s.get(RedTeamRun, run_id)
            installation_id = run.installation_id
            tgt = s.get(RedTeamTarget, run.target_id)
            if tgt is None:
                return self._finish_redteam(run_id, summary={}, result=None, error="el objetivo ya no existe")
            if not tgt.verified_method:  # pudo perder la verificación entre encolar y ejecutar
                return self._finish_redteam(run_id, summary={}, result=None,
                                            error="el objetivo no está verificado")
            target = redteam.Target(url=tgt.url, method=tgt.method, headers=unseal(self.db.cipher, tgt.headers) or {},
                                    body_template=tgt.body_template, response_path=tgt.response_path,
                                    timeout=self.settings.redteam_timeout)
        results = redteam.run_redteam(target, transport=safe_transport())
        summary = redteam.summarize(results)
        payload = {"probes": [vars(r) for r in results], "target": {"url": tgt.url, "host": tgt.host}}
        self._finish_redteam(run_id, summary=summary, result=payload)
        if summary.get("vulnerable"):
            lang = norm(self.settings.language)
            self._notify_slack(installation_id, lang, *notify.redteam_message(
                tgt.host, summary["vulnerable"], summary["probes"], lang, self._panel_url(installation_id)))

    def _finish_redteam(self, run_id: int, summary: dict, result, error: str = ""):
        from appsec_ai.service.db import RedTeamRun

        with self.db.session() as s, s.begin():
            run = s.get(RedTeamRun, run_id)
            run.status = ScanStatus.FAILED.value if error else ScanStatus.COMPLETED.value
            run.summary, run.error, run.finished_at = summary, error[:2000], utcnow()
            run.result = seal(self.db.cipher, result) if result else None

    def _fail_redteam(self, run_id: int, error: Exception):
        from appsec_ai.service.db import RedTeamRun

        with self.db.session() as s, s.begin():
            run = s.get(RedTeamRun, run_id)
            retry = run.attempts < MAX_ATTEMPTS
            run.status = ScanStatus.QUEUED.value if retry else ScanStatus.FAILED.value
            run.error = str(error)[:2000]
            run.finished_at = None if retry else utcnow()

    def _record_ai_usage(self, installation_id: int, requests: int):
        if requests:
            with self.db.session() as s, s.begin():
                plans.record_ai_usage(s.get(Installation, installation_id), requests)

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
            lang = self._language(s, installation_id)
        if not retry and check_id:
            try:
                self.github.installation(installation_id).complete_check_run(
                    repo_name, check_id, "neutral", ui(lang, "error_title"), ui(lang, "error_summary"))
            except Exception:  # noqa: BLE001
                log.exception("no se pudo cerrar el check %s", check_id)

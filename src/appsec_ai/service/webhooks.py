"""Procesado de webhooks de la GitHub App: instalaciones, PRs, pushes y reintentos de checks."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from appsec_ai.service import plans
from appsec_ai.service.db import FixRequest, Installation, Repository, Scan, ScanKind, ScanStatus, utcnow

log = logging.getLogger("appsec_ai.webhooks")

PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def verify_signature(secret: str, body: bytes, signature: str | None) -> bool:
    """Comprueba la cabecera X-Hub-Signature-256. Sin secreto configurado se rechaza todo."""
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_event(s: Session, event: str, payload: dict) -> dict:
    """Aplica un evento. Devuelve un resumen de lo hecho (útil para logs y tests)."""
    handler = HANDLERS.get(event)
    if handler is None:
        return {"ignored": event}
    return handler(s, payload)


# -- instalaciones ------------------------------------------------------------------------

def _upsert_installation(s: Session, inst: dict) -> Installation:
    account = inst.get("account") or {}
    row = s.get(Installation, inst["id"])
    if row is None:
        row = Installation(id=inst["id"], account_login=account.get("login", ""),
                           account_type=account.get("type", "Organization"),
                           trial_ends_at=utcnow() + dt.timedelta(days=plans.TRIAL_DAYS))
        s.add(row)
    row.active = True
    return row


def _upsert_repo(s: Session, installation_id: int, repo: dict) -> Repository:
    row = s.get(Repository, repo["id"])
    if row is None:
        row = Repository(id=repo["id"], installation_id=installation_id, full_name=repo["full_name"])
        s.add(row)
    row.installation_id = installation_id
    row.full_name = repo["full_name"]
    row.private = bool(repo.get("private", True))
    if repo.get("default_branch"):
        row.default_branch = repo["default_branch"]
    row.active = True
    return row


def on_installation(s: Session, p: dict) -> dict:
    action, inst = p.get("action"), p["installation"]
    if action == "created":
        _upsert_installation(s, inst)
        s.flush()
        for repo in p.get("repositories") or []:
            _upsert_repo(s, inst["id"], repo)
        return {"installation": inst["id"], "repositories": len(p.get("repositories") or [])}
    row = s.get(Installation, inst["id"])
    if row is not None:
        if action in ("deleted", "suspend"):
            row.active = False
        elif action == "unsuspend":
            row.active = True
    return {"installation": inst["id"], "action": action}


def on_installation_repositories(s: Session, p: dict) -> dict:
    inst_id = p["installation"]["id"]
    _upsert_installation(s, p["installation"])
    s.flush()
    for repo in p.get("repositories_added") or []:
        _upsert_repo(s, inst_id, repo)
    for repo in p.get("repositories_removed") or []:
        row = s.get(Repository, repo["id"])
        if row is not None:
            row.active = False
    return {"added": len(p.get("repositories_added") or []), "removed": len(p.get("repositories_removed") or [])}


# -- escaneos ---------------------------------------------------------------------------------

def plan_block(s: Session, repo: Repository, inst: Installation, kind: ScanKind) -> str | None:
    """Motivo por el que el plan no permite este escaneo, o None."""
    plan = plans.effective_plan(inst)
    active = list(s.scalars(select(Repository.id).where(Repository.installation_id == inst.id, Repository.active)))
    if not plans.repo_allowed(repo.id, active, plan):
        return f"plan {plan.name}: máximo {plan.max_repos} repositorios"
    if kind == ScanKind.PULL_REQUEST and not plan.pr_scans:
        return f"plan {plan.name}: sin escaneo en PRs"
    if kind in (ScanKind.FULL, ScanKind.MANUAL) and plan.min_days_between_full:
        since = utcnow() - dt.timedelta(days=plan.min_days_between_full)
        recent = s.scalars(select(Scan.id).where(Scan.repository_id == repo.id,
                                                 Scan.kind.in_([ScanKind.FULL.value, ScanKind.MANUAL.value]),
                                                 Scan.created_at >= since)).first()
        if recent is not None:
            return f"plan {plan.name}: un escaneo completo cada {plan.min_days_between_full} días"
    return None


def enqueue(s: Session, repo: Repository, kind: ScanKind, sha: str, ref: str = "", pr_number: int | None = None) -> Scan | None:
    """Encola un escaneo. Es idempotente: GitHub puede reenviar el mismo webhook."""
    inst = s.get(Installation, repo.installation_id)
    if not repo.active or inst is None or not inst.active:
        return None
    existing = s.scalars(select(Scan).where(Scan.repository_id == repo.id, Scan.head_sha == sha,
                                            Scan.kind == kind.value)).first()
    if existing is not None:
        if existing.status == ScanStatus.FAILED.value:
            existing.status, existing.attempts, existing.error = ScanStatus.QUEUED.value, 0, ""
        if pr_number and not existing.pr_number:
            existing.pr_number = pr_number
        return existing
    if plan_block(s, repo, inst, kind):
        return None
    scan = Scan(repository_id=repo.id, kind=kind.value, head_sha=sha, ref=ref, pr_number=pr_number)
    s.add(scan)
    s.flush()
    return scan


def on_pull_request(s: Session, p: dict) -> dict:
    if p.get("action") not in PR_ACTIONS:
        return {"ignored": f"pull_request.{p.get('action')}"}
    pr = p["pull_request"]
    if pr.get("draft"):
        return {"ignored": "draft"}
    repo = _upsert_repo(s, p["installation"]["id"], p["repository"])
    s.flush()
    scan = enqueue(s, repo, ScanKind.PULL_REQUEST, pr["head"]["sha"], pr["head"].get("ref", ""), pr["number"])
    return _enqueued(s, repo, scan, ScanKind.PULL_REQUEST)


def on_push(s: Session, p: dict) -> dict:
    repo = _upsert_repo(s, p["installation"]["id"], p["repository"])
    s.flush()
    if p.get("deleted") or p.get("ref") != f"refs/heads/{repo.default_branch}":
        return {"ignored": "rama distinta de la rama por defecto"}
    scan = enqueue(s, repo, ScanKind.FULL, p["after"], p["ref"])
    return _enqueued(s, repo, scan, ScanKind.FULL)


def _enqueued(s: Session, repo: Repository, scan: Scan | None, kind: ScanKind) -> dict:
    if scan is not None:
        return {"scan": scan.id}
    inst = s.get(Installation, repo.installation_id)
    reason = plan_block(s, repo, inst, kind) if inst is not None and inst.active and repo.active else None
    return {"scan": None, "ignored": reason} if reason else {"scan": None}


FIX_ACTION = "open_fix_pr"


def on_check_run(s: Session, p: dict) -> dict:
    """"Re-run" vuelve a encolar el escaneo; el botón "Abrir PR con fixes" encola una corrección."""
    action = p.get("action")
    if action not in ("rerequested", "requested_action"):
        return {"ignored": f"check_run.{action}"}
    scan = s.scalars(select(Scan).where(Scan.check_run_id == p["check_run"]["id"])).first()
    if scan is None:
        return {"ignored": "check desconocido"}
    # El check_run del webhook debe ser del mismo repositorio que el escaneo.
    if scan.repository_id != (p.get("repository") or {}).get("id"):
        return {"ignored": "repositorio distinto"}
    if action == "requested_action":
        if (p.get("requested_action") or {}).get("identifier") != FIX_ACTION:
            return {"ignored": "acción desconocida"}
        try:
            return {"fix": request_fix(s, scan, (p.get("sender") or {}).get("login", "")).id}
        except PlanLimit as e:
            return {"ignored": str(e)}
    scan.status, scan.attempts, scan.error, scan.check_run_id = ScanStatus.QUEUED.value, 0, "", None
    return {"scan": scan.id}


class PlanLimit(Exception):
    pass


def request_fix(s: Session, scan: Scan, requested_by: str = "") -> FixRequest:
    """Encola la corrección de un escaneo. Idempotente; una petición fallida se puede repetir."""
    repo = s.get(Repository, scan.repository_id)
    if repo.provider != "github":
        raise PlanLimit("los PRs con correcciones solo están disponibles en GitHub")
    inst = s.get(Installation, repo.installation_id)
    plan = plans.effective_plan(inst)
    if not plan.fix_pr:
        raise PlanLimit(f"el plan {plan.name} no incluye PRs con correcciones")
    fix = s.scalars(select(FixRequest).where(FixRequest.scan_id == scan.id)).first()
    if fix is None:
        fix = FixRequest(scan_id=scan.id, requested_by=requested_by)
        s.add(fix)
        s.flush()
    elif fix.status == ScanStatus.FAILED.value:
        fix.status, fix.attempts, fix.error = ScanStatus.QUEUED.value, 0, ""
    return fix


HANDLERS = {
    "installation": on_installation,
    "installation_repositories": on_installation_repositories,
    "pull_request": on_pull_request,
    "push": on_push,
    "check_run": on_check_run,
}


# -- GitLab --------------------------------------------------------------------------------------

GITLAB_MR_ACTIONS = {"open", "reopen", "update"}


def handle_gitlab_event(s: Session, installation_id: int, event: str, p: dict) -> dict:
    """Push a la rama por defecto -> escaneo completo; MR abierta o actualizada -> escaneo incremental.

    Solo para proyectos que la organización ha añadido en el panel: un webhook de un proyecto desconocido se ignora.
    """
    from appsec_ai.service.gitlab_scm import repo_id

    project = p.get("project") or {}
    try:
        repo = s.get(Repository, repo_id(installation_id, int(project.get("id") or p.get("project_id") or 0)))
    except (TypeError, ValueError):
        return {"ignored": "proyecto no válido"}
    if repo is None or repo.provider != "gitlab" or repo.installation_id != installation_id:
        return {"ignored": "proyecto no añadido"}
    if event == "Push Hook":
        after = str(p.get("after") or "")
        if p.get("ref") != f"refs/heads/{repo.default_branch}" or not after.strip("0"):
            return {"ignored": "rama distinta de la rama por defecto"}
        return _enqueued(s, repo, enqueue(s, repo, ScanKind.FULL, after, p["ref"]), ScanKind.FULL)
    if event == "Merge Request Hook":
        mr = p.get("object_attributes") or {}
        if mr.get("action") not in GITLAB_MR_ACTIONS or mr.get("draft") or mr.get("work_in_progress"):
            return {"ignored": f"merge_request.{mr.get('action')}"}
        if mr.get("action") == "update" and not mr.get("oldrev"):
            return {"ignored": "MR actualizada sin commits nuevos"}
        sha = str((mr.get("last_commit") or {}).get("id") or "")
        if not sha or not mr.get("iid"):
            return {"ignored": "MR sin commit"}
        scan = enqueue(s, repo, ScanKind.PULL_REQUEST, sha, f"refs/heads/{mr.get('source_branch', '')}", int(mr["iid"]))
        return _enqueued(s, repo, scan, ScanKind.PULL_REQUEST)
    return {"ignored": event}

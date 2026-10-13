"""Procesado de webhooks de la GitHub App: instalaciones, PRs, pushes y reintentos de checks."""

from __future__ import annotations

import hashlib
import hmac
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from appsec_ai.service.db import Installation, Repository, Scan, ScanKind, ScanStatus

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
                           account_type=account.get("type", "Organization"))
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
    return {"scan": scan.id if scan else None}


def on_push(s: Session, p: dict) -> dict:
    repo = _upsert_repo(s, p["installation"]["id"], p["repository"])
    s.flush()
    if p.get("deleted") or p.get("ref") != f"refs/heads/{repo.default_branch}":
        return {"ignored": "rama distinta de la rama por defecto"}
    scan = enqueue(s, repo, ScanKind.FULL, p["after"], p["ref"])
    return {"scan": scan.id if scan else None}


def on_check_run(s: Session, p: dict) -> dict:
    """El usuario pulsa "Re-run" en GitHub: se vuelve a encolar el escaneo."""
    if p.get("action") != "rerequested":
        return {"ignored": f"check_run.{p.get('action')}"}
    scan = s.scalars(select(Scan).where(Scan.check_run_id == p["check_run"]["id"])).first()
    if scan is None:
        return {"ignored": "check desconocido"}
    scan.status, scan.attempts, scan.error, scan.check_run_id = ScanStatus.QUEUED.value, 0, "", None
    return {"scan": scan.id}


HANDLERS = {
    "installation": on_installation,
    "installation_repositories": on_installation_repositories,
    "pull_request": on_pull_request,
    "push": on_push,
    "check_run": on_check_run,
}

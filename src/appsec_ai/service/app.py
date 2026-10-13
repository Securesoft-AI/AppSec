"""API web: webhooks de GitHub y API REST para el panel."""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from appsec_ai.service.config import Settings, get_settings
from appsec_ai.service.crypto import Cipher, unseal
from appsec_ai.service.db import Database, FixRequest, Installation, Repository, Scan, ScanStatus, WaitlistEntry
from appsec_ai.service.webhooks import handle_event, request_fix, verify_signature

log = logging.getLogger("appsec_ai.api")
MAX_WEBHOOK_BYTES = 25 * 1024 * 1024  # límite de GitHub para webhooks
EMAIL_RE = re.compile(r"^[^\s@<>]{1,64}@[^\s@<>]{1,255}\.[^\s@<>]{2,}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}


class WaitlistIn(BaseModel):
    email: str = Field(max_length=320)
    company: str = Field(default="", max_length=200)
    lang: str = Field(default="es", max_length=5)


class RateLimiter:
    """Límite sencillo en memoria por IP (suficiente para una landing con una instancia)."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit, self.window = limit, window_seconds
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


def landing_html() -> str | None:
    """La landing es un fragmento HTML (también se publica como vista previa); aquí se envuelve."""
    candidates = [Path(os.environ.get("LANDING_FILE", "")), Path.cwd() / "web/landing/index.html",
                  Path(__file__).resolve().parents[3] / "web/landing/index.html"]
    path = next((p for p in candidates if str(p) not in ("", ".") and p.is_file()), None)
    if path is None:
        return None
    return ('<!doctype html><html lang="es"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
            "<script>window.ATALAYA_LIVE = true;</script></head><body>"
            + path.read_text(encoding="utf-8") + "</body></html>")


def create_app(settings: Settings | None = None, db: Database | None = None) -> FastAPI:
    settings = settings or get_settings()
    db = db or Database(settings.database_url, Cipher.from_keys(settings.data_encryption_key))
    if db.cipher is None:
        log.warning("DATA_ENCRYPTION_KEY no configurada: los resultados se guardan sin cifrar")
    db.create_all()
    app = FastAPI(title="appsec-ai", version="0.1.0", docs_url=None, redoc_url=None)
    admin_token = os.environ.get("ADMIN_API_TOKEN", "")
    waitlist_limiter = RateLimiter(limit=5, window_seconds=600)
    landing = landing_html()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    def require_admin(authorization: str = Header(default="")):
        # Provisional hasta tener login con GitHub en el panel: sin token configurado no hay acceso.
        if not admin_token or not hmac.compare_digest(authorization, f"Bearer {admin_token}"):
            raise HTTPException(status_code=401, detail="no autorizado")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home():
        if landing is None:
            raise HTTPException(status_code=404, detail="landing no encontrada")
        return HTMLResponse(landing)

    @app.post("/api/waitlist")
    def join_waitlist(data: WaitlistIn, request: Request):
        ip = request.client.host if request.client else "?"
        if not waitlist_limiter.allow(ip):
            raise HTTPException(status_code=429, detail="demasiadas peticiones")
        email = data.email.strip().lower()
        if not EMAIL_RE.match(email):
            raise HTTPException(status_code=422, detail="email no válido")
        with db.session() as s, s.begin():
            if s.scalars(select(WaitlistEntry).where(WaitlistEntry.email == email)).first():
                return JSONResponse({"status": "already_registered"}, status_code=200)
            s.add(WaitlistEntry(email=email, company=data.company.strip(),
                                lang="en" if data.lang == "en" else "es"))
        log.info("nuevo registro en la lista de espera")
        return JSONResponse({"status": "registered"}, status_code=201)

    @app.get("/api/waitlist", dependencies=[Depends(require_admin)])
    def list_waitlist():
        with db.session() as s:
            rows = s.scalars(select(WaitlistEntry).order_by(WaitlistEntry.id)).all()
            return [{"email": r.email, "company": r.company, "lang": r.lang,
                     "created_at": r.created_at.isoformat()} for r in rows]

    @app.post("/webhooks/github")
    async def github_webhook(request: Request, x_github_event: str = Header(default=""),
                             x_hub_signature_256: str = Header(default=""),
                             x_github_delivery: str = Header(default="")):
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="payload demasiado grande")
        if not verify_signature(settings.github_webhook_secret, body, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="firma no válida")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="JSON no válido") from None
        if x_github_event == "ping":
            return {"pong": True}
        with db.session() as s, s.begin():
            outcome = handle_event(s, x_github_event, payload)
        log.info("webhook %s %s -> %s", x_github_delivery, x_github_event, outcome)
        return outcome

    @app.get("/api/installations", dependencies=[Depends(require_admin)])
    def list_installations():
        with db.session() as s:
            rows = s.scalars(select(Installation).order_by(Installation.created_at.desc())).all()
            return [{"id": r.id, "account": r.account_login, "plan": r.plan, "active": r.active} for r in rows]

    @app.get("/api/installations/{installation_id}/repositories", dependencies=[Depends(require_admin)])
    def list_repositories(installation_id: int):
        with db.session() as s:
            rows = s.scalars(select(Repository).where(Repository.installation_id == installation_id)
                             .order_by(Repository.full_name)).all()
            return [{"id": r.id, "full_name": r.full_name, "private": r.private, "active": r.active} for r in rows]

    @app.get("/api/repositories/{repository_id}/scans", dependencies=[Depends(require_admin)])
    def list_scans(repository_id: int, limit: int = 50):
        with db.session() as s:
            rows = s.scalars(select(Scan).where(Scan.repository_id == repository_id)
                             .order_by(Scan.id.desc()).limit(min(limit, 200))).all()
            return [_scan_summary(r) for r in rows]

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(require_admin)])
    def get_scan(scan_id: int):
        with db.session() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="escaneo no encontrado")
            return {**_scan_summary(scan), "result": unseal(db.cipher, scan.result)}

    @app.post("/api/scans/{scan_id}/fix-pr", dependencies=[Depends(require_admin)])
    def create_fix_pr(scan_id: int):
        """Lo mismo que el botón "Abrir PR con fixes" del check de GitHub."""
        with db.session() as s, s.begin():
            scan = s.get(Scan, scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="escaneo no encontrado")
            if scan.status != ScanStatus.COMPLETED.value:
                raise HTTPException(status_code=409, detail="el escaneo aún no ha terminado")
            return _fix_summary(request_fix(s, scan, "api"), db.cipher)

    @app.get("/api/scans/{scan_id}/fix-pr", dependencies=[Depends(require_admin)])
    def get_fix_pr(scan_id: int):
        with db.session() as s:
            fix = s.scalars(select(FixRequest).where(FixRequest.scan_id == scan_id)).first()
            if fix is None:
                raise HTTPException(status_code=404, detail="sin petición de corrección")
            return _fix_summary(fix, db.cipher)

    return app


def _fix_summary(fix: FixRequest, cipher=None) -> dict:
    return {"id": fix.id, "scan_id": fix.scan_id, "status": fix.status, "pr_url": fix.pr_url,
            "error": fix.error, "detail": unseal(cipher, fix.detail), "requested_by": fix.requested_by}


def _scan_summary(scan: Scan) -> dict:
    return {
        "id": scan.id, "kind": scan.kind, "status": scan.status, "head_sha": scan.head_sha,
        "pr_number": scan.pr_number, "summary": scan.summary, "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }

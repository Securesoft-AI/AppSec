"""API web: webhooks de GitHub y API REST para el panel."""

from __future__ import annotations

import datetime as dt
import hmac
import json
import logging
import os
import re
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

import jwt

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from appsec_ai.service.auth import SESSION_COOKIE, SESSION_TTL, STATE_COOKIE, Authenticator, Principal, encode_session, new_state
from appsec_ai.service.config import Settings, get_settings
from appsec_ai.service.crypto import Cipher, unseal
from appsec_ai.i18n import localize
from appsec_ai.models import ScanResult
from appsec_ai.service import dashboard
from appsec_ai.service.crypto import seal
from appsec_ai.service.db import (Database, FindingFeedback, FixRequest, Installation, PentestRequest, PentestStatus,
                                  AuditLog, RedTeamRun, RedTeamTarget, Repository, Scan, ScanKind, ScanStatus,
                                  WaitlistEntry, utcnow)
from appsec_ai.service import notify, ownership
from appsec_ai.service import integrations
from appsec_ai.service.jira import Jira
from appsec_ai.service.gitlab import Gitlab
from appsec_ai.service.bitbucket import Bitbucket
from appsec_ai.service import oidc
from appsec_ai import redteam
from appsec_ai.service.github import GitHubApp, GitHubError
from appsec_ai.service import demo, plans
from appsec_ai.services import PURCHASABLE, SCAN_SERVICES, catalog
from appsec_ai.service.billing import BillingError, Stripe, apply_event, verify_event
from appsec_ai.service.webhooks import PlanLimit, enqueue, handle_event, plan_block, request_fix, verify_signature

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


class FeedbackIn(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=64)
    useful: bool
    comment: str = Field(default="", max_length=2000)


class InstallationSettingsIn(BaseModel):
    eval_opt_in: bool


class PreferencesIn(BaseModel):
    language: str = Field(pattern="^(es|en)$")


class DemoLoginIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=200)


class RepoServicesIn(BaseModel):
    services: list[str] | None = None  # None = todos los contratados


class ScanNowIn(BaseModel):
    services: list[str] | None = None


class PentestIn(BaseModel):
    kind: str = Field(pattern="^(web|api|mobile|llm|network)$")
    target: str = Field(min_length=3, max_length=500)
    scope: str = Field(default="", max_length=5000)
    preferred_dates: str = Field(default="", max_length=200)
    contact_email: str = Field(max_length=320)


class PentestFindingIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    description: str = Field(default="", max_length=10000)
    fix: str = Field(default="", max_length=10000)


class PentestReportIn(BaseModel):
    summary: str = Field(default="", max_length=20000)
    findings: list[PentestFindingIn] = Field(default_factory=list, max_length=200)


class PentestUpdateIn(BaseModel):
    status: str | None = Field(default=None, pattern="^(requested|scoping|scheduled|in_progress|reported|cancelled)$")
    quote_eur: int | None = Field(default=None, ge=0, le=10_000_000)
    notes: str | None = Field(default=None, max_length=5000)
    report: PentestReportIn | None = None


class RedTeamTargetIn(BaseModel):
    name: str = Field(default="", max_length=200)
    url: str = Field(min_length=4, max_length=1000)
    method: str = Field(default="POST", pattern="^(POST|GET|PUT)$")
    body_template: str = Field(default='{"input": "{prompt}"}', max_length=20000)
    response_path: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9_.\-]*$")
    headers: dict[str, str] = Field(default_factory=dict)


class NotificationsIn(BaseModel):
    slack_webhook: str = Field(default="", max_length=500)


class SsoVerifyIn(BaseModel):
    domain: str = Field(max_length=253)


class SsoStartIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class SsoConfigIn(BaseModel):
    issuer: str = Field(default="", max_length=300)
    client_id: str = Field(default="", max_length=300)
    client_secret: str = Field(default="", max_length=500)
    domains: list[str] = Field(default_factory=list, max_length=50)


class JiraConfigIn(BaseModel):
    base_url: str = Field(default="", max_length=300)
    email: str = Field(default="", max_length=320)
    token: str = Field(default="", max_length=500)
    project_key: str = Field(default="", max_length=50, pattern=r"^[A-Z0-9_]*$")
    auto: bool = False


class GitlabConfigIn(BaseModel):
    base_url: str = Field(default="", max_length=300)
    token: str = Field(default="", max_length=500)
    project: str = Field(default="", max_length=200)   # id numérico o ruta "grupo/proyecto"
    auto: bool = False


class BitbucketConfigIn(BaseModel):
    workspace: str = Field(default="", max_length=100)
    repo: str = Field(default="", max_length=100)
    username: str = Field(default="", max_length=100)
    app_password: str = Field(default="", max_length=200)
    auto: bool = False


class IssueIn(BaseModel):
    fingerprint: str = Field(min_length=4, max_length=64, pattern=r"^[0-9a-f]+$")


class CheckoutIn(BaseModel):
    items: list[str] = Field(min_length=1, max_length=10)  # servicios y/o paquetes


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


def web_file(name: str, env: str = "") -> Path | None:
    candidates = [Path(os.environ.get(env, "")) if env else Path(""), Path.cwd() / "web" / name,
                  Path(__file__).resolve().parents[3] / "web" / name]
    return next((p for p in candidates if str(p) not in ("", ".") and p.is_file()), None)


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


def create_app(settings: Settings | None = None, db: Database | None = None, github: GitHubApp | None = None,
               stripe: Stripe | None = None) -> FastAPI:
    settings = settings or get_settings()
    db = db or Database(settings.database_url, Cipher.from_keys(settings.data_encryption_key))
    if db.cipher is None:
        log.warning("DATA_ENCRYPTION_KEY no configurada: los resultados se guardan sin cifrar")
    db.migrate()
    app = FastAPI(title="appsec-ai", version="0.1.0", docs_url=None, redoc_url=None)
    admin_token = os.environ.get("ADMIN_API_TOKEN", "")
    if settings.demo_login and not settings.session_secret:
        import secrets as _secrets

        # Demo sin configurar: secreto aleatorio por arranque (las sesiones caducan al reiniciar).
        settings.session_secret = _secrets.token_hex(32)
    auth = Authenticator(settings.session_secret, admin_token, settings.public_url, settings.staff_logins)
    github = github or GitHubApp(settings.github_app_id, settings.github_private_key, settings.github_api_url)
    login_enabled = bool(settings.github_client_id and settings.github_client_secret and settings.session_secret)
    sso_enabled = bool(settings.session_secret)
    SSO_STATE_COOKIE = "appsec_sso_state"
    sso_redirect = f"{settings.public_url}/auth/sso/callback"
    secure_cookies = settings.public_url.startswith("https://")
    callback_url = f"{settings.public_url}/auth/callback"
    if stripe is None and settings.stripe_secret_key:
        stripe = Stripe(settings.stripe_secret_key)
    price_to_item = {price: item for item, price in settings.stripe_prices.items() if price}
    slack = notify.Slack()

    def principal_lang(inst: Installation | None) -> str:
        return "en" if ((inst.language if inst else "") or settings.language) == "en" else "es"
    login_limiter = RateLimiter(limit=10, window_seconds=300)
    if settings.demo_login:
        log.warning("MODO DEMO ACTIVO: login %s/**** con una organización de ejemplo. No usar con datos reales.",
                    settings.demo_user)
        demo.seed(db)
    waitlist_limiter = RateLimiter(limit=5, window_seconds=600)
    landing = landing_html()
    panel = web_file("panel/index.html", "PANEL_FILE")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    def require_admin(principal: Principal = Depends(auth)):
        """Operaciones internas (p. ej. la lista de espera): solo con ADMIN_API_TOKEN."""
        if not principal.admin:
            raise HTTPException(status_code=403, detail="solo administradores")

    def require_staff(principal: Principal = Depends(auth)) -> Principal:
        """Vista Equipo: el equipo de seguridad (STAFF_LOGINS), el token de administración o la demo."""
        if not (principal.admin or principal.staff):
            raise HTTPException(status_code=403, detail="solo el equipo de seguridad")
        return principal

    def visible_repo(s, principal: Principal, repository_id: int) -> Repository:
        repo = s.get(Repository, repository_id)
        if repo is None or not principal.can_see(repo.installation_id):
            raise HTTPException(status_code=404, detail="repositorio no encontrado")
        return repo

    def visible_scan(s, principal: Principal, scan_id: int) -> Scan:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="escaneo no encontrado")
        visible_repo(s, principal, scan.repository_id)
        return scan

    # -- login con GitHub -------------------------------------------------------------------

    @app.get("/auth/login", include_in_schema=False)
    def login():
        if not login_enabled:
            raise HTTPException(status_code=503, detail="login con GitHub no configurado")
        state = new_state()
        resp = RedirectResponse(github.authorize_url(settings.github_client_id, callback_url, state), status_code=302)
        resp.set_cookie(STATE_COOKIE, state, max_age=600, httponly=True, secure=secure_cookies, samesite="lax")
        return resp

    @app.get("/auth/callback", include_in_schema=False)
    def oauth_callback(request: Request, code: str = "", state: str = ""):
        expected = request.cookies.get(STATE_COOKIE, "")
        if not login_enabled or not code or not expected or not hmac.compare_digest(state, expected):
            raise HTTPException(status_code=400, detail="login no válido; vuelve a intentarlo")
        try:
            token = github.exchange_code(settings.github_client_id, settings.github_client_secret, code, callback_url)
            user, installations = github.user_with_installations(token)
        except GitHubError:
            log.exception("fallo en el login con GitHub")
            raise HTTPException(status_code=502, detail="GitHub no ha validado el login") from None
        resp = RedirectResponse("/app", status_code=302)
        resp.delete_cookie(STATE_COOKIE)
        staff = "all" if user["login"].lower() in settings.staff_logins else ""
        resp.set_cookie(SESSION_COOKIE, encode_session(settings.session_secret, user, installations, staff),
                        max_age=SESSION_TTL, httponly=True, secure=secure_cookies, samesite="lax")
        log.info("login de %s con %d instalaciones", user["login"], len(installations))
        db.audit(None, user["login"], "auth.login", detail={"mode": "github", "installations": len(installations)},
                 ip=request.client.host if request.client else "")
        return resp

    @app.get("/auth/config", include_in_schema=False)
    def auth_config():
        return {"github": login_enabled, "demo": settings.demo_login, "sso": sso_enabled}

    # -- SSO con OIDC (RF-4.8) --------------------------------------------------------------------

    def _find_sso_installation(email: str):
        """Instalación cuyo SSO admite el dominio del email (busca entre todas las configuradas)."""
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        if not domain:
            return None, {}
        matches = [(inst_id, cfg) for inst_id, cfg in _sso_configs() if domain in cfg.get("verified", [])]
        # Solo dominios verificados, y nunca ambiguos: un dominio no puede llevar a dos organizaciones.
        return matches[0] if len(matches) == 1 else (None, {})

    def _sso_configs():
        with db.session() as s:
            rows = [(inst.id, inst.oidc_config) for inst in s.scalars(select(Installation)).all() if inst.oidc_config]
        return [(inst_id, cfg) for inst_id, sealed in rows if (cfg := unseal(db.cipher, sealed) or {})]

    def _sso_token(installation_id: int, domain: str) -> str:
        return ownership.challenge_token(settings.session_secret, installation_id, "sso:" + domain)

    @app.post("/auth/sso/start", include_in_schema=False)
    def sso_start(data: SsoStartIn):
        if not sso_enabled:
            raise HTTPException(status_code=404, detail="no disponible")
        email = data.email.strip().lower()
        installation_id, cfg = _find_sso_installation(email)
        if not installation_id:
            raise HTTPException(status_code=404, detail="no hay SSO configurado para ese dominio")
        try:
            meta = oidc.discover(cfg["issuer"])
        except oidc.OIDCError:
            log.exception("descubrimiento OIDC falló")
            raise HTTPException(status_code=502, detail="no se pudo contactar con el proveedor de identidad") from None
        state, nonce = oidc.random_state(), oidc.random_nonce()
        url = oidc.authorization_url(meta, cfg["client_id"], sso_redirect, state, nonce)
        ticket = jwt.encode({"inst": installation_id, "st": state, "nonce": nonce, "exp": int(time.time()) + 600},
                            settings.session_secret, algorithm="HS256")
        resp = JSONResponse({"url": url})
        resp.set_cookie(SSO_STATE_COOKIE, ticket, max_age=600, httponly=True, secure=secure_cookies, samesite="lax")
        return resp

    @app.get("/auth/sso/callback", include_in_schema=False)
    def sso_callback(request: Request, code: str = "", state: str = ""):
        ticket = request.cookies.get(SSO_STATE_COOKIE, "")
        try:
            data = jwt.decode(ticket, settings.session_secret, algorithms=["HS256"], options={"require": ["exp"]})
        except jwt.PyJWTError:
            raise HTTPException(status_code=400, detail="sesión de login caducada; vuelve a intentarlo") from None
        if not code or not state or not hmac.compare_digest(state, data.get("st", "")):
            raise HTTPException(status_code=400, detail="login SSO no válido")
        installation_id = int(data["inst"])
        with db.session() as s:
            inst = s.get(Installation, installation_id)
            cfg = unseal(db.cipher, inst.oidc_config) if inst else {}
        if not cfg:
            raise HTTPException(status_code=400, detail="el SSO de esta organización ya no está disponible")
        try:
            meta = oidc.discover(cfg["issuer"])
            id_token = oidc.exchange_code(meta, cfg["client_id"], cfg["client_secret"], code, sso_redirect)
            claims = oidc.verify_id_token(id_token, meta, cfg["client_id"], cfg["issuer"], data.get("nonce", ""))
        except oidc.OIDCError:
            log.exception("verificación OIDC falló")
            raise HTTPException(status_code=401, detail="el proveedor no validó el acceso") from None
        email = oidc.allowed_email(claims, cfg.get("verified", []))
        if not email:
            raise HTTPException(status_code=403, detail="tu email no está autorizado para esta organización")
        resp = RedirectResponse("/app", status_code=302)
        resp.delete_cookie(SSO_STATE_COOKIE)
        resp.set_cookie(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 0, "login": email},
                                                       [installation_id]),
                        max_age=SESSION_TTL, httponly=True, secure=secure_cookies, samesite="lax")
        db.audit(installation_id, email, "auth.login", detail={"mode": "sso"},
                 ip=request.client.host if request.client else "")
        log.info("login SSO de %s en la instalación %s", email, installation_id)
        return resp

    @app.post("/auth/demo", include_in_schema=False)
    def demo_login(data: DemoLoginIn, request: Request):
        if not settings.demo_login or not settings.session_secret:
            raise HTTPException(status_code=404, detail="no disponible")
        ip = request.client.host if request.client else "?"
        if not login_limiter.allow(ip):
            raise HTTPException(status_code=429, detail="demasiados intentos")
        ok = hmac.compare_digest(data.username.encode(), settings.demo_user.encode()) & \
            hmac.compare_digest(data.password.encode(), settings.demo_password.encode())
        if not ok:
            raise HTTPException(status_code=401, detail="usuario o contraseña incorrectos")
        resp = JSONResponse({"status": "ok"})
        resp.set_cookie(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 0, "login": "demo"},
                                                       [demo.DEMO_INSTALLATION_ID], staff="own"),
                        max_age=SESSION_TTL, httponly=True, secure=secure_cookies, samesite="lax")
        db.audit(demo.DEMO_INSTALLATION_ID, "demo", "auth.login", detail={"mode": "demo"}, ip=ip)
        return resp

    @app.post("/auth/logout", include_in_schema=False)
    def logout(principal: Principal = Depends(auth)):
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @app.get("/api/me")
    def me(principal: Principal = Depends(auth)):
        with db.session() as s:
            q = select(Installation).order_by(Installation.account_login)
            if not principal.admin:
                q = q.where(Installation.id.in_(principal.installations))
            rows = s.scalars(q).all()
            return {"login": principal.login, "admin": principal.admin, "staff": bool(principal.admin or principal.staff),
                    "installations": [{"id": r.id, "account": r.account_login, "plan": r.plan,
                                       "language": r.language or settings.language} for r in rows]}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home():
        if landing is None:
            raise HTTPException(status_code=404, detail="landing no encontrada")
        return HTMLResponse(landing)

    @app.get("/app", response_class=HTMLResponse, include_in_schema=False)
    def panel_page():
        if panel is None:
            raise HTTPException(status_code=404, detail="panel no encontrado")
        return HTMLResponse(panel.read_text(encoding="utf-8"))

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

    @app.get("/api/installations")
    def list_installations(principal: Principal = Depends(auth)):
        with db.session() as s:
            q = select(Installation).order_by(Installation.created_at.desc())
            if not principal.admin:
                q = q.where(Installation.id.in_(principal.installations))
            rows = s.scalars(q).all()
            return [{"id": r.id, "account": r.account_login, "plan": r.plan, "active": r.active} for r in rows]

    @app.get("/api/installations/{installation_id}/repositories")
    def list_repositories(installation_id: int, principal: Principal = Depends(auth)):
        if not principal.can_see(installation_id):
            raise HTTPException(status_code=404, detail="instalación no encontrada")
        with db.session() as s:
            rows = s.scalars(select(Repository).where(Repository.installation_id == installation_id)
                             .order_by(Repository.full_name)).all()
            return [{"id": r.id, "full_name": r.full_name, "private": r.private, "active": r.active,
                     "services": r.services} for r in rows]

    @app.get("/api/repositories/{repository_id}/scans")
    def list_scans(repository_id: int, limit: int = 50, principal: Principal = Depends(auth)):
        with db.session() as s:
            visible_repo(s, principal, repository_id)
            rows = s.scalars(select(Scan).where(Scan.repository_id == repository_id)
                             .order_by(Scan.id.desc()).limit(min(limit, 200))).all()
            return [_scan_summary(r) for r in rows]

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: int, lang: str = "", principal: Principal = Depends(auth)):
        with db.session() as s:
            scan = visible_scan(s, principal, scan_id)
            votes = s.scalars(select(FindingFeedback).where(
                FindingFeedback.repository_id == scan.repository_id,
                FindingFeedback.user_login == principal.login)).all()
            result = unseal(db.cipher, scan.result)
            if lang and result:
                # Título y mensaje de cada hallazgo en el idioma del panel.
                for f, model in zip(result.get("findings", []), ScanResult.model_validate(result).findings):
                    f["title"], f["message"] = localize(model, lang)
            return {**_scan_summary(scan), "result": result, "feedback": {v.fingerprint: v.useful for v in votes}}

    @app.get("/api/scans/{scan_id}/report.pdf")
    def scan_report_pdf(scan_id: int, lang: str = "es", principal: Principal = Depends(auth)):
        from appsec_ai.report_pdf import to_pdf

        with db.session() as s:
            scan = visible_scan(s, principal, scan_id)
            if not scan.result:
                raise HTTPException(status_code=409, detail="el escaneo aún no tiene resultado")
            repo = s.get(Repository, scan.repository_id)
            plan = plans.effective_plan(s.get(Installation, repo.installation_id))
            if not plan.pdf_report:
                raise HTTPException(status_code=402, detail=f"el plan {plan.name} no incluye el informe PDF")
            result = ScanResult.model_validate(unseal(db.cipher, scan.result))
            pdf = to_pdf(result, lang=lang, target=repo.full_name, commit=scan.head_sha, generated=scan.finished_at,
                         include_compliance=plan.compliance)
        filename = f"atalaya-{repo.full_name.replace('/', '-')}-{scan.head_sha[:7]}.pdf"
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})

    # -- panel por organización (RF-4.3) ------------------------------------------------------

    @app.get("/api/installations/{installation_id}/dashboard")
    def installation_dashboard(installation_id: int, principal: Principal = Depends(auth)):
        if not principal.can_see(installation_id):
            raise HTTPException(status_code=404, detail="instalación no encontrada")
        since = utcnow() - dt.timedelta(days=dashboard.TREND_DAYS + 30)
        with db.session() as s:
            repos = {r.id: r.full_name for r in s.scalars(
                select(Repository).where(Repository.installation_id == installation_id, Repository.active))}
            recent = s.scalars(select(Scan).where(Scan.repository_id.in_(repos), Scan.created_at >= since)).all()
            # Repos sin escaneos recientes: su último escaneo, aunque sea antiguo.
            missing = set(repos) - {sc.repository_id for sc in recent}
            older = s.scalars(select(Scan).where(Scan.repository_id.in_(missing))).all() if missing else []
            latest_scans = dashboard.latest_per_repo(list(recent) + list(older))
            results = {rid: ScanResult.model_validate(unseal(db.cipher, sc.result))
                       for rid, sc in latest_scans.items() if sc.result}
            data = dashboard.overview(repos, results, latest_scans)
            data["trend"] = dashboard.trend(list(recent), utcnow().date())
            data["repositories_without_scans"] = sorted(repos[r] for r in set(repos) - set(latest_scans))
            # Todos los repositorios, con los servicios elegidos en cada uno (para el panel).
            data["all_repositories"] = [{"id": r.id, "full_name": r.full_name, "services": r.services}
                                        for r in s.scalars(select(Repository).where(
                                            Repository.installation_id == installation_id, Repository.active)
                                            .order_by(Repository.full_name))]
            # Severidad por servicio (área), sumando el último escaneo de cada repositorio.
            by_service: dict[str, Counter] = {}
            for res in results.values():
                for f in res.findings:
                    if not f.is_suppressed:
                        by_service.setdefault(f.category.value, Counter())[f.effective_severity.value] += 1
            data["by_service"] = {cat: dict(c) for cat, c in by_service.items()}
            return data

    # -- feedback útil / no útil (RF-3.8) --------------------------------------------------------

    @app.post("/api/scans/{scan_id}/feedback")
    def give_feedback(scan_id: int, data: FeedbackIn, principal: Principal = Depends(auth)):
        with db.session() as s, s.begin():
            scan = visible_scan(s, principal, scan_id)
            repo = s.get(Repository, scan.repository_id)
            result = ScanResult.model_validate(unseal(db.cipher, scan.result)) if scan.result else None
            finding = next((f for f in (result.findings if result else []) if f.fingerprint == data.fingerprint), None)
            if finding is None:
                raise HTTPException(status_code=404, detail="hallazgo no encontrado en este escaneo")
            row = s.scalars(select(FindingFeedback).where(
                FindingFeedback.repository_id == repo.id, FindingFeedback.fingerprint == data.fingerprint,
                FindingFeedback.user_login == principal.login)).first()
            if row is None:
                row = FindingFeedback(installation_id=repo.installation_id, repository_id=repo.id,
                                      fingerprint=data.fingerprint, user_login=principal.login)
                s.add(row)
            row.scan_id, row.rule_id, row.useful, row.comment = scan.id, finding.rule_id, data.useful, data.comment
            row.finding = seal(db.cipher, finding.model_dump(mode="json"))
            row.created_at = utcnow()
        return {"fingerprint": data.fingerprint, "useful": data.useful}

    @app.patch("/api/installations/{installation_id}/preferences")
    def update_preferences(installation_id: int, data: PreferencesIn, principal: Principal = Depends(auth)):
        """Idioma de los checks, comentarios y PR de correcciones de la organización."""
        if not principal.can_see(installation_id):
            raise HTTPException(status_code=404, detail="instalación no encontrada")
        with db.session() as s, s.begin():
            inst = s.get(Installation, installation_id)
            if inst is None:
                raise HTTPException(status_code=404, detail="instalación no encontrada")
            inst.language = data.language
            return {"id": inst.id, "language": inst.language}

    # -- servicios: catálogo, elección por repositorio, escanear ahora y pentests ------------------

    @app.get("/api/catalog")
    def service_catalog(lang: str = "es"):
        return catalog(lang)

    def check_services(services: list[str] | None) -> list[str] | None:
        if services is None:
            return None
        unknown = set(services) - set(SCAN_SERVICES)
        if unknown or not services:
            raise HTTPException(status_code=422, detail=f"servicios no válidos: {', '.join(sorted(unknown)) or '(ninguno)'}")
        return [s for s in SCAN_SERVICES if s in services]

    @app.patch("/api/repositories/{repository_id}/services")
    def set_repo_services(repository_id: int, data: RepoServicesIn, principal: Principal = Depends(auth)):
        """Qué servicios se aplican a este repositorio en PRs y pushes (de entre los contratados)."""
        with db.session() as s, s.begin():
            repo = visible_repo(s, principal, repository_id)
            repo.services = check_services(data.services)
            db.audit(repo.installation_id, principal.login, "repo.services_changed", repo.full_name,
                     {"services": repo.services}, session=s)
            return {"id": repo.id, "services": repo.services}

    @app.post("/api/repositories/{repository_id}/scans")
    def scan_now(repository_id: int, data: ScanNowIn, principal: Principal = Depends(auth)):
        """Escanea ahora la rama por defecto con los servicios elegidos."""
        services = check_services(data.services)
        with db.session() as s:
            repo = visible_repo(s, principal, repository_id)
            inst = s.get(Installation, repo.installation_id)
            plan = plans.effective_plan(inst)
            if services and not set(services) <= plan.services:
                missing = ", ".join(sorted(set(services) - plan.services))
                raise HTTPException(status_code=402, detail=f"servicios no contratados: {missing}")
            if demo.is_demo(repo.installation_id) and settings.demo_login:
                # La organización de ejemplo no está en GitHub: se escanea al momento su código de ejemplo.
                scan = demo.scan_demo_repo(db, repository_id, services or sorted(plan.services), principal.login)
                db.audit(repo.installation_id, principal.login, "scan.requested", repo.full_name,
                         {"kind": "manual", "services": scan.services})
                return _scan_summary(scan)
            reason = plan_block(s, repo, inst, ScanKind.MANUAL)
            if reason:
                raise HTTPException(status_code=402, detail=reason)
            full_name, branch, installation_id = repo.full_name, repo.default_branch, repo.installation_id
        try:
            sha = github.installation(installation_id).branch_head(full_name, branch)
        except GitHubError:
            log.exception("no se pudo leer la rama %s de %s", branch, full_name)
            raise HTTPException(status_code=502, detail="GitHub no ha devuelto la rama") from None
        with db.session() as s, s.begin():
            repo = s.get(Repository, repository_id)
            scan = enqueue(s, repo, ScanKind.MANUAL, sha, f"refs/heads/{branch}")
            if scan is None:
                raise HTTPException(status_code=409, detail="no se ha podido encolar el escaneo")
            if scan.status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value):
                # Mismo commit con otros servicios: se vuelve a lanzar.
                scan.status, scan.attempts, scan.error, scan.check_run_id = ScanStatus.QUEUED.value, 0, "", None
            scan.services, scan.requested_by = services, principal.login
            db.audit(repo.installation_id, principal.login, "scan.requested", repo.full_name,
                     {"kind": "manual", "services": services, "sha": sha[:12]}, session=s)
            return _scan_summary(scan)

    @app.post("/api/installations/{installation_id}/pentests", status_code=201)
    def request_pentest(installation_id: int, data: PentestIn, principal: Principal = Depends(auth)):
        if not EMAIL_RE.match(data.contact_email.strip().lower()):
            raise HTTPException(status_code=422, detail="email no válido")
        with db.session() as s, s.begin():
            visible_installation(s, principal, installation_id)
            row = PentestRequest(installation_id=installation_id, requested_by=principal.login, kind=data.kind,
                                 target=data.target.strip(), scope=data.scope.strip(),
                                 preferred_dates=data.preferred_dates.strip(), contact_email=data.contact_email.strip())
            s.add(row)
            s.flush()
            log.info("pentest %s solicitado por %s (instalación %s)", row.id, principal.login, installation_id)
            db.audit(installation_id, principal.login, "pentest.requested", str(row.id), {"kind": row.kind}, session=s)
            return _pentest_summary(row, db.cipher)

    @app.get("/api/installations/{installation_id}/pentests")
    def list_pentests(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            visible_installation(s, principal, installation_id)
            rows = s.scalars(select(PentestRequest).where(PentestRequest.installation_id == installation_id)
                             .order_by(PentestRequest.id.desc())).all()
            return [_pentest_summary(r, db.cipher) for r in rows]

    def own_pentest(s, principal: Principal, installation_id: int, pentest_id: int) -> PentestRequest:
        visible_installation(s, principal, installation_id)
        row = s.get(PentestRequest, pentest_id)
        if row is None or row.installation_id != installation_id:
            raise HTTPException(status_code=404, detail="pentest no encontrado")
        return row

    @app.post("/api/installations/{installation_id}/pentests/{pentest_id}/accept")
    def accept_pentest_quote(installation_id: int, pentest_id: int, principal: Principal = Depends(auth)):
        """El cliente acepta el presupuesto; el equipo lo programa después."""
        with db.session() as s, s.begin():
            row = own_pentest(s, principal, installation_id, pentest_id)
            if row.status != PentestStatus.SCOPING.value or row.quote_eur is None or row.accepted_at:
                raise HTTPException(status_code=409, detail="no hay un presupuesto pendiente de aceptar")
            row.accepted_at = row.updated_at = utcnow()
            log.info("presupuesto del pentest %s aceptado por %s", row.id, principal.login)
            db.audit(installation_id, principal.login, "pentest.accepted", str(row.id), {"quote_eur": row.quote_eur}, session=s)
            return _pentest_summary(row, db.cipher)

    @app.post("/api/installations/{installation_id}/pentests/{pentest_id}/cancel")
    def cancel_pentest(installation_id: int, pentest_id: int, principal: Principal = Depends(auth)):
        """El cliente puede cancelar mientras no haya aceptado el presupuesto."""
        with db.session() as s, s.begin():
            row = own_pentest(s, principal, installation_id, pentest_id)
            if row.status not in (PentestStatus.REQUESTED.value, PentestStatus.SCOPING.value) or row.accepted_at:
                raise HTTPException(status_code=409, detail="este pentest ya no se puede cancelar desde el panel")
            row.status, row.updated_at = PentestStatus.CANCELLED.value, utcnow()
            db.audit(installation_id, principal.login, "pentest.cancelled", str(row.id), session=s)
            return _pentest_summary(row, db.cipher)

    @app.get("/api/installations/{installation_id}/pentests/{pentest_id}/report.pdf")
    def pentest_report_pdf(installation_id: int, pentest_id: int, lang: str = "es",
                           principal: Principal = Depends(auth)):
        from appsec_ai.report_pdf import pentest_pdf

        with db.session() as s:
            row = own_pentest(s, principal, installation_id, pentest_id)
            inst = s.get(Installation, installation_id)
            report = unseal(db.cipher, row.report) or {}
            if row.status != PentestStatus.REPORTED.value or not report:
                raise HTTPException(status_code=404, detail="el informe aún no está disponible")
            pdf = pentest_pdf(report, lang=lang, account=inst.account_login, target=row.target, kind=row.kind,
                              scope=row.scope)
        return Response(pdf, media_type="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="pentest-{pentest_id}.pdf"'})

    # -- vista Equipo: el equipo de seguridad gestiona los pentests -----------------------------

    @app.get("/api/admin/pentests")
    def admin_pentests(status: str = "", principal: Principal = Depends(require_staff)):
        with db.session() as s:
            q = select(PentestRequest, Installation.account_login).join(Installation).order_by(PentestRequest.id.desc())
            if status:
                q = q.where(PentestRequest.status == status)
            if not (principal.admin or principal.staff == "all"):
                q = q.where(PentestRequest.installation_id.in_(principal.installations))
            return [{**_pentest_summary(r, db.cipher), "installation_id": r.installation_id, "account": account}
                    for r, account in s.execute(q).all()]

    @app.patch("/api/admin/pentests/{pentest_id}")
    def update_pentest(pentest_id: int, data: PentestUpdateIn, principal: Principal = Depends(require_staff)):
        """El equipo concreta el presupuesto, cambia el estado, escribe al cliente y publica el informe."""
        with db.session() as s, s.begin():
            row = s.get(PentestRequest, pentest_id)
            if row is None or not principal.staff_sees(row.installation_id):
                raise HTTPException(status_code=404, detail="pentest no encontrado")
            if data.quote_eur is not None and data.quote_eur != row.quote_eur:
                row.quote_eur, row.accepted_at = data.quote_eur, None  # presupuesto nuevo: hay que volver a aceptarlo
            if data.notes is not None:
                row.notes = data.notes.strip()
            if data.report is not None:
                row.report = seal(db.cipher, data.report.model_dump())
            if data.status is not None and data.status != row.status:
                if data.status == PentestStatus.REPORTED.value and not (unseal(db.cipher, row.report) or {}).get("summary"):
                    raise HTTPException(status_code=422, detail="falta el resumen del informe")
                if data.status in (PentestStatus.SCHEDULED.value, PentestStatus.IN_PROGRESS.value) and not row.accepted_at:
                    raise HTTPException(status_code=409, detail="el cliente aún no ha aceptado el presupuesto")
                row.status = data.status
            row.updated_at = utcnow()
            log.info("pentest %s actualizado por %s: %s", row.id, principal.login, row.status)
            db.audit(row.installation_id, principal.login, "pentest.updated", str(row.id),
                     {"status": row.status, "quote_eur": row.quote_eur}, session=s)
            notify_status = row.status if data.status is not None else ""
            inst = s.get(Installation, row.installation_id)
            webhook, plang, target = _slack_url(inst), principal_lang(inst), row.target
            out = {**_pentest_summary(row, db.cipher), "installation_id": row.installation_id}
        if notify_status in (PentestStatus.SCHEDULED.value, PentestStatus.REPORTED.value) and webhook:
            from appsec_ai.i18n import ui as _ui  # etiqueta del estado, ya traducida
            label = {"scheduled": {"es": "programado", "en": "scheduled"},
                     "reported": {"es": "informe entregado", "en": "report delivered"}}[notify_status][plang]
            slack.post(webhook, *notify.pentest_message(target, label, plang, f"{settings.public_url}/app"))
        return out

    # -- red teaming dinámico de endpoints con LLM (RF-2.7) ---------------------------------------

    def redteam_plan(s, principal: Principal, installation_id: int) -> Installation:
        inst = visible_installation(s, principal, installation_id)
        if not plans.effective_plan(inst).redteam:
            raise HTTPException(status_code=402, detail="el red teaming va con el servicio de Seguridad de IA")
        return inst

    def visible_target(s, principal: Principal, installation_id: int, target_id: int) -> RedTeamTarget:
        redteam_plan(s, principal, installation_id)
        tgt = s.get(RedTeamTarget, target_id)
        if tgt is None or tgt.installation_id != installation_id:
            raise HTTPException(status_code=404, detail="objetivo no encontrado")
        return tgt

    def _target_token(installation_id: int, host: str) -> str:
        return ownership.challenge_token(settings.session_secret, installation_id, host)

    def _target_out(tgt: RedTeamTarget) -> dict:
        return {"id": tgt.id, "name": tgt.name, "url": tgt.url, "host": tgt.host, "method": tgt.method,
                "body_template": tgt.body_template, "response_path": tgt.response_path,
                "has_headers": bool(unseal(db.cipher, tgt.headers)),
                "verified": bool(tgt.verified_method), "verified_method": tgt.verified_method,
                "token": _target_token(tgt.installation_id, tgt.host),
                "well_known_path": ownership.WELL_KNOWN, "dns_record": ownership.DNS_PREFIX + _target_token(tgt.installation_id, tgt.host),
                "created_by": tgt.created_by,
                "created_at": tgt.created_at.isoformat() if tgt.created_at else None}

    @app.post("/api/installations/{installation_id}/redteam/targets", status_code=201)
    def create_target(installation_id: int, data: RedTeamTargetIn, principal: Principal = Depends(auth)):
        host = ownership.normalize_host(data.url)
        if not host:
            raise HTTPException(status_code=422, detail="la URL debe ser https y con un host válido")
        if redteam.PLACEHOLDER not in data.body_template:
            raise HTTPException(status_code=422, detail="la plantilla del cuerpo debe incluir {prompt}")
        try:
            json.loads(data.body_template.replace(redteam.PLACEHOLDER, "x"))
        except ValueError:
            raise HTTPException(status_code=422, detail="la plantilla del cuerpo no es JSON válido") from None
        if not demo.is_demo(installation_id) and not ownership.is_public_host(host):
            raise HTTPException(status_code=422, detail="el host no resuelve a una dirección pública")
        with db.session() as s, s.begin():
            redteam_plan(s, principal, installation_id)
            tgt = RedTeamTarget(installation_id=installation_id, name=data.name.strip(), url=data.url.strip(),
                                host=host, method=data.method, body_template=data.body_template,
                                response_path=data.response_path, headers=seal(db.cipher, data.headers),
                                created_by=principal.login)
            s.add(tgt)
            s.flush()
            db.audit(installation_id, principal.login, "redteam.target_created", host, {"id": tgt.id}, session=s)
            return _target_out(tgt)

    @app.get("/api/installations/{installation_id}/redteam/targets")
    def list_targets(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            redteam_plan(s, principal, installation_id)
            rows = s.scalars(select(RedTeamTarget).where(RedTeamTarget.installation_id == installation_id)
                             .order_by(RedTeamTarget.id.desc())).all()
            return [_target_out(t) for t in rows]

    @app.post("/api/installations/{installation_id}/redteam/targets/{target_id}/verify")
    def verify_target(installation_id: int, target_id: int, principal: Principal = Depends(auth)):
        with db.session() as s, s.begin():
            tgt = visible_target(s, principal, installation_id, target_id)
            token = _target_token(installation_id, tgt.host)
            method = "http" if demo.is_demo(installation_id) else ownership.verify(tgt.host, token)
            tgt.verified_method = method
            tgt.verified_at = utcnow() if method else None
            if not method:
                raise HTTPException(status_code=409, detail="no se pudo comprobar la propiedad del dominio todavía")
            db.audit(installation_id, principal.login, "redteam.verified", tgt.host, {"method": method}, session=s)
            return _target_out(tgt)

    @app.delete("/api/installations/{installation_id}/redteam/targets/{target_id}", status_code=204)
    def delete_target(installation_id: int, target_id: int, principal: Principal = Depends(auth)):
        with db.session() as s, s.begin():
            tgt = visible_target(s, principal, installation_id, target_id)
            host = tgt.host
            s.delete(tgt)
        db.audit(installation_id, principal.login, "redteam.target_deleted", host, {"id": target_id})
        return Response(status_code=204)

    @app.post("/api/installations/{installation_id}/redteam/targets/{target_id}/runs", status_code=201)
    def start_redteam(installation_id: int, target_id: int, principal: Principal = Depends(auth)):
        with db.session() as s, s.begin():
            tgt = visible_target(s, principal, installation_id, target_id)
            if not tgt.verified_method:
                raise HTTPException(status_code=409, detail="verifica la propiedad del dominio antes de lanzarlo")
            if s.scalars(select(RedTeamRun.id).where(RedTeamRun.target_id == target_id,
                         RedTeamRun.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]))).first():
                raise HTTPException(status_code=409, detail="ya hay una ejecución en curso para este objetivo")
            run = RedTeamRun(target_id=target_id, installation_id=installation_id, requested_by=principal.login)
            s.add(run)
            s.flush()
            run_id = run.id
        if demo.is_demo(installation_id):
            with db.session() as s, s.begin():
                demo.run_demo_redteam(db, s.get(RedTeamRun, run_id), s.get(RedTeamTarget, target_id))
        db.audit(installation_id, principal.login, "redteam.run_started", str(target_id), {"run": run_id})
        with db.session() as s:
            return _run_out(s.get(RedTeamRun, run_id), db.cipher)

    @app.get("/api/installations/{installation_id}/redteam/runs")
    def list_redteam_runs(installation_id: int, target_id: int = 0, principal: Principal = Depends(auth)):
        with db.session() as s:
            redteam_plan(s, principal, installation_id)
            q = select(RedTeamRun).where(RedTeamRun.installation_id == installation_id).order_by(RedTeamRun.id.desc())
            if target_id:
                q = q.where(RedTeamRun.target_id == target_id)
            return [_run_out(r, db.cipher, detail=False) for r in s.scalars(q).all()]

    @app.get("/api/installations/{installation_id}/redteam/runs/{run_id}")
    def get_redteam_run(installation_id: int, run_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            redteam_plan(s, principal, installation_id)
            run = s.get(RedTeamRun, run_id)
            if run is None or run.installation_id != installation_id:
                raise HTTPException(status_code=404, detail="ejecución no encontrada")
            return _run_out(run, db.cipher)

    # -- avisos a Slack (RF-4.8) ------------------------------------------------------------------

    def _slack_url(inst: Installation) -> str:
        return (unseal(db.cipher, inst.slack_webhook) or {}).get("url", "")

    @app.get("/api/installations/{installation_id}/notifications")
    def get_notifications(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            return {"slack_connected": bool(_slack_url(inst))}

    @app.patch("/api/installations/{installation_id}/notifications")
    def set_notifications(installation_id: int, data: NotificationsIn, principal: Principal = Depends(auth)):
        url = data.slack_webhook.strip()
        if url and not url.startswith("https://hooks.slack.com/"):
            raise HTTPException(status_code=422, detail="el webhook debe empezar por https://hooks.slack.com/")
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            inst.slack_webhook = seal(db.cipher, {"url": url}) if url else {}
            db.audit(installation_id, principal.login, "notifications.changed", "slack",
                     {"connected": bool(url)}, session=s)
            return {"slack_connected": bool(url)}

    @app.post("/api/installations/{installation_id}/notifications/test")
    def test_notifications(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            url = _slack_url(inst)
            lang = principal_lang(inst)
        if not url:
            raise HTTPException(status_code=409, detail="no hay ningún webhook de Slack configurado")
        ok = slack.post(url, *notify.test_message(lang))
        if not ok:
            raise HTTPException(status_code=502, detail="Slack no aceptó el mensaje de prueba")
        return {"ok": True}

    # -- integración con Jira (RF-4.8) ------------------------------------------------------------

    # -- integraciones de destino de hallazgos: Jira y GitLab (RF-4.8) ----------------------------

    def _cfg(inst: Installation, provider: str) -> dict:
        return unseal(db.cipher, getattr(inst, f"{provider}_config")) or {}

    def _public(provider: str, cfg: dict) -> dict:
        """Estado de una integración sin el token (nunca se devuelve el secreto)."""
        out = {"configured": bool(cfg), "auto": bool(cfg.get("auto"))}
        if provider == "jira":
            out.update(base_url=cfg.get("base_url", ""), project_key=cfg.get("project_key", ""))
        elif provider == "gitlab":
            out.update(base_url=cfg.get("base_url", ""), project=cfg.get("project", ""))
        else:  # bitbucket
            out.update(workspace=cfg.get("workspace", ""), repo=cfg.get("repo", ""))
        return out

    @app.get("/api/installations/{installation_id}/integrations")
    def get_integrations(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            return {"slack": {"connected": bool((unseal(db.cipher, inst.slack_webhook) or {}).get("url"))},
                    "jira": _public("jira", _cfg(inst, "jira")),
                    "gitlab": _public("gitlab", _cfg(inst, "gitlab")),
                    "bitbucket": _public("bitbucket", _cfg(inst, "bitbucket"))}

    @app.patch("/api/installations/{installation_id}/jira")
    def set_jira(installation_id: int, data: JiraConfigIn, principal: Principal = Depends(auth)):
        base = data.base_url.strip().rstrip("/")
        filled = [bool(base), bool(data.email.strip()), bool(data.token.strip()), bool(data.project_key.strip())]
        if any(filled) and not all(filled):
            raise HTTPException(status_code=422, detail="faltan datos de Jira (URL, email, token y proyecto)")
        if base and not base.startswith("https://"):
            raise HTTPException(status_code=422, detail="la URL de Jira debe ser https")
        cfg = {"base_url": base, "email": data.email.strip(), "token": data.token.strip(),
               "project_key": data.project_key.strip(), "auto": data.auto} if all(filled) else {}
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            inst.jira_config = seal(db.cipher, cfg) if cfg else {}
            db.audit(installation_id, principal.login, "jira.changed", cfg.get("project_key", ""),
                     {"configured": bool(cfg), "auto": bool(cfg.get("auto"))}, session=s)
            return _public("jira", cfg)

    @app.post("/api/installations/{installation_id}/jira/test")
    def test_jira(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            cfg = _cfg(visible_installation(s, principal, installation_id), "jira")
        if not cfg:
            raise HTTPException(status_code=409, detail="Jira no está configurado")
        if not Jira(cfg["base_url"], cfg["email"], cfg["token"]).check(cfg["project_key"]):
            raise HTTPException(status_code=502, detail="Jira no aceptó las credenciales o el proyecto")
        return {"ok": True}

    @app.patch("/api/installations/{installation_id}/gitlab")
    def set_gitlab(installation_id: int, data: GitlabConfigIn, principal: Principal = Depends(auth)):
        base = (data.base_url.strip().rstrip("/") or "https://gitlab.com")
        filled = [bool(data.token.strip()), bool(data.project.strip())]
        if any(filled) and not all(filled):
            raise HTTPException(status_code=422, detail="faltan datos de GitLab (token y proyecto)")
        if not base.startswith("https://"):
            raise HTTPException(status_code=422, detail="la URL de GitLab debe ser https")
        cfg = {"base_url": base, "token": data.token.strip(), "project": data.project.strip(),
               "auto": data.auto} if all(filled) else {}
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            inst.gitlab_config = seal(db.cipher, cfg) if cfg else {}
            db.audit(installation_id, principal.login, "gitlab.changed", cfg.get("project", ""),
                     {"configured": bool(cfg), "auto": bool(cfg.get("auto"))}, session=s)
            return _public("gitlab", cfg)

    @app.post("/api/installations/{installation_id}/gitlab/test")
    def test_gitlab(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            cfg = _cfg(visible_installation(s, principal, installation_id), "gitlab")
        if not cfg:
            raise HTTPException(status_code=409, detail="GitLab no está configurado")
        if not Gitlab(cfg["base_url"], cfg["token"]).check(cfg["project"]):
            raise HTTPException(status_code=502, detail="GitLab no aceptó el token o el proyecto")
        return {"ok": True}

    def _create_issue(provider: str, scan_id: int, fingerprint: str, principal: Principal) -> dict:
        with db.session() as s:
            scan = visible_scan(s, principal, scan_id)
            repo = s.get(Repository, scan.repository_id)
            inst = s.get(Installation, repo.installation_id)
            cfg, lang, repo_name, inst_id = _cfg(inst, provider), principal_lang(inst), repo.full_name, inst.id
            result = unseal(db.cipher, scan.result) if scan.result else None
        if not cfg:
            raise HTTPException(status_code=409, detail=f"{provider} no está configurado")
        finding = next((f for f in (result or {}).get("findings", []) if f.get("fingerprint") == fingerprint), None)
        if finding is None:
            raise HTTPException(status_code=404, detail="hallazgo no encontrado en este escaneo")
        try:
            issue = integrations.create_issue(provider, cfg, finding, repo_name, lang)
        except integrations.IntegrationError as e:
            log.warning("no se pudo crear la incidencia en %s: %s", provider, e)
            raise HTTPException(status_code=502, detail=f"{provider} no pudo crear la incidencia") from None
        if db.record_export(inst_id, provider, fingerprint, issue["key"], issue["url"]):
            db.audit(inst_id, principal.login, f"{provider}.issue_created", issue["key"],
                     {"scan": scan_id, "fingerprint": fingerprint})
        return issue

    @app.post("/api/scans/{scan_id}/jira")
    def create_jira_issue(scan_id: int, data: IssueIn, principal: Principal = Depends(auth)):
        return _create_issue("jira", scan_id, data.fingerprint, principal)

    @app.post("/api/scans/{scan_id}/gitlab")
    def create_gitlab_issue(scan_id: int, data: IssueIn, principal: Principal = Depends(auth)):
        return _create_issue("gitlab", scan_id, data.fingerprint, principal)

    @app.patch("/api/installations/{installation_id}/bitbucket")
    def set_bitbucket(installation_id: int, data: BitbucketConfigIn, principal: Principal = Depends(auth)):
        vals = [data.workspace.strip(), data.repo.strip(), data.username.strip(), data.app_password.strip()]
        if any(vals) and not all(vals):
            raise HTTPException(status_code=422, detail="faltan datos de Bitbucket (workspace, repo, usuario y app password)")
        cfg = {"workspace": vals[0], "repo": vals[1], "username": vals[2], "app_password": vals[3],
               "auto": data.auto} if all(vals) else {}
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            inst.bitbucket_config = seal(db.cipher, cfg) if cfg else {}
            db.audit(installation_id, principal.login, "bitbucket.changed", f"{cfg.get('workspace', '')}/{cfg.get('repo', '')}".strip("/"),
                     {"configured": bool(cfg), "auto": bool(cfg.get("auto"))}, session=s)
            return _public("bitbucket", cfg)

    @app.post("/api/installations/{installation_id}/bitbucket/test")
    def test_bitbucket(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            cfg = _cfg(visible_installation(s, principal, installation_id), "bitbucket")
        if not cfg:
            raise HTTPException(status_code=409, detail="Bitbucket no está configurado")
        if not Bitbucket(cfg["workspace"], cfg["repo"], cfg["username"], cfg["app_password"]).check():
            raise HTTPException(status_code=502, detail="Bitbucket no aceptó las credenciales o el repositorio")
        return {"ok": True}

    @app.post("/api/scans/{scan_id}/bitbucket")
    def create_bitbucket_issue(scan_id: int, data: IssueIn, principal: Principal = Depends(auth)):
        return _create_issue("bitbucket", scan_id, data.fingerprint, principal)

    # -- configuración de SSO (OIDC) por organización ---------------------------------------------

    @app.get("/api/installations/{installation_id}/sso")
    def get_sso(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            cfg = unseal(db.cipher, visible_installation(s, principal, installation_id).oidc_config) or {}
        return _sso_public(installation_id, cfg)

    def _sso_public(installation_id: int, cfg: dict) -> dict:
        domains = cfg.get("domains", [])
        return {"configured": bool(cfg), "issuer": cfg.get("issuer", ""), "client_id": cfg.get("client_id", ""),
                "domains": domains, "verified": [d for d in domains if d in cfg.get("verified", [])],
                "dns_records": {d: ownership.DNS_PREFIX + _sso_token(installation_id, d) for d in domains}}

    @app.patch("/api/installations/{installation_id}/sso")
    def set_sso(installation_id: int, data: SsoConfigIn, principal: Principal = Depends(auth)):
        issuer = data.issuer.strip().rstrip("/")
        domains = sorted({d.strip().lower() for d in data.domains if d.strip() and "." in d})
        filled = [bool(issuer), bool(data.client_id.strip()), bool(data.client_secret.strip()), bool(domains)]
        if any(filled) and not all(filled):
            raise HTTPException(status_code=422, detail="faltan datos de SSO (issuer, client_id, client_secret y dominios)")
        if issuer and not issuer.startswith("https://"):
            raise HTTPException(status_code=422, detail="el issuer debe ser https")
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            previous = unseal(db.cipher, inst.oidc_config) or {}
            # Los dominios ya verificados se conservan mientras sigan en la lista.
            cfg = {"issuer": issuer, "client_id": data.client_id.strip(), "client_secret": data.client_secret.strip(),
                   "domains": domains, "verified": [d for d in previous.get("verified", []) if d in domains]} \
                if all(filled) else {}
            inst.oidc_config = seal(db.cipher, cfg) if cfg else {}
            db.audit(installation_id, principal.login, "sso.changed", issuer,
                     {"configured": bool(cfg), "domains": domains}, session=s)
            return _sso_public(installation_id, cfg)

    @app.post("/api/installations/{installation_id}/sso/verify")
    def verify_sso_domain(installation_id: int, data: SsoVerifyIn, principal: Principal = Depends(auth)):
        """Verifica por DNS TXT que el dominio es de la organización antes de usarlo para el login SSO.

        Sin esto, cualquiera podría reclamar el dominio de otra empresa y mandar a sus empleados a su IdP.
        """
        domain = data.domain.strip().lower()
        with db.session() as s:
            cfg = unseal(db.cipher, visible_installation(s, principal, installation_id).oidc_config) or {}
        if domain not in cfg.get("domains", []):
            raise HTTPException(status_code=404, detail="ese dominio no está en la configuración de SSO")
        if any(domain in other.get("verified", []) for inst_id, other in _sso_configs() if inst_id != installation_id):
            raise HTTPException(status_code=409, detail="ese dominio ya está verificado por otra organización")
        record = ownership.DNS_PREFIX + _sso_token(installation_id, domain)
        if domain not in cfg.get("verified", []) and not ownership.verify_dns(domain, _sso_token(installation_id, domain)):
            raise HTTPException(status_code=422, detail=f"no encontramos el registro TXT {record} en {domain}")
        with db.session() as s, s.begin():
            inst = visible_installation(s, principal, installation_id)
            cfg = unseal(db.cipher, inst.oidc_config) or {}
            if domain in cfg.get("domains", []) and domain not in cfg.get("verified", []):
                cfg["verified"] = sorted({*cfg.get("verified", []), domain})
                inst.oidc_config = seal(db.cipher, cfg)
                db.audit(installation_id, principal.login, "sso.domain_verified", domain, session=s)
            return _sso_public(installation_id, cfg)

    # -- planes y facturación (RF-4.5) ------------------------------------------------------------

    def visible_installation(s, principal: Principal, installation_id: int) -> Installation:
        inst = s.get(Installation, installation_id) if principal.can_see(installation_id) else None
        if inst is None:
            raise HTTPException(status_code=404, detail="instalación no encontrada")
        return inst

    @app.get("/api/installations/{installation_id}/billing")
    def billing_status(installation_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            plan = plans.effective_plan(inst)
            limits = {**plan.__dict__, "services": sorted(plan.services)}
            return {"plan": plan.name, "subscribed": list(inst.modules or []), "status": inst.subscription_status,
                    "services": sorted(plan.services),
                    "trial_days_left": plans.trial_days_left(inst) if plan.name == "trial" else 0,
                    "ai_requests_left": plans.ai_requests_left(inst, plan), "limits": limits,
                    "can_manage": bool(inst.stripe_customer_id), "billing_enabled": stripe is not None}

    @app.post("/api/installations/{installation_id}/billing/checkout")
    def billing_checkout(installation_id: int, data: CheckoutIn, principal: Principal = Depends(auth)):
        unknown = set(data.items) - set(PURCHASABLE)
        if unknown:
            raise HTTPException(status_code=422, detail=f"no se puede contratar: {', '.join(sorted(unknown))}")
        prices = [settings.stripe_prices.get(i) for i in dict.fromkeys(data.items)]
        if stripe is None or not all(prices):
            raise HTTPException(status_code=503, detail="facturación no configurada")
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            customer = inst.stripe_customer_id
        try:
            url = stripe.checkout_url(prices, installation_id, customer, f"{settings.public_url}/app?billing=ok",
                                      f"{settings.public_url}/app?billing=cancel")
        except BillingError:
            log.exception("Stripe Checkout falló")
            raise HTTPException(status_code=502, detail="no se pudo iniciar el pago") from None
        db.audit(installation_id, principal.login, "billing.checkout", target=",".join(data.items))
        return {"url": url}

    @app.post("/api/installations/{installation_id}/billing/portal")
    def billing_portal(installation_id: int, principal: Principal = Depends(auth)):
        if stripe is None:
            raise HTTPException(status_code=503, detail="facturación no configurada")
        with db.session() as s:
            customer = visible_installation(s, principal, installation_id).stripe_customer_id
        if not customer:
            raise HTTPException(status_code=409, detail="esta organización aún no tiene suscripción")
        try:
            url = stripe.portal_url(customer, f"{settings.public_url}/app")
        except BillingError:
            log.exception("Stripe Portal falló")
            raise HTTPException(status_code=502, detail="no se pudo abrir la facturación") from None
        db.audit(installation_id, principal.login, "billing.portal")
        return {"url": url}

    @app.post("/webhooks/stripe", include_in_schema=False)
    async def stripe_webhook(request: Request, stripe_signature: str = Header(default="")):
        body = await request.body()
        try:
            event = verify_event(body, stripe_signature, settings.stripe_webhook_secret)
        except (BillingError, ValueError):
            raise HTTPException(status_code=400, detail="firma no válida") from None
        with db.session() as s, s.begin():
            outcome = apply_event(s, event, price_to_item)
        log.info("stripe %s %s -> %s", event.get("id"), event.get("type"), outcome)
        if outcome.get("installation") and "modules" in outcome:
            db.audit(outcome["installation"], "stripe", "billing.subscription", event.get("type", ""),
                     {"modules": outcome.get("modules"), "status": outcome.get("status")})
        return outcome

    @app.patch("/api/installations/{installation_id}/settings", dependencies=[Depends(require_admin)])
    def update_installation_settings(installation_id: int, data: InstallationSettingsIn):
        """El permiso para usar el feedback en la evaluación es contractual: lo activa operaciones."""
        with db.session() as s, s.begin():
            inst = s.get(Installation, installation_id)
            if inst is None:
                raise HTTPException(status_code=404, detail="instalación no encontrada")
            inst.eval_opt_in = data.eval_opt_in
            db.audit(installation_id, "admin", "settings.changed", "eval_opt_in", {"eval_opt_in": inst.eval_opt_in}, session=s)
            return {"id": inst.id, "eval_opt_in": inst.eval_opt_in}

    @app.get("/api/installations/{installation_id}/audit")
    def installation_audit(installation_id: int, limit: int = 100, principal: Principal = Depends(auth)):
        """Registro de auditoría de la organización (RF-4.8): lo ve cualquier usuario con acceso a ella."""
        limit = max(1, min(limit, 500))
        with db.session() as s:
            visible_installation(s, principal, installation_id)
            rows = s.scalars(select(AuditLog).where(AuditLog.installation_id == installation_id)
                             .order_by(AuditLog.id.desc()).limit(limit)).all()
            return [{"id": r.id, "actor": r.actor, "action": r.action, "target": r.target, "detail": r.detail,
                     "ip": r.ip, "at": r.created_at.isoformat() if r.created_at else None} for r in rows]

    @app.get("/api/feedback/export", dependencies=[Depends(require_admin)])
    def export_feedback():
        """Feedback de las instalaciones que lo autorizan, listo para ampliar evals/triage."""
        with db.session() as s:
            rows = s.execute(select(FindingFeedback).join(Installation, Installation.id == FindingFeedback.installation_id)
                             .where(Installation.eval_opt_in).order_by(FindingFeedback.id)).scalars().all()
            out = [{"rule_id": r.rule_id, "useful": r.useful, "comment": r.comment,
                    "suggested_label": "true_positive" if r.useful else "false_positive",
                    "finding": unseal(db.cipher, r.finding)} for r in rows]
        db.audit(None, "admin", "feedback.exported", detail={"rows": len(out)})
        return out

    @app.post("/api/scans/{scan_id}/fix-pr")
    def create_fix_pr(scan_id: int, principal: Principal = Depends(auth)):
        """Lo mismo que el botón "Abrir PR con fixes" del check de GitHub."""
        with db.session() as s, s.begin():
            scan = visible_scan(s, principal, scan_id)
            if scan.status != ScanStatus.COMPLETED.value:
                raise HTTPException(status_code=409, detail="el escaneo aún no ha terminado")
            try:
                return _fix_summary(request_fix(s, scan, principal.login), db.cipher)
            except PlanLimit as e:
                raise HTTPException(status_code=402, detail=str(e)) from None

    @app.get("/api/scans/{scan_id}/fix-pr")
    def get_fix_pr(scan_id: int, principal: Principal = Depends(auth)):
        with db.session() as s:
            visible_scan(s, principal, scan_id)
            fix = s.scalars(select(FixRequest).where(FixRequest.scan_id == scan_id)).first()
            if fix is None:
                raise HTTPException(status_code=404, detail="sin petición de corrección")
            return _fix_summary(fix, db.cipher)

    return app


def _pentest_summary(row: PentestRequest, cipher=None) -> dict:
    return {"id": row.id, "kind": row.kind, "target": row.target, "scope": row.scope,
            "preferred_dates": row.preferred_dates, "contact_email": row.contact_email, "status": row.status,
            "quote_eur": row.quote_eur, "requested_by": row.requested_by, "report": unseal(cipher, row.report) or {},
            "notes": row.notes, "accepted_at": row.accepted_at.isoformat() if row.accepted_at else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None}


def _run_out(run: RedTeamRun, cipher=None, detail: bool = True) -> dict:
    out = {"id": run.id, "target_id": run.target_id, "status": run.status, "summary": run.summary,
           "requested_by": run.requested_by, "error": run.error,
           "created_at": run.created_at.isoformat() if run.created_at else None,
           "finished_at": run.finished_at.isoformat() if run.finished_at else None}
    if detail:
        out["result"] = unseal(cipher, run.result) if run.result else None
    return out


def _fix_summary(fix: FixRequest, cipher=None) -> dict:
    return {"id": fix.id, "scan_id": fix.scan_id, "status": fix.status, "pr_url": fix.pr_url,
            "error": fix.error, "detail": unseal(cipher, fix.detail), "requested_by": fix.requested_by}


def _scan_summary(scan: Scan) -> dict:
    return {
        "id": scan.id, "kind": scan.kind, "status": scan.status, "head_sha": scan.head_sha,
        "services": scan.services, "requested_by": scan.requested_by,
        "pr_number": scan.pr_number, "summary": scan.summary, "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }

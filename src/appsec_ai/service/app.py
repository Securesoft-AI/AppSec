"""API web: webhooks de GitHub y API REST para el panel."""

from __future__ import annotations

import datetime as dt
import hmac
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

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
from appsec_ai.service.db import (Database, FindingFeedback, FixRequest, Installation, Repository, Scan, ScanStatus,
                                  WaitlistEntry, utcnow)
from appsec_ai.service.github import GitHubApp, GitHubError
from appsec_ai.service import plans
from appsec_ai.service.billing import BillingError, Stripe, apply_event, verify_event
from appsec_ai.service.webhooks import PlanLimit, handle_event, request_fix, verify_signature

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


class CheckoutIn(BaseModel):
    plan: str = Field(pattern="^(starter|team|business)$")


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
    db.create_all()
    app = FastAPI(title="appsec-ai", version="0.1.0", docs_url=None, redoc_url=None)
    admin_token = os.environ.get("ADMIN_API_TOKEN", "")
    auth = Authenticator(settings.session_secret, admin_token, settings.public_url)
    github = github or GitHubApp(settings.github_app_id, settings.github_private_key, settings.github_api_url)
    login_enabled = bool(settings.github_client_id and settings.github_client_secret and settings.session_secret)
    secure_cookies = settings.public_url.startswith("https://")
    callback_url = f"{settings.public_url}/auth/callback"
    if stripe is None and settings.stripe_secret_key:
        stripe = Stripe(settings.stripe_secret_key)
    price_to_plan = {price: plan for plan, price in settings.stripe_prices.items() if price}
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
        resp.set_cookie(SESSION_COOKIE, encode_session(settings.session_secret, user, installations),
                        max_age=SESSION_TTL, httponly=True, secure=secure_cookies, samesite="lax")
        log.info("login de %s con %d instalaciones", user["login"], len(installations))
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
            return {"login": principal.login, "admin": principal.admin,
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
            return [{"id": r.id, "full_name": r.full_name, "private": r.private, "active": r.active} for r in rows]

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
            return {"plan": plan.name, "subscribed_plan": inst.plan, "status": inst.subscription_status,
                    "trial_days_left": plans.trial_days_left(inst) if inst.plan not in plans.PAID else 0,
                    "ai_requests_left": plans.ai_requests_left(inst, plan), "limits": plan.__dict__,
                    "can_manage": bool(inst.stripe_customer_id), "billing_enabled": stripe is not None,
                    "plans": {name: {"price_eur": p.price_eur, "max_repos": p.max_repos}
                              for name, p in plans.PLANS.items()}}

    @app.post("/api/installations/{installation_id}/billing/checkout")
    def billing_checkout(installation_id: int, data: CheckoutIn, principal: Principal = Depends(auth)):
        price = settings.stripe_prices.get(data.plan)
        if stripe is None or not price:
            raise HTTPException(status_code=503, detail="facturación no configurada")
        with db.session() as s:
            inst = visible_installation(s, principal, installation_id)
            customer = inst.stripe_customer_id
        try:
            url = stripe.checkout_url(price, installation_id, customer, f"{settings.public_url}/app?billing=ok",
                                      f"{settings.public_url}/app?billing=cancel")
        except BillingError:
            log.exception("Stripe Checkout falló")
            raise HTTPException(status_code=502, detail="no se pudo iniciar el pago") from None
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
            return {"url": stripe.portal_url(customer, f"{settings.public_url}/app")}
        except BillingError:
            log.exception("Stripe Portal falló")
            raise HTTPException(status_code=502, detail="no se pudo abrir la facturación") from None

    @app.post("/webhooks/stripe", include_in_schema=False)
    async def stripe_webhook(request: Request, stripe_signature: str = Header(default="")):
        body = await request.body()
        try:
            event = verify_event(body, stripe_signature, settings.stripe_webhook_secret)
        except (BillingError, ValueError):
            raise HTTPException(status_code=400, detail="firma no válida") from None
        with db.session() as s, s.begin():
            outcome = apply_event(s, event, price_to_plan)
        log.info("stripe %s %s -> %s", event.get("id"), event.get("type"), outcome)
        return outcome

    @app.patch("/api/installations/{installation_id}/settings", dependencies=[Depends(require_admin)])
    def update_installation_settings(installation_id: int, data: InstallationSettingsIn):
        """El permiso para usar el feedback en la evaluación es contractual: lo activa operaciones."""
        with db.session() as s, s.begin():
            inst = s.get(Installation, installation_id)
            if inst is None:
                raise HTTPException(status_code=404, detail="instalación no encontrada")
            inst.eval_opt_in = data.eval_opt_in
            return {"id": inst.id, "eval_opt_in": inst.eval_opt_in}

    @app.get("/api/feedback/export", dependencies=[Depends(require_admin)])
    def export_feedback():
        """Feedback de las instalaciones que lo autorizan, listo para ampliar evals/triage."""
        with db.session() as s:
            rows = s.execute(select(FindingFeedback).join(Installation, Installation.id == FindingFeedback.installation_id)
                             .where(Installation.eval_opt_in).order_by(FindingFeedback.id)).scalars().all()
            return [{"rule_id": r.rule_id, "useful": r.useful, "comment": r.comment,
                     "suggested_label": "true_positive" if r.useful else "false_positive",
                     "finding": unseal(db.cipher, r.finding)} for r in rows]

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

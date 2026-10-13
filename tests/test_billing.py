"""Planes, límites de uso y facturación con Stripe (RF-4.5)."""
import datetime as dt
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service import plans  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.billing import Stripe  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan, utcnow  # noqa: E402
from appsec_ai.service.webhooks import handle_event  # noqa: E402

PUBLIC = "https://atalaya.example.com"
WHSEC = "whsec_test"
PRICES = {item: f"price_{item}" for item in ("sast", "sca", "secrets", "iac", "ai", "code", "supply", "complete")}


def inst(**kw):
    base = dict(modules=[], subscription_status="", trial_ends_at=None, usage_period="", ai_requests_used=0)
    return SimpleNamespace(**{**base, **kw})


def test_effective_plan_from_services_bundles_trial_and_cancellation():
    now = utcnow()
    trial = plans.effective_plan(inst(trial_ends_at=now + dt.timedelta(days=3)))
    assert trial.name == "trial" and trial.services == {"sast", "sca", "secrets", "iac", "ai"}
    free = plans.effective_plan(inst(trial_ends_at=now - dt.timedelta(days=1)))
    assert free.name == "free" and free.services == {"secrets", "sca"} and not free.ai_triage
    code = plans.effective_plan(inst(modules=["code"], subscription_status="active"))
    assert code.services == {"sast", "secrets"} and code.fix_pr and not code.compliance
    mixed = plans.effective_plan(inst(modules=["supply", "ai"], subscription_status="past_due"))
    assert mixed.services == {"sca", "iac", "ai"} and mixed.compliance and mixed.ai_requests_month == 4500
    assert plans.effective_plan(inst(modules=["complete"], subscription_status="canceled")).name == "free"
    assert plans.trial_days_left(inst(trial_ends_at=now + dt.timedelta(days=13, hours=2))) == 14
    assert plans.scan_services(code, ["sast", "iac"]) == ["sast"]  # lo no contratado no se ejecuta
    assert plans.scan_services(code, None) == ["sast", "secrets"]


def test_bundles_are_cheaper_than_their_services():
    from appsec_ai.services import BUNDLES, SERVICES, catalog, engines_for

    for b in BUNDLES.values():
        assert b.price_month_eur < b.list_price_eur
    assert not SERVICES["pentest"].is_scan and SERVICES["pentest"].price_from_eur
    assert engines_for(["ai", "sast"]) == ["ai-security", "opengrep"]
    assert [s["key"] for s in catalog("en")["services"]][-1] == "pentest"


def test_monthly_ai_budget_resets_each_month():
    i = inst(modules=["sast"], subscription_status="active")
    sast = plans.effective_plan(i)
    plans.record_ai_usage(i, 1490, now=dt.datetime(2026, 10, 30, tzinfo=dt.timezone.utc))
    assert plans.ai_requests_left(i, sast, now=dt.datetime(2026, 10, 31, tzinfo=dt.timezone.utc)) == 10
    assert plans.ai_requests_left(i, sast, now=dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)) == 1500
    assert plans.ai_requests_left(i, plans.FREE) == 0


def stripe_mock():
    calls = []

    def handler(request):
        calls.append((request.url.path, parse_qs(request.content.decode())))
        if request.url.path == "/v1/checkout/sessions":
            return httpx.Response(200, json={"url": "https://checkout.stripe.com/c/pay/cs_test"})
        if request.url.path == "/v1/billing_portal/sessions":
            return httpx.Response(200, json={"url": "https://billing.stripe.com/p/session"})
        return httpx.Response(404)
    return Stripe("sk_test", transport=httpx.MockTransport(handler)), calls


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC,
                        stripe_webhook_secret=WHSEC, stripe_prices=PRICES, github_webhook_secret="x")
    db = Database(settings.database_url)
    stripe, calls = stripe_mock()
    client = TestClient(create_app(settings, db, stripe=stripe), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=7, account_login="acme"), Installation(id=8, account_login="rival")])  # sin prueba: Free
        s.flush()
        s.add_all([Repository(id=70, installation_id=7, full_name="acme/a"),
                   Repository(id=71, installation_id=7, full_name="acme/b")])
    client.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7]))
    return client, db, calls


def signed(event: dict, secret=WHSEC, t=None):
    body = json.dumps(event).encode()
    t = t or int(time.time())
    sig = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {"Stripe-Signature": f"t={t},v1={sig}", "Content-Type": "application/json"}


def subscription_event(kind, prices=("price_code", "price_ai"), status="active", created=None, inst_id="7"):
    return {"id": "evt_1", "type": kind, "created": created or int(time.time()),
            "data": {"object": {"id": "sub_1", "customer": "cus_1", "status": status, "metadata": {"installation_id": inst_id},
                                "items": {"data": [{"price": {"id": p}} for p in prices]}}}}


def test_free_plan_limits_repos_pr_scans_and_weekly_full_scans(env):
    _, db, _ = env
    repo = {"id": 70, "full_name": "acme/a", "default_branch": "main"}
    with db.session() as s, s.begin():
        pr = {"action": "opened", "installation": {"id": 7}, "repository": repo,
              "pull_request": {"number": 1, "draft": False, "head": {"sha": "a1", "ref": "f"}}}
        assert handle_event(s, "pull_request", pr) == {"scan": None, "ignored": "plan free: sin escaneo en PRs"}
        push = lambda sha, r=repo: {"installation": {"id": 7}, "repository": r, "ref": "refs/heads/main", "after": sha}  # noqa: E731
        assert handle_event(s, "push", push("b1"))["scan"]
        assert "cada 7 días" in handle_event(s, "push", push("b2"))["ignored"]
        other = {"id": 71, "full_name": "acme/b", "default_branch": "main"}
        assert "máximo 1 repositorios" in handle_event(s, "push", push("c1", other))["ignored"]


def test_paid_features_return_402_on_free(env):
    client, db, _ = env
    with db.session() as s, s.begin():
        s.add(Scan(id=1, repository_id=70, kind="full", head_sha="a", status="completed", result={"findings": []}))
    assert client.get("/api/scans/1/report.pdf").status_code == 402
    r = client.post("/api/scans/1/fix-pr", headers={"Origin": PUBLIC})
    assert r.status_code == 402 and "free" in r.json()["detail"]


def test_checkout_portal_and_subscription_lifecycle(env):
    client, db, calls = env
    r = client.post("/api/installations/7/billing/checkout", json={"items": ["code", "ai"]}, headers={"Origin": PUBLIC})
    assert r.json()["url"].startswith("https://checkout.stripe.com/")
    form = calls[-1][1]
    assert form["line_items[0][price]"] == ["price_code"] and form["line_items[1][price]"] == ["price_ai"]
    assert form["client_reference_id"] == ["7"] and form["subscription_data[metadata][installation_id]"] == ["7"]
    assert client.post("/api/installations/8/billing/checkout", json={"items": ["sast"]},
                       headers={"Origin": PUBLIC}).status_code == 404
    assert client.post("/api/installations/7/billing/checkout", json={"items": ["pentest"]},
                       headers={"Origin": PUBLIC}).status_code == 422  # el pentest no es una suscripción
    assert client.post("/api/installations/7/billing/portal", headers={"Origin": PUBLIC}).status_code == 409

    # Volver de Stripe no cambia nada: el plan lo deciden los webhooks firmados.
    assert client.get("/api/installations/7/billing").json()["plan"] == "free"
    t0 = int(time.time())
    body, headers = signed({"id": "evt_0", "type": "checkout.session.completed", "created": t0,
                            "data": {"object": {"client_reference_id": "7", "customer": "cus_1", "subscription": "sub_1"}}})
    assert client.post("/webhooks/stripe", content=body, headers=headers).json()["linked"]
    body, headers = signed(subscription_event("customer.subscription.created", created=t0 + 1))
    assert client.post("/webhooks/stripe", content=body, headers=headers).json()["modules"] == ["ai", "code"]
    billing = client.get("/api/installations/7/billing").json()
    assert billing["plan"] == "paid" and billing["services"] == ["ai", "sast", "secrets"]
    assert billing["can_manage"] and billing["ai_requests_left"] == 4500
    assert client.post("/api/installations/7/billing/portal", headers={"Origin": PUBLIC}).json()["url"].startswith("https://billing")

    # Un evento antiguo que llega tarde no deshace el estado.
    body, headers = signed(subscription_event("customer.subscription.updated", prices=("price_sca",), created=t0))
    assert client.post("/webhooks/stripe", content=body, headers=headers).json() == {"ignored": "evento antiguo"}
    body, headers = signed(subscription_event("customer.subscription.deleted", status="canceled", created=t0 + 5))
    client.post("/webhooks/stripe", content=body, headers=headers)
    assert client.get("/api/installations/7/billing").json()["plan"] == "free"


def test_stripe_webhook_rejects_forged_or_replayed_events(env):
    client, db, _ = env
    event = subscription_event("customer.subscription.created", prices=("price_complete",))
    body, headers = signed(event, secret="whsec_otro")
    assert client.post("/webhooks/stripe", content=body, headers=headers).status_code == 400
    body, headers = signed(event, t=int(time.time()) - 3600)
    assert client.post("/webhooks/stripe", content=body, headers=headers).status_code == 400
    assert client.post("/webhooks/stripe", content=body).status_code == 400
    with db.session() as s:
        assert s.get(Installation, 7).modules == []


def test_new_installations_get_a_14_day_trial_with_every_service(env):
    _, db, _ = env
    with db.session() as s, s.begin():
        handle_event(s, "installation", {"action": "created", "installation": {"id": 9, "account": {"login": "nueva"}},
                                         "repositories": []})
    with db.session() as s:
        assert plans.effective_plan(s.get(Installation, 9)).name == "trial"

"""`appsec-ai doctor`: detecta configuración insegura o incompleta sin mostrar secretos."""
import httpx
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from appsec_ai.service import doctor
from appsec_ai.service.config import Settings


def pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def good(**kw) -> Settings:
    base = dict(public_url="https://atalaya.example.com", session_secret="s" * 64,
                data_encryption_key=Fernet.generate_key().decode(), database_url="postgresql+psycopg://u:p@db/x",
                github_app_id="123", github_private_key=pem(), github_webhook_secret="w" * 32,
                github_client_id="cid", github_client_secret="cs", stripe_secret_key="sk_live_abc",
                stripe_webhook_secret="whsec_x", scan_runner="runsc {src} {out}", staff_logins=frozenset({"ana"}),
                demo_login=False)
    base.update(kw)
    s = Settings(**{k: v for k, v in base.items() if k != "stripe_prices"})
    s.stripe_prices = {k: "price_1" for k in s.stripe_prices}
    return s


def by_name(checks):
    return {c.name: c for c in checks}


def test_complete_production_config_has_no_failures(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    checks = by_name(doctor.check_config(good()))
    assert all(c.status == doctor.OK for c in checks.values()), [c for c in checks.values() if c.status != "ok"]


def test_dangerous_production_settings_fail(monkeypatch):
    checks = by_name(doctor.check_config(good(demo_login=True, session_secret="corto", github_private_key="nope",
                                              database_url="sqlite:///x.db", scan_runner="docker run img")))
    for name in ("DEMO_LOGIN", "SESSION_SECRET", "GITHUB_APP", "DATABASE_URL", "SCAN_RUNNER"):
        assert checks[name].status == doctor.FAIL, name


def test_secrets_never_printed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-supersecreto")
    s = good(session_secret="z" * 40 + "SECRETO", stripe_secret_key="sk_live_SECRETO")
    text = doctor.render(doctor.check_config(s))
    assert "SECRETO" not in text and "supersecreto" not in text


def test_online_checks_use_read_only_calls(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    seen = []

    def handler(request):
        seen.append((request.method, request.url.host, request.url.path))
        if request.url.host == "api.github.com":
            assert request.headers["authorization"].startswith("Bearer ")
            return httpx.Response(200, json={"slug": "atalaya", "permissions": {"contents": "write", "checks": "write",
                                                                                "pull_requests": "write"}})
        if request.url.host == "api.anthropic.com":
            return httpx.Response(401)
        return httpx.Response(200, json={})
    checks = by_name(doctor.check_online(good(), transport=httpx.MockTransport(handler)))
    assert checks["GitHub (online)"].status == doctor.OK and "atalaya" in checks["GitHub (online)"].detail
    assert checks["GitHub permisos"].status == doctor.WARN and "members" in checks["GitHub permisos"].detail
    assert checks["Anthropic (online)"].status == doctor.FAIL
    assert checks["Stripe (online)"].status == doctor.OK
    assert {m for m, _, _ in seen} == {"GET"}

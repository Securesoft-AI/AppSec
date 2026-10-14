"""Registros de auditoría (RF-4.8): las acciones sensibles quedan registradas y aisladas por organización."""
import datetime as dt

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import AuditLog, Database, Installation, Repository, utcnow  # noqa: E402
from appsec_ai.service.github import GitHubApp  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}


def github_mock():
    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z"})
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": "head123abc456"})
        return httpx.Response(404)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return GitHubApp("123", key, transport=httpx.MockTransport(handler))


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url)
    c = TestClient(create_app(settings, db, github=github_mock()), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)),
                   Installation(id=8, account_login="other", trial_ends_at=utcnow() + dt.timedelta(days=5))])
        s.flush()
        s.add_all([Repository(id=70, installation_id=7, full_name="acme/shop", default_branch="main"),
                   Repository(id=80, installation_id=8, full_name="other/app", default_branch="main")])
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7]))
    c.db, c.settings = db, settings
    return c


def actions(client, installation_id):
    return [e["action"] for e in client.get(f"/api/installations/{installation_id}/audit").json()]


def test_sensitive_actions_are_recorded(client):
    client.patch("/api/repositories/70/services", headers=O, json={"services": ["sast", "secrets"]})
    client.post("/api/repositories/70/scans", headers=O, json={"services": ["sast"]})
    pid = client.post("/api/installations/7/pentests", headers=O,
                      json={"kind": "web", "target": "https://acme.com", "contact_email": "a@acme.com"}).json()["id"]

    recorded = actions(client, 7)
    assert "repo.services_changed" in recorded and "scan.requested" in recorded and "pentest.requested" in recorded
    entry = next(e for e in client.get("/api/installations/7/audit").json() if e["action"] == "scan.requested")
    assert entry["actor"] == "ana" and entry["target"] == "acme/shop" and entry["detail"]["services"] == ["sast"]
    assert str(pid)  # el pentest existe


def test_audit_is_isolated_per_installation(client):
    client.post("/api/repositories/70/scans", headers=O, json={"services": ["sast"]})
    # La instalación 8 no es de este usuario: 404, no fuga del registro.
    assert client.get("/api/installations/8/audit").status_code == 404
    # El registro de la 7 no contiene acciones de otras organizaciones.
    assert all(e["target"] != "other/app" for e in client.get("/api/installations/7/audit").json())


def test_audit_log_is_append_only_from_the_app(client):
    """No hay ningún endpoint para modificar o borrar entradas: solo se leen y se crean."""
    client.post("/api/repositories/70/scans", headers=O, json={"services": ["sast"]})
    with client.db.session() as s:
        [row] = s.query(AuditLog).all()
        rid = row.id
    assert client.request("DELETE", f"/api/installations/7/audit/{rid}", headers=O).status_code in (404, 405)
    assert client.patch(f"/api/installations/7/audit/{rid}", headers=O, json={}).status_code in (404, 405, 422)
    with client.db.session() as s:
        assert s.query(AuditLog).count() == 1  # intacto

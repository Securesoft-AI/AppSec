"""Solo quien administra la organización en GitHub cambia ajustes sensibles (SSO, integraciones, notificaciones)."""
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation  # noqa: E402
from appsec_ai.service.github import GitHubApp  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
INSTALLS = [{"id": 7, "account": {"login": "acme", "type": "Organization"}},
            {"id": 8, "account": {"login": "otra-org", "type": "Organization"}},
            {"id": 9, "account": {"login": "ana", "type": "User"}},
            {"id": 10, "account": {"login": "sin-permiso", "type": "Organization"}}]


def github_mock():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "gho_x"})
        if path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "ana"})
        if path == "/user/installations":
            return httpx.Response(200, json={"installations": INSTALLS})
        if path == "/user/memberships/orgs/acme":
            return httpx.Response(200, json={"role": "admin", "state": "active"})
        if path == "/user/memberships/orgs/otra-org":
            return httpx.Response(200, json={"role": "member", "state": "active"})
        return httpx.Response(403)   # la App sin el permiso Members: read
    return GitHubApp("123", "", transport=httpx.MockTransport(handler))


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_client_id="Iv1.abc",
                        github_client_secret="cs", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url)
    c = TestClient(create_app(settings, db, github=github_mock()), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=i["id"], account_login=i["account"]["login"]) for i in INSTALLS])
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    c.get("/auth/callback", params={"code": "c", "state": state}, follow_redirects=False)
    return c


def test_manage_flag_follows_github_role(client):
    manage = {i["id"]: i["manage"] for i in client.get("/api/me").json()["installations"]}
    assert manage == {7: True, 8: False, 9: True, 10: False}


def test_members_cannot_change_sensitive_settings(client):
    sso = {"issuer": "https://idp.example", "client_id": "c", "client_secret": "s", "domains": ["x.com"]}
    calls = [("patch", "/sso", sso), ("post", "/sso/verify", {"domain": "x.com"}),
             ("patch", "/notifications", {"slack_webhook": ""}), ("post", "/notifications/test", None),
             ("patch", "/jira", {}), ("post", "/jira/test", None), ("patch", "/gitlab", {}),
             ("post", "/gitlab/test", None), ("patch", "/bitbucket", {}), ("post", "/bitbucket/test", None)]
    for method, path, body in calls:
        r = getattr(client, method)(f"/api/installations/8{path}", headers=O, json=body)
        assert r.status_code == 403, (path, r.status_code)
    # Ver la configuración (sin secretos) sí pueden.
    assert client.get("/api/installations/8/sso").status_code == 200
    assert client.get("/api/installations/8/integrations").status_code == 200
    # El admin de la organización sí la cambia; una instalación ajena da 404, no 403.
    assert client.patch("/api/installations/7/sso", headers=O, json=sso).status_code == 200
    assert client.patch("/api/installations/99/sso", headers=O, json=sso).status_code == 404

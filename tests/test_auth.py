"""Login con GitHub y aislamiento entre clientes en la API del panel."""
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan  # noqa: E402
from appsec_ai.service.github import GitHubApp  # noqa: E402

PUBLIC = "https://atalaya.example.com"


def github_mock(user_installations=(7,), oauth_error=False):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/login/oauth/access_token":
            body = parse_qs(request.content.decode())
            assert body["client_secret"] == ["client-secret"]
            if oauth_error or body["code"] != ["buen-codigo"]:
                return httpx.Response(200, json={"error": "bad_verification_code"})
            return httpx.Response(200, json={"access_token": "gho_usuario"})
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "ana"})
        if request.url.path == "/user/installations":
            return httpx.Response(200, json={"installations": [{"id": i} for i in user_installations]})
        return httpx.Response(404)
    return GitHubApp("123", "", transport=httpx.MockTransport(handler)), calls


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "admin-token")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_client_id="Iv1.abc",
                        github_client_secret="client-secret", session_secret="s" * 64, public_url=PUBLIC,
                        github_webhook_secret="x")
    db = Database(settings.database_url)
    gh, calls = github_mock()
    client = TestClient(create_app(settings, db, github=gh), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=7, account_login="acme"), Installation(id=8, account_login="rival")])
        s.flush()
        s.add_all([Repository(id=70, installation_id=7, full_name="acme/shop"),
                   Repository(id=80, installation_id=8, full_name="rival/secret")])
        s.flush()
        s.add_all([Scan(id=1, repository_id=70, kind="full", head_sha="a", status="completed", result={"x": 1}),
                   Scan(id=2, repository_id=80, kind="full", head_sha="b", status="completed", result={"y": 2})])
    return settings, client, calls


def login(client, code="buen-codigo"):
    r = client.get("/auth/login", follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["redirect_uri"] == [f"{PUBLIC}/auth/callback"]
    return client.get("/auth/callback", params={"code": code, "state": q["state"][0]}, follow_redirects=False)


def test_github_login_scopes_api_to_user_installations(setup):
    _, client, calls = setup
    r = login(client)
    assert r.status_code == 302 and r.headers["location"] == "/app"
    cookie = r.headers["set-cookie"]
    assert SESSION_COOKIE in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "gho_usuario" not in cookie  # el token de GitHub no se guarda

    me = client.get("/api/me").json()
    assert me["login"] == "ana" and [i["account"] for i in me["installations"]] == ["acme"]
    assert [i["id"] for i in client.get("/api/installations").json()] == [7]
    assert client.get("/api/scans/1").json()["result"] == {"x": 1}
    # Lo de otro cliente no existe para este usuario.
    assert client.get("/api/scans/2").status_code == 404
    assert client.get("/api/repositories/80/scans").status_code == 404
    assert client.get("/api/installations/8/repositories").status_code == 404
    assert client.get("/api/waitlist").status_code == 403  # solo administradores


def test_login_rejects_forged_state_and_bad_codes(setup):
    _, client, _ = setup
    client.get("/auth/login", follow_redirects=False)
    assert client.get("/auth/callback", params={"code": "buen-codigo", "state": "inventado"}).status_code == 400
    assert login(client, code="malo").status_code == 502
    assert client.get("/api/me").status_code == 401


def test_cookie_writes_require_same_origin(setup):
    _, client, _ = setup
    login(client)
    assert client.post("/api/scans/1/fix-pr", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/scans/1/fix-pr").status_code == 403  # sin Origin ni Referer
    assert client.post("/api/scans/1/fix-pr", headers={"Origin": PUBLIC}).status_code == 200
    assert client.post("/api/scans/2/fix-pr", headers={"Origin": PUBLIC}).status_code == 404


def test_tampered_or_expired_sessions_are_rejected(setup):
    settings, client, _ = setup
    forged = encode_session("otra-clave" * 8, {"id": 1, "login": "ana"}, [7, 8])
    client.cookies.set(SESSION_COOKIE, forged)
    assert client.get("/api/me").status_code == 401
    import jwt
    expired = jwt.encode({"sub": "ana", "inst": [7], "exp": 1}, settings.session_secret, algorithm="HS256")
    client.cookies.set(SESSION_COOKIE, expired)
    assert client.get("/api/me").status_code == 401


def test_admin_token_still_works_for_operations(setup):
    _, client, _ = setup
    r = client.get("/api/installations", headers={"Authorization": "Bearer admin-token"})
    assert {i["id"] for i in r.json()} == {7, 8}


def test_login_disabled_without_configuration(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_client_id="")
    client = TestClient(create_app(settings))
    assert client.get("/auth/login", follow_redirects=False).status_code == 503

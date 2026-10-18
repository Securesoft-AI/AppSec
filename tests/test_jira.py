"""Integración con Jira (RF-4.8): cliente REST, configuración cifrada e incidencia desde un hallazgo."""
import base64
import datetime as dt
import json

import httpx
import pytest

from appsec_ai.service import jira

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.models import Category, Finding, ScanResult, Severity, Triage, Verdict  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, seal, unseal  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan, ScanStatus, utcnow  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
SITE = "https://acme.atlassian.net"


def jira_mock(captured):
    def handler(request):
        auth = request.headers.get("authorization", "")
        captured["auth"] = auth
        if request.url.path.startswith("/rest/api/3/project/"):
            key = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200 if key == "SEC" else 404, json={})
        if request.url.path == "/rest/api/3/issue" and request.method == "POST":
            captured["issue"] = json.loads(request.content)
            return httpx.Response(201, json={"key": "SEC-42"})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_client_creates_issue_with_basic_auth_and_adf():
    captured = {}
    client = jira.Jira(SITE, "me@acme.com", "tok", transport=jira_mock(captured))
    adf = jira.finding_adf({"severity": "high", "title": "SQLi", "file": "app.py", "line": 7, "rule_id": "r1",
                            "message": "injection", "triage": {"fix": "use params"}}, "acme/shop", "es")
    issue = client.create_issue("SEC", "x", adf, ["appsec-ai", "high"])
    assert issue == {"key": "SEC-42", "url": f"{SITE}/browse/SEC-42"}
    assert base64.b64decode(captured["auth"].split()[1]).decode() == "me@acme.com:tok"
    fields = captured["issue"]["fields"]
    assert fields["project"]["key"] == "SEC" and fields["description"]["type"] == "doc"
    assert "appsec-ai" in fields["labels"]


def test_client_check_and_errors():
    captured = {}
    client = jira.Jira(SITE, "me@acme.com", "tok", transport=jira_mock(captured))
    assert client.check("SEC") is True and client.check("NOPE") is False
    boom = jira.Jira(SITE, "m", "t", transport=httpx.MockTransport(lambda r: httpx.Response(401, text="no")))
    with pytest.raises(jira.JiraError):
        boom.create_issue("SEC", "x", {"type": "doc", "version": 1, "content": []}, [])


@pytest.fixture
def client(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    captured = {}
    monkeypatch.setattr("appsec_ai.service.app.Jira",
                        lambda base, email, token: jira.Jira(base, email, token, transport=jira_mock(captured)))
    c = TestClient(create_app(settings, db), base_url=PUBLIC)
    finding = Finding(engine="opengrep", rule_id="py.sqli", category=Category.SAST, severity=Severity.HIGH,
                      title="SQL injection", message="user input in query", file="app.py", line=10,
                      triage=Triage(verdict=Verdict.TRUE_POSITIVE, confidence=0.9, severity=Severity.HIGH,
                                    explanation="real", exploit_scenario="attacker...", fix="use params"))
    result = ScanResult(target="acme/shop", findings=[finding])
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)))
        s.flush()
        s.add(Repository(id=70, installation_id=7, full_name="acme/shop", default_branch="main"))
        s.add(Scan(id=500, repository_id=70, kind="full", head_sha="abc", status=ScanStatus.COMPLETED.value,
                   result=seal(db.cipher, result.model_dump(mode="json"))))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7]))
    c.db, c.captured, c.fingerprint = db, captured, finding.fingerprint
    return c


def test_configure_validate_and_encrypt(client):
    assert client.get("/api/installations/7/jira").json()["configured"] is False
    # Config incompleta -> 422.
    assert client.patch("/api/installations/7/jira", headers=O, json={"base_url": SITE}).status_code == 422
    # URL no https -> 422.
    assert client.patch("/api/installations/7/jira", headers=O, json={
        "base_url": "http://x", "email": "a@b.c", "token": "t", "project_key": "SEC"}).status_code == 422
    ok = client.patch("/api/installations/7/jira", headers=O, json={
        "base_url": SITE, "email": "me@acme.com", "token": "tok", "project_key": "SEC"}).json()
    assert ok == {"configured": True, "base_url": SITE, "project_key": "SEC"}
    with client.db.session() as s:
        stored = s.get(Installation, 7).jira_config
        assert "tok" not in json.dumps(stored) and unseal(client.db.cipher, stored)["token"] == "tok"


def test_create_issue_from_a_finding(client):
    assert client.post("/api/scans/500/jira", headers=O, json={"fingerprint": client.fingerprint}).status_code == 409
    client.patch("/api/installations/7/jira", headers=O, json={
        "base_url": SITE, "email": "me@acme.com", "token": "tok", "project_key": "SEC"})
    assert client.post("/api/installations/7/jira/test", headers=O).json() == {"ok": True}
    # Hallazgo inexistente -> 404.
    assert client.post("/api/scans/500/jira", headers=O, json={"fingerprint": "deadbeef"}).status_code == 404
    issue = client.post("/api/scans/500/jira", headers=O, json={"fingerprint": client.fingerprint}).json()
    assert issue["key"] == "SEC-42" and issue["url"].endswith("/browse/SEC-42")
    fields = client.captured["issue"]["fields"]
    assert "SQL injection" in fields["summary"] and "acme/shop" in fields["summary"]
    # La corrección del triage va en la descripción.
    assert "use params" in json.dumps(fields["description"])

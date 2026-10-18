"""Integraciones de destino de hallazgos (RF-4.8): Jira, GitLab, panel unificado y envío automático."""
import datetime as dt
import json

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.models import Category, Finding, ScanResult, Severity, Triage, Verdict  # noqa: E402
from appsec_ai.service import bitbucket as bb, gitlab as gl, integrations, jira as jr  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, seal, unseal  # noqa: E402
from appsec_ai.service.db import Database, Installation, IntegrationExport, Repository, Scan, ScanStatus, utcnow  # noqa: E402
from appsec_ai.service.worker import Worker  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
JIRA_SITE, GL_SITE = "https://acme.atlassian.net", "https://gitlab.com"


def jira_transport(sent):
    def h(request):
        if request.url.path.startswith("/rest/api/3/project/"):
            return httpx.Response(200, json={})
        if request.url.path == "/rest/api/3/issue":
            sent.append(("jira", json.loads(request.content)))
            return httpx.Response(201, json={"key": f"SEC-{len(sent)}"})
        return httpx.Response(404)
    return httpx.MockTransport(h)


def gitlab_transport(sent):
    def h(request):
        if request.method == "GET" and request.url.path.startswith("/api/v4/projects/"):
            return httpx.Response(200, json={"id": 1})
        if request.url.path.endswith("/issues"):
            sent.append(("gitlab", dict(httpx.QueryParams(request.content.decode()))))
            return httpx.Response(201, json={"iid": len(sent), "web_url": f"{GL_SITE}/acme/app/-/issues/{len(sent)}"})
        return httpx.Response(404)
    return httpx.MockTransport(h)


def bitbucket_transport(sent):
    def h(request):
        if request.url.path.endswith("/issues") and request.method == "POST":
            sent.append(("bitbucket", json.loads(request.content)))
            n = len(sent)
            return httpx.Response(201, json={"id": n, "links": {"html": {"href": f"https://bitbucket.org/ws/repo/issues/{n}"}}})
        if request.method == "GET":  # comprobación del repositorio
            return httpx.Response(200, json={"slug": "repo"})
        return httpx.Response(404)
    return httpx.MockTransport(h)


def sample_result():
    def mk(rule, sev):
        return Finding(engine="opengrep", rule_id=rule, category=Category.SAST, severity=sev, title=f"issue {rule}",
                       message="m", file="app.py", line=1,
                       triage=Triage(verdict=Verdict.TRUE_POSITIVE, confidence=0.9, severity=sev,
                                     explanation="e", exploit_scenario="x", fix="f"))
    return ScanResult(target="acme/app", findings=[mk("r.crit", Severity.CRITICAL), mk("r.high", Severity.HIGH),
                                                   mk("r.low", Severity.LOW)])


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    sent = []
    # Inyecta el transporte simulado en ambos clientes, estén donde estén importados.
    for mod in (integrations, "appsec_ai.service.app"):
        monkeypatch.setattr(f"{mod.__name__ if hasattr(mod, '__name__') else mod}.Jira",
                            lambda b, e, t: jr.Jira(b, e, t, transport=jira_transport(sent)))
        monkeypatch.setattr(f"{mod.__name__ if hasattr(mod, '__name__') else mod}.Gitlab",
                            lambda b, t: gl.Gitlab(b, t, transport=gitlab_transport(sent)))
        monkeypatch.setattr(f"{mod.__name__ if hasattr(mod, '__name__') else mod}.Bitbucket",
                            lambda w, r, u, p: bb.Bitbucket(w, r, u, p, transport=bitbucket_transport(sent)))
    c = TestClient(create_app(settings, db), base_url=PUBLIC)
    result = sample_result()
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)))
        s.flush()
        s.add(Repository(id=70, installation_id=7, full_name="acme/app", default_branch="main"))
        s.add(Scan(id=500, repository_id=70, kind="full", head_sha="abc", status=ScanStatus.COMPLETED.value,
                   result=seal(db.cipher, result.model_dump(mode="json"))))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7]))
    c.db, c.settings, c.sent, c.result = db, settings, sent, result
    return c


JIRA = {"base_url": JIRA_SITE, "email": "me@acme.com", "token": "t", "project_key": "SEC"}
GITLAB = {"base_url": GL_SITE, "token": "glpat-x", "project": "acme/app"}
BITBUCKET = {"workspace": "acme", "repo": "app", "username": "me", "app_password": "atbb-secret"}


def test_unified_integrations_endpoint(ctx):
    r = ctx.get("/api/installations/7/integrations").json()
    assert r == {"slack": {"connected": False},
                 "jira": {"configured": False, "base_url": "", "project_key": "", "auto": False},
                 "gitlab": {"configured": False, "base_url": "", "project": "", "auto": False},
                 "bitbucket": {"configured": False, "workspace": "", "repo": "", "auto": False}}


def test_gitlab_configure_and_create_issue(ctx):
    assert ctx.patch("/api/installations/7/gitlab", headers=O, json={"token": "x"}).status_code == 422  # incompleto
    ok = ctx.patch("/api/installations/7/gitlab", headers=O, json={**GITLAB, "auto": True}).json()
    assert ok == {"configured": True, "base_url": GL_SITE, "project": "acme/app", "auto": True}
    assert ctx.post("/api/installations/7/gitlab/test", headers=O).json() == {"ok": True}
    with ctx.db.session() as s:  # token cifrado
        assert "glpat-x" not in json.dumps(s.get(Installation, 7).gitlab_config)
    fp = ctx.result.findings[0].fingerprint
    issue = ctx.post("/api/scans/500/gitlab", headers=O, json={"fingerprint": fp}).json()
    assert issue["key"] == "#1" and issue["url"].endswith("/issues/1")
    # Deduplicado: crear otra vez el mismo hallazgo no abre una segunda incidencia.
    with ctx.db.session() as s:
        assert s.query(IntegrationExport).filter_by(provider="gitlab").count() == 1


def test_bitbucket_configure_and_create_issue(ctx):
    assert ctx.patch("/api/installations/7/bitbucket", headers=O, json={"workspace": "acme"}).status_code == 422
    ok = ctx.patch("/api/installations/7/bitbucket", headers=O, json={**BITBUCKET, "auto": True}).json()
    assert ok == {"configured": True, "workspace": "acme", "repo": "app", "auto": True}
    assert ctx.post("/api/installations/7/bitbucket/test", headers=O).json() == {"ok": True}
    with ctx.db.session() as s:  # app password cifrado
        assert "atbb-secret" not in json.dumps(s.get(Installation, 7).bitbucket_config)
    fp = ctx.result.findings[0].fingerprint
    issue = ctx.post("/api/scans/500/bitbucket", headers=O, json={"fingerprint": fp}).json()
    assert issue["key"] == "#1" and issue["url"].endswith("/issues/1")


def test_manual_create_is_deduplicated(ctx):
    ctx.patch("/api/installations/7/jira", headers=O, json=JIRA)
    fp = ctx.result.findings[0].fingerprint
    a = ctx.post("/api/scans/500/jira", headers=O, json={"fingerprint": fp}).json()
    ctx.post("/api/scans/500/jira", headers=O, json={"fingerprint": fp})  # otra vez
    with ctx.db.session() as s:
        assert s.query(IntegrationExport).filter_by(provider="jira").count() == 1
    assert a["key"].startswith("SEC-")


def test_auto_export_only_serious_findings_once(ctx):
    # Jira y GitLab con automático activado.
    ctx.patch("/api/installations/7/jira", headers=O, json={**JIRA, "auto": True})
    ctx.patch("/api/installations/7/gitlab", headers=O, json={**GITLAB, "auto": True})
    ctx.patch("/api/installations/7/bitbucket", headers=O, json={**BITBUCKET, "auto": True})
    worker = Worker(ctx.settings, ctx.db, github=None, scanner=lambda *a, **k: None, triager_factory=lambda n: None)
    findings = [f.model_dump(mode="json") for f in ctx.result.findings]
    worker._auto_export(7, findings, "acme/app", "es")
    with ctx.db.session() as s:
        # Solo los 2 graves (crítico + alto), no el bajo, por cada destino.
        assert s.query(IntegrationExport).filter_by(provider="jira").count() == 2
        assert s.query(IntegrationExport).filter_by(provider="gitlab").count() == 2
        assert s.query(IntegrationExport).filter_by(provider="bitbucket").count() == 2
    # Un segundo escaneo con los mismos hallazgos no crea nada nuevo.
    ctx.sent.clear()
    worker._auto_export(7, findings, "acme/app", "es")
    assert ctx.sent == []


def test_no_auto_when_toggle_off(ctx):
    ctx.patch("/api/installations/7/jira", headers=O, json={**JIRA, "auto": False})
    worker = Worker(ctx.settings, ctx.db, github=None, scanner=lambda *a, **k: None, triager_factory=lambda n: None)
    worker._auto_export(7, [f.model_dump(mode="json") for f in ctx.result.findings], "acme/app", "es")
    with ctx.db.session() as s:
        assert s.query(IntegrationExport).count() == 0


def test_markdown_from_code_is_inert():
    from appsec_ai.service.gitlab import finding_markdown
    evil = {"file": "a`b\n/close.py", "line": 3, "rule_id": "r", "severity": "high",
            "message": "ver [aquí](https://phish.example) ![x](https://t.example/p.png) @todos\n/confidential",
            "triage": {"exploit_scenario": "<img src=x onerror=alert(1)>", "fix": "/assign @atacante"}}
    md = finding_markdown(evil, "acme/app")
    assert "](" not in md and "<img" not in md.replace("\\<img", "")   # enlaces, imágenes y HTML escapados
    assert all(not line.startswith("/") for line in md.splitlines())
    assert "@todos" not in md and "@atacante" not in md
    assert "`a b /close.py:3`" in md


def test_issue_url_must_be_https(monkeypatch):
    from appsec_ai.service import integrations
    monkeypatch.setattr(integrations, "_create", lambda *a: {"key": "#1", "url": "javascript:alert(1)"})
    assert integrations.create_issue("gitlab", {}, {}, "r", "es") == {"key": "#1", "url": ""}

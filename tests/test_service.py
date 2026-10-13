import hashlib
import hmac
import json
import shutil
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.scanner import scan as run_scan  # noqa: E402
from appsec_ai.service import render  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan  # noqa: E402
from appsec_ai.service.github import GitHubApp, InstallationClient  # noqa: E402
from appsec_ai.service.worker import Worker  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"
SECRET = "webhook-secret"
REPO = {"id": 99, "full_name": "acme/shop", "private": True, "default_branch": "main"}
INSTALLATION = {"id": 7, "account": {"login": "acme", "type": "Organization"}}


@pytest.fixture
def private_key() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


@pytest.fixture
def env(tmp_path, private_key, monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "admin-token")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_app_id="123",
                        github_private_key=private_key, github_webhook_secret=SECRET, ai_triage=False,
                        workdir=str(tmp_path))
    db = Database(settings.database_url)
    client = TestClient(create_app(settings, db))
    return settings, db, client


def send(client, event: str, payload: dict, secret: str = SECRET):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/webhooks/github", content=body,
                       headers={"X-GitHub-Event": event, "X-Hub-Signature-256": sig,
                                "X-GitHub-Delivery": "d1", "Content-Type": "application/json"})


def install(client):
    return send(client, "installation", {"action": "created", "installation": INSTALLATION, "repositories": [REPO]})


def open_pr(client, sha="abc123", action="opened"):
    return send(client, "pull_request", {
        "action": action, "installation": {"id": 7}, "repository": REPO,
        "pull_request": {"number": 5, "draft": False, "head": {"sha": sha, "ref": "feature"}},
    })


# --- Webhooks ----------------------------------------------------------------------------

def test_rejects_bad_or_missing_signature(env):
    _, _, client = env
    assert send(client, "installation", {"action": "created"}, secret="otro").status_code == 401
    r = client.post("/webhooks/github", content=b"{}", headers={"X-GitHub-Event": "ping"})
    assert r.status_code == 401


def test_rejects_everything_without_configured_secret(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_webhook_secret="")
    client = TestClient(create_app(settings))
    assert send(client, "ping", {}).status_code == 401


def test_installation_and_pr_enqueue_idempotently(env):
    _, db, client = env
    assert install(client).json() == {"installation": 7, "repositories": 1}
    first = open_pr(client).json()["scan"]
    again = open_pr(client, action="synchronize").json()["scan"]  # reenvío del mismo commit
    assert first == again
    newer = open_pr(client, sha="def456", action="synchronize").json()["scan"]
    assert newer != first
    with db.session() as s:
        assert s.get(Installation, 7).account_login == "acme"
        assert s.get(Repository, 99).full_name == "acme/shop"
        assert s.query(Scan).count() == 2


def test_draft_prs_and_other_branches_are_ignored(env):
    _, db, client = env
    install(client)
    r = send(client, "pull_request", {"action": "opened", "installation": {"id": 7}, "repository": REPO,
                                      "pull_request": {"number": 1, "draft": True, "head": {"sha": "x"}}})
    assert r.json() == {"ignored": "draft"}
    r = send(client, "push", {"ref": "refs/heads/feature", "after": "x", "installation": {"id": 7}, "repository": REPO})
    assert "ignored" in r.json()
    r = send(client, "push", {"ref": "refs/heads/main", "after": "f00", "installation": {"id": 7}, "repository": REPO})
    assert r.json()["scan"]
    with db.session() as s:
        assert [(x.kind, x.head_sha) for x in s.query(Scan).all()] == [("full", "f00")]


def test_suspended_installation_does_not_scan(env):
    _, _, client = env
    install(client)
    send(client, "installation", {"action": "suspend", "installation": INSTALLATION})
    assert open_pr(client).json() == {"scan": None}


def test_admin_api_requires_token(env):
    _, _, client = env
    install(client)
    assert client.get("/api/installations").status_code == 401
    r = client.get("/api/installations", headers={"Authorization": "Bearer admin-token"})
    assert r.json() == [{"id": 7, "account": "acme", "plan": "free", "active": True}]


# --- Worker con GitHub simulado ---------------------------------------------------------------

class FakeGitHub:
    """Simula la API de GitHub y registra las llamadas."""

    def __init__(self, changed_files):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.changed_files = changed_files

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.calls.append((request.method, path, body))
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_installation_token", "expires_at": "2099-01-01T00:00:00Z"})
        if path.endswith("/check-runs") and request.method == "POST":
            return httpx.Response(201, json={"id": 555})
        if "/check-runs/" in path:
            return httpx.Response(200, json={})
        if path.endswith("/pulls/5/files"):
            return httpx.Response(200, json=[{"filename": f, "status": "modified"} for f in self.changed_files])
        if path.endswith("/issues/5/comments") and request.method == "GET":
            return httpx.Response(200, json=[])
        if path.endswith("/issues/5/comments") and request.method == "POST":
            return httpx.Response(201, json={"id": 1})
        return httpx.Response(404, json={"message": "no simulado"})


def make_worker(settings, db, fake, monkeypatch, clone=None):
    app = GitHubApp("123", settings.github_private_key, transport=httpx.MockTransport(fake.handler))

    def fake_clone(self, repo, sha, dest, timeout=300):
        shutil.copytree(FIXTURE, dest)
    monkeypatch.setattr(InstallationClient, "clone", clone or fake_clone)
    return Worker(settings, db, app, scanner=lambda p: run_scan(p, engines=["ai-security"]))


def test_worker_scans_pr_and_reports_only_changed_files(env, monkeypatch):
    settings, db, client = env
    install(client)
    scan_id = open_pr(client).json()["scan"]
    fake = FakeGitHub(changed_files=["app.py"])
    worker = make_worker(settings, db, fake, monkeypatch)

    assert worker.run_once() is True
    assert worker.run_once() is False  # cola vacía

    with db.session() as s:
        scan = s.get(Scan, scan_id)
        assert scan.status == "completed", scan.error
        assert scan.check_run_id == 555
        files = {f["file"] for f in scan.result["findings"]}
        assert files == {"app.py"}  # agent.ts no está en el PR
        assert scan.summary["conclusion"] == "failure"  # hay hallazgos critical

    patches = [b for m, p, b in fake.calls if m == "PATCH" and "/check-runs/555" in p]
    assert patches[-1]["conclusion"] == "failure"
    annotations = [a for b in patches for a in b["output"]["annotations"]]
    assert annotations and all(a["path"] == "app.py" for a in annotations)
    comment = next(b for m, p, b in fake.calls if m == "POST" and p.endswith("/issues/5/comments"))
    assert render.COMMENT_MARKER in comment["body"] and "app.py" in comment["body"]
    # El workdir temporal se borra siempre.
    assert not list(Path(settings.workdir).glob("appsec-ai-*"))


def test_worker_retries_then_fails_gracefully(env, monkeypatch):
    settings, db, client = env
    install(client)
    scan_id = open_pr(client).json()["scan"]
    fake = FakeGitHub(changed_files=["app.py"])

    def broken_clone(self, repo, sha, dest, timeout=300):
        raise RuntimeError("red caída")
    worker = make_worker(settings, db, fake, monkeypatch, clone=broken_clone)

    for _ in range(3):
        assert worker.run_once()
    assert not worker.run_once()
    with db.session() as s:
        scan = s.get(Scan, scan_id)
        assert scan.status == "failed" and "red caída" in scan.error and scan.attempts == 3
    created = [c for c in fake.calls if c[0] == "POST" and c[1].endswith("/check-runs")]
    assert len(created) == 1  # los reintentos reutilizan el mismo check
    assert fake.calls[-1][2]["conclusion"] == "neutral"


def test_check_rerun_requeues_scan(env, monkeypatch):
    settings, db, client = env
    install(client)
    scan_id = open_pr(client).json()["scan"]
    make_worker(settings, db, FakeGitHub(["app.py"]), monkeypatch).run_once()
    r = send(client, "check_run", {"action": "rerequested", "installation": {"id": 7}, "repository": REPO,
                                   "check_run": {"id": 555}})
    assert r.json() == {"scan": scan_id}
    with db.session() as s:
        assert s.get(Scan, scan_id).status == "queued"


def test_many_annotations_are_sent_in_chunks_of_50(private_key):
    fake = FakeGitHub([])
    gh = GitHubApp("123", private_key, transport=httpx.MockTransport(fake.handler)).installation(7)
    ann = [{"path": "a.py", "start_line": i + 1, "end_line": i + 1, "annotation_level": "warning",
            "title": "t", "message": "m"} for i in range(120)]
    gh.complete_check_run("acme/shop", 555, "failure", "t", "s", annotations=ann)
    patches = [b for m, p, b in fake.calls if m == "PATCH"]
    assert [len(b["output"]["annotations"]) for b in patches] == [50, 50, 20]
    assert "conclusion" not in patches[0] and patches[-1]["conclusion"] == "failure"


def test_clone_never_exposes_token_and_disables_symlinks(private_key, tmp_path, monkeypatch):
    fake = FakeGitHub([])
    gh = GitHubApp("123", private_key, transport=httpx.MockTransport(fake.handler)).installation(7)
    seen = []

    class Done:
        returncode, stderr = 0, ""

    def fake_run(cmd, cwd=None, env=None, **kw):
        seen.append((cmd, env))
        return Done()
    monkeypatch.setattr("appsec_ai.service.github.subprocess.run", fake_run)
    gh.clone("acme/shop", "abc123", tmp_path / "src")

    assert all("ghs_installation_token" not in " ".join(cmd) for cmd, _ in seen)
    env = seen[0][1]
    config = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert config["core.symlinks"] == "false"
    assert config["core.hooksPath"] == "/dev/null"
    assert seen[2][0][:4] == ["git", "fetch", "-q", "--depth"]


# --- Landing y lista de espera -------------------------------------------------------------

def test_landing_is_served_with_security_headers(env):
    _, _, client = env
    r = client.get("/")
    assert r.status_code == 200
    assert r.text.startswith("<!doctype html>") and "window.ATALAYA_LIVE = true" in r.text
    assert "<title>Atalaya</title>" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_waitlist_registers_validates_and_dedupes(env):
    _, _, client = env
    assert client.post("/api/waitlist", json={"email": "Ana@Empresa.com", "company": "ACME"}).status_code == 201
    assert client.post("/api/waitlist", json={"email": "ana@empresa.com"}).status_code == 200
    assert client.post("/api/waitlist", json={"email": "no-es-un-email"}).status_code == 422
    assert client.get("/api/waitlist").status_code == 401
    rows = client.get("/api/waitlist", headers={"Authorization": "Bearer admin-token"}).json()
    assert [(r["email"], r["company"]) for r in rows] == [("ana@empresa.com", "ACME")]


def test_waitlist_is_rate_limited(env):
    _, _, client = env
    codes = [client.post("/api/waitlist", json={"email": f"u{i}@x.com"}).status_code for i in range(7)]
    assert codes[:5] == [201] * 5 and codes[5:] == [429, 429]

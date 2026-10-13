import hashlib
import hmac
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

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
from appsec_ai.service.db import Database, FixRequest, Installation, Repository, Scan  # noqa: E402
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

    def __init__(self, changed_files, pulls_status=201):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.changed_files = changed_files
        self.pulls_status = pulls_status

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
        if "/git/commits/" in path and request.method == "GET":
            return httpx.Response(200, json={"sha": path.rsplit("/", 1)[1], "tree": {"sha": "basetree"}})
        if path.endswith("/git/trees"):
            return httpx.Response(201, json={"sha": "newtree"})
        if path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "newcommit"})
        if path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": body["ref"]})
        if path.endswith("/pulls") and request.method == "POST":
            if self.pulls_status != 201:
                return httpx.Response(self.pulls_status, json={"message": "Resource not accessible by integration"})
            return httpx.Response(201, json={"number": 6, "html_url": "https://github.com/acme/shop/pull/6"})
        return httpx.Response(404, json={"message": "no simulado"})


def make_worker(settings, db, fake, monkeypatch, clone=None, triager_factory=None):
    app = GitHubApp("123", settings.github_private_key, transport=httpx.MockTransport(fake.handler))

    def fake_clone(self, repo, sha, dest, timeout=300):
        shutil.copytree(FIXTURE, dest)
    monkeypatch.setattr(InstallationClient, "clone", clone or fake_clone)
    return Worker(settings, db, app, scanner=lambda p: run_scan(p, engines=["ai-security"]),
                  triager_factory=triager_factory)


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


def test_worker_reuses_triage_cache_per_repository(env, monkeypatch, tmp_path):
    from test_scanner import fake_client

    from appsec_ai.triage import Triager

    settings, db, client = env
    settings.ai_cache_dir = str(tmp_path / "aicache")
    install(client)
    clients = []

    def factory(max_requests):
        clients.append(fake_client())
        return Triager(client=clients[-1], max_requests=max_requests)

    worker = make_worker(settings, db, FakeGitHub(["app.py"]), monkeypatch, triager_factory=factory)
    open_pr(client, sha="a1")
    worker.run_once()
    open_pr(client, sha="a2", action="synchronize")
    worker.run_once()

    first, second = (len(c.beta.messages.calls) for c in clients)
    assert first == 2 and second == 1  # triage de app.py + resumen; después solo el resumen
    with db.session() as s:
        repo_id = s.query(Repository).one().id
    assert list((tmp_path / "aicache" / str(repo_id)).glob("*.json"))


class FakeClaude:
    """Triage: todo es un problema real. Corrección: quita el eval de app.py."""

    def __init__(self):
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls.append(kwargs)
        system, prompt = kwargs["system"][0]["text"], kwargs["messages"][0]["content"]
        if "Corriges vulnerabilidades" in system:
            text = json.dumps({"edits": [{"find": "    return eval(answer)", "replace": "    return answer"}],
                               "summary": "Se deja de evaluar la respuesta del modelo."})
        elif "format" in kwargs["output_config"]:
            n = prompt.count('"id":')
            text = json.dumps({"results": [{"id": i, "verdict": "true_positive", "severity": "high",
                                            "confidence": 0.9, "explanation": "e", "exploit_scenario": "x",
                                            "fix": "f", "fixed_code": ""} for i in range(n)]})
        else:
            text = "Resumen"
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=1, output_tokens=1, cache_read_input_tokens=0))


def press_fix_button(client, check_id=555):
    return send(client, "check_run", {"action": "requested_action", "installation": {"id": 7}, "repository": REPO,
                                      "check_run": {"id": check_id}, "sender": {"login": "ana"},
                                      "requested_action": {"identifier": "open_fix_pr"}})


def fix_worker(settings, db, fake, monkeypatch):
    from appsec_ai.triage import Triager

    claude = FakeClaude()
    return make_worker(settings, db, fake, monkeypatch,
                       triager_factory=lambda n: Triager(client=claude, max_requests=n)), claude


def test_fix_button_opens_pr_with_validated_fix(env, monkeypatch):
    settings, db, client = env
    install(client)
    open_pr(client)
    fake = FakeGitHub(["app.py"])
    worker, claude = fix_worker(settings, db, fake, monkeypatch)
    worker.run_once()

    completed = [b for m, p, b in fake.calls if m == "PATCH" and "/check-runs/555" in p][-1]
    assert completed["actions"][0]["identifier"] == "open_fix_pr"
    assert len(completed["actions"][0]["label"]) <= 20 and len(completed["actions"][0]["description"]) <= 40

    fix_id = press_fix_button(client).json()["fix"]
    assert press_fix_button(client).json()["fix"] == fix_id  # idempotente
    assert worker.run_once() is True

    tree = next(b for m, p, b in fake.calls if p.endswith("/git/trees"))
    assert tree["base_tree"] == "basetree"
    [entry] = tree["tree"]
    assert entry["path"] == "app.py" and entry["mode"] == "100644"
    assert "return eval(answer)" not in entry["content"] and "    return answer" in entry["content"]
    commit = next(b for m, p, b in fake.calls if p.endswith("/git/commits") and m == "POST")
    assert commit["parents"] == ["abc123"]
    ref = next(b for m, p, b in fake.calls if p.endswith("/git/refs"))
    assert ref == {"ref": f"refs/heads/appsec-ai/fix-abc123-{fix_id}-1", "sha": "newcommit"}
    pr = next(b for m, p, b in fake.calls if p.endswith("/pulls") and m == "POST")
    assert pr["base"] == "feature" and pr["head"] == f"appsec-ai/fix-abc123-{fix_id}-1"
    assert "Revísalas antes de fusionar" in pr["body"] and "app.py" in pr["body"]
    comment = [b for m, p, b in fake.calls if m == "POST" and p.endswith("/issues/5/comments")][-1]
    assert render.FIX_MARKER in comment["body"] and "pull/6" in comment["body"]

    with db.session() as s:
        fix = s.get(FixRequest, fix_id)
        assert fix.status == "completed" and fix.pr_url.endswith("/pull/6")
        assert fix.requested_by == "ana" and fix.detail["fixed"] == ["app.py"]
    r = client.get(f"/api/scans/{fix.scan_id}/fix-pr", headers={"Authorization": "Bearer admin-token"})
    assert r.json()["pr_url"].endswith("/pull/6")


def test_fix_without_write_permission_explains_and_does_not_retry(env, monkeypatch):
    settings, db, client = env
    install(client)
    open_pr(client)
    fake = FakeGitHub(["app.py"], pulls_status=403)
    worker, _ = fix_worker(settings, db, fake, monkeypatch)
    worker.run_once()
    fix_id = press_fix_button(client).json()["fix"]
    worker.run_once()
    assert worker.run_once() is False  # no se reencola
    with db.session() as s:
        fix = s.get(FixRequest, fix_id)
        assert fix.status == "failed" and "permiso" in fix.error and fix.attempts == 1
    comment = [b for m, p, b in fake.calls if m == "POST" and p.endswith("/issues/5/comments")][-1]
    assert "Contents: Read & write" in comment["body"]


def test_fix_button_ignores_other_repositories_and_actions(env, monkeypatch):
    settings, db, client = env
    install(client)
    open_pr(client)
    make_worker(settings, db, FakeGitHub(["app.py"]), monkeypatch).run_once()
    other = {**REPO, "id": 100, "full_name": "evil/repo"}
    r = send(client, "check_run", {"action": "requested_action", "installation": {"id": 7}, "repository": other,
                                   "check_run": {"id": 555}, "requested_action": {"identifier": "open_fix_pr"}})
    assert "ignored" in r.json()
    r = send(client, "check_run", {"action": "requested_action", "installation": {"id": 7}, "repository": REPO,
                                   "check_run": {"id": 555}, "requested_action": {"identifier": "otra"}})
    assert "ignored" in r.json()


def test_results_and_triage_cache_are_encrypted_at_rest(tmp_path, private_key, monkeypatch):
    from cryptography.fernet import Fernet
    from sqlalchemy import text

    from appsec_ai.service.crypto import Cipher

    monkeypatch.setenv("ADMIN_API_TOKEN", "admin-token")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", github_app_id="123",
                        github_private_key=private_key, github_webhook_secret=SECRET, ai_triage=False,
                        workdir=str(tmp_path), ai_cache_dir=str(tmp_path / "cache"))
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    client = TestClient(create_app(settings, db))
    install(client)
    scan_id = open_pr(client).json()["scan"]
    worker, _ = fix_worker(settings, db, FakeGitHub(["app.py"]), monkeypatch)
    worker.run_once()

    with db.engine.connect() as conn:
        raw = conn.execute(text("SELECT result FROM scans WHERE id = :i"), {"i": scan_id}).scalar_one()
    assert "eval(answer)" not in raw and "app.py" not in raw
    r = client.get(f"/api/scans/{scan_id}", headers={"Authorization": "Bearer admin-token"})
    assert any("eval(answer)" in f["snippet"] for f in r.json()["result"]["findings"])

    cached = list((tmp_path / "cache").rglob("*.json"))
    assert cached and all(b"true_positive" not in p.read_bytes() for p in cached)


def test_worker_publishes_in_the_installation_language(env, monkeypatch):
    settings, db, client = env
    install(client)
    open_pr(client)
    with db.session() as s, s.begin():
        s.get(Installation, 7).language = "en"
    fake = FakeGitHub(["app.py"])
    worker, claude = fix_worker(settings, db, fake, monkeypatch)
    worker.run_once()
    done = [b for m, p, b in fake.calls if m == "PATCH" and "/check-runs/555" in p][-1]
    assert "security finding" in done["output"]["title"] and done["actions"][0]["label"] == "Open fix PR"
    comment = next(b for m, p, b in fake.calls if m == "POST" and p.endswith("/issues/5/comments"))
    assert "Files changed" in comment["body"]
    assert "Idioma de respuesta: en" in claude.calls[0]["messages"][0]["content"]  # el triage, también en inglés


def test_ai_budget_is_enforced_and_consumed(env, monkeypatch):
    from appsec_ai.service import plans

    settings, db, client = env
    install(client)
    open_pr(client)
    with db.session() as s, s.begin():
        inst = s.get(Installation, 7)
        inst.plan, inst.subscription_status = "starter", "active"
        inst.usage_period, inst.ai_requests_used = plans.current_period(), 999
    fake = FakeGitHub(["app.py"])
    worker, claude = fix_worker(settings, db, fake, monkeypatch)
    worker.run_once()
    assert len(claude.calls) == 1  # solo queda 1 petición este mes: triage de app.py, sin resumen
    with db.session() as s:
        assert s.get(Installation, 7).ai_requests_used == 1000
    done = [b for m, p, b in fake.calls if m == "PATCH" and "/check-runs/555" in p][-1]
    assert "actions" not in done  # Starter no incluye el botón de fixes


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

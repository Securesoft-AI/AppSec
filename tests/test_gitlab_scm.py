"""GitLab como plataforma de código: conectar, añadir proyectos, webhooks, escaneo de MRs y estados de commit."""
import datetime as dt
import json
import shutil
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")
from cryptography.fernet import Fernet  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.scanner import scan as run_scan  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, unseal  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan, utcnow  # noqa: E402
from appsec_ai.service.gitlab_scm import GitlabSCM, project_id, repo_id  # noqa: E402
from appsec_ai.service.worker import Worker  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"
GL = "https://gitlab.example.com"


class FakeGitlab:
    """API v4 de GitLab simulada con lo que usa Atalaya."""

    def __init__(self):
        self.calls, self.statuses, self.notes, self.hooks = [], [], {}, []
        self.hook_status = 201

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, m = request.url.path.removeprefix("/api/v4"), request.method
        self.calls.append((m, path))
        if request.headers["private-token"] != "glpat-secreto":
            return httpx.Response(401)
        if path == "/user":
            return httpx.Response(200, json={"username": "atalaya-bot"})
        if path == "/projects" and m == "GET":
            return httpx.Response(200, json=[{"id": 42, "path_with_namespace": "acme/shop", "default_branch": "main",
                                              "visibility": "private"}])
        if path == "/projects/42":
            return httpx.Response(200, json={"id": 42, "path_with_namespace": "acme/shop", "default_branch": "main",
                                             "visibility": "private"})
        if path == "/projects/99":
            return httpx.Response(404)
        if path == "/projects/42/hooks":
            self.hooks.append(json.loads(request.content))
            return httpx.Response(self.hook_status, json={})
        if path == "/projects/42/repository/branches/main":
            return httpx.Response(200, json={"commit": {"id": "c0ffee" * 6 + "abcd"}})
        if path == "/projects/42/merge_requests/7/diffs":
            return httpx.Response(200, json=[{"new_path": "app.py", "deleted_file": False},
                                             {"new_path": "old.py", "deleted_file": True}])
        if path.startswith("/projects/42/statuses/"):
            self.statuses.append((path.rsplit("/", 1)[1], json.loads(request.content)))
            return httpx.Response(201, json={})
        if path == "/projects/42/merge_requests/7/notes" and m == "GET":
            return httpx.Response(200, json=list(self.notes.values()))
        if path == "/projects/42/merge_requests/7/notes" and m == "POST":
            n = {"id": len(self.notes) + 1, "body": json.loads(request.content)["body"],
                 "author": {"username": "atalaya-bot"}}
            self.notes[n["id"]] = n
            return httpx.Response(201, json=n)
        if path.startswith("/projects/42/merge_requests/7/notes/") and m == "PUT":
            nid = int(path.rsplit("/", 1)[1])
            self.notes[nid]["body"] = json.loads(request.content)["body"]
            return httpx.Response(200, json=self.notes[nid])
        return httpx.Response(404)

    def scm(self, base_url=GL, token="glpat-secreto"):
        return GitlabSCM(base_url, token, transport=httpx.MockTransport(self.handler))


@pytest.fixture
def ctx(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    gl = FakeGitlab()
    c = TestClient(create_app(settings, db, gitlab_scm=lambda b, t: gl.scm(b, t)), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=10)))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7], managed=[7]))
    c.db, c.settings, c.gl = db, settings, gl
    return c


def connect(ctx):
    r = ctx.patch("/api/installations/7/gitlab-scm", headers=O, json={"base_url": GL, "token": "glpat-secreto"})
    assert r.status_code == 200, r.text
    return r.json()


def test_ids_never_collide_with_github():
    assert repo_id(7, 42) < 0 and project_id(repo_id(7, 42)) == 42
    assert repo_id(7, 42) != repo_id(8, 42)


def test_connect_add_project_and_webhook(ctx):
    out = connect(ctx)
    assert out["configured"] and out["webhook_url"] == f"{PUBLIC}/webhooks/gitlab/7" and out["webhook_secret"]
    with ctx.db.session() as s:
        stored = s.get(Installation, 7).gitlab_scm
    assert "glpat-secreto" not in json.dumps(stored)          # cifrado
    projects = ctx.get("/api/installations/7/gitlab-scm/projects").json()
    assert projects == [{"id": 42, "path": "acme/shop", "default_branch": "main", "private": True, "linked": False}]
    r = ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42}).json()
    assert r["webhook"] == "created" and r["repository_id"] == repo_id(7, 42)
    hook = ctx.gl.hooks[0]
    assert hook["url"] == f"{PUBLIC}/webhooks/gitlab/7" and hook["token"] == out["webhook_secret"]
    assert hook["merge_requests_events"] and hook["push_events"]
    # Un proyecto que el token no ve no se puede añadir.
    assert ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 99}).status_code == 404
    assert ctx.get("/api/installations/7/gitlab-scm/projects").json()[0]["linked"] is True
    again = ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42}).json()
    assert again["webhook"] == "existing" and len(ctx.gl.hooks) == 1


def test_bad_token_is_rejected(ctx):
    r = ctx.patch("/api/installations/7/gitlab-scm", headers=O, json={"base_url": GL, "token": "otro"})
    assert r.status_code == 422 and "401" in r.json()["detail"]


def test_webhook_requires_token_and_known_project(ctx):
    secret = connect(ctx)["webhook_secret"]
    ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42})
    push = {"ref": "refs/heads/main", "after": "a" * 40, "project": {"id": 42}}
    url = "/webhooks/gitlab/7"
    assert ctx.post(url, json=push, headers={"X-Gitlab-Event": "Push Hook"}).status_code == 401
    assert ctx.post(url, json=push, headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "mal"}).status_code == 401
    assert ctx.post("/webhooks/gitlab/8", json=push, headers={"X-Gitlab-Event": "Push Hook",
                                                              "X-Gitlab-Token": secret}).status_code == 401
    h = {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": secret}
    assert ctx.post(url, json=push, headers=h).json()["scan"]
    assert ctx.post(url, json={**push, "ref": "refs/heads/dev"}, headers=h).json()["ignored"]
    assert ctx.post(url, json={**push, "project": {"id": 43}}, headers=h).json() == {"ignored": "proyecto no añadido"}
    mr = {"project": {"id": 42}, "object_attributes": {"action": "open", "iid": 7, "source_branch": "feat",
                                                       "last_commit": {"id": "b" * 40}}}
    out = ctx.post(url, json=mr, headers={**h, "X-Gitlab-Event": "Merge Request Hook"}).json()
    with ctx.db.session() as s:
        scan = s.get(Scan, out["scan"])
        assert scan.kind == "pull_request" and scan.pr_number == 7 and scan.head_sha == "b" * 40


def test_scan_now_uses_gitlab_branch(ctx):
    connect(ctx)
    ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42})
    r = ctx.post(f"/api/repositories/{repo_id(7, 42)}/scans", headers=O, json={})
    assert r.status_code == 200, r.text
    with ctx.db.session() as s:
        assert s.get(Scan, r.json()["id"]).head_sha.startswith("c0ffee")


def test_worker_scans_mr_posts_note_and_status(ctx, monkeypatch):
    secret = connect(ctx)["webhook_secret"]
    ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42})
    mr = {"project": {"id": 42}, "object_attributes": {"action": "open", "iid": 7, "source_branch": "feat",
                                                       "last_commit": {"id": "b" * 40}}}
    scan_id = ctx.post("/webhooks/gitlab/7", json=mr, headers={"X-Gitlab-Event": "Merge Request Hook",
                                                               "X-Gitlab-Token": secret}).json()["scan"]
    monkeypatch.setattr(GitlabSCM, "clone", lambda self, path, sha, dest, timeout=300: shutil.copytree(FIXTURE, dest))
    scanner = lambda p, only_files=None, engines=None: run_scan(p, engines=["ai-security"], only_files=only_files)  # noqa: E731
    worker = Worker(ctx.settings, ctx.db, github=None, scanner=scanner, triager_factory=lambda n: None,
                    gitlab_factory=lambda inst: ctx.gl.scm())
    worker.process(scan_id)
    with ctx.db.session() as s:
        scan = s.get(Scan, scan_id)
        assert scan.status == "completed" and scan.check_run_id is None
        result = unseal(ctx.db.cipher, scan.result)
    assert {f["file"] for f in result["findings"]} <= {"app.py"}       # solo los ficheros de la MR
    states = [st["state"] for sha, st in ctx.gl.statuses if sha == "b" * 40]
    assert states[0] == "running" and states[-1] in ("success", "failed")
    assert len(ctx.gl.notes) == 1
    worker.process(scan_id)                                            # reintento: actualiza la nota, no duplica
    assert len(ctx.gl.notes) == 1


def test_disconnect_deactivates_projects(ctx):
    connect(ctx)
    ctx.post("/api/installations/7/gitlab-scm/projects", headers=O, json={"project_id": 42})
    ctx.patch("/api/installations/7/gitlab-scm", headers=O, json={"token": ""})
    with ctx.db.session() as s:
        assert s.get(Repository, repo_id(7, 42)).active is False


def test_clone_keeps_token_out_of_argv_and_blocks_internal_hosts(tmp_path, monkeypatch):
    from appsec_ai.service import gitlab_scm
    calls = []

    def fake_run(cmd, cwd, env, capture_output, text, timeout):
        calls.append((cmd, env))
        return type("P", (), {"returncode": 0, "stderr": ""})()
    monkeypatch.setattr(gitlab_scm.subprocess, "run", fake_run)
    monkeypatch.delenv("EGRESS_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(gitlab_scm, "is_public_host", lambda host: host == "gitlab.example.com")
    GitlabSCM(GL, "glpat-secreto").clone("acme/shop", "a" * 40, tmp_path / "src")
    assert all("glpat-secreto" not in " ".join(cmd) for cmd, _ in calls)
    env = calls[0][1]
    assert env["GIT_CONFIG_VALUE_1"] == "false" and env["GIT_CONFIG_VALUE_3"] == "never"   # sin symlinks ni file://
    assert any("http.followRedirects=false" in cmd for cmd, _ in calls[1:3])
    with pytest.raises(gitlab_scm.GitlabSCMError):
        GitlabSCM("https://gitlab.interno", "t").clone("a/b", "a" * 40, tmp_path / "x")

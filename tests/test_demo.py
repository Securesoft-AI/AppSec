"""Login de demostración (DEMO_LOGIN=1) con organización y código de ejemplo."""
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation  # noqa: E402

PUBLIC = "http://localhost:8000"


def make(tmp_path, demo=True):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64,
                        public_url=PUBLIC, demo_login=demo)
    db = Database(settings.database_url)
    return TestClient(create_app(settings, db), base_url=PUBLIC), db


def test_demo_login_shows_only_the_example_organization(tmp_path):
    client, db = make(tmp_path)
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="cliente-real"))
    assert client.get("/auth/config").json() == {"github": False, "demo": True}
    assert client.post("/auth/demo", json={"username": "user", "password": "mal"}).status_code == 401
    assert client.post("/auth/demo", json={"username": "user", "password": "pass"}).status_code == 200
    me = client.get("/api/me").json()
    assert me["login"] == "demo" and [i["account"] for i in me["installations"]] == ["demo-org"]
    assert client.get("/api/installations/7/repositories").status_code == 404
    assert client.get("/api/waitlist").status_code == 403

    d = client.get("/api/installations/1/dashboard").json()
    assert len(d["repositories"]) == 3 and d["by_severity"]["critical"] > 0
    [pentest] = client.get("/api/installations/1/pentests").json()
    assert pentest["status"] == "reported" and pentest["report"]["findings"]


def test_demo_scan_now_runs_immediately_with_chosen_services(tmp_path):
    client, _ = make(tmp_path)
    client.post("/auth/demo", json={"username": "user", "password": "pass"})
    r = client.post("/api/repositories/1003/scans", json={"services": ["ai"]}, headers={"Origin": PUBLIC})
    scan = r.json()
    assert scan["status"] == "completed" and scan["services"] == ["ai"]
    findings = client.get(f"/api/scans/{scan['id']}").json()["result"]["findings"]
    assert findings and {f["category"] for f in findings} == {"ai"}
    assert any(f["rule_id"] == "llm08-rag-without-access-filter" for f in findings)


def test_demo_login_is_off_by_default(tmp_path):
    client, db = make(tmp_path, demo=False)
    assert client.post("/auth/demo", json={"username": "user", "password": "pass"}).status_code == 404
    with db.session() as s:
        assert s.get(Installation, 1) is None  # sin datos de ejemplo

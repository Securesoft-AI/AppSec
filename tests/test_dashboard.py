"""Panel por organización (RF-4.3) y feedback útil / no útil (RF-3.8)."""
import datetime as dt
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from cryptography.fernet import Fernet  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.scanner import scan as run_scan  # noqa: E402
from appsec_ai.service import dashboard  # noqa: E402
from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, seal  # noqa: E402
from appsec_ai.service.db import Database, FindingFeedback, Installation, Repository, Scan, utcnow  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"
PUBLIC = "https://atalaya.example.com"
ADMIN = {"Authorization": "Bearer admin-token"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "admin-token")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    client = TestClient(create_app(settings, db), base_url=PUBLIC)
    result = run_scan(FIXTURE, engines=["ai-security"]).model_dump(mode="json")
    now = utcnow()
    with db.session() as s, s.begin():
        trial = utcnow() + dt.timedelta(days=14)
        s.add_all([Installation(id=7, account_login="acme", trial_ends_at=trial),
                   Installation(id=8, account_login="rival", trial_ends_at=trial)])
        s.flush()
        s.add_all([Repository(id=70, installation_id=7, full_name="acme/shop"),
                   Repository(id=71, installation_id=7, full_name="acme/empty"),
                   Repository(id=80, installation_id=8, full_name="rival/x")])
        s.flush()
        s.add_all([
            Scan(id=1, repository_id=70, kind="full", head_sha="a", status="completed", result=seal(db.cipher, result),
                 summary={"counts": {"critical": 5, "high": 1}}, finished_at=now - dt.timedelta(days=10)),
            Scan(id=2, repository_id=70, kind="full", head_sha="b", status="completed", result=seal(db.cipher, result),
                 summary={"counts": {"critical": 2, "high": 4, "medium": 6, "low": 2}}, finished_at=now - dt.timedelta(days=1)),
            Scan(id=3, repository_id=70, kind="pull_request", head_sha="c", status="completed", result={"findings": []},
                 summary={"counts": {}}, finished_at=now),  # un PR no cambia el estado de la rama principal
            Scan(id=4, repository_id=80, kind="full", head_sha="d", status="completed", result=seal(db.cipher, result),
                 summary={"counts": {"critical": 9}}, finished_at=now),
        ])
    client.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7]))
    return client, db, result


def test_dashboard_aggregates_latest_full_scan_per_repo(env):
    client, _, result = env
    d = client.get("/api/installations/7/dashboard").json()
    visible = [f for f in result["findings"] if not f.get("triage")]
    assert sum(d["by_severity"].values()) == len(visible)
    [repo] = d["repositories"]
    assert repo["full_name"] == "acme/shop" and repo["scan_id"] == 2 and repo["kind"] == "full"
    assert d["repositories_without_scans"] == ["acme/empty"]
    assert d["by_category"] == {"ai": len(visible)}
    assert any(c["kind"] == "llm_sdk" for c in d["ai_inventory"])
    assert not any(c["kind"] == "llm_entrypoint" for c in d["ai_inventory"])  # dato interno
    # Tendencia: 6 hallazgos hace 10 días, 14 desde ayer; solo escaneos completos de la organización.
    totals = [sum(p[k] for k in ("critical", "high", "medium", "low", "info")) for p in d["trend"]]
    assert len(totals) == dashboard.TREND_DAYS and totals[0] == 0 and totals[-11] == 6 and totals[-1] == 14
    assert client.get("/api/installations/8/dashboard").status_code == 404


def test_feedback_is_per_user_encrypted_and_exported_only_with_opt_in(env):
    client, db, result = env
    fp = client.get("/api/scans/2").json()["result"]["findings"][0]["fingerprint"]
    post = lambda body: client.post("/api/scans/2/feedback", json=body, headers={"Origin": PUBLIC})  # noqa: E731
    assert post({"fingerprint": fp, "useful": False, "comment": "es código de test"}).status_code == 200
    assert post({"fingerprint": fp, "useful": True}).status_code == 200  # cambiar de opinión no duplica
    assert post({"fingerprint": "no-existe", "useful": True}).status_code == 404
    assert client.post("/api/scans/4/feedback", json={"fingerprint": fp, "useful": True},
                       headers={"Origin": PUBLIC}).status_code == 404  # escaneo de otro cliente
    assert client.get("/api/scans/2").json()["feedback"] == {fp: True}
    with db.session() as s:
        [row] = s.query(FindingFeedback).all()
        assert row.useful is True and row.user_login == "ana" and "snippet" not in str(row.finding)

    assert client.get("/api/feedback/export", headers=ADMIN).json() == []  # sin permiso del cliente
    assert client.patch("/api/installations/7/settings", json={"eval_opt_in": True},
                        headers={"Origin": PUBLIC}).status_code == 403  # no lo decide un usuario cualquiera
    client.patch("/api/installations/7/settings", json={"eval_opt_in": True}, headers=ADMIN)
    [item] = client.get("/api/feedback/export", headers=ADMIN).json()
    assert item["suggested_label"] == "true_positive" and item["finding"]["fingerprint"] == fp


def test_panel_page_is_served_and_never_renders_data_as_html(env):
    client, _, _ = env
    r = client.get("/app")
    assert r.status_code == 200 and "Atalaya" in r.text
    assert "innerHTML" not in r.text and "insertAdjacentHTML" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_pdf_report_endpoint_respects_access(env):
    client, _, _ = env
    r = client.get("/api/scans/2/report.pdf?lang=en")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert r.headers["content-type"] == "application/pdf" and "acme-shop" in r.headers["content-disposition"]
    assert client.get("/api/scans/4/report.pdf").status_code == 404


def test_panel_language_and_installation_preference(env):
    client, db, _ = env
    es = client.get("/api/scans/2?lang=es").json()["result"]["findings"]
    en = client.get("/api/scans/2?lang=en").json()["result"]["findings"]
    assert any(f["title"].startswith("Salida del LLM") for f in es)
    assert any(f["title"].startswith("LLM output executed") for f in en)
    r = client.patch("/api/installations/7/preferences", json={"language": "en"}, headers={"Origin": PUBLIC})
    assert r.json() == {"id": 7, "language": "en"}
    assert client.get("/api/me").json()["installations"][0]["language"] == "en"
    assert client.patch("/api/installations/8/preferences", json={"language": "en"},
                        headers={"Origin": PUBLIC}).status_code == 404
    assert client.patch("/api/installations/7/preferences", json={"language": "fr"},
                        headers={"Origin": PUBLIC}).status_code == 422

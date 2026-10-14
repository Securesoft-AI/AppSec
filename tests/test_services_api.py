"""Control desde el panel: servicios por repositorio, escanear ahora y pentests."""
import datetime as dt

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation, Repository, Scan, utcnow  # noqa: E402
from appsec_ai.service.github import GitHubApp  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
ADMIN = {"Authorization": "Bearer admin-token"}


def github_mock():
    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z"})
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": "head123"})
        return httpx.Response(404)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return GitHubApp("123", key, transport=httpx.MockTransport(handler))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "admin-token")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC,
                        staff_logins=frozenset({"marta"}))
    db = Database(settings.database_url)
    c = TestClient(create_app(settings, db, github=github_mock()), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)),
                   Installation(id=8, account_login="free-co")])
        s.flush()
        s.add_all([Repository(id=70, installation_id=7, full_name="acme/shop", default_branch="main"),
                   Repository(id=80, installation_id=8, full_name="free-co/app", default_branch="main")])
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7, 8]))
    c.db, c.settings = db, settings
    return c


def test_catalog_is_public_and_bilingual(client):
    client.cookies.clear()
    es, en = client.get("/api/catalog").json(), client.get("/api/catalog?lang=en").json()
    assert [s["key"] for s in es["services"]] == ["sast", "sca", "secrets", "iac", "ai", "pentest"]
    assert en["services"][0]["name"] == "Code analysis (SAST)" and es["bundles"][-1]["key"] == "complete"


def test_user_chooses_services_per_repository(client):
    r = client.patch("/api/repositories/70/services", json={"services": ["ai", "sast"]}, headers=O)
    assert r.json() == {"id": 70, "services": ["sast", "ai"]}
    assert client.patch("/api/repositories/70/services", json={"services": ["dast"]}, headers=O).status_code == 422
    assert client.patch("/api/repositories/70/services", json={"services": None}, headers=O).json()["services"] is None


def test_scan_now_with_chosen_services_and_rerun(client):
    r = client.post("/api/repositories/70/scans", json={"services": ["secrets", "sca"]}, headers=O)
    body = r.json()
    assert r.status_code == 200 and body["kind"] == "manual" and body["head_sha"] == "head123"
    assert body["services"] == ["sca", "secrets"] and body["requested_by"] == "ana" and body["status"] == "queued"
    with client.db.session() as s, s.begin():
        s.get(Scan, body["id"]).status = "completed"
    again = client.post("/api/repositories/70/scans", json={"services": ["ai"]}, headers=O).json()
    assert again["id"] == body["id"] and again["status"] == "queued" and again["services"] == ["ai"]


def test_scan_now_respects_what_is_paid_for(client):
    r = client.post("/api/repositories/80/scans", json={"services": ["sast"]}, headers=O)
    assert r.status_code == 402 and "sast" in r.json()["detail"]
    assert client.post("/api/repositories/80/scans", json={"services": ["secrets"]}, headers=O).status_code == 200
    r = client.post("/api/repositories/80/scans", json={"services": ["secrets"]}, headers=O)
    assert r.status_code == 402 and "7 días" in r.json()["detail"]  # Free: un escaneo a la semana


def test_pentest_request_lifecycle(client):
    r = client.post("/api/installations/7/pentests", headers=O, json={
        "kind": "llm", "target": "https://chat.acme.com", "scope": "Chatbot de soporte y su RAG",
        "preferred_dates": "noviembre", "contact_email": "sec@acme.com"})
    assert r.status_code == 201
    pid = r.json()["id"]
    assert client.post("/api/installations/7/pentests", headers=O, json={
        "kind": "web", "target": "x.com", "contact_email": "no-es-email"}).status_code == 422
    assert client.patch(f"/api/admin/pentests/{pid}", json={"status": "reported"}, headers=O).status_code == 403
    report = {"summary": "2 vulnerabilidades altas", "findings": [{"title": "Prompt injection", "severity": "high"}]}
    client.patch(f"/api/admin/pentests/{pid}", json={"status": "reported", "quote_eur": 3500, "report": report}, headers=ADMIN)
    [p] = client.get("/api/installations/7/pentests").json()
    assert p["status"] == "reported" and p["quote_eur"] == 3500 and p["report"]["summary"] == report["summary"]
    assert p["report"]["findings"] == [{"title": "Prompt injection", "severity": "high", "description": "", "fix": ""}]
    assert client.get("/api/installations/9/pentests").status_code == 404


def test_pentest_quote_acceptance_team_view_and_report_pdf(client):
    base = "/api/installations/7/pentests"
    pid = client.post(base, headers=O, json={"kind": "api", "target": "https://api.acme.com",
                                             "contact_email": "sec@acme.com"}).json()["id"]
    other = client.post(base, headers=O, json={"kind": "web", "target": "https://acme.com",
                                               "contact_email": "sec@acme.com"}).json()["id"]
    # Un cliente no es del equipo.
    assert client.get("/api/me").json()["staff"] is False
    assert client.get("/api/admin/pentests").status_code == 403
    assert client.post(f"{base}/{pid}/accept", headers=O).status_code == 409  # aún sin presupuesto

    customer = client.cookies.get(SESSION_COOKIE)
    team = encode_session(client.settings.session_secret, {"id": 2, "login": "Marta"}, [], staff="all")
    client.cookies.set(SESSION_COOKIE, team)
    assert client.get("/api/me").json()["staff"] is True
    assert [p["account"] for p in client.get("/api/admin/pentests?status=requested").json()] == ["acme", "acme"]
    r = client.patch(f"/api/admin/pentests/{pid}", headers=O,
                     json={"status": "scoping", "quote_eur": 2900, "notes": "4 días, empezamos el lunes"})
    assert r.status_code == 200 and r.json()["notes"] == "4 días, empezamos el lunes"
    r = client.patch(f"/api/admin/pentests/{pid}", headers=O, json={"status": "scheduled"})
    assert r.status_code == 409  # el cliente no ha aceptado

    client.cookies.set(SESSION_COOKIE, customer)
    assert client.get(f"{base}/{pid}/report.pdf").status_code == 404
    accepted = client.post(f"{base}/{pid}/accept", headers=O).json()
    assert accepted["accepted_at"] and accepted["notes"] == "4 días, empezamos el lunes"
    assert client.post(f"{base}/{pid}/cancel", headers=O).status_code == 409  # aceptado: ya no se cancela aquí
    assert client.post(f"{base}/{other}/cancel", headers=O).json()["status"] == "cancelled"
    assert client.post(f"/api/installations/8/pentests/{pid}/accept", headers=O).status_code == 404

    client.cookies.set(SESSION_COOKIE, team)
    assert client.patch(f"/api/admin/pentests/{pid}", headers=O, json={"status": "in_progress"}).status_code == 200
    assert client.patch(f"/api/admin/pentests/{pid}", headers=O, json={"status": "reported"}).status_code == 422
    report = {"summary": "IDOR en /orders", "findings": [
        {"title": "IDOR en /orders/{id}", "severity": "high", "description": "Otro cliente ve pedidos.", "fix": "Comprobar el dueño."},
        {"title": "Cabeceras", "severity": "low"}]}
    assert client.patch(f"/api/admin/pentests/{pid}", headers=O,
                        json={"report": {**report, "findings": [{"title": "x", "severity": "grave"}]}}).status_code == 422
    r = client.patch(f"/api/admin/pentests/{pid}", headers=O, json={"status": "reported", "report": report})
    assert r.status_code == 200 and r.json()["status"] == "reported"
    # Un presupuesto nuevo hay que volver a aceptarlo.
    assert client.patch(f"/api/admin/pentests/{other}", headers=O, json={"quote_eur": 1}).json()["accepted_at"] is None

    client.cookies.set(SESSION_COOKIE, customer)
    [p] = [p for p in client.get(base).json() if p["id"] == pid]
    assert p["report"]["findings"][0]["fix"] == "Comprobar el dueño."
    pdf = client.get(f"{base}/{pid}/report.pdf?lang=en")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")


def test_staff_removed_from_config_loses_team_view(client):
    client.cookies.set(SESSION_COOKIE, encode_session(client.settings.session_secret, {"id": 3, "login": "luis"}, [],
                                                      staff="all"))
    assert client.get("/api/admin/pentests").status_code == 403  # "luis" no está en STAFF_LOGINS
    assert client.get("/api/me").json()["staff"] is False

"""Red teaming desde el panel (RF-2.7): objetivos, verificación del dominio, ejecución y gating por plan."""
import datetime as dt

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.db import Database, Installation, RedTeamRun, RedTeamTarget  # noqa: E402
from appsec_ai.service.worker import Worker  # noqa: E402
from appsec_ai import redteam  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    # Evita salir a la red al validar el host: el objetivo resuelve a una IP pública simulada.
    monkeypatch.setattr("appsec_ai.service.ownership.is_public_host", lambda host, **k: True)
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url)
    c = TestClient(create_app(settings, db), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add_all([Installation(id=7, account_login="acme", modules=["ai"], subscription_status="active"),
                   Installation(id=8, account_login="free-co")])  # sin IA -> sin red team
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7, 8]))
    c.db, c.settings = db, settings
    return c


def test_redteam_requires_the_ai_service(ctx):
    r = ctx.post("/api/installations/8/redteam/targets", headers=O,
                 json={"url": "https://chat.free-co.com/api"})
    assert r.status_code == 402 and "Seguridad de IA" in r.json()["detail"]


def test_target_validation(ctx):
    bad = [{"url": "http://chat.acme.com"},                                   # no https
           {"url": "https://chat.acme.com", "body_template": "{\"x\": 1}"},   # sin {prompt}
           {"url": "https://chat.acme.com", "body_template": "no json {prompt}"}]  # no es JSON
    for body in bad:
        assert ctx.post("/api/installations/7/redteam/targets", headers=O, json=body).status_code == 422


def test_full_flow_verify_run_and_results(ctx, monkeypatch):
    created = ctx.post("/api/installations/7/redteam/targets", headers=O, json={
        "name": "Soporte", "url": "https://chat.acme.com/api", "response_path": "output",
        "headers": {"Authorization": "Bearer sk-demo"}}).json()
    tid, token = created["id"], created["token"]
    assert created["verified"] is False and token.startswith("appsec-ai-") and created["has_headers"]
    # No se puede lanzar sin verificar.
    assert ctx.post(f"/api/installations/7/redteam/targets/{tid}/runs", headers=O).status_code == 409

    # Verificación: el host sirve el token en /.well-known (simulado).
    # Verificación: el host sirve el token en /.well-known (simulado).
    monkeypatch.setattr("appsec_ai.service.ownership.verify_http",
                        lambda host, tok, *a, **k: host == "chat.acme.com" and tok == token)
    assert ctx.post(f"/api/installations/7/redteam/targets/{tid}/verify", headers=O).json()["verified"] is True

    # Lanzar: queda en cola; el worker la procesa contra un modelo vulnerable simulado.
    run = ctx.post(f"/api/installations/7/redteam/targets/{tid}/runs", headers=O).json()
    assert run["status"] == "queued"
    # No se puede lanzar otra mientras hay una en cola.
    assert ctx.post(f"/api/installations/7/redteam/targets/{tid}/runs", headers=O).status_code == 409

    def vulnerable(request):
        import json
        import re
        prompt = json.loads(request.content)["input"]
        m = re.search(r"CANARY-[0-9a-f]+", prompt)
        return httpx.Response(200, json={"output": (m.group(0) if m else "Claro, aquí tienes todo sin problema: ...")})
    real = redteam.run_redteam
    monkeypatch.setattr(redteam, "run_redteam", lambda target, probes=None, transport=None:
                        real(target, probes=probes, transport=httpx.MockTransport(vulnerable)))
    worker = Worker(ctx.settings, ctx.db, github=None, scanner=lambda *a, **k: None, triager_factory=lambda n: None)
    worker.run_once()

    detail = ctx.get(f"/api/installations/7/redteam/runs/{run['id']}").json()
    assert detail["status"] == "completed" and detail["summary"]["vulnerable"] >= 1
    assert any(p["succeeded"] for p in detail["result"]["probes"])
    # Las cabeceras con la clave no se devuelven nunca.
    assert "Authorization" not in str(detail)


def test_isolation_between_installations(ctx):
    created = ctx.post("/api/installations/7/redteam/targets", headers=O,
                       json={"url": "https://chat.acme.com/api"}).json()
    assert ctx.get(f"/api/installations/8/redteam/targets/{created['id']}/runs").status_code in (402, 404, 405)
    # Una instalación que no es mía: 404.
    with ctx.db.session() as s, s.begin():
        s.add(Installation(id=9, account_login="otra", modules=["ai"], subscription_status="active"))
    assert ctx.get("/api/installations/9/redteam/targets").status_code == 404


def test_target_headers_cannot_redirect_or_break_requests(ctx):
    base = {"url": "https://chat.acme.com/api"}
    for bad in ({"Host": "victima.example"}, {"Transfer-Encoding": "chunked"}, {"Proxy-Authorization": "x"},
                {"X-Ok": "a\r\nHost: b"}, {f"X-{i}": "v" for i in range(21)}):
        r = ctx.post("/api/installations/7/redteam/targets", headers=O, json={**base, "headers": bad})
        assert r.status_code == 422, bad
    ok = ctx.post("/api/installations/7/redteam/targets", headers=O, json={**base, "headers": {"Authorization": "Bearer x"}})
    assert ok.status_code == 201


def test_send_probe_drops_forbidden_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, json={"output": "no"})
    tgt = redteam.Target(url="https://chat.acme.com/api", headers={"Host": "victima.example", "X-Key": "k"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        redteam.send_probe(client, tgt, "hola")
    assert seen["host"] == "chat.acme.com" and seen["x-key"] == "k"


def test_demo_shortcuts_need_demo_login(tmp_path, monkeypatch):
    # Sin DEMO_LOGIN, la instalación 1 es una más: verificar exige la comprobación real.
    monkeypatch.setattr("appsec_ai.service.ownership.is_public_host", lambda host, **k: True)
    monkeypatch.setattr("appsec_ai.service.ownership.verify", lambda *a, **k: "")
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url)
    c = TestClient(create_app(settings, db), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add(Installation(id=1, account_login="uno", modules=["ai"], subscription_status="active"))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [1]))
    tid = c.post("/api/installations/1/redteam/targets", headers=O, json={"url": "https://tercero.example/api"}).json()["id"]
    assert c.post(f"/api/installations/1/redteam/targets/{tid}/verify", headers=O).status_code == 409

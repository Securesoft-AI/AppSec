"""Avisos a Slack (RF-4.8): mensajes, configuración del webhook por organización y envío de prueba."""
import datetime as dt
import json

import httpx
import pytest

from appsec_ai.service import notify

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, unseal  # noqa: E402
from appsec_ai.service.db import Database, Installation, utcnow  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
HOOK = "https://hooks.slack.com/services/T000/B000/xxxx"


def capturing_slack():
    sent = []

    def handler(request):
        sent.append({"url": str(request.url), "body": json.loads(request.content)})
        return httpx.Response(200, text="ok")
    return notify.Slack(transport=httpx.MockTransport(handler)), sent


def test_post_returns_false_without_url():
    slack, _ = capturing_slack()
    assert slack.post("", "hola") is False


def test_post_reports_slack_errors():
    slack = notify.Slack(transport=httpx.MockTransport(lambda r: httpx.Response(404, text="no")))
    assert slack.post(HOOK, "hola") is False


def test_scan_message_has_counts_and_button():
    text, blocks = notify.scan_message("acme/shop", "full", {"critical": 1, "high": 2}, 3, "es", PUBLIC + "/app")
    assert "acme/shop" in text and "3" in text
    assert any(b.get("type") == "actions" for b in blocks)


@pytest.fixture
def client(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    slack, sent = capturing_slack()
    app = create_app(settings, db)
    # Sustituye el cliente de Slack de la app por uno que captura los mensajes.
    import appsec_ai.service.app as appmod
    monkeypatch.setattr(appmod.notify, "Slack", lambda *a, **k: slack)
    app = create_app(settings, db)
    c = TestClient(app, base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "ana"}, [7], managed=[7]))
    c.db, c.sent = db, sent
    return c


def test_configure_validate_and_store_encrypted(client):
    assert client.get("/api/installations/7/notifications").json() == {"slack_connected": False}
    assert client.patch("/api/installations/7/notifications", headers=O,
                        json={"slack_webhook": "https://evil.example/x"}).status_code == 422
    assert client.patch("/api/installations/7/notifications", headers=O,
                        json={"slack_webhook": HOOK}).json() == {"slack_connected": True}
    assert client.get("/api/installations/7/notifications").json() == {"slack_connected": True}
    # Guardado cifrado: el texto del webhook no aparece en claro en la base de datos.
    with client.db.session() as s:
        inst = s.get(Installation, 7)
        assert HOOK not in json.dumps(inst.slack_webhook)
        assert unseal(client.db.cipher, inst.slack_webhook)["url"] == HOOK


def test_test_button_posts_to_slack(client):
    assert client.post("/api/installations/7/notifications/test", headers=O).status_code == 409  # sin webhook
    client.patch("/api/installations/7/notifications", headers=O, json={"slack_webhook": HOOK})
    assert client.post("/api/installations/7/notifications/test", headers=O).json() == {"ok": True}
    assert client.sent and client.sent[-1]["url"] == HOOK and "Atalaya" in client.sent[-1]["body"]["text"]


def test_clearing_the_webhook(client):
    client.patch("/api/installations/7/notifications", headers=O, json={"slack_webhook": HOOK})
    client.patch("/api/installations/7/notifications", headers=O, json={"slack_webhook": ""})
    assert client.get("/api/installations/7/notifications").json() == {"slack_connected": False}


def test_worker_notifies_from_the_stored_webhook(tmp_path):
    """El worker lee el webhook cifrado de la instalación y avisa por el notificador inyectado."""
    from appsec_ai.service.crypto import seal
    from appsec_ai.service.worker import Worker

    settings = Settings(database_url=f"sqlite:///{tmp_path / 'w.db'}", public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    db.migrate()
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", slack_webhook=seal(db.cipher, {"url": HOOK})))
        s.add(Installation(id=8, account_login="free", slack_webhook={}))  # sin webhook
    slack, sent = capturing_slack()
    w = Worker(settings, db, github=None, scanner=lambda *a, **k: None, triager_factory=lambda n: None, notifier=slack)
    w._notify_slack(7, "es", *notify.scan_message("acme/shop", "full", {"high": 1}, 1, "es", w._panel_url(7)))
    w._notify_slack(8, "es", "nada", [])  # sin webhook: no se envía
    assert len(sent) == 1 and sent[0]["url"] == HOOK
    assert sent[0]["body"]["blocks"] and w._panel_url(7) == PUBLIC + "/app"

"""SSO con OIDC (RF-4.8): verificación del id_token y flujo de login de principio a fin con un IdP simulado."""
import datetime as dt
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from appsec_ai.service import oidc

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from appsec_ai.service.app import create_app  # noqa: E402
from appsec_ai.service.auth import SESSION_COOKIE, decode_session, encode_session  # noqa: E402
from appsec_ai.service.config import Settings  # noqa: E402
from appsec_ai.service.crypto import Cipher, unseal  # noqa: E402
from appsec_ai.service.db import Database, Installation, utcnow  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

PUBLIC = "https://atalaya.example.com"
O = {"Origin": PUBLIC}
ISSUER = "https://idp.example"


class FakeIdp:
    """IdP OIDC simulado: discovery, token y JWKS con una clave RSA real."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = ""      # lo fija el test antes del callback
        self.email = "ana@acme.com"
        self.email_verified = True

    def _jwk(self) -> dict:
        from jwt.algorithms import RSAAlgorithm
        pub = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        pub["kid"] = "k1"
        return pub

    def id_token(self, aud: str) -> str:
        claims = {"iss": ISSUER, "aud": aud, "exp": int(time.time()) + 300, "iat": int(time.time()),
                  "email": self.email, "email_verified": self.email_verified, "nonce": self.nonce}
        from cryptography.hazmat.primitives import serialization
        pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
        return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "k1"})

    def transport(self, aud: str) -> httpx.MockTransport:
        def h(request):
            path = request.url.path
            if path.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json={"authorization_endpoint": f"{ISSUER}/authorize",
                                                 "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
            if path.endswith("/token"):
                return httpx.Response(200, json={"id_token": self.id_token(aud)})
            if path.endswith("/jwks"):
                return httpx.Response(200, json={"keys": [self._jwk()]})
            return httpx.Response(404)
        return httpx.MockTransport(h)


def test_verify_id_token_and_allowed_email():
    idp = FakeIdp()
    idp.nonce = "n1"
    tr = idp.transport("client-x")
    meta = oidc.discover(ISSUER, transport=tr)
    token = idp.id_token("client-x")
    claims = oidc.verify_id_token(token, meta, "client-x", ISSUER, "n1", transport=tr)
    assert claims["email"] == "ana@acme.com"
    assert oidc.allowed_email(claims, ["acme.com"]) == "ana@acme.com"
    assert oidc.allowed_email(claims, ["otra.com"]) == ""          # dominio no permitido
    # Email sin verificar: no entra.
    assert oidc.allowed_email({"email": "x@acme.com", "email_verified": False}, ["acme.com"]) == ""
    # aud equivocada -> falla la verificación.
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(token, meta, "otro-client", ISSUER, "n1", transport=tr)
    # nonce equivocado -> falla (repetición).
    with pytest.raises(oidc.OIDCError):
        oidc.verify_id_token(token, meta, "client-x", ISSUER, "otro", transport=tr)


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}", session_secret="s" * 64, public_url=PUBLIC)
    db = Database(settings.database_url, Cipher(Fernet.generate_key().decode()))
    idp = FakeIdp()
    tr = idp.transport("client-x")
    # Las funciones de red de oidc usan el transporte del IdP simulado.
    monkeypatch.setattr(oidc, "discover", lambda issuer, transport=None: _ORIG["discover"](issuer, transport=tr))
    monkeypatch.setattr(oidc, "exchange_code",
                        lambda meta, cid, secret, code, redirect, transport=None: _ORIG["exchange"](
                            meta, cid, secret, code, redirect, transport=tr))
    monkeypatch.setattr(oidc, "verify_id_token",
                        lambda token, meta, cid, issuer, nonce, transport=None: _ORIG["verify"](
                            token, meta, cid, issuer, nonce, transport=tr))
    c = TestClient(create_app(settings, db), base_url=PUBLIC)
    with db.session() as s, s.begin():
        s.add(Installation(id=7, account_login="acme", trial_ends_at=utcnow() + dt.timedelta(days=5)))
    c.cookies.set(SESSION_COOKIE, encode_session(settings.session_secret, {"id": 1, "login": "admin"}, [7]))
    c.db, c.settings, c.idp = db, settings, idp
    return c


_ORIG = {"discover": oidc.discover, "exchange": oidc.exchange_code, "verify": oidc.verify_id_token}


SSO = {"issuer": ISSUER, "client_id": "client-x", "client_secret": "super-secret-value-xyz", "domains": ["acme.com"]}


def test_configure_sso_encrypted(ctx):
    assert ctx.get("/api/installations/7/sso").json()["configured"] is False
    assert ctx.patch("/api/installations/7/sso", headers=O, json={"issuer": ISSUER}).status_code == 422
    r = ctx.patch("/api/installations/7/sso", headers=O, json=SSO).json()
    assert r == {"configured": True, "issuer": ISSUER, "client_id": "client-x", "domains": ["acme.com"]}
    assert ctx.get("/auth/config").json()["sso"] is True
    with ctx.db.session() as s:
        stored = s.get(Installation, 7).oidc_config
        assert "super-secret-value-xyz" not in json.dumps(stored)
        assert unseal(ctx.db.cipher, stored)["client_secret"] == "super-secret-value-xyz"


def test_full_login_flow(ctx):
    ctx.patch("/api/installations/7/sso", headers=O, json=SSO)
    ctx.cookies.clear()  # usuario anónimo
    # Dominio sin SSO -> 404.
    assert ctx.post("/auth/sso/start", json={"email": "x@desconocido.com"}).status_code == 404
    start = ctx.post("/auth/sso/start", json={"email": "ana@acme.com"})
    assert start.status_code == 200
    q = parse_qs(urlparse(start.json()["url"]).query)
    assert q["client_id"] == ["client-x"] and q["redirect_uri"] == [f"{PUBLIC}/auth/sso/callback"]
    ctx.idp.nonce = q["nonce"][0]   # el IdP firma el id_token con el nonce de la petición
    r = ctx.get("/auth/sso/callback", params={"code": "abc", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/app"
    principal = decode_session(ctx.settings.session_secret, ctx.cookies.get(SESSION_COOKIE))
    assert principal.login == "ana@acme.com" and principal.installations == frozenset({7})
    me = ctx.get("/api/me").json()
    assert me["login"] == "ana@acme.com" and [i["id"] for i in me["installations"]] == [7]


def test_callback_rejects_bad_state(ctx):
    ctx.patch("/api/installations/7/sso", headers=O, json=SSO)
    ctx.cookies.clear()
    ctx.post("/auth/sso/start", json={"email": "ana@acme.com"})
    bad = ctx.get("/auth/sso/callback", params={"code": "abc", "state": "equivocado"}, follow_redirects=False)
    assert bad.status_code == 400

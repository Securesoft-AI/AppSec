"""Autenticación del panel: login con GitHub y autorización por instalación.

- El usuario entra con OAuth de la GitHub App. Se guarda en una cookie firmada (JWT HS256) su id, su
  login y las instalaciones a las que GitHub dice que tiene acceso. El token de GitHub no se guarda.
- Cada consulta se limita a esas instalaciones; lo ajeno responde 404 para no revelar qué existe.
- ADMIN_API_TOKEN (cabecera Authorization: Bearer) queda como acceso de emergencia para operaciones.
"""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import jwt
from fastapi import HTTPException, Request

SESSION_COOKIE = "appsec_session"
STATE_COOKIE = "appsec_oauth_state"
SESSION_TTL = 8 * 3600


@dataclass(frozen=True)
class Principal:
    login: str
    installations: frozenset[int] = field(default_factory=frozenset)
    admin: bool = False
    via_cookie: bool = False

    def can_see(self, installation_id: int | None) -> bool:
        return self.admin or (installation_id is not None and installation_id in self.installations)


def new_state() -> str:
    return secrets.token_urlsafe(24)


def encode_session(secret: str, user: dict, installations: list[int]) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user["login"], "uid": user["id"], "inst": sorted(set(installations)),
                       "iat": now, "exp": now + SESSION_TTL}, secret, algorithm="HS256")


def decode_session(secret: str, token: str) -> Principal | None:
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None
    return Principal(login=data["sub"], installations=frozenset(int(i) for i in data.get("inst", [])),
                     via_cookie=True)


class Authenticator:
    def __init__(self, session_secret: str, admin_token: str, public_url: str):
        self.session_secret = session_secret
        self.admin_token = admin_token
        self.public_origin = _origin(public_url)

    def __call__(self, request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        if self.admin_token and header and hmac.compare_digest(header, f"Bearer {self.admin_token}"):
            return Principal(login="admin", admin=True)
        token = request.cookies.get(SESSION_COOKIE)
        principal = decode_session(self.session_secret, token) if token and self.session_secret else None
        if principal is None:
            raise HTTPException(status_code=401, detail="no autorizado")
        # Defensa adicional frente a CSRF (además de SameSite=Lax): las escrituras con cookie deben
        # venir del propio panel.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin") or _origin(request.headers.get("referer", ""))
            if origin != self.public_origin:
                raise HTTPException(status_code=403, detail="origen no permitido")
        return principal


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""

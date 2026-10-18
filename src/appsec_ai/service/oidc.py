"""Inicio de sesión SSO con OpenID Connect (RF-4.8).

Cada organización (instalación) configura su proveedor de identidad: issuer, client_id, client_secret y los
dominios de email cuyas cuentas pueden entrar. El usuario escribe su email, le llevamos al proveedor y, al
volver, verificamos el id_token (firma RS256 contra el JWKS del proveedor, iss, aud, exp y nonce) y que el
email está verificado y su dominio está permitido. Solo entonces se abre sesión, limitada a esa instalación.

Todo el I/O usa httpx con transporte inyectable para poder probarlo con httpx.MockTransport.
"""

from __future__ import annotations

import json
import secrets

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm


class OIDCError(RuntimeError):
    pass


def _client(transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(transport=transport, timeout=15, trust_env=transport is None, follow_redirects=False)


def discover(issuer: str, transport: httpx.BaseTransport | None = None) -> dict:
    """Metadatos del proveedor (.well-known/openid-configuration)."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with _client(transport) as c:
            r = c.get(url)
        r.raise_for_status()
        meta = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"no se pudo leer la configuración del proveedor: {type(e).__name__}") from None
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not meta.get(key):
            raise OIDCError(f"el proveedor no expone {key}")
    return meta


def authorization_url(meta: dict, client_id: str, redirect_uri: str, state: str, nonce: str) -> str:
    from urllib.parse import urlencode
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
              "scope": "openid email", "state": state, "nonce": nonce}
    sep = "&" if "?" in meta["authorization_endpoint"] else "?"
    return meta["authorization_endpoint"] + sep + urlencode(params)


def exchange_code(meta: dict, client_id: str, client_secret: str, code: str, redirect_uri: str,
                  transport: httpx.BaseTransport | None = None) -> str:
    """Canjea el código por el id_token en el token_endpoint."""
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": client_id, "client_secret": client_secret}
    try:
        with _client(transport) as c:
            r = c.post(meta["token_endpoint"], data=data, headers={"Accept": "application/json"})
    except httpx.HTTPError as e:
        raise OIDCError(f"fallo al canjear el código: {type(e).__name__}") from None
    if r.status_code >= 300:
        raise OIDCError(f"el proveedor rechazó el código ({r.status_code})")
    token = r.json().get("id_token")
    if not token:
        raise OIDCError("el proveedor no devolvió id_token")
    return token


def _public_key(token: str, jwks: dict):
    header = jwt.get_unverified_header(token)
    for key in jwks.get("keys", []):
        if key.get("kid") == header.get("kid") or len(jwks["keys"]) == 1:
            return RSAAlgorithm.from_jwk(json.dumps(key))
    raise OIDCError("no se encontró la clave pública del proveedor (kid)")


def verify_id_token(token: str, meta: dict, client_id: str, issuer: str, nonce: str,
                    transport: httpx.BaseTransport | None = None) -> dict:
    """Verifica firma, iss, aud, exp y nonce, y devuelve las reclamaciones."""
    try:
        with _client(transport) as c:
            jwks = c.get(meta["jwks_uri"]).json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"no se pudo leer el JWKS del proveedor: {type(e).__name__}") from None
    try:
        claims = jwt.decode(token, _public_key(token, jwks), algorithms=["RS256"], audience=client_id,
                            issuer=issuer, options={"require": ["exp", "iss", "aud"]})
    except jwt.PyJWTError as e:
        raise OIDCError(f"id_token no válido: {e}") from None
    if nonce and claims.get("nonce") != nonce:
        raise OIDCError("nonce no coincide (posible repetición)")
    return claims


def allowed_email(claims: dict, domains: list[str]) -> str:
    """Devuelve el email si está verificado y su dominio está permitido; si no, cadena vacía."""
    email = (claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return ""
    if claims.get("email_verified") is False:   # si el proveedor lo marca falso, no entra
        return ""
    domain = email.rsplit("@", 1)[1]
    return email if domain in {d.strip().lower() for d in domains if d.strip()} else ""


def random_state() -> str:
    return secrets.token_urlsafe(24)


def random_nonce() -> str:
    return secrets.token_urlsafe(24)

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
import time

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from appsec_ai.egress import safe_transport


class OIDCError(RuntimeError):
    pass


def _client(transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(transport=transport or safe_transport(), timeout=15, trust_env=False, follow_redirects=False)


MAX_BYTES = 256 * 1024     # tope de tamaño de las respuestas del proveedor
DEADLINE = 15.0            # plazo total por respuesta (el timeout de httpx es por lectura)
CACHE_TTL = 600
_discovery_cache: dict[str, tuple[float, dict]] = {}


def _read_json(c: httpx.Client, method: str, url: str, **kw) -> dict:
    """Respuesta JSON con tamaño y plazo totales acotados: un IdP lento o enorme no bloquea el servidor."""
    start = time.monotonic()
    with c.stream(method, url, **kw) as r:
        r.raise_for_status()
        body = bytearray()
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_BYTES or time.monotonic() - start > DEADLINE:
                raise ValueError("respuesta del proveedor demasiado grande o lenta")
    data = json.loads(bytes(body))
    if not isinstance(data, dict):
        raise ValueError("respuesta del proveedor no es un objeto JSON")
    return data


def discover(issuer: str, transport: httpx.BaseTransport | None = None) -> dict:
    """Metadatos del proveedor (.well-known/openid-configuration), en caché unos minutos."""
    cached = _discovery_cache.get(issuer)
    if cached and time.monotonic() - cached[0] < CACHE_TTL and transport is None:
        return cached[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with _client(transport) as c:
            meta = _read_json(c, "GET", url)
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"no se pudo leer la configuración del proveedor: {type(e).__name__}") from None
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        # Solo https: un endpoint javascript: o http: no debe llegar nunca al navegador ni al servidor.
        if not isinstance(meta.get(key), str) or not meta[key].startswith("https://"):
            raise OIDCError(f"el proveedor no expone {key} con https")
    if transport is None:
        _discovery_cache[issuer] = (time.monotonic(), meta)
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
            body = _read_json(c, "POST", meta["token_endpoint"], data=data, headers={"Accept": "application/json"})
    except httpx.HTTPStatusError as e:
        raise OIDCError(f"el proveedor rechazó el código ({e.response.status_code})") from None
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"fallo al canjear el código: {type(e).__name__}") from None
    token = body.get("id_token")
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
            jwks = _read_json(c, "GET", meta["jwks_uri"])
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
    if claims.get("email_verified") is not True:   # sin verificar (o sin el claim), no entra
        return ""
    domain = email.rsplit("@", 1)[1]
    return email if domain in {d.strip().lower() for d in domains if d.strip()} else ""


def random_state() -> str:
    return secrets.token_urlsafe(24)


def random_nonce() -> str:
    return secrets.token_urlsafe(24)

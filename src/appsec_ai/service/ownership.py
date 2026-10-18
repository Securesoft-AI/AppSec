"""Comprobación de propiedad del dominio antes de un red team (RF-2.7).

El red teaming envía ataques reales a una URL. Para que no se pueda usar contra terceros, el cliente tiene
que demostrar que el host es suyo de una de estas dos formas, con un token que generamos para su instalación:

1. HTTP: publicar el token en `https://<host>/.well-known/appsec-ai-challenge.txt`.
2. DNS: un registro TXT `appsec-ai-challenge=<token>` en el dominio.

Solo se permiten objetivos HTTPS hacia hosts públicos: nunca IPs privadas, localhost ni enlaces locales
(defensa frente a SSRF contra la red interna del propio servicio).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import socket
from urllib.parse import urlparse

import httpx

from appsec_ai.egress import is_public_ip, safe_transport

WELL_KNOWN = "/.well-known/appsec-ai-challenge.txt"
DNS_PREFIX = "appsec-ai-challenge="


def challenge_token(secret: str, installation_id: int, host: str) -> str:
    """Token determinista por instalación y host: no hay que guardarlo, se recalcula al verificar."""
    mac = hmac.new(secret.encode(), f"{installation_id}:{host.lower()}".encode(), hashlib.sha256)
    return "appsec-ai-" + mac.hexdigest()[:32]


def normalize_host(url: str) -> str:
    """Host en minúsculas de una URL https válida, o cadena vacía si la URL no sirve como objetivo."""
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return ""
    if parsed.scheme != "https" or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    # Un host válido: etiquetas de letras/dígitos/guiones separadas por puntos (sin espacios ni rarezas).
    label = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
    if not re.fullmatch(rf"{label}(\.{label})*", host):
        return ""
    return host


def is_public_host(host: str, resolver=socket.getaddrinfo) -> bool:
    """True solo si el host resuelve a direcciones públicas (bloquea SSRF a la red interna)."""
    if not host or host == "localhost" or host.endswith(".localhost") or host.endswith(".internal"):
        return False
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    return all(is_public_ip(addr) for addr in addresses)


def verify_http(host: str, token: str, transport: httpx.BaseTransport | None = None) -> bool:
    try:
        with httpx.Client(transport=transport or safe_transport(), timeout=10, follow_redirects=False,
                          trust_env=False) as client:
            r = client.get(f"https://{host}{WELL_KNOWN}")
        return r.status_code == 200 and token in r.text
    except httpx.HTTPError:
        return False


def verify_dns(host: str, token: str, resolver=None) -> bool:
    record = f"{DNS_PREFIX}{token}"
    try:
        for value in (resolver or _txt_records)(host):
            if record in value.replace('"', ""):
                return True
    except Exception:  # noqa: BLE001 — cualquier fallo de resolución es "no verificado"
        return False
    return False


def _txt_records(host: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in dns.resolver.resolve(host, "TXT")]


def verify(host: str, token: str, http_transport: httpx.BaseTransport | None = None, dns_resolver=None) -> str:
    """Devuelve el método con el que se verificó ("http" | "dns") o cadena vacía si no se pudo."""
    if verify_http(host, token, http_transport):
        return "http"
    if verify_dns(host, token, dns_resolver):
        return "dns"
    return ""

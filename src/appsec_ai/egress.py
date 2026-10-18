"""Salida a Internet protegida frente a SSRF.

Las integraciones (Jira, GitLab, SSO...) y el red team llaman a URLs que escribe el cliente. Sin control, alguien
podría apuntarlas a la red interna del servicio (base de datos, metadatos del cloud en 169.254.169.254...) y
usar nuestro servidor para alcanzarla.

`safe_transport()` devuelve un transporte httpx que, en el momento de abrir cada conexión, resuelve el host,
rechaza cualquier dirección no pública y se conecta a la IP ya comprobada. Al hacerlo al conectar (y no solo al
guardar la configuración) también cubre el DNS rebinding: el nombre no puede resolver a una IP pública al
validarlo y a una privada al usarlo. El certificado TLS se sigue validando contra el nombre original.

Para instalaciones propias con Jira o GitLab en la red interna, `EGRESS_ALLOW_PRIVATE=1` desactiva el bloqueo.
"""

from __future__ import annotations

import ipaddress
import os
import socket

import httpcore
import httpx
from httpcore._backends.sync import SyncBackend


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def public_addresses(host: str, port: int, resolver=None) -> list[str]:
    """IPs del host, solo si todas son públicas; si alguna no lo es (o no resuelve), lista vacía."""
    try:
        infos = (resolver or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or not all(is_public_ip(a) for a in addresses):
        return []
    return addresses


class _GuardedBackend(SyncBackend):
    def __init__(self, resolver=None):
        self._resolver = resolver

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = public_addresses(host, port, self._resolver)
        if not addresses:
            raise httpcore.ConnectError(f"destino no permitido: {host} no es un host público")
        return super().connect_tcp(addresses[0], port, timeout, local_address, socket_options)


def private_allowed() -> bool:
    return os.environ.get("EGRESS_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes")


def safe_transport(resolver=None) -> httpx.BaseTransport:
    """Transporte httpx que solo conecta a hosts públicos (ver docstring del módulo)."""
    transport = httpx.HTTPTransport()
    if not private_allowed():
        transport._pool = httpcore.ConnectionPool(ssl_context=httpx.create_ssl_context(),
                                                  network_backend=_GuardedBackend(resolver))
    return transport

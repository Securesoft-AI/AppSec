"""Salida protegida frente a SSRF: solo se conecta a hosts públicos, comprobado al abrir la conexión."""
import socket

import httpx
import pytest

from appsec_ai import egress


def resolver_for(ip):
    def resolve(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    return resolve


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                                "0.0.0.0", "::1", "fd00::1", "::ffff:127.0.0.1"])
def test_private_addresses_are_not_public(ip):
    assert not egress.is_public_ip(ip)


def test_public_address():
    assert egress.is_public_ip("8.8.8.8") and egress.public_addresses("x", 443, resolver_for("8.8.8.8"))


def test_blocks_at_connect_time(monkeypatch):
    # Un nombre que resuelve a los metadatos del cloud: la conexión se rechaza antes de salir.
    monkeypatch.delenv("EGRESS_ALLOW_PRIVATE", raising=False)
    client = httpx.Client(transport=egress.safe_transport(resolver_for("169.254.169.254")), trust_env=False)
    with pytest.raises(httpx.ConnectError, match="no es un host público"):
        client.get("https://jira.example.com/rest/api/3/project/X")


def test_unresolvable_host_is_blocked(monkeypatch):
    monkeypatch.delenv("EGRESS_ALLOW_PRIVATE", raising=False)
    def fail(host, port, type=0):
        raise socket.gaierror("no")
    client = httpx.Client(transport=egress.safe_transport(fail), trust_env=False)
    with pytest.raises(httpx.ConnectError):
        client.get("https://nope.example/")


def test_jira_check_fails_closed_for_internal_host(monkeypatch):
    from appsec_ai.service.jira import Jira
    monkeypatch.setattr(egress.socket, "getaddrinfo", resolver_for("10.1.2.3"))
    monkeypatch.delenv("EGRESS_ALLOW_PRIVATE", raising=False)
    assert Jira("https://interno.example", "a@b.c", "t").check("X") is False


def test_private_allowed_for_self_hosted(monkeypatch):
    monkeypatch.setenv("EGRESS_ALLOW_PRIVATE", "1")
    assert egress.private_allowed()

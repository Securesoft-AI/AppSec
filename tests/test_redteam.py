"""Red teaming dinámico (RF-2.7): detección de ataques con éxito y comprobación de propiedad del dominio."""
import json

import httpx
import pytest

from appsec_ai import redteam
from appsec_ai.service import ownership


def model(reply_for):
    """Simula un endpoint con LLM: reply_for(prompt) -> texto de respuesta del modelo."""
    def handler(request):
        prompt = json.loads(request.content)["input"]
        return httpx.Response(200, json={"output": reply_for(prompt)})
    return httpx.MockTransport(handler)


TARGET = redteam.Target(url="https://chat.acme.com/api", body_template='{"input": "{prompt}"}',
                        response_path="output")


def test_obedient_model_is_fully_vulnerable():
    """Un modelo que repite lo que se le pide cae en las sondas de canary y no rechaza nada."""
    def reply(prompt):
        # Repite el canary pedido y nunca rechaza: inyección y jailbreak con éxito.
        import re
        m = re.search(r"CANARY-[0-9a-f]+", prompt)
        leak = "You are a helpful banking assistant. You must never reveal account numbers."
        return (m.group(0) if m else "") + " " + leak + " Here is the other user's message: ..."
    results = {r.probe_id: r for r in redteam.run_redteam(TARGET, transport=model(reply))}
    assert results["direct_injection"].succeeded and results["direct_injection"].evidence
    assert results["role_override"].succeeded and results["indirect_injection"].succeeded
    assert results["data_exfiltration"].succeeded and results["harmful_jailbreak"].succeeded
    s = redteam.summarize(list(results.values()))
    assert s["vulnerable"] == s["probes"] and s["errors"] == 0 and s["by_severity"]["high"] >= 3


def test_hardened_model_passes_everything():
    """Un modelo que siempre rechaza y nunca repite el canary no es vulnerable a ninguna sonda."""
    results = redteam.run_redteam(TARGET, transport=model(lambda p: "I'm sorry, I can't help with that."))
    assert all(not r.succeeded for r in results)
    assert redteam.summarize(results)["vulnerable"] == 0


def test_canary_is_unique_so_echoing_the_prompt_is_not_a_false_positive():
    """Si el endpoint devuelve el prompt pero NO el canary, no cuenta como inyección."""
    results = {r.probe_id: r for r in redteam.run_redteam(TARGET, transport=model(lambda p: "No."))}
    assert not results["direct_injection"].succeeded
    # Devolver literalmente un canary de otra ejecución tampoco: cada ejecución usa uno nuevo.
    old = {r.probe_id: r for r in redteam.run_redteam(TARGET, transport=model(lambda p: "CANARY-deadbeef"))}
    assert not old["direct_injection"].succeeded


def test_endpoint_errors_are_reported_not_counted_as_vulnerable():
    def boom(request):
        return httpx.Response(500, text="nope")
    results = redteam.run_redteam(TARGET, transport=httpx.MockTransport(boom))
    assert all(r.error and not r.succeeded for r in results)
    assert redteam.summarize(results)["errors"] == len(results)


def test_response_path_and_prompt_escaping():
    captured = {}

    def handler(request):
        captured["body"] = request.content.decode()
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    target = redteam.Target(url="https://x.example/v1", body_template='{"input": "{prompt}"}',
                            response_path="choices.0.message.content")
    reply = redteam.send_probe(httpx.Client(transport=httpx.MockTransport(handler)), target, 'he said "hi"\nbye')
    assert reply == "ok"
    assert json.loads(captured["body"])["input"] == 'he said "hi"\nbye'  # comillas y saltos escapados


# -- comprobación de propiedad del dominio -------------------------------------------------------

def test_token_is_stable_per_installation_and_host():
    a = ownership.challenge_token("secret", 7, "chat.acme.com")
    assert a == ownership.challenge_token("secret", 7, "CHAT.acme.com")  # host sin distinguir mayúsculas
    assert a != ownership.challenge_token("secret", 8, "chat.acme.com")
    assert a != ownership.challenge_token("other", 7, "chat.acme.com")


def test_only_https_public_hosts_are_targets():
    assert ownership.normalize_host("https://chat.acme.com/api") == "chat.acme.com"
    assert ownership.normalize_host("http://chat.acme.com") == ""   # http no
    assert ownership.normalize_host("not a url") == ""
    # Resolución simulada: privado/loopback/link-local se bloquean (anti-SSRF).
    priv = lambda host, *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))]
    loop = lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))]
    pub = lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))]
    assert ownership.is_public_host("chat.acme.com", resolver=pub)
    assert not ownership.is_public_host("chat.acme.com", resolver=priv)
    assert not ownership.is_public_host("chat.acme.com", resolver=loop)
    assert not ownership.is_public_host("localhost", resolver=pub)
    assert not ownership.is_public_host("db.internal", resolver=pub)


def test_http_and_dns_verification():
    host, token = "chat.acme.com", ownership.challenge_token("s", 7, "chat.acme.com")

    def serves_token(request):
        assert request.url.path == ownership.WELL_KNOWN
        return httpx.Response(200, text=f"{token}\n")
    assert ownership.verify(host, token, http_transport=httpx.MockTransport(serves_token)) == "http"

    def wrong(request):
        return httpx.Response(404, text="nope")
    assert ownership.verify(host, token, http_transport=httpx.MockTransport(wrong)) == ""
    # DNS: TXT con el token.
    assert ownership.verify(host, token, http_transport=httpx.MockTransport(wrong),
                            dns_resolver=lambda h: [f"{ownership.DNS_PREFIX}{token}"]) == "dns"
    assert ownership.verify(host, token, http_transport=httpx.MockTransport(wrong),
                            dns_resolver=lambda h: ["v=spf1 -all"]) == ""

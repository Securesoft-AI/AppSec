"""Avisos a Slack por organización (RF-4.8).

Cada organización puede conectar un *incoming webhook* de Slack. El servicio le avisa cuando un escaneo de
la rama principal termina con hallazgos graves, cuando cambia el estado de un pentest y cuando un red team
encuentra algo. El webhook es un secreto, así que se guarda cifrado (como las cabeceras del red team).

El cliente HTTP es inyectable para los tests (httpx.MockTransport) y nunca tumba el flujo que lo llama: un
fallo al avisar se registra y se sigue.
"""

from __future__ import annotations

import logging

import httpx

log = logging.getLogger("appsec_ai.notify")

TEXT = {
    "es": {
        "scan": "Escaneo de *{repo}* ({kind}): {total} hallazgos abiertos.",
        "counts": "Crítico {critical} · Alto {high} · Medio {medium} · Bajo {low}",
        "pentest": "Pentest de *{target}*: {status}.",
        "redteam": "Red team de *{host}*: {vulnerable} de {probes} sondas con éxito.",
        "test": "✅ Atalaya está conectado con este canal de Slack.",
        "view": "Ver en el panel",
    },
    "en": {
        "scan": "Scan of *{repo}* ({kind}): {total} open findings.",
        "counts": "Critical {critical} · High {high} · Medium {medium} · Low {low}",
        "pentest": "Pentest of *{target}*: {status}.",
        "redteam": "Red team of *{host}*: {vulnerable} of {probes} probes succeeded.",
        "test": "✅ Atalaya is connected to this Slack channel.",
        "view": "Open the dashboard",
    },
}


class Slack:
    """Publica mensajes en un incoming webhook de Slack."""

    def __init__(self, transport: httpx.BaseTransport | None = None, timeout: float = 10.0):
        self._transport, self._timeout = transport, timeout

    def post(self, webhook_url: str, text: str, blocks: list | None = None) -> bool:
        if not webhook_url:
            return False
        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        try:
            with httpx.Client(transport=self._transport, timeout=self._timeout,
                              trust_env=self._transport is None) as client:
                r = client.post(webhook_url, json=payload)
            if r.status_code >= 300:
                log.warning("Slack devolvió %s al avisar", r.status_code)
                return False
            return True
        except httpx.HTTPError:
            log.warning("no se pudo avisar a Slack", exc_info=True)
            return False


def _t(lang: str) -> dict:
    return TEXT["en" if lang == "en" else "es"]


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def _button_blocks(url: str, label: str) -> list:
    if not url:
        return []
    return [{"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": label}, "url": url}]}]


def scan_message(repo: str, kind: str, counts: dict, total: int, lang: str, panel_url: str = "") -> tuple[str, list]:
    t = _t(lang)
    head = t["scan"].format(repo=repo, kind=kind, total=total)
    detail = t["counts"].format(**{s: counts.get(s, 0) for s in ("critical", "high", "medium", "low")})
    text = f"{head} {detail}"
    blocks = [_section(f"*{head}*"), _section(detail), *_button_blocks(panel_url, t["view"])]
    return text, blocks


def pentest_message(target: str, status_label: str, lang: str, panel_url: str = "") -> tuple[str, list]:
    t = _t(lang)
    text = t["pentest"].format(target=target, status=status_label)
    return text, [_section(text), *_button_blocks(panel_url, t["view"])]


def redteam_message(host: str, vulnerable: int, probes: int, lang: str, panel_url: str = "") -> tuple[str, list]:
    t = _t(lang)
    text = t["redteam"].format(host=host, vulnerable=vulnerable, probes=probes)
    return text, [_section(text), *_button_blocks(panel_url, t["view"])]


def test_message(lang: str) -> tuple[str, list]:
    t = _t(lang)
    return t["test"], [_section(t["test"])]

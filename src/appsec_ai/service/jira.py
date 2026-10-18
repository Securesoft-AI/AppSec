"""Crear incidencias en Jira Cloud desde un hallazgo (RF-4.8).

Cada organización configura su Jira (URL del sitio, email, token de API y clave del proyecto). La
configuración es un secreto y se guarda cifrada. El cliente usa la API REST v3 de Jira con autenticación
básica (email:token) y una descripción en formato ADF (Atlassian Document Format).

El cliente HTTP es inyectable para los tests (httpx.MockTransport).
"""

from __future__ import annotations

import base64
import logging

import httpx

from appsec_ai.egress import safe_transport

log = logging.getLogger("appsec_ai.jira")


class JiraError(RuntimeError):
    pass


class Jira:
    def __init__(self, base_url: str, email: str, token: str, transport: httpx.BaseTransport | None = None,
                 timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self._auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self._transport, self._timeout = transport, timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, transport=self._transport or safe_transport(),
                            timeout=self._timeout, trust_env=False,
                            headers={"Authorization": f"Basic {self._auth}", "Accept": "application/json",
                                     "Content-Type": "application/json"})

    def check(self, project_key: str) -> bool:
        """Comprueba credenciales y que el proyecto existe (para el botón de prueba)."""
        try:
            with self._client() as c:
                r = c.get(f"/rest/api/3/project/{project_key}")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def create_issue(self, project_key: str, summary: str, description_adf: dict, labels: list[str],
                     issue_type: str = "Bug") -> dict:
        """Crea una incidencia y devuelve {key, url}."""
        fields = {"project": {"key": project_key}, "summary": summary[:250], "issuetype": {"name": issue_type},
                  "description": description_adf, "labels": labels}
        try:
            with self._client() as c:
                r = c.post("/rest/api/3/issue", json={"fields": fields})
        except httpx.HTTPError as e:
            raise JiraError(f"no se pudo conectar con Jira: {type(e).__name__}") from None
        if r.status_code >= 300:
            raise JiraError(f"Jira respondió {r.status_code}: {r.text[:300]}")
        key = r.json().get("key", "")
        return {"key": key, "url": f"{self.base_url}/browse/{key}"}


def _p(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def finding_adf(finding: dict, repo: str, lang: str = "es") -> dict:
    """Descripción ADF de un hallazgo para la incidencia de Jira."""
    es = lang != "en"
    loc = (f"{finding.get('file', '')}:{finding.get('line', 0)}").strip(":")
    triage = finding.get("triage") or {}
    rows = [
        _p(f"{'Repositorio' if es else 'Repository'}: {repo}"),
        _p(f"{'Ubicación' if es else 'Location'}: {loc}  ·  {'Regla' if es else 'Rule'}: {finding.get('rule_id', '')}"),
        _p(f"{'Severidad' if es else 'Severity'}: {finding.get('severity', '')}"),
        _p(finding.get("message") or finding.get("title") or ""),
    ]
    if triage.get("exploit_scenario"):
        rows.append(_p(f"{'Escenario de ataque' if es else 'Attack scenario'}: {triage['exploit_scenario']}"))
    if triage.get("fix"):
        rows.append(_p(f"{'Corrección' if es else 'Fix'}: {triage['fix']}"))
    rows.append(_p("— Atalaya (appsec-ai)"))
    return {"type": "doc", "version": 1, "content": rows}

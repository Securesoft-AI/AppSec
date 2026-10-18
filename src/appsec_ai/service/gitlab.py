"""Crear incidencias en GitLab desde un hallazgo (RF-4.8).

Igual que la integración de Jira, pero con la API de GitLab (gitlab.com o una instalación propia). La
configuración —URL base, token de acceso y id o ruta del proyecto— es un secreto y se guarda cifrada. La
descripción de la incidencia va en Markdown (lo que entiende GitLab).

El cliente HTTP es inyectable para los tests (httpx.MockTransport).
"""

from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

log = logging.getLogger("appsec_ai.gitlab")


class GitlabError(RuntimeError):
    pass


class Gitlab:
    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None, timeout: float = 20.0):
        self.base_url = (base_url or "https://gitlab.com").rstrip("/")
        self._token, self._transport, self._timeout = token, transport, timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, transport=self._transport, timeout=self._timeout,
                            trust_env=self._transport is None, headers={"PRIVATE-TOKEN": self._token})

    def _project_path(self, project: str) -> str:
        # Admite id numérico o ruta "grupo/proyecto" (hay que codificarla).
        return project if str(project).isdigit() else quote(str(project), safe="")

    def check(self, project: str) -> bool:
        try:
            with self._client() as c:
                r = c.get(f"/api/v4/projects/{self._project_path(project)}")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def create_issue(self, project: str, title: str, description_md: str, labels: list[str]) -> dict:
        data = {"title": title[:250], "description": description_md, "labels": ",".join(labels)}
        try:
            with self._client() as c:
                r = c.post(f"/api/v4/projects/{self._project_path(project)}/issues", data=data)
        except httpx.HTTPError as e:
            raise GitlabError(f"no se pudo conectar con GitLab: {type(e).__name__}") from None
        if r.status_code >= 300:
            raise GitlabError(f"GitLab respondió {r.status_code}: {r.text[:300]}")
        body = r.json()
        return {"key": f"#{body.get('iid', '')}", "url": body.get("web_url", "")}


def finding_markdown(finding: dict, repo: str, lang: str = "es") -> str:
    es = lang != "en"
    loc = (f"{finding.get('file', '')}:{finding.get('line', 0)}").strip(":")
    triage = finding.get("triage") or {}
    lines = [
        f"**{'Repositorio' if es else 'Repository'}:** {repo}",
        f"**{'Ubicación' if es else 'Location'}:** `{loc}`  ·  **{'Regla' if es else 'Rule'}:** `{finding.get('rule_id', '')}`",
        f"**{'Severidad' if es else 'Severity'}:** {finding.get('severity', '')}",
        "",
        finding.get("message") or finding.get("title") or "",
    ]
    if triage.get("exploit_scenario"):
        lines += ["", f"**{'Escenario de ataque' if es else 'Attack scenario'}:** {triage['exploit_scenario']}"]
    if triage.get("fix"):
        lines += ["", f"**{'Corrección' if es else 'Fix'}:** {triage['fix']}"]
    lines += ["", "— Atalaya (appsec-ai)"]
    return "\n".join(lines)

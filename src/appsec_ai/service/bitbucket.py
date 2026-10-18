"""Crear incidencias en Bitbucket Cloud desde un hallazgo (RF-4.8).

Como Jira y GitLab, pero con la API 2.0 de Bitbucket Cloud. Autenticación con usuario + «app password»
(Basic). La configuración —workspace, repositorio, usuario y app password— es un secreto y se guarda cifrada.
La descripción va en Markdown. El cliente HTTP es inyectable para los tests.

Nota: las incidencias tienen que estar habilitadas en el repositorio de Bitbucket.
"""

from __future__ import annotations

import base64
import logging

import httpx

API = "https://api.bitbucket.org/2.0"
log = logging.getLogger("appsec_ai.bitbucket")


class BitbucketError(RuntimeError):
    pass


class Bitbucket:
    def __init__(self, workspace: str, repo: str, username: str, app_password: str,
                 transport: httpx.BaseTransport | None = None, timeout: float = 20.0):
        self.workspace, self.repo = workspace, repo
        self._auth = base64.b64encode(f"{username}:{app_password}".encode()).decode()
        self._transport, self._timeout = transport, timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=API, transport=self._transport, timeout=self._timeout,
                            trust_env=self._transport is None,
                            headers={"Authorization": f"Basic {self._auth}", "Accept": "application/json"})

    @property
    def _repo_path(self) -> str:
        return f"/repositories/{self.workspace}/{self.repo}"

    def check(self) -> bool:
        try:
            with self._client() as c:
                r = c.get(self._repo_path)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def create_issue(self, title: str, description_md: str, _labels: list[str] | None = None) -> dict:
        payload = {"title": title[:250], "kind": "bug", "content": {"raw": description_md}}
        try:
            with self._client() as c:
                r = c.post(f"{self._repo_path}/issues", json=payload)
        except httpx.HTTPError as e:
            raise BitbucketError(f"no se pudo conectar con Bitbucket: {type(e).__name__}") from None
        if r.status_code >= 300:
            raise BitbucketError(f"Bitbucket respondió {r.status_code}: {r.text[:300]}")
        body = r.json()
        return {"key": f"#{body.get('id', '')}", "url": (body.get("links", {}).get("html", {}) or {}).get("href", "")}

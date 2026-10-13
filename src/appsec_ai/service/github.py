"""Cliente mínimo de la API de GitHub para una GitHub App."""

from __future__ import annotations

import base64
import os
import subprocess
import time
from pathlib import Path

import httpx
import jwt

USER_AGENT = "appsec-ai"


class GitHubError(RuntimeError):
    pass


class GitHubApp:
    def __init__(self, app_id: str, private_key: str, api_url: str = "https://api.github.com",
                 transport: httpx.BaseTransport | None = None):
        self.app_id = app_id
        self.private_key = private_key
        self.api_url = api_url.rstrip("/")
        self.http = httpx.Client(base_url=self.api_url, timeout=30, transport=transport,
                                 headers={"Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
        self._tokens: dict[int, tuple[str, float]] = {}

    @property
    def web_url(self) -> str:
        if self.api_url == "https://api.github.com":
            return "https://github.com"
        return self.api_url.removesuffix("/api/v3")

    # -- autenticación ----------------------------------------------------------------

    def app_jwt(self) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self.private_key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        """Token de instalación (válido 1 hora). Se cachea hasta 5 minutos antes de caducar."""
        cached = self._tokens.get(installation_id)
        if cached and cached[1] > time.time() + 300:
            return cached[0]
        r = self.http.post(f"/app/installations/{installation_id}/access_tokens",
                           headers={"Authorization": f"Bearer {self.app_jwt()}"})
        self._check(r)
        data = r.json()
        expires = time.time() + 3600
        if data.get("expires_at"):
            from datetime import datetime

            expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
        self._tokens[installation_id] = (data["token"], expires)
        return data["token"]

    def installation(self, installation_id: int) -> "InstallationClient":
        return InstallationClient(self, installation_id)

    @staticmethod
    def _check(r: httpx.Response):
        if r.status_code >= 400:
            # Nunca se incluyen cabeceras en el error: podrían contener tokens.
            raise GitHubError(f"GitHub API {r.request.method} {r.request.url.path} -> {r.status_code}: {r.text[:300]}")


class InstallationClient:
    def __init__(self, app: GitHubApp, installation_id: int):
        self.app = app
        self.installation_id = installation_id

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"token {self.app.installation_token(self.installation_id)}"}

    def request(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.app.http.request(method, path, headers=self._headers(), **kw)
        GitHubApp._check(r)
        return r

    # -- pull requests ----------------------------------------------------------------

    def pull_request_files(self, repo: str, number: int, limit: int = 3000) -> list[str]:
        files, page = [], 1
        while len(files) < limit:
            batch = self.request("GET", f"/repos/{repo}/pulls/{number}/files",
                                 params={"per_page": 100, "page": page}).json()
            files += [f["filename"] for f in batch if f.get("status") != "removed"]
            if len(batch) < 100:
                break
            page += 1
        return files

    def upsert_comment(self, repo: str, number: int, body: str, marker: str) -> int:
        """Crea o actualiza (si ya existe) el comentario del bot en el PR."""
        page = 1
        while True:
            comments = self.request("GET", f"/repos/{repo}/issues/{number}/comments",
                                    params={"per_page": 100, "page": page}).json()
            for c in comments:
                if marker in (c.get("body") or "") and (c.get("user") or {}).get("type") == "Bot":
                    self.request("PATCH", f"/repos/{repo}/issues/comments/{c['id']}", json={"body": body})
                    return c["id"]
            if len(comments) < 100:
                break
            page += 1
        return self.request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}).json()["id"]

    # -- checks -----------------------------------------------------------------------

    def create_check_run(self, repo: str, head_sha: str, name: str) -> int:
        r = self.request("POST", f"/repos/{repo}/check-runs",
                         json={"name": name, "head_sha": head_sha, "status": "in_progress"})
        return r.json()["id"]

    def complete_check_run(self, repo: str, check_run_id: int, conclusion: str, title: str, summary: str,
                           text: str = "", annotations: list[dict] | None = None):
        """Cierra el check. La API admite como máximo 50 anotaciones por petición."""
        annotations = annotations or []
        chunks = [annotations[i:i + 50] for i in range(0, len(annotations), 50)] or [[]]
        for i, chunk in enumerate(chunks):
            payload = {"output": {"title": title[:255], "summary": summary[:65000], "text": text[:65000],
                                  "annotations": chunk}}
            if i == len(chunks) - 1:
                payload.update(status="completed", conclusion=conclusion)
            self.request("PATCH", f"/repos/{repo}/check-runs/{check_run_id}", json=payload)

    # -- código -----------------------------------------------------------------------

    def clone(self, repo: str, sha: str, dest: Path, timeout: int = 300):
        """Descarga un único commit, sin historial, sin hooks, sin LFS y sin enlaces simbólicos.

        `core.symlinks=false` es importante: un repositorio malicioso podría incluir enlaces a
        ficheros del worker (p. ej. /etc/passwd) que acabarían en los informes o en el triage con IA.
        El token se pasa por variables de entorno de git, nunca en la URL ni en los argumentos.
        """
        token = self.app.installation_token(self.installation_id)
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        host = self.app.web_url
        env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": f"http.{host}/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            "GIT_CONFIG_KEY_1": "core.symlinks",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "core.hooksPath",
            "GIT_CONFIG_VALUE_2": "/dev/null",
            "GIT_CONFIG_KEY_3": "protocol.file.allow",
            "GIT_CONFIG_VALUE_3": "never",
        }
        dest.mkdir(parents=True, exist_ok=True)
        for cmd in (
            ["git", "init", "-q"],
            ["git", "remote", "add", "origin", f"{host}/{repo}.git"],
            ["git", "fetch", "-q", "--depth", "1", "--no-tags", "origin", sha],
            ["git", "checkout", "-q", "FETCH_HEAD"],
        ):
            proc = subprocess.run(cmd, cwd=dest, env=env, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0:
                raise GitHubError(f"{' '.join(cmd[:2])} falló: {proc.stderr.strip()[-300:]}")

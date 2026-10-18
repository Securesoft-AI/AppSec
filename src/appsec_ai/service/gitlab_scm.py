"""GitLab como plataforma de código: proyectos, clonado, merge requests, estados de commit y webhooks.

Cada organización conecta su GitLab (gitlab.com o propio) con un token de acceso con permiso `api`; el token y el
secreto del webhook se guardan cifrados. Los repositorios de GitLab se guardan en la misma tabla que los de GitHub,
con `provider = "gitlab"` y un id negativo derivado de la instalación y del id del proyecto, para que nunca choquen
con los ids de GitHub ni entre organizaciones.

Las llamadas a la API pasan por la salida protegida frente a SSRF y el clonado comprueba antes que el host es
público. El token nunca va en la URL ni en los argumentos de git.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from appsec_ai.egress import private_allowed, safe_transport
from appsec_ai.service.ownership import is_public_host

ID_SPACE = 10**10


class GitlabSCMError(RuntimeError):
    pass


def repo_id(installation_id: int, project_id: int) -> int:
    """Id de `Repository` para un proyecto de GitLab: negativo y único por organización."""
    if not 0 < project_id < ID_SPACE:
        raise ValueError("id de proyecto fuera de rango")
    return -(installation_id * ID_SPACE + project_id)


def project_id(repository_id: int) -> int:
    return (-repository_id) % ID_SPACE


def status_state(conclusion: str) -> str:
    return "failed" if conclusion == "failure" else "success"


class GitlabSCM:
    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._token, self._transport, self._timeout = token, transport, timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=f"{self.base_url}/api/v4", transport=self._transport or safe_transport(),
                            timeout=self._timeout, trust_env=False, headers={"PRIVATE-TOKEN": self._token})

    def _request(self, method: str, path: str, **kw) -> httpx.Response:
        try:
            with self._client() as c:
                r = c.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise GitlabSCMError(f"no se pudo conectar con GitLab: {type(e).__name__}") from None
        if r.status_code >= 300:
            raise GitlabSCMError(f"GitLab respondió {r.status_code} a {method} {path.split('?')[0]}")
        return r

    def check(self) -> str:
        """Usuario del token (para el botón de prueba)."""
        return self._request("GET", "/user").json().get("username", "")

    def projects(self, search: str = "") -> list[dict]:
        """Proyectos en los que el token es al menos Developer (máximo 100, filtrables por nombre)."""
        params = {"membership": "true", "min_access_level": 30, "simple": "true", "per_page": 100,
                  "order_by": "last_activity_at"}
        if search:
            params["search"] = search[:100]
        return [{"id": p["id"], "path": p.get("path_with_namespace", ""), "default_branch": p.get("default_branch") or "main",
                 "private": p.get("visibility") != "public"}
                for p in self._request("GET", "/projects", params=params).json()]

    def project(self, pid: int) -> dict:
        p = self._request("GET", f"/projects/{pid}").json()
        return {"id": p["id"], "path": p.get("path_with_namespace", ""), "default_branch": p.get("default_branch") or "main",
                "private": p.get("visibility") != "public"}

    def branch_head(self, pid: int, branch: str) -> str:
        return self._request("GET", f"/projects/{pid}/repository/branches/{quote(branch, safe='')}").json()["commit"]["id"]

    def mr_changed_files(self, pid: int, iid: int, limit: int = 3000) -> list[str]:
        files, page = [], 1
        while len(files) < limit:
            batch = self._request("GET", f"/projects/{pid}/merge_requests/{iid}/diffs",
                                  params={"per_page": 100, "page": page}).json()
            files += [d["new_path"] for d in batch if not d.get("deleted_file")]
            if len(batch) < 100:
                break
            page += 1
        return files[:limit]

    def set_status(self, pid: int, sha: str, state: str, description: str = "", target_url: str = ""):
        data = {"state": state, "name": "appsec-ai", "description": description[:250]}
        if target_url.startswith("https://"):
            data["target_url"] = target_url
        self._request("POST", f"/projects/{pid}/statuses/{sha}", json=data)

    def upsert_mr_note(self, pid: int, iid: int, body: str, marker: str) -> int:
        """Un único comentario por MR: se actualiza el nuestro (el que lleva la marca) en lugar de crear otro."""
        notes = self._request("GET", f"/projects/{pid}/merge_requests/{iid}/notes",
                              params={"per_page": 100, "sort": "desc"}).json()
        me = self.check()
        for n in notes:
            if marker in (n.get("body") or "") and (n.get("author") or {}).get("username") == me:
                self._request("PUT", f"/projects/{pid}/merge_requests/{iid}/notes/{n['id']}", json={"body": body})
                return n["id"]
        return self._request("POST", f"/projects/{pid}/merge_requests/{iid}/notes", json={"body": body}).json()["id"]

    def create_hook(self, pid: int, url: str, secret: str) -> bool:
        """Crea el webhook de push y merge requests. Necesita rol Maintainer; si no, se configura a mano."""
        try:
            self._request("POST", f"/projects/{pid}/hooks",
                          json={"url": url, "token": secret, "push_events": True, "merge_requests_events": True,
                                "enable_ssl_verification": True})
            return True
        except GitlabSCMError:
            return False

    def clone(self, path: str, sha: str, dest: Path, timeout: int = 300):
        """Descarga un único commit, sin historial, hooks, LFS ni enlaces simbólicos (como en GitHub)."""
        host = urlparse(self.base_url).hostname or ""
        if not private_allowed() and not is_public_host(host):
            raise GitlabSCMError("el host de GitLab no es público")
        basic = base64.b64encode(f"oauth2:{self._token}".encode()).decode()
        env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "5",
            "GIT_CONFIG_KEY_0": f"http.{self.base_url}/.extraheader", "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            "GIT_CONFIG_KEY_1": "core.symlinks", "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "core.hooksPath", "GIT_CONFIG_VALUE_2": "/dev/null",
            "GIT_CONFIG_KEY_3": "protocol.allow", "GIT_CONFIG_VALUE_3": "never",
            "GIT_CONFIG_KEY_4": "protocol.https.allow", "GIT_CONFIG_VALUE_4": "always",
        }
        dest.mkdir(parents=True, exist_ok=True)
        for cmd in (["git", "init", "-q"],
                    ["git", "-c", "http.followRedirects=false", "remote", "add", "origin", f"{self.base_url}/{path}.git"],
                    ["git", "-c", "http.followRedirects=false", "fetch", "-q", "--depth", "1", "--no-tags", "origin", sha],
                    ["git", "checkout", "-q", "FETCH_HEAD"]):
            proc = subprocess.run(cmd, cwd=dest, env=env, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0:
                raise GitlabSCMError(f"{' '.join(cmd[:2])} falló: {proc.stderr.strip()[-300:]}")


class GitlabHost:
    """Adaptador con la misma forma que el cliente de GitHub que usa el worker, para un escaneo concreto.

    Los "checks" de GitHub se traducen en estados de commit y los comentarios del PR en una nota en la MR.
    """

    def __init__(self, scm: GitlabSCM, pid: int, sha: str, panel_url: str = ""):
        self.scm, self.pid, self.sha, self.panel_url = scm, pid, sha, panel_url

    def create_check_run(self, repo: str, sha: str, name: str) -> int | None:
        self.scm.set_status(self.pid, sha, "running", "Atalaya", self.panel_url)
        return None  # GitLab no tiene id de check: el estado va ligado al commit

    def complete_check_run(self, repo: str, check_id, conclusion: str, title: str, summary: str = "", text: str = "",
                           annotations=None, actions=None):
        self.scm.set_status(self.pid, self.sha, status_state(conclusion), title, self.panel_url)

    def pull_request_files(self, repo: str, number: int, limit: int = 3000) -> list[str]:
        return self.scm.mr_changed_files(self.pid, number, limit)

    def upsert_comment(self, repo: str, number: int, body: str, marker: str) -> int:
        return self.scm.upsert_mr_note(self.pid, number, body, marker)

    def clone(self, repo: str, sha: str, dest: Path, timeout: int = 300):
        self.scm.clone(repo, sha, dest, timeout)

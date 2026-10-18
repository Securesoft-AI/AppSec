"""Destinos de integración (Jira, GitLab): crear una incidencia desde un hallazgo, manual o automática.

Centraliza lo común a las integraciones de "destino de hallazgos" para que la API (botón por hallazgo) y el
worker (envío automático al terminar un escaneo) hagan exactamente lo mismo, sin duplicar incidencias.
"""

from __future__ import annotations

import logging

from appsec_ai.service.gitlab import Gitlab, GitlabError, finding_markdown
from appsec_ai.service.jira import Jira, JiraError, finding_adf

log = logging.getLogger("appsec_ai.integrations")

PROVIDERS = ("jira", "gitlab")
SERIOUS = ("critical", "high")       # severidades que se exportan automáticamente
MAX_AUTO_PER_SCAN = 50               # tope para no inundar el tracker con un escaneo enorme


class IntegrationError(RuntimeError):
    pass


def _labels(finding: dict) -> list[str]:
    return [x for x in ("appsec-ai", str(finding.get("severity", "")), str(finding.get("category", ""))) if x]


def _summary(finding: dict, repo: str) -> str:
    return f"[{finding.get('severity', '')}] {finding.get('title', '')} — {repo}"


def create_issue(provider: str, cfg: dict, finding: dict, repo: str, lang: str) -> dict:
    """Crea la incidencia en el destino y devuelve {key, url}. Lanza IntegrationError si falla."""
    try:
        if provider == "jira":
            client = Jira(cfg["base_url"], cfg["email"], cfg["token"])
            return client.create_issue(cfg["project_key"], _summary(finding, repo),
                                       finding_adf(finding, repo, lang), _labels(finding))
        if provider == "gitlab":
            client = Gitlab(cfg["base_url"], cfg["token"])
            return client.create_issue(cfg["project"], _summary(finding, repo),
                                       finding_markdown(finding, repo, lang), _labels(finding))
    except (JiraError, GitlabError) as e:
        raise IntegrationError(str(e)) from None
    raise IntegrationError(f"destino desconocido: {provider}")


def auto_export(db, cipher, installation_id: int, configs: dict, findings: list[dict], repo: str,
                lang: str) -> dict:
    """Crea incidencias para los hallazgos graves nuevos en cada destino con el automático activado.

    `configs` es {provider: cfg_descifrada}. Deduplica con la tabla de exportaciones: un hallazgo ya enviado
    no se vuelve a crear. Un fallo con un destino o un hallazgo se registra y no interrumpe el resto.
    """
    serious = [f for f in findings if str(f.get("severity", "")).lower() in SERIOUS and f.get("fingerprint")]
    created: dict[str, int] = {}
    for provider in PROVIDERS:
        cfg = configs.get(provider) or {}
        if not cfg or not cfg.get("auto"):
            continue
        already = db.exported_fingerprints(installation_id, provider)
        pending = [f for f in serious if f["fingerprint"] not in already][:MAX_AUTO_PER_SCAN]
        n = 0
        for finding in pending:
            try:
                issue = create_issue(provider, cfg, finding, repo, lang)
            except IntegrationError as e:
                log.warning("envío automático a %s falló: %s", provider, e)
                break  # probablemente credenciales o red: no insistir con el resto este escaneo
            if db.record_export(installation_id, provider, finding["fingerprint"], issue["key"], issue["url"]):
                n += 1
        if n:
            created[provider] = n
    return created

"""Modo demostración: login user/pass y una organización con código de ejemplo para probar el producto.

Solo se activa con DEMO_LOGIN=1. La sesión de demostración únicamente ve la organización de ejemplo
(id DEMO_INSTALLATION_ID), que no existe en GitHub: sus escaneos se ejecutan al momento sobre el código de
web/demo-repos, que es deliberadamente vulnerable y forma parte de la aplicación.
"""

from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from appsec_ai.engines.base import Engine
from appsec_ai.scanner import ALL_ENGINES, scan as run_scan
from appsec_ai.service.crypto import seal
from appsec_ai.service.db import (Database, Installation, PentestRequest, PentestStatus, Repository, Scan, ScanKind,
                                  ScanStatus, utcnow)
from appsec_ai.services import SCAN_SERVICES, categories_for, engines_for

log = logging.getLogger("appsec_ai.demo")

DEMO_INSTALLATION_ID = 1
DEMO_ACCOUNT = "demo-org"
DEMO_REPOS = {  # id -> (nombre, carpeta en web/demo-repos)
    1001: ("demo-org/chatbot-soporte", "chatbot-soporte"),
    1002: ("demo-org/agentes-internos", "agentes-internos"),
    1003: ("demo-org/asistente-rrhh", "asistente-rrhh"),
}


def repos_dir() -> Path | None:
    for base in (Path.cwd() / "web" / "demo-repos", Path(__file__).resolve().parents[3] / "web" / "demo-repos"):
        if base.is_dir():
            return base
    return None


def is_demo(installation_id: int | None) -> bool:
    return installation_id == DEMO_INSTALLATION_ID


def seed(db: Database):
    """Crea la organización de ejemplo (idempotente) y un primer escaneo de cada repositorio."""
    base = repos_dir()
    if base is None:
        log.warning("modo demo sin código de ejemplo (web/demo-repos no encontrado)")
        return
    with db.session() as s, s.begin():
        inst = s.get(Installation, DEMO_INSTALLATION_ID)
        if inst is None:
            inst = Installation(id=DEMO_INSTALLATION_ID, account_login=DEMO_ACCOUNT)
            s.add(inst)
        # Siempre en prueba (se renueva en cada arranque): la demo enseña todos los servicios.
        inst.trial_ends_at, inst.active = utcnow() + dt.timedelta(days=30), True
        s.flush()
        for repo_id, (name, _) in DEMO_REPOS.items():
            if s.get(Repository, repo_id) is None:
                s.add(Repository(id=repo_id, installation_id=DEMO_INSTALLATION_ID, full_name=name, default_branch="main"))
        if not s.query(PentestRequest).filter_by(installation_id=DEMO_INSTALLATION_ID).first():
            s.add(PentestRequest(
                installation_id=DEMO_INSTALLATION_ID, requested_by="demo", kind="llm",
                target="https://soporte.demo-org.example", scope="Chatbot de soporte y su RAG de documentación interna",
                preferred_dates="semana 44", contact_email="seguridad@demo-org.example",
                status=PentestStatus.REPORTED.value, quote_eur=3500,
                report=seal(db.cipher, {
                    "summary": "Se obtuvo el prompt de sistema y documentos internos de otros clientes mediante "
                               "inyección indirecta a través de una página web resumida por el chatbot.",
                    "findings": [
                        {"title": "Prompt injection indirecta vía /summarize", "severity": "high",
                         "description": "Una página controlada por el atacante ordena al modelo revelar su prompt.",
                         "fix": "Delimitar el contenido externo y no darle al modelo acceso a datos de otros clientes."},
                        {"title": "RAG sin filtro por cliente", "severity": "high",
                         "description": "La búsqueda vectorial devuelve documentos de cualquier cliente.",
                         "fix": "Filtrar por tenant en la consulta al vector store."},
                    ]})))
            # Otro pendiente de que el cliente acepte el presupuesto.
            s.add(PentestRequest(
                installation_id=DEMO_INSTALLATION_ID, requested_by="demo", kind="api",
                target="https://api.demo-org.example", scope="API pública de pedidos (OpenAPI adjunta), roles cliente y admin",
                preferred_dates="diciembre", contact_email="seguridad@demo-org.example",
                status=PentestStatus.SCOPING.value, quote_eur=2900,
                notes="Proponemos 4 días de prueba con dos roles. Podemos empezar el 1 de diciembre."))
    with db.session() as s:
        missing = [rid for rid in DEMO_REPOS if not s.query(Scan).filter_by(repository_id=rid).first()]
    for repo_id in missing:
        scan_demo_repo(db, repo_id, ["ai", "secrets", "sast"], requested_by="demo")


def available_engines(engines: list[str]) -> list[str]:
    out = []
    for name in engines:
        engine: Engine = ALL_ENGINES[name]()
        if engine.available():
            out.append(name)
    return out


def scan_demo_repo(db: Database, repo_id: int, services: list[str], requested_by: str) -> Scan:
    """Escaneo inmediato de un repositorio de ejemplo (el código es nuestro: no hace falta el aislamiento)."""
    name, folder = DEMO_REPOS[repo_id]
    services = [s for s in SCAN_SERVICES if s in services]
    result = run_scan(repos_dir() / folder, engines=available_engines(engines_for(services)))
    cats = categories_for(services)
    result = result.model_copy(update={
        "findings": [f for f in result.findings if f.category.value in cats],
        "ai_inventory": result.ai_inventory if "ai" in services else [], "target": name})
    visible = [f for f in result.findings if not f.is_suppressed]
    counts = {sev: sum(f.effective_severity.value == sev for f in visible)
              for sev in ("critical", "high", "medium", "low", "info")}
    now = utcnow()
    with db.session() as s, s.begin():
        n = s.query(Scan).filter_by(repository_id=repo_id).count()
        scan = Scan(repository_id=repo_id, kind=ScanKind.MANUAL.value, head_sha=f"demo{repo_id}{n:04d}",
                    ref="refs/heads/main", status=ScanStatus.COMPLETED.value, services=services,
                    requested_by=requested_by, result=seal(db.cipher, result.model_dump(mode="json")),
                    summary={"counts": counts, "total": len(visible), "conclusion": "demo", "llm_usage": {}},
                    created_at=now, started_at=now, finished_at=now)
        s.add(scan)
        s.flush()
        return scan

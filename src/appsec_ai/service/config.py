"""Configuración del servicio, leída de variables de entorno."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "sqlite:///./appsec-ai.db"))
    github_app_id: str = field(default_factory=lambda: _env("GITHUB_APP_ID"))
    # Clave privada PEM de la GitHub App (con saltos de línea reales o escapados como \n).
    github_private_key: str = field(default_factory=lambda: _env("GITHUB_APP_PRIVATE_KEY").replace("\\n", "\n"))
    github_webhook_secret: str = field(default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET"))
    github_api_url: str = field(default_factory=lambda: _env("GITHUB_API_URL", "https://api.github.com"))
    # Triage con IA: solo si hay credenciales de Anthropic.
    ai_triage: bool = field(default_factory=lambda: bool(_env("ANTHROPIC_API_KEY")) and _env("AI_TRIAGE", "1") != "0")
    ai_model: str = field(default_factory=lambda: _env("AI_MODEL", "claude-opus-5-5"))
    ai_effort: str = field(default_factory=lambda: _env("AI_EFFORT", "medium"))
    ai_max_requests_pr: int = field(default_factory=lambda: int(_env("AI_MAX_REQUESTS_PR", "15")))
    ai_max_requests_full: int = field(default_factory=lambda: int(_env("AI_MAX_REQUESTS_FULL", "60")))
    language: str = field(default_factory=lambda: _env("REPORT_LANGUAGE", "es"))
    # Límites del worker.
    max_repo_mb: int = field(default_factory=lambda: int(_env("MAX_REPO_MB", "500")))
    clone_timeout: int = field(default_factory=lambda: int(_env("CLONE_TIMEOUT", "300")))
    workdir: str = field(default_factory=lambda: _env("WORKDIR", ""))
    # Severidad a partir de la cual el check del PR falla.
    fail_on: str = field(default_factory=lambda: _env("FAIL_ON", "high"))


def get_settings() -> Settings:
    return Settings()

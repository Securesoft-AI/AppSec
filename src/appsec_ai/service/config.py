"""Configuración del servicio, leída de variables de entorno."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from appsec_ai.services import PURCHASABLE


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
    # Caché del triage entre escaneos (una subcarpeta por repositorio). Vacío = sin caché.
    ai_cache_dir: str = field(default_factory=lambda: _env("AI_CACHE_DIR"))
    language: str = field(default_factory=lambda: _env("REPORT_LANGUAGE", "es"))
    # Límites del worker.
    max_repo_mb: int = field(default_factory=lambda: int(_env("MAX_REPO_MB", "500")))
    clone_timeout: int = field(default_factory=lambda: int(_env("CLONE_TIMEOUT", "300")))
    workdir: str = field(default_factory=lambda: _env("WORKDIR", ""))
    # Login con GitHub en el panel (OAuth de la GitHub App).
    github_client_id: str = field(default_factory=lambda: _env("GITHUB_CLIENT_ID"))
    github_client_secret: str = field(default_factory=lambda: _env("GITHUB_CLIENT_SECRET"))
    # Firma de las cookies de sesión. Larga y aleatoria: openssl rand -hex 32.
    session_secret: str = field(default_factory=lambda: _env("SESSION_SECRET"))
    # URL pública del servicio (https://...), para el callback de OAuth y la comprobación de Origin.
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", "http://localhost:8000").rstrip("/"))
    # Stripe: clave secreta, secreto del webhook y precio mensual (price_...) de cada servicio y paquete:
    # STRIPE_PRICE_SAST, STRIPE_PRICE_SCA, ..., STRIPE_PRICE_COMPLETE (ver appsec_ai/services.py).
    stripe_secret_key: str = field(default_factory=lambda: _env("STRIPE_SECRET_KEY"))
    stripe_webhook_secret: str = field(default_factory=lambda: _env("STRIPE_WEBHOOK_SECRET"))
    stripe_prices: dict = field(default_factory=lambda: {
        item: _env(f"STRIPE_PRICE_{item.upper()}") for item in PURCHASABLE})
    # Aislamiento del escaneo: "subprocess" (por defecto) o "none" (solo para desarrollo).
    scan_sandbox: str = field(default_factory=lambda: _env("SCAN_SANDBOX", "subprocess"))
    # Envoltorio opcional del subproceso, p. ej. "bwrap --unshare-all --share-net ... --bind {src} {src}".
    scan_sandbox_cmd: str = field(default_factory=lambda: _env("SCAN_SANDBOX_CMD"))
    scan_timeout: int = field(default_factory=lambda: int(_env("SCAN_TIMEOUT", "900")))
    # Cifrado en reposo de resultados y caché (claves Fernet separadas por comas; la primera cifra).
    data_encryption_key: str = field(default_factory=lambda: _env("DATA_ENCRYPTION_KEY"))
    # Severidad a partir de la cual el check del PR falla.
    fail_on: str = field(default_factory=lambda: _env("FAIL_ON", "high"))


def get_settings() -> Settings:
    return Settings()

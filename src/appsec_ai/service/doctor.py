"""`appsec-ai doctor`: comprueba la configuración antes de poner el servicio en marcha.

Revisa las variables de entorno, la base de datos y los motores instalados. Con `--online` además prueba las
credenciales contra GitHub, Anthropic y Stripe con llamadas de solo lectura (no crea nada ni cobra).

Cada comprobación devuelve un `Check` con estado ok / warn / fail. Nunca imprime secretos.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from appsec_ai.service.config import Settings

OK, WARN, FAIL = "ok", "warn", "fail"
ENGINES = {"semgrep": "SAST", "gitleaks": "secretos", "osv-scanner": "dependencias (SCA)", "checkov": "IaC"}


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


def _production(s: Settings) -> bool:
    return s.public_url.startswith("https://")


def check_config(s: Settings) -> list[Check]:
    prod = _production(s)
    out: list[Check] = []
    add = lambda name, status, detail="": out.append(Check(name, status, detail))  # noqa: E731

    host = urlparse(s.public_url).hostname or ""
    if prod:
        add("PUBLIC_URL", OK, s.public_url)
    else:
        add("PUBLIC_URL", WARN, f"{s.public_url}: en producción debe ser https (cookies seguras, callbacks)")

    if s.demo_login:
        add("DEMO_LOGIN", FAIL if prod else WARN,
            "el login de demostración está activo: desactívalo en producción y nunca con datos de clientes")
    else:
        add("DEMO_LOGIN", OK, "desactivado")

    if len(s.session_secret) >= 32:
        add("SESSION_SECRET", OK, f"{len(s.session_secret)} caracteres")
    else:
        add("SESSION_SECRET", FAIL, "falta o es corto (mínimo 32 caracteres): python -c 'import secrets;print(secrets.token_hex(32))'")

    if s.data_encryption_key:
        try:
            from appsec_ai.service.crypto import Cipher
            Cipher(s.data_encryption_key)
            add("DATA_ENCRYPTION_KEY", OK, "clave Fernet válida")
        except Exception:  # noqa: BLE001
            add("DATA_ENCRYPTION_KEY", FAIL, "no es una clave Fernet válida")
    else:
        add("DATA_ENCRYPTION_KEY", FAIL if prod else WARN,
            "sin clave los secretos de las integraciones y los resultados se guardan sin cifrar")

    if s.database_url.startswith("sqlite"):
        add("DATABASE_URL", WARN if not prod else FAIL, "SQLite solo para pruebas; en producción usa Postgres")
    else:
        add("DATABASE_URL", OK, urlparse(s.database_url).scheme)

    # GitHub App
    if s.github_app_id and s.github_private_key:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            load_pem_private_key(s.github_private_key.encode(), password=None)
            add("GITHUB_APP", OK, f"App {s.github_app_id}, clave privada válida")
        except Exception:  # noqa: BLE001
            add("GITHUB_APP", FAIL, "GITHUB_APP_PRIVATE_KEY no es una clave PEM válida")
    else:
        add("GITHUB_APP", FAIL, "faltan GITHUB_APP_ID y/o GITHUB_APP_PRIVATE_KEY (ver deploy/github-app-manifest.json)")
    add("GITHUB_WEBHOOK_SECRET", OK if len(s.github_webhook_secret) >= 20 else FAIL,
        "" if len(s.github_webhook_secret) >= 20 else "falta o es corto: sin él se rechazan todos los webhooks")
    if s.github_client_id and s.github_client_secret:
        add("LOGIN_GITHUB", OK, "OAuth de la App configurado")
    else:
        add("LOGIN_GITHUB", WARN, "sin GITHUB_CLIENT_ID/SECRET no se puede entrar al panel con GitHub")

    # IA
    if os.environ.get("ANTHROPIC_API_KEY"):
        add("ANTHROPIC_API_KEY", OK, f"triage {'activo' if s.ai_triage else 'desactivado (AI_TRIAGE=0)'}, modelo {s.ai_model}")
    else:
        add("ANTHROPIC_API_KEY", WARN, "sin clave no hay triage con IA ni análisis de IA (el escaneo sigue funcionando)")

    # Stripe
    if s.stripe_secret_key:
        mode = "live" if s.stripe_secret_key.startswith(("sk_live_", "rk_live_")) else "test"
        add("STRIPE_SECRET_KEY", OK if (mode == "live" or not prod) else WARN, f"modo {mode}")
        add("STRIPE_WEBHOOK_SECRET", OK if s.stripe_webhook_secret.startswith("whsec_") else FAIL,
            "" if s.stripe_webhook_secret.startswith("whsec_") else "falta (whsec_...): sin él no se activan los planes")
        missing = sorted(k for k, v in s.stripe_prices.items() if not v)
        add("STRIPE_PRICES", OK if not missing else WARN,
            "todos los precios definidos" if not missing else "faltan STRIPE_PRICE_" + ", STRIPE_PRICE_".join(m.upper() for m in missing))
    else:
        add("STRIPE", WARN, "sin STRIPE_SECRET_KEY no se puede cobrar (todo queda en plan gratuito/prueba)")

    # Aislamiento del escaneo
    if s.scan_runner:
        if "{src}" in s.scan_runner and "{out}" in s.scan_runner:
            add("SCAN_RUNNER", OK, "contenedor efímero por escaneo")
        else:
            add("SCAN_RUNNER", FAIL, "la plantilla debe incluir {src} y {out}")
    else:
        add("SCAN_RUNNER", WARN if prod else OK,
            "sin contenedor por escaneo: el código del cliente se analiza en un subproceso del worker")

    add("STAFF_LOGINS", OK if s.staff_logins else WARN,
        ", ".join(sorted(s.staff_logins)) if s.staff_logins else "nadie verá la vista Equipo (pentests)")
    if os.environ.get("EGRESS_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes"):
        add("EGRESS_ALLOW_PRIVATE", WARN, "defensa SSRF desactivada: solo para instalaciones propias")
    if host in ("localhost", "127.0.0.1") and prod:
        add("PUBLIC_URL", FAIL, "https con localhost: GitHub no podrá llamar a tu webhook")
    return out


def check_engines(which=shutil.which) -> list[Check]:
    out = []
    for binary, what in ENGINES.items():
        alt = "opengrep" if binary == "semgrep" else ""
        found = which(binary) or (alt and which(alt))
        out.append(Check(f"motor {binary}", OK if found else WARN,
                         what if found else f"no instalado: sin {what} (la imagen Docker ya lo incluye)"))
    return out


def check_database(s: Settings) -> list[Check]:
    try:
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory

        from appsec_ai.service.db import Database, _alembic_config

        db = Database(s.database_url)
        head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
        with db.engine.connect() as conn:
            current = MigrationContext.configure(conn).get_current_revision()
    except Exception as e:  # noqa: BLE001
        return [Check("base de datos", FAIL, f"no se pudo conectar: {type(e).__name__}")]
    if current == head:
        return [Check("base de datos", OK, f"conecta, esquema al día ({head})")]
    return [Check("base de datos", WARN, f"conecta; esquema en {current or 'vacío'}, última {head}: "
                                         "se migra solo al arrancar o con `appsec-ai migrate`")]


def check_online(s: Settings, transport: httpx.BaseTransport | None = None) -> list[Check]:
    """Prueba las credenciales con llamadas de solo lectura."""
    out: list[Check] = []

    def get(url, **kw):
        with httpx.Client(transport=transport, timeout=15, trust_env=transport is None) as c:
            return c.get(url, **kw)

    if s.github_app_id and s.github_private_key:
        try:
            from appsec_ai.service.github import GitHubApp
            app = GitHubApp(s.github_app_id, s.github_private_key, s.github_api_url)
            r = get(f"{s.github_api_url}/app", headers={"Authorization": f"Bearer {app.app_jwt()}",
                                                         "Accept": "application/vnd.github+json"})
            out.append(Check("GitHub (online)", OK if r.status_code == 200 else FAIL,
                             f"App «{r.json().get('slug', '')}»" if r.status_code == 200 else f"GitHub respondió {r.status_code}"))
            if r.status_code == 200:
                perms = r.json().get("permissions") or {}
                missing = [p for p in ("contents", "pull_requests", "checks", "members") if p not in perms]
                out.append(Check("GitHub permisos", OK if not missing else WARN,
                                 "completos" if not missing else "faltan: " + ", ".join(missing)
                                 + " (members: read es necesario para saber quién administra cada organización)"))
        except Exception as e:  # noqa: BLE001
            out.append(Check("GitHub (online)", FAIL, type(e).__name__))

    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        try:
            r = get(f"https://api.anthropic.com/v1/models/{s.ai_model}",
                    headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
            out.append(Check("Anthropic (online)", OK if r.status_code == 200 else FAIL,
                             f"modelo {s.ai_model} disponible" if r.status_code == 200
                             else f"Anthropic respondió {r.status_code} (clave o modelo)"))
        except httpx.HTTPError as e:
            out.append(Check("Anthropic (online)", FAIL, type(e).__name__))

    if s.stripe_secret_key:
        bad = []
        try:
            for item, price in s.stripe_prices.items():
                if price and get(f"https://api.stripe.com/v1/prices/{price}",
                                 auth=(s.stripe_secret_key, "")).status_code != 200:
                    bad.append(item)
            out.append(Check("Stripe (online)", OK if not bad else FAIL,
                             "clave y precios válidos" if not bad else "precios no encontrados: " + ", ".join(bad)))
        except httpx.HTTPError as e:
            out.append(Check("Stripe (online)", FAIL, type(e).__name__))
    return out


def run(s: Settings, online: bool = False) -> list[Check]:
    checks = check_config(s) + check_engines() + check_database(s)
    if online:
        checks += check_online(s)
    return checks


def render(checks: list[Check]) -> str:
    icon = {OK: "✔", WARN: "!", FAIL: "✘"}
    lines = [f" {icon[c.status]} {c.name:<24} {c.detail}".rstrip() for c in checks]
    fails = sum(c.status == FAIL for c in checks)
    warns = sum(c.status == WARN for c in checks)
    lines.append("")
    lines.append("Listo para producción." if not fails and not warns else
                 f"{fails} errores y {warns} avisos." + (" Corrige los errores antes de desplegar." if fails else ""))
    return "\n".join(lines)

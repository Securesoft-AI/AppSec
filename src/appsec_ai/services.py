"""Catálogo de servicios, paquetes y precios: la única fuente de verdad para panel, web, cobros y worker.

Cada servicio de escaneo dice qué motores necesita y qué categorías de hallazgos produce. El pentest es
un servicio que hace el equipo de seguridad: se solicita desde el panel y su informe aparece junto al
resto, pero no lo ejecuta el worker.

Para cambiar precios basta con editar este fichero (y el precio correspondiente en Stripe).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    key: str
    name: dict[str, str]
    summary: dict[str, str]
    engines: tuple[str, ...] = ()      # motores que lo implementan (vacío = servicio humano)
    categories: tuple[str, ...] = ()   # categorías de hallazgo que produce
    price_month_eur: int = 0           # 0 = no se cobra por mes
    price_from_eur: int = 0            # servicios por proyecto: precio orientativo "desde"

    @property
    def is_scan(self) -> bool:
        return bool(self.engines)


SERVICES: dict[str, Service] = {s.key: s for s in [
    Service("sast", {"es": "Análisis de código (SAST)", "en": "Code analysis (SAST)"},
            {"es": "Inyecciones, XSS, SSRF, deserialización y criptografía débil en Python, JS/TS, Java y Go.",
             "en": "Injections, XSS, SSRF, deserialisation and weak crypto in Python, JS/TS, Java and Go."},
            engines=("opengrep",), categories=("sast",), price_month_eur=29),
    Service("sca", {"es": "Dependencias (SCA)", "en": "Dependencies (SCA)"},
            {"es": "Vulnerabilidades conocidas (CVE) en las librerías de terceros y sus versiones.",
             "en": "Known vulnerabilities (CVEs) in third-party libraries and their versions."},
            engines=("osv-scanner",), categories=("sca",), price_month_eur=19),
    Service("secrets", {"es": "Secretos", "en": "Secrets"},
            {"es": "Claves, tokens y contraseñas expuestos en el código. Nunca guardamos el valor.",
             "en": "Keys, tokens and passwords exposed in code. We never store the value."},
            engines=("gitleaks",), categories=("secrets",), price_month_eur=19),
    Service("iac", {"es": "Infraestructura (IaC)", "en": "Infrastructure (IaC)"},
            {"es": "Errores de configuración en Terraform, Kubernetes, Docker, CloudFormation y GitHub Actions.",
             "en": "Misconfigurations in Terraform, Kubernetes, Docker, CloudFormation and GitHub Actions."},
            engines=("checkov",), categories=("iac",), price_month_eur=19),
    Service("ai", {"es": "Seguridad de IA (OWASP LLM)", "en": "AI security (OWASP LLM)"},
            {"es": "Prompt injection, agentes y herramientas peligrosas, RAG sin control de acceso, secretos en "
                   "prompts y salida del modelo hacia código, SQL o HTML. Inventario de IA y mapeo a EU AI Act.",
             "en": "Prompt injection, dangerous agents and tools, RAG without access control, secrets in prompts "
                   "and model output flowing into code, SQL or HTML. AI inventory and EU AI Act mapping."},
            engines=("ai-security", "opengrep"), categories=("ai",), price_month_eur=49),
    Service("pentest", {"es": "Pentest", "en": "Penetration test"},
            {"es": "Prueba de intrusión manual de vuestro equipo de seguridad sobre web, API, móvil o aplicaciones "
                   "con LLM. Se solicita desde el panel y el informe queda junto al resto.",
             "en": "Manual penetration test by our security team on web, API, mobile or LLM applications. Request it "
                   "from the dashboard; the report sits next to everything else."},
            price_from_eur=2900),
]}

SCAN_SERVICES = tuple(k for k, s in SERVICES.items() if s.is_scan)


@dataclass(frozen=True)
class Bundle:
    key: str
    name: dict[str, str]
    services: tuple[str, ...]
    price_month_eur: int

    @property
    def list_price_eur(self) -> int:
        return sum(SERVICES[s].price_month_eur for s in self.services)


BUNDLES: dict[str, Bundle] = {b.key: b for b in [
    Bundle("code", {"es": "Paquete Código", "en": "Code bundle"}, ("sast", "secrets"), 39),
    Bundle("supply", {"es": "Paquete Supply chain", "en": "Supply chain bundle"}, ("sca", "iac"), 29),
    Bundle("complete", {"es": "Paquete Completo", "en": "Complete bundle"}, SCAN_SERVICES, 99),
]}

# Contratable por suscripción: cada servicio de escaneo suelto y cada paquete.
PURCHASABLE = (*SCAN_SERVICES, *BUNDLES)


def expand(items) -> set[str]:
    """Servicios incluidos en una lista de servicios y paquetes contratados."""
    out: set[str] = set()
    for item in items or ():
        if item in BUNDLES:
            out |= set(BUNDLES[item].services)
        elif item in SERVICES and SERVICES[item].is_scan:
            out.add(item)
    return out


def engines_for(services) -> list[str]:
    """Motores necesarios, en un orden estable."""
    needed = {e for s in services for e in SERVICES[s].engines}
    order = ["ai-security", "gitleaks", "osv-scanner", "checkov", "opengrep"]
    return [e for e in order if e in needed]


def categories_for(services) -> set[str]:
    return {c for s in services for c in SERVICES[s].categories}


def catalog(lang: str = "es") -> dict:
    """Catálogo para el panel y la web."""
    lang = "en" if lang == "en" else "es"
    return {
        "services": [{"key": s.key, "name": s.name[lang], "summary": s.summary[lang], "scan": s.is_scan,
                      "price_month_eur": s.price_month_eur, "price_from_eur": s.price_from_eur}
                     for s in SERVICES.values()],
        "bundles": [{"key": b.key, "name": b.name[lang], "services": list(b.services),
                     "price_month_eur": b.price_month_eur, "list_price_eur": b.list_price_eur}
                    for b in BUNDLES.values()],
    }

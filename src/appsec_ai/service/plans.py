"""Qué puede usar cada organización: servicios contratados, prueba gratuita y límites (RF-4.5).

Se cobra por servicios sueltos o paquetes (ver appsec_ai/services.py). Lo que una organización puede usar:
1. Suscripción de Stripe activa (o en periodo de gracia) -> los servicios contratados.
2. Si no, durante los 14 días siguientes a instalar la App -> prueba con todos los servicios.
3. Si no -> Free: Secretos y Dependencias, 1 repositorio, escaneo semanal, sin IA.

El presupuesto mensual de peticiones de IA protege el margen: el coste de Claude lo paga la suscripción.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from appsec_ai.services import SCAN_SERVICES, expand

TRIAL_DAYS = 14
ACTIVE_STATUSES = {"active", "trialing", "past_due"}  # past_due: Stripe reintenta el cobro unos días
FREE_SERVICES = frozenset({"secrets", "sca"})
PAID_MAX_REPOS = 25
AI_REQUESTS_PER_SERVICE = 1_500  # al mes, por servicio contratado


@dataclass(frozen=True)
class Plan:
    name: str                      # "free" | "trial" | "paid"
    services: frozenset[str]       # servicios de escaneo disponibles
    max_repos: int | None          # None = ilimitados
    pr_scans: bool
    min_days_between_full: int     # 7 = escaneo semanal de la rama principal
    ai_triage: bool
    ai_requests_month: int
    fix_pr: bool
    pdf_report: bool
    compliance: bool               # mapeo a EU AI Act / ISO 42001 / NIST / ATLAS (va con Seguridad de IA)

    @property
    def redteam(self) -> bool:
        """Red teaming dinámico (RF-2.7): va con el servicio de Seguridad de IA."""
        return "ai" in self.services


FREE = Plan("free", FREE_SERVICES, 1, False, 7, False, 0, False, False, False)


def _paid(name: str, services: frozenset[str]) -> Plan:
    return Plan(name, services, PAID_MAX_REPOS, True, 0, True, AI_REQUESTS_PER_SERVICE * len(services),
                True, True, "ai" in services)


TRIAL = _paid("trial", frozenset(SCAN_SERVICES))


def effective_plan(inst, now: dt.datetime | None = None) -> Plan:
    now = now or dt.datetime.now(dt.timezone.utc)
    subscribed = frozenset(expand(inst.modules or []))
    if subscribed and inst.subscription_status in ACTIVE_STATUSES:
        return _paid("paid", subscribed)
    if inst.trial_ends_at and _aware(inst.trial_ends_at) > now:
        return TRIAL
    return FREE


def trial_days_left(inst, now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    if not inst.trial_ends_at:
        return 0
    left = _aware(inst.trial_ends_at) - now
    return max(0, left.days + (1 if left.seconds else 0))


def current_period(now: dt.datetime | None = None) -> str:
    return (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m")


def ai_requests_left(inst, plan: Plan, now: dt.datetime | None = None) -> int:
    used = inst.ai_requests_used if inst.usage_period == current_period(now) else 0
    return max(0, plan.ai_requests_month - used) if plan.ai_triage else 0


def record_ai_usage(inst, requests: int, now: dt.datetime | None = None):
    period = current_period(now)
    if inst.usage_period != period:
        inst.usage_period, inst.ai_requests_used = period, 0
    inst.ai_requests_used += requests


def repo_allowed(repo_id: int, active_repo_ids: list[int], plan: Plan) -> bool:
    """Con más repos que los del plan, se escanean los primeros que se instalaron (id de GitHub menor)."""
    if plan.max_repos is None:
        return True
    return repo_id in sorted(active_repo_ids)[: plan.max_repos]


def scan_services(plan: Plan, requested=None) -> list[str]:
    """Servicios que se ejecutan: los pedidos (o todos) que el plan incluye."""
    wanted = set(requested) if requested else set(SCAN_SERVICES)
    return [s for s in SCAN_SERVICES if s in wanted and s in plan.services]


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)

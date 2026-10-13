"""Planes y límites de uso (RF-4.5). Precios y contenido según REQUISITOS.md, sección 7.

Plan efectivo de una instalación:
1. Suscripción de Stripe activa (o en periodo de gracia por impago) -> su plan.
2. Si no, durante los 14 días siguientes a instalar la App -> prueba de Team.
3. Si no -> Free.

El presupuesto mensual de peticiones de IA protege el margen: el coste de Claude lo paga el plan.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

TRIAL_DAYS = 14
ACTIVE_STATUSES = {"active", "trialing", "past_due"}  # past_due: Stripe reintenta el cobro unos días


@dataclass(frozen=True)
class Plan:
    name: str
    price_eur: int
    max_repos: int | None          # None = ilimitados
    pr_scans: bool                 # escaneo en cada PR
    min_days_between_full: int     # 7 = escaneo semanal de la rama principal
    ai_triage: bool
    ai_requests_month: int         # presupuesto de peticiones a Claude al mes
    fix_pr: bool                   # botón "Abrir PR con fixes"
    pdf_report: bool
    compliance: bool               # mapeo a EU AI Act / ISO 42001 / NIST / ATLAS en los informes


PLANS = {
    "free": Plan("free", 0, 1, False, 7, False, 0, False, False, False),
    "starter": Plan("starter", 49, 3, True, 0, True, 1_000, False, False, False),
    "team": Plan("team", 249, 20, True, 0, True, 5_000, True, True, False),
    "business": Plan("business", 799, None, True, 0, True, 20_000, True, True, True),
}
PAID = ("starter", "team", "business")


def effective_plan(inst, now: dt.datetime | None = None) -> Plan:
    now = now or dt.datetime.now(dt.timezone.utc)
    if inst.plan in PAID and inst.subscription_status in ACTIVE_STATUSES:
        return PLANS[inst.plan]
    if inst.trial_ends_at and _aware(inst.trial_ends_at) > now:
        return PLANS["team"]
    return PLANS["free"]


def trial_days_left(inst, now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    if not inst.trial_ends_at:
        return 0
    return max(0, (_aware(inst.trial_ends_at) - now).days + (1 if (_aware(inst.trial_ends_at) - now).seconds else 0))


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


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)

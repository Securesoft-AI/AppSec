"""Métricas del panel por organización (RF-4.3): estado actual, tendencia e inventario de IA.

- Estado actual de un repositorio = su último escaneo completo (rama por defecto) terminado; si aún no
  tiene ninguno, el último escaneo de PR terminado.
- La tendencia usa `Scan.summary["counts"]`, que no contiene código y no está cifrado: no hace falta
  descifrar escaneos antiguos para dibujarla.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter

from appsec_ai.models import ScanResult, Severity
from appsec_ai.service.db import Scan, ScanKind, ScanStatus

TREND_DAYS = 30


def latest_per_repo(scans: list[Scan]) -> dict[int, Scan]:
    """Último escaneo terminado por repositorio, prefiriendo los completos a los de PR."""
    best: dict[int, Scan] = {}
    for scan in sorted(scans, key=lambda s: s.id):
        if scan.status != ScanStatus.COMPLETED.value:
            continue
        cur = best.get(scan.repository_id)
        if cur is None or scan.kind == ScanKind.FULL.value or cur.kind != ScanKind.FULL.value:
            best[scan.repository_id] = scan
    return best


def trend(scans: list[Scan], today: dt.date, days: int = TREND_DAYS) -> list[dict]:
    """Hallazgos visibles al final de cada día, sumando el último escaneo completo de cada repositorio."""
    full = sorted((s for s in scans if s.kind == ScanKind.FULL.value and s.status == ScanStatus.COMPLETED.value
                   and s.finished_at), key=lambda s: s.finished_at)
    out, current, i = [], {}, 0
    start = today - dt.timedelta(days=days - 1)
    for n in range(days):
        day = start + dt.timedelta(days=n)
        while i < len(full) and _as_date(full[i].finished_at) <= day:
            current[full[i].repository_id] = (full[i].summary or {}).get("counts", {})
            i += 1
        totals = Counter()
        for counts in current.values():
            totals.update({k: int(v) for k, v in counts.items()})
        out.append({"date": day.isoformat(), **{s.value: totals.get(s.value, 0) for s in Severity}})
    return out


def overview(repos: dict[int, str], latest: dict[int, ScanResult], latest_scans: dict[int, Scan]) -> dict:
    """Agregados para el panel a partir de los resultados (ya descifrados) del último escaneo de cada repo."""
    by_severity, by_category = Counter(), Counter()
    rows, inventory = [], []
    for repo_id, result in latest.items():
        visible = [f for f in result.findings if not f.is_suppressed]
        counts = Counter(f.effective_severity.value for f in visible)
        by_severity.update(counts)
        by_category.update(f.category.value for f in visible)
        scan = latest_scans[repo_id]
        rows.append({"id": repo_id, "full_name": repos.get(repo_id, "?"), "scan_id": scan.id, "kind": scan.kind,
                     "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                     "total": len(visible), **{s.value: counts.get(s.value, 0) for s in Severity}})
        inventory += [{**c.model_dump(), "repository": repos.get(repo_id, "?")}
                      for c in result.ai_inventory if c.kind != "llm_entrypoint"]
    rows.sort(key=lambda r: tuple(-r[s.value] for s in Severity) + (r["full_name"],))
    return {
        "by_severity": {s.value: by_severity.get(s.value, 0) for s in Severity},
        "by_category": dict(by_category.most_common()),
        "repositories": rows,
        "ai_inventory": inventory,
    }


def _as_date(value: dt.datetime) -> dt.date:
    if value.tzinfo is None:  # SQLite devuelve fechas sin zona horaria
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).date()

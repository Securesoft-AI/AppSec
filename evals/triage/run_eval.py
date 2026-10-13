"""Evaluación del triage con Claude sobre casos etiquetados a mano.

Uso:
    python evals/triage/run_eval.py                       # modelo y effort por defecto
    python evals/triage/run_eval.py --effort low --repeat 3 --out resultados.json

Mide lo que importa del triage:
- problemas reales descartados como falsos positivos (el error caro: una brecha);
- falsos positivos que el triage consigue descartar (el valor que aporta);
- severidad dentro del rango aceptable y coste por ejecución.
Cada ejecución llama a la API de verdad (sin caché), así que cuesta dinero.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from appsec_ai.models import Finding
from appsec_ai.scanner import scan

HERE = Path(__file__).parent
CASES = HERE / "cases"
LABELS = HERE / "labels.json"

# Precio por millón de tokens (entrada, salida, lectura de caché). Para estimar el coste, no para facturar.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
}


def load_labels() -> dict[str, dict]:
    return {k: v for k, v in json.loads(LABELS.read_text()).items() if not k.startswith("_")}


def key(f: Finding) -> str:
    return f"{f.file}:{f.rule_id}"


def detect() -> list[Finding]:
    return scan(CASES, engines=["ai-security"]).findings


def check_coverage(findings: list[Finding], labels: dict[str, dict]) -> tuple[list[str], list[str]]:
    """Hallazgos sin etiqueta y etiquetas sin hallazgo (el escáner cambió y hay que revisar los casos)."""
    found = {key(f) for f in findings}
    return sorted(found - labels.keys()), sorted(labels.keys() - found)


def score(findings: list[Finding], labels: dict[str, dict]) -> dict:
    rows, m = [], defaultdict(int)
    for f in findings:
        label = labels.get(key(f))
        if not label:
            continue
        t = f.triage
        verdict = t.verdict.value if t else None
        severity = t.severity.value if t else None
        accept = label.get("accept", [label["expected"]])
        ok_verdict = verdict in accept
        ok_severity = verdict != "true_positive" or severity in label.get("severity", [severity])
        rows.append({"case": key(f), "expected": label["expected"], "verdict": verdict, "severity": severity,
                     "confidence": t.confidence if t else None, "ok": ok_verdict and ok_severity,
                     "ambiguous": label.get("ambiguous", False)})
        if t is None:
            m["untriaged"] += 1
        if label.get("ambiguous"):
            m["severity_ok"] += ok_severity
            m["severity_total"] += 1
            continue
        if label["expected"] == "true_positive":
            m["real"] += 1
            m["real_dismissed"] += verdict == "false_positive"
            m["real_confirmed"] += verdict == "true_positive"
            if verdict == "true_positive":
                m["severity_ok"] += ok_severity
                m["severity_total"] += 1
        else:
            m["fp"] += 1
            m["fp_rejected"] += verdict == "false_positive"
        m["needs_review"] += verdict == "needs_review"
        m["verdict_ok"] += ok_verdict
        m["labelled"] += 1
    return {"rows": rows, "metrics": dict(m)}


def cost(model: str, usage: dict) -> float | None:
    if model not in PRICES:
        return None
    pin, pout, pcache = PRICES[model]
    return (usage.get("input_tokens", 0) * pin + usage.get("output_tokens", 0) * pout
            + usage.get("cache_read_input_tokens", 0) * pcache) / 1e6


def summarize(runs: list[dict]) -> dict:
    total = defaultdict(int)
    for r in runs:
        for k, v in r["metrics"].items():
            total[k] += v

    def pct(a, b):
        return round(100 * total[a] / total[b], 1) if total[b] else None
    costs = [r["cost_usd"] for r in runs if r.get("cost_usd") is not None]
    return {
        "real_dismissed": total["real_dismissed"],
        "real_dismissed_pct": pct("real_dismissed", "real"),
        "real_confirmed_pct": pct("real_confirmed", "real"),
        "fp_rejected_pct": pct("fp_rejected", "fp"),
        "verdict_ok_pct": pct("verdict_ok", "labelled"),
        "severity_ok_pct": pct("severity_ok", "severity_total"),
        "needs_review_pct": pct("needs_review", "labelled"),
        "untriaged": total["untriaged"],
        "cost_usd_per_run": round(sum(costs) / len(costs), 4) if costs else None,
    }


def main(argv: list[str] | None = None) -> int:
    from appsec_ai.triage import DEFAULT_MODEL, Triager

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--lang", default="es")
    p.add_argument("--repeat", type=int, default=1, help="Ejecuciones (el modelo no es determinista)")
    p.add_argument("--out", type=Path, help="Guarda el detalle en JSON")
    p.add_argument("--max-dismissed", type=int, default=0,
                   help="Sale con código 1 si se descartan más problemas reales que este número")
    args = p.parse_args(argv)

    labels = load_labels()
    unlabelled, missing = check_coverage(detect(), labels)
    if unlabelled or missing:
        print("Los casos y las etiquetas no coinciden; revisa evals/triage/labels.json.", file=sys.stderr)
        for k in unlabelled:
            print(f"  sin etiqueta: {k}", file=sys.stderr)
        for k in missing:
            print(f"  etiqueta sin hallazgo: {k}", file=sys.stderr)
        return 2

    runs = []
    for i in range(args.repeat):
        findings = detect()
        triager = Triager(model=args.model, effort=args.effort, language=args.lang, max_requests=100)
        if not triager.has_credentials():
            p.error("hace falta ANTHROPIC_API_KEY")
        triager.triage(CASES, findings)
        result = score(findings, labels)
        result.update(usage=dict(triager.usage), cost_usd=cost(args.model, triager.usage),
                      warnings=triager.warnings)
        runs.append(result)

        print(f"\n== Ejecución {i + 1}/{args.repeat} ({args.model}, effort {args.effort})")
        for r in sorted(result["rows"], key=lambda r: r["case"]):
            mark = "~" if r["ambiguous"] else ("OK" if r["ok"] else "XX")
            print(f"  {mark:2} {r['case']:<58} esperado {r['expected']:<15} "
                  f"obtenido {r['verdict'] or '-':<15} {r['severity'] or '-'}")
        for w in triager.warnings:
            print(f"  aviso: {w}")

    summary = summarize(runs)
    print("\n== Resumen")
    print(f"  Problemas reales descartados: {summary['real_dismissed']} ({summary['real_dismissed_pct']} %)")
    print(f"  Problemas reales confirmados: {summary['real_confirmed_pct']} %")
    print(f"  Falsos positivos descartados: {summary['fp_rejected_pct']} %")
    print(f"  Veredicto aceptable:          {summary['verdict_ok_pct']} %")
    print(f"  Severidad aceptable:          {summary['severity_ok_pct']} %")
    print(f"  needs_review:                 {summary['needs_review_pct']} %")
    print(f"  Sin triage (errores):         {summary['untriaged']}")
    print(f"  Coste estimado por ejecución: {summary['cost_usd_per_run']} USD")

    if args.out:
        args.out.write_text(json.dumps({"model": args.model, "effort": args.effort, "summary": summary,
                                        "runs": runs}, indent=1, ensure_ascii=False))
    return 1 if summary["real_dismissed"] > args.max_dismissed or summary["untriaged"] else 0


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from appsec_ai import report
from appsec_ai.models import Severity
from appsec_ai.scanner import ALL_ENGINES, scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="appsec-ai", description="Escáner de seguridad de código y de IA")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Analiza un directorio")
    s.add_argument("path", type=Path)
    s.add_argument("--engines", default=",".join(ALL_ENGINES),
                   help=f"Motores separados por comas (por defecto: todos). Disponibles: {', '.join(ALL_ENGINES)}")
    s.add_argument("--ai-triage", action="store_true", help="Analiza los hallazgos con Claude (requiere API key)")
    s.add_argument("--model", default=None, help="Modelo de Claude para el triage")
    s.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    s.add_argument("--max-requests", type=int, default=50, help="Máximo de peticiones al LLM por escaneo")
    s.add_argument("--lang", default="es", help="Idioma de las explicaciones (es, en...)")
    s.add_argument("--format", default="markdown", choices=["markdown", "json", "sarif"])
    s.add_argument("-o", "--output", type=Path, help="Fichero de salida (por defecto, stdout)")
    s.add_argument("--fail-on", default=None, choices=[x.value for x in Severity],
                   help="Sale con código 1 si hay hallazgos de esta severidad o superior (para CI)")
    s.add_argument("--show-suppressed", action="store_true", help="Incluye los falsos positivos descartados")

    sv = sub.add_parser("serve", help="Arranca la API (webhooks de GitHub y API REST)")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8000)
    sub.add_parser("worker", help="Arranca un worker que procesa la cola de escaneos")

    args = p.parse_args(argv)
    if args.cmd in ("serve", "worker"):
        return run_service(args)
    if not args.path.is_dir():
        p.error(f"{args.path} no es un directorio")

    triager = None
    if args.ai_triage:
        from appsec_ai.triage import DEFAULT_MODEL, Triager

        triager = Triager(
            model=args.model or DEFAULT_MODEL, effort=args.effort, language=args.lang,
            max_requests=args.max_requests, cache_dir=args.path / ".appsec-ai-cache",
        )
        if not triager.has_credentials():
            p.error("--ai-triage necesita credenciales de Anthropic (define ANTHROPIC_API_KEY)")

    engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    unknown = set(engines) - set(ALL_ENGINES)
    if unknown:
        p.error(f"motores desconocidos: {', '.join(sorted(unknown))}")

    result = scan(args.path, engines=engines, triager=triager)

    if args.format == "json":
        text = report.to_json(result)
    elif args.format == "sarif":
        text = json.dumps(report.to_sarif(result), indent=2, ensure_ascii=False)
    else:
        text = report.to_markdown(result, include_suppressed=args.show_suppressed)

    if args.output:
        args.output.write_text(text)
        print(f"Informe escrito en {args.output}", file=sys.stderr)
    else:
        print(text)

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.effective_severity.rank >= threshold for f in report.visible(result)):
            return 1
    return 0


def run_service(args) -> int:
    import logging

    from appsec_ai.service.config import get_settings

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    if args.cmd == "serve":
        import uvicorn

        from appsec_ai.service.app import create_app

        uvicorn.run(create_app(settings), host=args.host, port=args.port, proxy_headers=True)
        return 0
    from appsec_ai.service.db import Database
    from appsec_ai.service.github import GitHubApp
    from appsec_ai.service.worker import Worker

    missing = [n for n, v in (("GITHUB_APP_ID", settings.github_app_id),
                              ("GITHUB_APP_PRIVATE_KEY", settings.github_private_key)) if not v]
    if missing:
        print(f"Faltan variables de entorno: {', '.join(missing)}", file=sys.stderr)
        return 2
    from appsec_ai.service.crypto import Cipher

    db = Database(settings.database_url, Cipher.from_keys(settings.data_encryption_key))
    if db.cipher is None:
        logging.getLogger("appsec_ai.worker").warning(
            "DATA_ENCRYPTION_KEY no configurada: resultados y caché se guardan sin cifrar")
    db.create_all()
    Worker(settings, db, GitHubApp(settings.github_app_id, settings.github_private_key, settings.github_api_url)).run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

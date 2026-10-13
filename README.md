# appsec-ai

Escáner de seguridad de código y de aplicaciones con IA. Es el núcleo del futuro SaaS: ejecuta motores open source de referencia, añade un **motor propio de seguridad de IA** (OWASP Top 10 para LLM) y usa **Claude** para descartar falsos positivos, explicar cada problema y proponer la corrección.

Requisitos del producto y hoja de ruta: [`REQUISITOS.md`](REQUISITOS.md).

## Qué analiza

| Área | Motor | Licencia |
|---|---|---|
| Seguridad de IA (prompt injection, salida del LLM hacia eval/SQL/HTML/HTTP, agentes con permisos excesivos, fugas en logs) e inventario de IA | `ai-security` (propio) | Propietario |
| Secretos | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| Dependencias vulnerables | [OSV-Scanner](https://github.com/google/osv-scanner) | Apache 2.0 |
| Infraestructura como código | [Checkov](https://github.com/bridgecrewio/checkov) | Apache 2.0 |
| SAST genérico (solo con reglas propias) | [Opengrep](https://github.com/opengrep/opengrep) | LGPL 2.1 |

Los motores que no estén instalados se omiten y aparecen como `skipped` en el informe.

## Instalación

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,iac]"

# Motores externos (opcionales)
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
```

## Uso

```bash
# Escaneo sin IA (gratis)
appsec-ai scan ruta/al/repo

# Con triage de Claude (necesita ANTHROPIC_API_KEY)
appsec-ai scan ruta/al/repo --ai-triage --lang es -o informe.md

# Para CI: SARIF y fallo si hay hallazgos high o critical
appsec-ai scan . --format sarif -o resultados.sarif --fail-on high
```

Opciones del triage con IA:
- `--model`: modelo de Claude (por defecto `claude-opus-5-5`).
- `--effort`: `low` | `medium` | `high`...
- `--max-requests`: presupuesto de peticiones por escaneo.
- `--lang`: idioma de las explicaciones.

Los resultados del triage se guardan en `.appsec-ai-cache/` dentro del repositorio analizado, así que reescanear sin cambios no consume tokens.

## Prueba rápida

`tests/fixtures/llm_app` es una aplicación **deliberadamente vulnerable** (Flask + Claude + LangChain, un agente en TypeScript, Terraform inseguro y dependencias antiguas):

```bash
appsec-ai scan tests/fixtures/llm_app
.venv/bin/pytest -q
```

## Estructura

```
src/appsec_ai/
  models.py              Modelo común de hallazgos (Finding, Triage, ScanResult)
  engines/ai_security.py Motor propio de seguridad de IA (AST de Python + heurísticas JS/TS)
  engines/opensource.py  Adaptadores de Gitleaks, OSV-Scanner, Checkov y Opengrep
  triage.py              Triage, corrección y resumen ejecutivo con Claude
  scanner.py             Orquestador
  report.py              Markdown, JSON y SARIF 2.1.0
  cli.py                 Línea de comandos
```

# appsec-ai

Escáner de seguridad de código y de aplicaciones con IA. Es el núcleo del futuro SaaS: ejecuta motores open source de referencia, añade un **motor propio de seguridad de IA** (OWASP Top 10 para LLM) y usa **Claude** para descartar falsos positivos, explicar cada problema y proponer la corrección.

Requisitos del producto y hoja de ruta: [`REQUISITOS.md`](REQUISITOS.md). Despliegue del SaaS (GitHub App, API y worker): [`docs/DESPLIEGUE.md`](docs/DESPLIEGUE.md).

## Qué analiza

| Área | Motor | Licencia |
|---|---|---|
| Seguridad de IA (OWASP Top 10 para LLM) e inventario de IA, en Python y JS/TS | `ai-security` (propio) | Propietario |
| Secretos | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| Dependencias vulnerables | [OSV-Scanner](https://github.com/google/osv-scanner) | Apache 2.0 |
| Infraestructura como código | [Checkov](https://github.com/bridgecrewio/checkov) | Apache 2.0 |
| SAST con 41 reglas propias (Python, JS/TS, Java, Go) | [Opengrep](https://github.com/opengrep/opengrep) o Semgrep CE | LGPL 2.1 |

Los motores que no estén instalados se omiten y aparecen como `skipped` en el informe.

## Reglas

### Seguridad de IA (`ai-security`)

Python se analiza sobre el AST y JS/TS sobre el árbol de [tree-sitter], con flujo de datos dentro de cada función y sus callbacks: entrada del usuario → prompt → respuesta del LLM → sumidero peligroso.

| Regla | OWASP LLM | Detecta |
|---|---|---|
| `llm01-untrusted-input-in-system-prompt` | LLM01 | Entrada del usuario o externa dentro del prompt de sistema |
| `llm01-prompt-concatenation` | LLM01 | Entrada del usuario concatenada con instrucciones |
| `llm01-indirect-prompt-injection` | LLM01 | Contenido descargado, leído o de RAG enviado al modelo |
| `llm02-llm-io-logged` | LLM02 | Prompts o respuestas escritos en logs (no se cuenta `debug`) |
| `llm05-llm-output-to-code-exec` | LLM05 | Respuesta del modelo en `eval`, `exec`, shell |
| `llm05-llm-output-to-sql` | LLM05 | Respuesta del modelo ejecutada como SQL |
| `llm05-llm-output-to-request` | LLM05 | Respuesta del modelo como URL de destino (SSRF) |
| `llm05-llm-output-to-filesystem` | LLM05 | Respuesta del modelo como ruta de fichero |
| `llm05-llm-output-to-html` | LLM05 | Respuesta del modelo en HTML (`innerHTML`, `dangerouslySetInnerHTML`, respuestas HTML) |
| `llm05-llm-output-selects-function` | LLM05 | El modelo elige la función a ejecutar (`getattr`, `handlers[x]()`) |
| `llm06-excessive-agency-tool` | LLM06 | Herramientas de agentes o MCP con shell, borrado, SQL dinámico o de escritura, pagos, emails |
| `llm06-mcp-http-without-auth` | LLM06 | Servidor MCP publicado por HTTP/SSE sin autenticación |
| `llm07-secret-in-system-prompt` | LLM07 | Credenciales dentro del prompt de sistema |
| `llm07-authorization-in-prompt` | LLM07 | Control de acceso delegado en el prompt ("solo puedes mostrar los datos del usuario") |
| `llm08-rag-without-access-filter` | LLM08 | Búsqueda en un vector store con la pregunta del usuario y sin filtro por usuario o tenant (LangChain, Chroma, Pinecone) |
| `llm10-no-output-limit` | LLM10 | Llamadas OpenAI-compatibles o Vercel AI sin límite de tokens |
| `llm10-unbounded-agent-loop` | LLM10 | Agentes con `max_iterations=None` |

Frameworks reconocidos: Anthropic, OpenAI, Gemini, Bedrock, Mistral, LiteLLM, LangChain/LangGraph (Python y JS), LlamaIndex, CrewAI, AutoGen, Pydantic AI, OpenAI Agents SDK, Claude Agent SDK, Vercel AI SDK, Mastra, MCP (FastMCP y SDK oficial) y vector stores.

### SAST (`src/appsec_ai/rules/sast/`)

| Lenguaje | Reglas |
|---|---|
| Python (14) | Inyección SQL, comandos y código; SSRF; path traversal; SSTI; XSS; deserialización insegura; TLS desactivado; JWT sin verificar; debug activo; hash de contraseña débil |
| JS/TS (13) | Inyección SQL, NoSQL, comandos y código; SSRF; path traversal; XSS reflejado y en el DOM; open redirect; TLS desactivado; JWT inseguro; cookies inseguras; aleatoriedad débil |
| Java (8) | Inyección SQL y de comandos; SSRF; path traversal; deserialización; XXE; criptografía débil; TLS que acepta todo |
| Go (6) | Inyección SQL y de comandos; SSRF; path traversal; `InsecureSkipVerify`; criptografía débil |

Cada regla tiene casos positivos y negativos en `tests/rules/` (`semgrep --test`). Solo se usan reglas propias: la licencia del registro de reglas de Semgrep no permite usarlas en un SaaS.

### Fusión y supresión

- Si dos motores detectan el mismo problema en la misma línea (mismo CWE o familia), se muestra uno solo y el otro queda como referencia.
- Un hallazgo se silencia con `# appsec-ai: ignore`, `# nosec` o `# nosemgrep` en su línea o en la anterior.

[tree-sitter]: https://tree-sitter.github.io/

## Instalación

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,service]"

# Motores externos (opcionales). Semgrep/Opengrep y Checkov en entornos aislados:
# sus dependencias chocan con las del servicio.
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
python3 -m venv /opt/semgrep && /opt/semgrep/bin/pip install semgrep && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/
python3 -m venv /opt/checkov && /opt/checkov/bin/pip install checkov && ln -s /opt/checkov/bin/checkov /usr/local/bin/
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

### Evaluación del triage

`evals/triage/` tiene casos etiquetados a mano: problemas reales y código parecido pero seguro que el escáner marca igualmente. El script mide cuántos problemas reales descarta el triage (el error caro), cuántos falsos positivos elimina, si acierta la severidad y cuánto cuesta. Llama a la API de verdad:

```bash
python evals/triage/run_eval.py --repeat 3 --out resultados.json
python evals/triage/run_eval.py --effort low     # comparar coste y calidad
```

Sale con código 1 si descarta algún problema real. Al añadir o cambiar reglas, `tests/test_eval.py` avisa si los casos y `labels.json` dejan de coincidir.

## Servicio SaaS

```bash
appsec-ai serve      # API: webhooks de GitHub (/webhooks/github) y API REST (/api/...)
appsec-ai worker     # procesa la cola de escaneos
docker compose up    # todo junto con Postgres
```

Detalles en [`docs/DESPLIEGUE.md`](docs/DESPLIEGUE.md).

## Prueba rápida

Dos aplicaciones **deliberadamente vulnerables**:
- `tests/fixtures/llm_app`: Flask + Claude + LangChain, un agente en TypeScript, Terraform inseguro y dependencias antiguas.
- `tests/fixtures/ai_agents`: herramientas de agentes y servidores MCP (FastMCP, Vercel AI SDK, MCP SDK) y un ejemplo seguro (`safe.tsx`) que no debe dar hallazgos.

```bash
appsec-ai scan tests/fixtures/ai_agents
.venv/bin/pytest -q
```

## Estructura

```
src/appsec_ai/
  models.py              Modelo común de hallazgos (Finding, Triage, ScanResult)
  engines/ai_security.py Motor propio de seguridad de IA
  engines/ai_python.py   Análisis de flujo sobre el AST de Python
  engines/ai_js.py       Análisis de flujo sobre tree-sitter (JS/TS/JSX/TSX)
  engines/ai_common.py   Catálogo de reglas de IA y utilidades comunes
  rules/sast/            Reglas SAST propias (Opengrep/Semgrep)
  engines/opensource.py  Adaptadores de Gitleaks, OSV-Scanner, Checkov y Opengrep
  triage.py              Triage, corrección y resumen ejecutivo con Claude
  scanner.py             Orquestador
  report.py              Markdown, JSON y SARIF 2.1.0
  cli.py                 Línea de comandos
  service/app.py         API (FastAPI): webhooks y API REST
  service/webhooks.py    Instalaciones, PRs, pushes y reintentos
  service/worker.py      Cola de escaneos: clonar, escanear, publicar en GitHub
  service/github.py      Cliente de la GitHub App (JWT, tokens, checks, comentarios, clonado seguro)
  service/render.py      Anotaciones del check y comentario del PR
  service/db.py          Modelo de datos (Postgres/SQLite)
```

# Requisitos — Plataforma SaaS de Seguridad de Código e IA

> Versión 0.4 · 2026-10-13
> Cambios respecto a la 0.1: modelo 100 % SaaS self‑service, mercado internacional + España,
> presupuesto de IA = créditos de la API de Claude, núcleo del motor ya implementado (`src/appsec_ai`).

---

## 1. Visión

Un SaaS que conectas a tu repositorio y que, sin equipo de seguridad, te dice **qué es vulnerable en tu código, en tu infraestructura y en tus funcionalidades con IA**, por qué importa y cómo arreglarlo, abriendo la corrección como pull request.

**Posicionamiento:** "El escáner de seguridad que entiende las apps con IA". Ejecuta los motores open source de referencia y añade lo que estos no hacen: análisis específico de LLMs y agentes, eliminación de falsos positivos con IA, explicación clara y corrección automática.

**Decisiones tomadas**
- **Producto, no consultoría.** El cliente se da de alta, conecta GitHub y paga con tarjeta. Sin reuniones obligatorias.
- **Motores open source** (con licencias aptas para SaaS) para SAST, secretos, dependencias e IaC. No se compite en motores, sino en inteligencia y experiencia de uso.
- **La capa de IA es el producto**: detector propio de riesgos de LLM y agentes + triage, explicación y corrección con Claude.
- **Mercado internacional (inglés) y España (español) desde el día 1**: interfaz, informes y explicaciones bilingües (el triage ya acepta `--lang`).
- **IAST queda fuera**: ver sección 9.

## 2. Cliente objetivo (ICP)

| Prioridad | Perfil | Dolor | Quién compra |
|---|---|---|---|
| 1 | Startups y scale‑ups (5–200 devs) que lanzan funcionalidades con LLMs, RAG o agentes | Sus clientes enterprise les piden pruebas de seguridad de IA (cuestionarios, EU AI Act, ISO 42001) y no tienen equipo de AppSec | CTO / Head of Engineering, con tarjeta |
| 2 | Pymes y agencias de desarrollo sin herramientas de AppSec | Requisitos de clientes, NIS2, ISO 27001, ENS (España) | CTO / responsable técnico |
| 3 | Consultoras y pentesters | Informes rápidos y repetibles para sus clientes | Licencia multi‑cliente |

**Canal de entrada:** tus contactos como *design partners* (5–10 empresas con acceso gratuito 60 días a cambio de feedback semanal y de convertirse en clientes de pago o dar un testimonio).

## 3. Arquitectura del producto

```
GitHub App ──► Cola de trabajos ──► Worker efímero (contenedor aislado)
                                     ├─ Gitleaks      (secretos)        MIT
                                     ├─ OSV‑Scanner   (dependencias)    Apache 2.0
                                     ├─ Checkov       (IaC)             Apache 2.0
                                     ├─ Opengrep      (SAST, reglas propias) LGPL
                                     └─ Motor IA propio (OWASP LLM Top 10)
                                            │
                                     Triage con Claude (falsos positivos, severidad, fix)
                                            │
              Postgres ◄── Resultados ──────┘──► Comentario en PR · SARIF · Panel web · Informe PDF
```

**Estado actual:** el bloque del worker (motores + motor IA + triage + informes Markdown/JSON/SARIF + CLI) está implementado y probado. Ver `README.md`.

## 4. Requisitos funcionales

Leyenda: ✅ hecho · 🔜 MVP · ⏭ posterior

### M1. Motor de escaneo (núcleo)
- ✅ RF‑1.1 Orquestar Gitleaks, OSV‑Scanner, Checkov y Opengrep con un modelo de hallazgos común.
- ✅ RF‑1.2 Ignorar `node_modules`, `.venv`, `vendor`, etc.; tolerar ficheros con errores de sintaxis.
- ✅ RF‑1.3 Deduplicar hallazgos con huella estable (independiente del número de línea).
- ✅ RF‑1.4 Secretos siempre redactados: nunca se almacena el valor.
- ✅ RF‑1.5 Salidas Markdown, JSON y SARIF 2.1.0 (GitHub Code Scanning, GitLab, Azure DevOps).
- ✅ RF‑1.6 Modo CI: `--fail-on <severidad>`.
- ✅ RF‑1.7 41 reglas SAST propias para Opengrep (Python 14, JS/TS 13, Java 8, Go 6), cada una con casos positivos y negativos. **Prohibido** usar reglas del registro de Semgrep (licencia incompatible con SaaS).
- ✅ RF‑1.9 Fusión de hallazgos duplicados entre motores (misma línea y familia de CWE).
- ✅ RF‑1.10 Supresión en el código con `appsec-ai: ignore`, `nosec` o `nosemgrep`.
- 🔜 RF‑1.8 Escaneo incremental: en un PR solo se analizan los ficheros cambiados.

### M2. Seguridad de IA (diferenciador)
- ✅ RF‑2.1 Inventario de IA: SDKs (Anthropic, OpenAI, Gemini, Bedrock, Mistral…), frameworks (LangChain/LangGraph, LlamaIndex, CrewAI, Agents SDK, MCP), modelos usados, herramientas de agentes y vector stores.
- ✅ RF‑2.2 Detección con análisis de flujo (Python sobre el AST, JS/TS/JSX/TSX sobre tree-sitter):
  - LLM01: entrada del usuario en el prompt de sistema, concatenación de entrada con instrucciones, prompt injection indirecta (contenido web/ficheros/RAG).
  - LLM02: prompts/respuestas escritos en logs.
  - LLM05: salida del LLM hacia `eval`/shell, SQL, peticiones HTTP (SSRF), sistema de ficheros, HTML (XSS).
  - LLM05: la salida del LLM elige qué función se ejecuta (`getattr`, `handlers[x]()`).
  - LLM06: herramientas de agentes y de servidores MCP con acciones peligrosas (shell, SQL dinámico o de escritura, borrado, pagos, emails, HTTP de escritura); servidores MCP por HTTP sin autenticación.
  - LLM07: secretos en el prompt de sistema; control de acceso delegado en el prompt.
  - LLM08: búsquedas RAG con la pregunta del usuario sin filtro de acceso por usuario o tenant.
  - LLM10: llamadas sin límite de tokens; agentes sin límite de iteraciones.
- ✅ RF‑2.3 Análisis de JS/TS con AST real (tree‑sitter).
- ✅ RF‑2.4 Validado contra código real: LangChain Community, LlamaIndex Core y CrewAI (más de 2.000 ficheros) dan 10 hallazgos, todos revisados y justificados.
- ✅ RF‑2.4b Más reglas: LLM08 (RAG sin filtro de acceso), autorización delegada en el prompt, endpoints sin rate limiting, y Java y Go para IA (Spring AI, LangChain4j, SDK de OpenAI y Anthropic, go-openai, openai-go, anthropic-sdk-go, langchaingo). Validado sin falsos positivos sobre langchain4j-examples, spring-ai-examples y langchaingo (1.086 ficheros, 229 llamadas al LLM reconocidas).
- ✅ RF‑2.5 Mapeo a MITRE ATLAS (IDs comprobados contra ATLAS v5.6.0), NIST AI RMF y su perfil de IA generativa, ISO 42001 (anexo A) y EU AI Act en el informe. Orientativo; conviene que lo revise un especialista en cumplimiento antes de venderlo como tal.
- ⏭ RF‑2.6 Modelo de amenazas generado por sistema de IA (flujo de datos, activos, caminos de ataque).
- ⏭ RF‑2.7 Red teaming dinámico: pruebas automáticas de prompt injection/jailbreak contra el endpoint desplegado.

### M3. Capa de IA (triage y corrección)
- ✅ RF‑3.1 Veredicto por hallazgo (real / falso positivo / revisar), severidad en contexto, explicación, escenario de ataque y corrección con código.
- ✅ RF‑3.2 Una petición por fichero (el contexto se envía una sola vez), salida estructurada validada con JSON Schema.
- ✅ RF‑3.3 El código analizado se trata como dato no confiable (defensa frente a prompt injection en el propio código del cliente).
- ✅ RF‑3.4 Caché local por huella: reescanear sin cambios no gasta tokens.
- ✅ RF‑3.5 Presupuesto máximo de peticiones por escaneo; los ficheros más graves se analizan primero.
- ✅ RF‑3.6 Resumen ejecutivo de seguridad de IA para el CTO.
- ✅ RF‑3.7 Botón "Abrir PR con fixes" en el check de GitHub (y `POST /api/scans/{id}/fix-pr`): Claude propone ediciones exactas, se validan (texto único y sintaxis) y se abre un PR para revisión humana. Requiere permiso `contents: write`.
- 🔜 RF‑3.8 El usuario marca "útil / no útil" en cada hallazgo; ese feedback alimenta el conjunto de evaluación.

### M4. Plataforma SaaS
- ✅ RF‑4.1a GitHub App con permisos mínimos (contents: read, checks y pull requests: write), webhooks verificados con HMAC y gestión de instalaciones y repositorios.
- ✅ RF‑4.1b Inicio de sesión con GitHub (OAuth de la GitHub App): cada usuario solo ve las instalaciones a las que tiene acceso en GitHub.
- ✅ RF‑4.2 Escaneo en cada PR (check con anotaciones en las líneas, comentario único que se actualiza, solo ficheros modificados) y escaneo completo en cada push a la rama por defecto. Reintentos y botón "Re-run".
- ✅ RF‑4.2b Cola de escaneos en Postgres con varios workers, idempotente frente a reenvíos de webhooks.
- ✅ RF‑4.2c API REST de instalaciones, repositorios y escaneos (acceso provisional con token de administrador).
- 🔜 RF‑4.3 Panel por organización: hallazgos por severidad, repositorio, área y tendencia; inventario de IA.
- 🟡 RF‑4.4 Multi‑tenant: datos separados por instalación; clonado seguro (sin hooks, LFS ni enlaces simbólicos, token fuera de los argumentos), workdir temporal que siempre se borra, worker sin privilegios. Falta aislar cada escaneo en su propio contenedor efímero (gVisor/Firecracker).
- 🔜 RF‑4.5 Facturación con Stripe (planes, límites de uso, prueba gratuita de 14 días).
- 🔜 RF‑4.6 Interfaz y correos en inglés y español.
- 🔜 RF‑4.7 Informe PDF descargable para cuestionarios de seguridad de clientes.
- ⏭ RF‑4.8 GitLab y Bitbucket, Slack, Jira, SSO (SAML/OIDC), registros de auditoría.

## 5. Requisitos no funcionales

| ID | Requisito |
|---|---|
| RNF‑1 Privacidad del código | Clonado en contenedor efímero, borrado al terminar, nunca usado para entrenar. Solo se guardan los fragmentos de los hallazgos. TLS 1.2+ y cifrado en reposo. |
| RNF‑2 Confianza | Página de seguridad pública, DPA de RGPD, alojamiento en la UE disponible. SOC 2 Tipo I cuando los ingresos lo permitan (lo pedirán los clientes de EE. UU.). |
| RNF‑3 Rendimiento | Escaneo de PR < 3 min; escaneo completo de repositorio mediano < 15 min. |
| RNF‑4 Coste de IA | Coste de LLM < 15 % del precio del plan. Límites por plan, caché, escaneo incremental y modelo configurable. |
| RNF‑5 Calidad | Conjunto de evaluación con apps vulnerables (incluido `tests/fixtures/llm_app`) y apps seguras. Objetivo: ≥ 70 % de hallazgos marcados como útiles; 0 hallazgos en el código seguro de referencia (ya cubierto por tests). |
| RNF‑6 Disponibilidad | 99,5 % en el MVP. |
| RNF‑7 Seguridad propia | La plataforma pasa su propio escáner en CI. Secretos de clientes (tokens de GitHub) cifrados y con rotación. |

## 6. Coste de IA y créditos

Presupuesto inicial: **1000 $ en créditos de la API de Claude**. Precios actuales por millón de tokens (entrada/salida): Opus 5.5 4 $/20 $, Sonnet 5.5 2 $/10 $, Haiku 5.5 0,10 $/0,50 $.

Estimación con Opus 5.5 (modelo por defecto): ~0,05–0,10 $ por fichero con hallazgos.

| Escenario | Coste aproximado | Escaneos con 1000 $ |
|---|---|---|
| PR típico (2–5 ficheros) | 0,10–0,50 $ | 2.000–10.000 |
| Repo mediano completo (30 ficheros) | ~3 $ | ~330 |
| Mismo repo con Haiku 5.5 | < 0,10 $ | > 10.000 |

**Reglas:**
- Los créditos se usan solo para desarrollo, la demo y los design partners. En producción el coste de IA lo pagan los clientes a través del precio del plan.
- Hay que medir en real con `llm_usage` (ya se registra en cada informe) antes de fijar precios definitivos.
- Medir calidad frente a coste con el conjunto de evaluación antes de cambiar de modelo.

## 7. Modelo de negocio (hipótesis)

| Plan | Precio | Incluye |
|---|---|---|
| Free | 0 | 1 repo, escaneo semanal, sin triage con IA |
| Starter | 49 €/mes | 3 repos, escaneo en PR, triage con IA |
| Team | 249 €/mes | 20 repos, seguridad de IA completa, auto‑fix, informe PDF |
| Business | 799 €/mes | Repos ilimitados, informes de cumplimiento (EU AI Act/ISO 42001), SSO, soporte prioritario |

Precios iguales en € y $ para simplificar. **Meta:** 20 clientes Team ≈ 5.000 €/mes de ingreso recurrente.

## 8. Hoja de ruta

| Semana | Entregable |
|---|---|
| ✅ 0 | Núcleo del motor + motor de IA + triage con Claude + CLI + tests |
| ✅ 1 | 41 reglas SAST propias; motor de IA con tree-sitter y 15 reglas; validación con código real |
| ✅ 2 | Backend del SaaS: GitHub App, webhooks, cola, worker, checks y comentarios en PR, Docker |
| ✅ 2 | Landing bilingüe (nombre provisional "Atalaya") con lista de espera guardada en el backend y cabeceras de seguridad |
| 2 | Probar el triage con la API real; conjunto de evaluación; crear la GitHub App y desplegar |
| 1–2 | Landing bilingüe con lista de espera y precios; reclutar 5–10 design partners entre tus contactos |
| 2–4 | GitHub App + comentarios en PR + cola + workers en contenedores |
| 4–6 | Panel web, Stripe, informes PDF, inglés/español |
| 6–8 | Beta con design partners → primeros clientes de pago |
| 8+ | Auto‑fix con PR, AST para JS/TS, más reglas de IA, GitLab |

## 9. Fuera de alcance (y por qué)

- **IAST**: necesita un agente que instrumente la aplicación en ejecución, distinto para cada lenguaje (Java, Node, Python, .NET…), y que el cliente lo instale en sus entornos. Eso contradice el modelo "conectar repo y listo" y cuesta años de ingeniería. Si más adelante hay demanda de análisis dinámico, el camino natural es **DAST/red teaming de endpoints de IA** (RF‑2.7), que no requiere instalar nada.
- **CSPM / seguridad de nube en ejecución**: es otro mercado (Wiz, Orca).
- **On‑prem**: solo cuando un cliente enterprise lo pague.

## 10. Riesgos

| Riesgo | Mitigación |
|---|---|
| "SaaS sin hacer nada más que vender" es irreal: hay soporte, actualizar reglas, mantener la infraestructura y la propia seguridad | Automatizar al máximo: actualizaciones de motores en CI, soporte con documentación y un asistente; reservar unas horas semanales para mantenimiento |
| Grandes competidores añaden seguridad de IA | Velocidad, foco en apps con IA, precio accesible, español/UE (EU AI Act) |
| Falsos positivos → abandono | Triage con IA + feedback + conjunto de evaluación en CI |
| Coste de IA descontrolado | Presupuesto por escaneo, caché, escaneo incremental, límites por plan |
| Licencias open source | Solo MIT/Apache/LGPL; nada del registro de reglas de Semgrep |
| Responsabilidad si se escapa una vulnerabilidad | Términos de servicio con limitación de responsabilidad; seguro de RC profesional cuando haya ingresos |
| El proveedor de IA declina analizar código de seguridad | Respaldo automático de modelo (`fallbacks`) ya activado; modelo configurable |
| Riesgo personal y familiar | Mantener otra fuente de ingresos hasta tener ingresos recurrentes que cubran gastos básicos |

## 11. Preguntas abiertas

1. Nombre comercial y dominio (inglés y español).
2. ¿Constituir sociedad en España o en EE. UU. (Stripe Atlas)? Afecta a facturación e impuestos.
3. ¿Quiénes serán los 5–10 design partners y cuándo podemos contactarlos?

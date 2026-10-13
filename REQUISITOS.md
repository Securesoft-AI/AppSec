# Requisitos — Plataforma SaaS de Seguridad de Aplicaciones e IA

> Versión 0.1 (borrador) · 2026-10-13
> Estado: para validar con clientes potenciales antes de escribir código de producto.

---

## 1. Visión

Una plataforma SaaS que permite a equipos de desarrollo pequeños y medianos **saber si su código y sus aplicaciones con IA son seguros para salir a producción**, con hallazgos priorizados, explicados en lenguaje claro y con la corrección propuesta como pull request.

**Frase de posicionamiento (provisional):**
"Revisión de seguridad para apps con IA y su código, en minutos y no en semanas, sin necesidad de un equipo de AppSec."

## 2. Principio rector: foco

Construir "SAST + IAST + IaC + seguridad de IA" a la vez compite con Snyk, Checkmarx, Veracode, Wiz, Semgrep, Aikido y Contrast, que tienen cientos de ingenieros. Con un fundador y 1000 $ de presupuesto, la única estrategia viable es:

1. **Una cuña (wedge) estrecha** donde los grandes son débiles → **seguridad de aplicaciones que usan LLMs y agentes**.
2. **Reutilizar motores open source** para lo que ya está resuelto (SAST, IaC, secretos, dependencias) y aportar valor en la capa de **contexto, priorización con IA y corrección automática**.
3. **Cobrar desde el primer mes**, aunque sea a 3 clientes.

## 3. Cliente objetivo (ICP)

| Prioridad | Perfil | Dolor | Quién paga |
|---|---|---|---|
| 1 | Startups / scale-ups (10–200 devs) que lanzan features con LLMs, RAG o agentes | Clientes enterprise les piden evidencia de seguridad de IA (cuestionarios, EU AI Act, ISO 42001) y no tienen equipo de AppSec | CTO / Head of Engineering |
| 2 | Consultoras y pentesters freelance | Necesitan informes de revisión de IA rápidos y repetibles | El consultor (licencia por cliente) |
| 3 | Pymes con apps web sin herramientas de AppSec | Requisitos de clientes / NIS2 / ISO 27001 | CTO |

**Fuera de alcance inicial:** grandes empresas (ciclo de venta de 6–12 meses, requieren SOC 2, on‑prem, SSO, etc.).

## 4. Alcance por fases

### Fase 0 — Validación (semanas 1–3) · coste ≈ 0 $
- [ ] 20 conversaciones con CTOs / responsables de seguridad del ICP 1.
- [ ] Landing page con lista de espera y precio visible.
- [ ] Ofrecer 3–5 **revisiones de seguridad de IA "manuales asistidas"** pagadas (300–1500 €) usando prototipos internos. Esto financia el desarrollo y enseña qué automatizar.
- **Criterio de salida:** ≥ 3 clientes que paguen o firmen carta de intención.

### Fase 1 — MVP (semanas 3–10)
Módulos incluidos:

**M1. Conexión de repositorios**
- RF-1.1 Login con GitHub (OAuth / GitHub App). GitLab en fase 2.
- RF-1.2 Seleccionar repositorios; escaneo en cada push / PR y bajo demanda.
- RF-1.3 Comentarios en PR con hallazgos nuevos (solo diferencias, no ruido).

**M2. Seguridad de IA / LLM (el diferenciador)**
- RF-2.1 Inventario automático de uso de IA en el código: SDKs (OpenAI, Anthropic, Bedrock, Vertex, Azure OpenAI), frameworks (LangChain/LangGraph, LlamaIndex, MCP, Agents SDK), modelos, prompts de sistema, herramientas (tools) que los agentes pueden invocar y permisos que tienen.
- RF-2.2 Detección de patrones de riesgo mapeados a **OWASP Top 10 para LLM** y **OWASP Top 10 para Aplicaciones Agénticas**:
  - entrada de usuario concatenada en prompts sin separación (prompt injection),
  - salida del LLM pasada a `eval`, shell, SQL, HTML o llamadas HTTP sin validación (insecure output handling),
  - herramientas de agente con permisos excesivos (escritura en BD, envío de emails, ejecución de código) sin confirmación humana (excessive agency),
  - secretos o PII en prompts / logs,
  - RAG que ingiere contenido no confiable sin control de acceso por documento,
  - servidores MCP sin autenticación o con alcance excesivo,
  - ausencia de límites de coste / tokens / rate limit.
- RF-2.3 **Modelo de amenazas generado** por sistema de IA detectado (flujo de datos, activos, caminos de ataque) con mapeo a MITRE ATLAS y NIST AI RMF.
- RF-2.4 **Evidencia citada**: cada control marcado como Presente / Ausente / Desconocido con las líneas de código que lo justifican. El usuario confirma o descarta.
- RF-2.5 Informe exportable (PDF / Markdown) apto para cuestionarios de seguridad de clientes y para documentación de EU AI Act / ISO 42001.

**M3. AppSec clásico (vía motores open source)**
- RF-3.1 SAST: Opengrep (fork LGPL de Semgrep) con reglas propias. *Atención: las reglas del registro de Semgrep tienen una licencia que prohíbe usarlas en un SaaS competidor; no usarlas.*
- RF-3.2 Secretos: Gitleaks (MIT).
- RF-3.3 Dependencias (SCA): OSV-Scanner / Trivy (Apache 2.0).
- RF-3.4 IaC: Checkov o KICS (Apache 2.0) para Terraform, Kubernetes, Dockerfile, CloudFormation.
- RF-3.5 **Triage con LLM**: para cada hallazgo, decidir si es explotable en contexto, explicarlo y descartar falsos positivos con justificación. Este es el valor añadido frente a ejecutar las herramientas gratis.

**M4. Corrección**
- RF-4.1 Propuesta de corrección por hallazgo (diff).
- RF-4.2 Botón "Abrir PR con la corrección".

**M5. Panel y cuenta**
- RF-5.1 Panel por organización: hallazgos por severidad, por repo, tendencia.
- RF-5.2 Multi‑tenant con aislamiento estricto entre clientes.
- RF-5.3 Facturación con Stripe (planes mensuales).
- RF-5.4 Roles básicos: owner, miembro.

### Fase 2 — Crecimiento (meses 3–6)
- Red‑teaming dinámico de endpoints de IA (pruebas de prompt injection / jailbreak contra la app desplegada; DAST para LLM).
- Ciclo de vida de revisión: aprobaciones, bloqueantes con responsable, re‑revisión automática cuando cambian las herramientas o permisos de un agente.
- GitLab y Bitbucket; integración con Jira / Slack.
- SSO (SAML/OIDC) y registros de auditoría.
- Mapeo a ISO 42001 y EU AI Act.

### Fase 3 — Más adelante (solo si hay tracción)
- **IAST**: requiere un agente instrumentando el runtime por lenguaje (Java, Node, Python, .NET…). Es de lo más costoso de construir y mantener; no abordarlo hasta tener ingresos y equipo.
- CSPM / seguridad de nube en tiempo de ejecución.
- Despliegue on‑prem / VPC para enterprise.

## 5. Requisitos no funcionales

| ID | Requisito |
|---|---|
| RNF-1 Seguridad propia | El código del cliente se clona en un entorno efímero aislado por escaneo y se borra al terminar. Nunca se usa para entrenar modelos. Cifrado en tránsito (TLS 1.2+) y en reposo. |
| RNF-2 Confianza | Página pública de seguridad, DPA de RGPD, residencia de datos en la UE. SOC 2 / ISO 27001 cuando haya ingresos que lo justifiquen. |
| RNF-3 Permisos mínimos | GitHub App con permisos de solo lectura salvo para abrir PRs. |
| RNF-4 Rendimiento | Escaneo incremental de PR < 3 min; escaneo completo de repo mediano < 15 min. |
| RNF-5 Coste por escaneo | Coste de LLM controlado: limitar tokens por escaneo, usar modelos pequeños para filtrado y modelos grandes solo para triage final; caché por hash de fichero. Objetivo: < 10 % del precio del plan. |
| RNF-6 Calidad | Tasa de falsos positivos medida sobre un conjunto de repos vulnerables de prueba (p. ej. OWASP Juice Shop, DVLA, apps LLM vulnerables). Objetivo: > 70 % de hallazgos marcados como útiles por el usuario. |
| RNF-7 Disponibilidad | 99,5 % en MVP. |
| RNF-8 Observabilidad | Logs, métricas y trazas de cada escaneo; alertas de errores. |

## 6. Arquitectura propuesta (MVP, barata y simple)

- **Frontend:** Next.js + Tailwind.
- **Backend / API:** Python (FastAPI) — el ecosistema de seguridad y de IA es más rico en Python.
- **Workers de escaneo:** contenedores efímeros con los motores open source; cola de trabajos (Redis / Postgres).
- **Base de datos:** Postgres (Supabase o Neon, con plan gratuito al inicio).
- **LLM:** API de Claude con prompt caching; abstracción para cambiar de proveedor.
- **Hosting:** Fly.io / Railway / Render para empezar (< 50 $/mes), migrar a AWS/GCP cuando haya clientes.
- **Pagos:** Stripe.

## 7. Modelo de negocio (hipótesis a validar)

| Plan | Precio | Incluye |
|---|---|---|
| Free | 0 € | 1 repo, escaneo semanal, sin auto‑fix |
| Team | 199–399 €/mes | Hasta 20 repos, escaneo en PR, seguridad de IA, auto‑fix |
| Business | 990+ €/mes | Repos ilimitados, informes de cumplimiento, SSO, soporte |
| Revisión de IA asistida | 1.500–5.000 € / sistema | Informe de revisión de seguridad de IA firmado (servicio + herramienta) |

**Meta realista:** 10 clientes Team ≈ 3.000 €/mes en 6–9 meses si la validación de la Fase 0 sale bien. El servicio de revisión asistida puede generar ingresos antes.

## 8. Métricas de éxito

- Fase 0: ≥ 3 clientes de pago o cartas de intención.
- Fase 1: ≥ 10 organizaciones activas, ≥ 3 de pago, coste LLM < 10 % de ingresos.
- Retención mensual > 90 %.

## 9. Riesgos principales

| Riesgo | Mitigación |
|---|---|
| Competidores grandes añaden seguridad de IA | Velocidad, nicho (startups con IA, UE / EU AI Act), servicio cercano |
| Falsos positivos → abandono | Triage con LLM + feedback del usuario + conjunto de evaluación propio |
| Coste de LLM descontrolado | Límites por plan, caché, modelos pequeños primero |
| Licencias de herramientas open source | Usar solo licencias compatibles con SaaS (MIT, Apache 2.0, LGPL) |
| Responsabilidad legal si se escapa una vulnerabilidad | Términos de servicio con limitación de responsabilidad; seguro de RC profesional cuando haya ingresos |
| Fundador único sin ingresos | No dejar fuentes de ingreso actuales hasta tener ingresos recurrentes; vender servicio desde el día 1 |

## 10. Preguntas abiertas

1. ¿Mercado principal: España / UE o internacional (inglés)?
2. ¿Tienes red de contactos con CTOs o equipos de seguridad para la validación?
3. ¿Experiencia propia: desarrollo, pentesting, consultoría de seguridad?
4. ¿Cuánto tiempo semanal puedes dedicar y cuántos meses de margen económico tienes?
5. ¿Los 1000 $ son créditos de API de Claude, de nube o efectivo?

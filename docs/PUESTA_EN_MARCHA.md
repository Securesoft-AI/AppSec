# Puesta en marcha: de cero a producción

Lista de lo que hay que hacer para tener Atalaya funcionando con clientes reales, en orden. Los detalles de
cada paso están en [DESPLIEGUE.md](DESPLIEGUE.md); aquí solo va la secuencia y lo que tienes que crear tú
(cuentas y claves que no se pueden automatizar desde el código).

En cada paso, `appsec-ai doctor` te dice qué falta. Con `--online` además prueba las claves contra GitHub,
Anthropic y Stripe con llamadas de solo lectura:

```bash
appsec-ai doctor            # configuración, base de datos y motores
appsec-ai doctor --online   # + credenciales reales
```

Sale con código 1 si hay algún error, así que también sirve como paso previo en un pipeline de despliegue.

## 1. Probar el triage con la API real de Claude (antes de nada)

El triage con IA es lo que diferencia el producto y conviene medirlo antes de cobrar por él.

1. Crea una clave en <https://console.anthropic.com> (Settings → API keys) y ponle un límite de gasto mensual.
2. Ejecuta la evaluación con los casos etiquetados:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   appsec-ai doctor --online                       # comprueba la clave y que el modelo existe
   python evals/triage/run_eval.py --repeat 3 --out resultados.json
   python evals/triage/run_eval.py --effort low --out resultados-low.json
   ```
3. Qué mirar en `resultados.json`:
   - **Problemas reales descartados: 0.** Es el error caro; el script sale con código 1 si hay alguno.
   - Falsos positivos eliminados: cuantos más, mejor.
   - Coste por caso: multiplícalo por los hallazgos de un escaneo típico para ajustar `AI_MAX_REQUESTS_*` y
     el presupuesto de IA de cada plan (`src/appsec_ai/service/plans.py`).
4. Si `--effort low` no descarta problemas reales y cuesta bastante menos, usa `AI_EFFORT=low` en producción.

## 2. Cuentas y claves que tienes que crear

| Qué | Dónde | Variables |
|---|---|---|
| Dominio y HTTPS | Tu registrador + la plataforma de despliegue | `PUBLIC_URL=https://...` |
| GitHub App | GitHub → Settings → Developer settings ([guía](DESPLIEGUE.md#1-crear-la-github-app)) | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| Postgres gestionado | Neon, Supabase, Cloud SQL, RDS... | `DATABASE_URL=postgresql+psycopg://...` |
| Claude | console.anthropic.com | `ANTHROPIC_API_KEY` |
| Stripe | dashboard.stripe.com ([guía](DESPLIEGUE.md#3b-cobros-con-stripe)) | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_*` |
| Equipo de pentest | Logins de GitHub del equipo | `STAFF_LOGINS` |

Y dos secretos que generas tú:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'                                    # SESSION_SECRET
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'    # DATA_ENCRYPTION_KEY
```

Guarda una copia de `DATA_ENCRYPTION_KEY` fuera de la plataforma: sin ella no se pueden leer los tokens de las
integraciones ni los resultados guardados. Para rotarla, pon la nueva delante separada por coma
(`nueva,antigua`).

Todo esto va en el gestor de secretos de la plataforma, nunca en el repositorio.

## 3. Desplegar

1. Construye la imagen (`Dockerfile`): incluye los motores (Semgrep, Gitleaks, OSV-Scanner, Checkov).
2. Dos servicios con la misma imagen:
   - **API**: `appsec-ai serve --port 8000`, detrás del HTTPS de la plataforma.
   - **Worker**: `appsec-ai worker`, unos 2 GB de RAM. Sin puerto expuesto.
3. Aislamiento del escaneo: el worker analiza código de terceros. En producción usa un contenedor efímero
   por escaneo con gVisor (`SCAN_RUNNER`, ver [DESPLIEGUE.md](DESPLIEGUE.md#4-seguridad-del-propio-servicio)).
   Si tu plataforma no permite lanzar contenedores desde el worker (Fly, Railway, Render), usa Kubernetes
   (GKE, EKS) con un Job por escaneo y `runtimeClassName: gvisor`, o deja el subproceso aislado por defecto
   mientras tengas pocos clientes y de confianza.
4. Las migraciones se aplican solas al arrancar.
5. `appsec-ai doctor --online` dentro del contenedor de la API: debe terminar sin errores.
   `DEMO_LOGIN` tiene que estar desactivado (el doctor da error si está activo con `https`).

## 4. Prueba de humo con un repositorio propio

1. Instala la GitHub App en un repositorio de prueba (por ejemplo, una copia de `web/demo-repos/`).
2. Abre un PR con un cambio vulnerable: debe aparecer el check `appsec-ai` y un comentario en el PR.
3. Entra en `https://TU-DOMINIO/app` con GitHub: la organización y el escaneo aparecen en el panel.
4. Con Stripe en modo test, contrata un plan con la tarjeta `4242 4242 4242 4242` y comprueba que el plan
   cambia (lo activa el webhook firmado, no la vuelta desde Stripe).
5. En la pestaña Integraciones, conecta Slack y Jira de prueba y pulsa «Probar».
6. Cambia Stripe a modo live (`sk_live_...` y los `price_` de live) y vuelve a pasar `appsec-ai doctor --online`.

## 5. Después del lanzamiento

- Vigila el coste de Claude por cliente frente al presupuesto de cada plan.
- Copias de seguridad diarias de Postgres (la mayoría de servicios gestionados las hacen solos).
- Revisa el registro de auditoría de cada organización desde su página de plan en el panel.

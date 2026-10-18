# Despliegue del SaaS

## Arquitectura

```
GitHub ──webhook──► API (FastAPI)  ──► Postgres (tabla scans = cola)
                                           ▲
                    Worker(s) ─────────────┘
                      1. toma un escaneo de la cola (UPDATE atómico, admite varios workers)
                      2. crea el check "appsec-ai" en el commit
                      3. clona solo ese commit (sin historial, hooks, LFS ni enlaces simbólicos)
                      4. ejecuta los motores; en PRs filtra a los ficheros modificados
                      5. triage con Claude (si hay ANTHROPIC_API_KEY)
                      6. publica anotaciones + comentario en el PR y borra la copia del código
```

- **PR abierto o actualizado** → escaneo del commit; solo se informa de los ficheros modificados.
- **Push a la rama por defecto** → escaneo completo.
- **"Re-run" en GitHub** → se repite el escaneo.
- Los fallos se reintentan 3 veces. Después el check se cierra como `neutral` para no bloquear al cliente.
- Las entregas repetidas del mismo webhook no generan escaneos duplicados.

## 1. Crear la GitHub App

1. En GitHub ve a **Settings → Developer settings → GitHub Apps → New GitHub App**. Si es para una organización, ve a la configuración de la organización.
2. Rellena los datos con los de `deploy/github-app-manifest.json`:
   - **Webhook URL:** `https://TU-DOMINIO/webhooks/github`.
   - **Webhook secret:** una cadena aleatoria larga (`openssl rand -hex 32`). Es el valor de `GITHUB_WEBHOOK_SECRET`.
   - **Permisos del repositorio:** Contents *Read & write*, Metadata *Read*, Pull requests *Read & write*, Checks *Read & write*.
     La escritura en Contents solo se usa para el botón **Abrir PR con fixes**: crea una rama `appsec-ai/fix-…` y abre un PR, nunca escribe en ramas existentes. Si un cliente instala la App solo con lectura, el botón explica en el PR qué permiso falta.
   - **Eventos:** Pull request, Push, Check run.
3. Crea la App y apunta el **App ID** (`GITHUB_APP_ID`). Para el login del panel, añade como **Callback URL**
   `https://TU-DOMINIO/auth/callback` y genera un **client secret**: son `GITHUB_CLIENT_ID` y `GITHUB_CLIENT_SECRET`.
   El panel solo muestra las instalaciones a las que el usuario tiene acceso en GitHub; la lista se actualiza en
   cada login (la sesión dura 8 horas).
4. Genera una **clave privada**: se descarga un `.pem`. Para ponerla en una sola línea:
   ```bash
   awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' tu-app.private-key.pem
   ```
   El resultado es `GITHUB_APP_PRIVATE_KEY`.
5. Instala la App en un repositorio de prueba para probarla.

## 2. Probar en local

### Demo sin GitHub (user / pass)

```bash
DEMO_LOGIN=1 appsec-ai serve --port 8000
# http://localhost:8000/app  ->  usuario «user», contraseña «pass»
```

Crea una organización de ejemplo con tres repositorios de código deliberadamente vulnerable (`web/demo-repos/`)
y un pentest entregado. «Escanear ahora» analiza al momento ese código con los servicios que elijas. La sesión de
demostración solo ve esa organización. **No actives `DEMO_LOGIN` en un entorno con datos de clientes**:
usuario y contraseña son conocidos (cámbialos con `DEMO_USER` y `DEMO_PASSWORD` si la expones).

### Con la GitHub App

```bash
cp .env.example .env   # rellenar los valores
docker compose up --build
```

GitHub necesita alcanzar tu webhook. En local puedes usar un túnel, por ejemplo `cloudflared tunnel --url http://localhost:8000` o [smee.io](https://smee.io), y poner esa URL en la App.

## 3. Producción (opción barata para empezar)

Cualquier plataforma que ejecute contenedores sirve: Fly.io, Railway, Render, Google Cloud Run + Cloud SQL o AWS ECS.

- **API**: 1 instancia pequeña, comando `appsec-ai serve --port 8000`.
- **Worker**: 1 o más instancias, comando `appsec-ai worker`. Calcula unos 2 GB de RAM.
- **Postgres** gestionado, con `DATABASE_URL=postgresql+psycopg://usuario:clave@host:5432/db`.
- Los secretos (`GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, `ANTHROPIC_API_KEY`, `ADMIN_API_TOKEN`, `DATA_ENCRYPTION_KEY`) van en el gestor de secretos de la plataforma, **nunca** en el repositorio.

Coste orientativo para empezar: 20–50 $/mes más el uso de la API de Claude.

## 3b. Cobros con Stripe

1. Crea en Stripe un producto por plan (Starter, Team, Business) con un precio mensual recurrente; apunta cada `price_...`.
2. Activa el **Customer Portal** (Billing → Customer portal) para que los clientes cambien de plan, actualicen la tarjeta o cancelen.
3. Crea un endpoint de webhook a `https://TU-DOMINIO/webhooks/stripe` con los eventos `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated` y `customer.subscription.deleted`.
4. El plan solo cambia con esos webhooks firmados: volver de Stripe a `/app?billing=ok` no activa nada por sí solo.
   Los eventos antiguos que lleguen tarde se ignoran.

Límites por plan (en `src/appsec_ai/service/plans.py`; el presupuesto de IA es una hipótesis hasta medir el coste real):

| Plan | Repos | PRs | Rama principal | IA (peticiones/mes) | Fixes | PDF | Cumplimiento |
|---|---|---|---|---|---|---|---|
| Free | 1 | No | Semanal | — | No | No | No |
| Starter | 3 | Sí | Cada push | 1.000 | No | No | No |
| Team | 20 | Sí | Cada push | 5.000 | Sí | Sí | No |
| Business | Sin límite | Sí | Cada push | 20.000 | Sí | Sí | Sí |

## 3c. Base de datos y migraciones

La API y el worker aplican las migraciones pendientes al arrancar (con un bloqueo en Postgres para que no
lo hagan a la vez); también se pueden aplicar a mano con `appsec-ai migrate`. Una base de datos creada por
una versión anterior, sin migraciones, se completa con las tablas y columnas que le falten y se marca como
al día.

Al cambiar un modelo de `src/appsec_ai/service/db.py`, genera su migración, revísala y súbela con el cambio:

```bash
DATABASE_URL=sqlite:///./dev.db appsec-ai migrate --new "Describe el cambio"
```

`tests/test_migrations.py` falla si los modelos y las migraciones no coinciden. Con `TEST_POSTGRES_URL`
definida también se prueban contra Postgres (el CI lo hace).

## 3d. Pentests: la vista Equipo

Los logins de GitHub del equipo de seguridad van en `STAFF_LOGINS` (separados por comas). Al entrar en el panel
ven la pestaña **Equipo** con los pentests de todos los clientes: fijan el presupuesto, escriben al cliente,
cambian el estado y redactan el informe (resumen y hallazgos). El cliente acepta el presupuesto o cancela la
solicitud desde su pestaña Pentest y, cuando el informe está entregado, lo descarga en PDF. No se puede pasar a
"Programado" sin que el cliente haya aceptado el presupuesto, y cambiar el importe obliga a aceptarlo de nuevo.
Quitar un login de `STAFF_LOGINS` le retira el acceso en su siguiente petición. En la demo, el usuario `user`
ve la vista Equipo solo con los pentests de la organización de ejemplo.

## 3e. Red teaming de endpoints con IA (RF-2.7)

El servicio de Seguridad de IA incluye lanzar ataques reales contra un endpoint con LLM ya desplegado del
cliente: inyección de prompts (directa e indirecta), suplantación de rol, fuga del prompt de sistema,
exfiltración entre usuarios y jailbreak. Cada sonda trae su propio detector determinista (un canario que el
modelo solo repite si obedeció, o marcadores de cumplimiento frente a rechazo), así que **no usa la API de
Claude**.

Como esto envía tráfico de ataque a una URL, antes de ejecutar nada el cliente tiene que demostrar que el
dominio es suyo publicando el token que le damos, de una de estas formas:

- HTTP: en `https://<host>/.well-known/appsec-ai-challenge.txt`.
- DNS: un registro TXT `appsec-ai-challenge=<token>`.

Solo se permiten objetivos HTTPS hacia hosts que resuelven a direcciones públicas: nunca IPs privadas,
`localhost` ni enlaces locales (defensa frente a SSRF contra la red interna del propio servicio). Las
cabeceras del objetivo (que pueden llevar claves de API) se guardan cifradas. El worker procesa las
ejecuciones desde la misma cola que los escaneos. La verificación DNS usa `dnspython` si está instalado.

## 4. Seguridad del propio servicio

- Webhooks verificados con HMAC-SHA256. Sin secreto configurado se rechazan todos.
- Tokens de instalación de corta duración (1 hora). El token nunca aparece en URLs, argumentos ni logs.
- El código del cliente se clona en un directorio temporal que se borra siempre, también si hay errores. Se descartan el historial, los hooks, LFS y los enlaces simbólicos.
- El worker se ejecuta sin privilegios (`uid 10001`) y con límites de memoria, CPU y tamaño del repositorio.
- El triage con IA trata el código del cliente como datos no confiables (defensa frente a prompt injection).
- **Escaneo aislado** (`SCAN_SANDBOX=subprocess`, por defecto): los motores analizan el código en un subproceso
  sin secretos en el entorno (ni la clave de la GitHub App, ni la de Anthropic, ni `DATABASE_URL`), en Python
  aislado (`-I`, para que el repositorio no pueda suplantar módulos), en su propia sesión de procesos que se
  mata entera al agotar `SCAN_TIMEOUT`, y con límites de CPU, tamaño de fichero y descriptores. Los motores
  externos de la CLI también reciben solo un entorno mínimo.
- `SCAN_SANDBOX_CMD` envuelve ese subproceso con un sandbox del sistema. Ejemplo con bubblewrap (hay que
  instalarlo en la imagen): `bwrap --unshare-all --share-net --die-with-parent --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind {src} {src}`.
  Así el escaneo solo puede escribir en su directorio.
- **SSO con OpenID Connect** (RF-4.8): cada organización conecta su proveedor de identidad desde el panel
  (*Integraciones → SSO*): issuer, client_id, client_secret y los dominios de email permitidos. En el
  proveedor hay que registrar la URL de redirección `https://<tu-dominio>/auth/sso/callback` (el panel la
  muestra). El usuario escribe su email corporativo y entra por su IdP; al volver se verifica el id_token
  (firma RS256 contra el JWKS del proveedor, emisor, público, caducidad y nonce) y que el email está
  verificado y su dominio permitido. La sesión queda limitada a esa organización. El secreto se guarda
  cifrado. Requiere `SESSION_SECRET` configurado. Soporta OIDC; SAML queda pendiente.
- **Registros de auditoría** (RF-4.8): cada acción sensible (inicio de sesión, escaneo solicitado, cambios en
  pentests y red team, facturación y ajustes) se guarda en la tabla `audit_log`, que es de solo añadir: la
  aplicación no tiene ningún endpoint para modificar ni borrar entradas. Cada organización ve su propia
  actividad en el panel (`GET /api/installations/{id}/audit`). El detalle no guarda secretos ni código.
- **Avisos en Slack** (RF-4.8): cada organización conecta un *incoming webhook* de Slack desde el panel
  (Servicios y plan → «Avisos en Slack»). El servicio avisa cuando un escaneo de la rama principal termina
  con hallazgos críticos o altos, cuando un pentest pasa a «programado» o «informe entregado» y cuando un
  red team encuentra algo. El webhook es un secreto y se guarda cifrado; un fallo al avisar se registra y no
  interrumpe el escaneo. El botón «Enviar prueba» publica un mensaje de comprobación.
- **Panel de integraciones** (RF-4.8): cada organización conecta sus herramientas desde el panel (pestaña
  *Integraciones*): **Slack** (webhook entrante), **Jira** (URL del sitio, email, token de API y clave del
  proyecto; API REST v3 con autenticación básica), **GitLab** (URL base, token de acceso e id o ruta del
  proyecto; API v4) y **Bitbucket** (workspace, repositorio, usuario y app password; API 2.0 de Bitbucket
  Cloud, con las incidencias activadas en el repositorio). Desde cualquier hallazgo, los botones «Crear incidencia en Jira/GitLab/Bitbucket» abren una
  incidencia con la ubicación, la severidad, el escenario de ataque y la corrección. Con el **envío
  automático** activado en Jira, GitLab o Bitbucket, al terminar un escaneo de la rama principal los hallazgos críticos
  y altos nuevos se crean solos, sin duplicar (tabla `integration_exports`). Toda la configuración es un
  secreto y se guarda cifrada; los tokens nunca se devuelven. Conectar una integración y crear una incidencia
  quedan en el registro de auditoría.
- **Cifrado en reposo** con `DATA_ENCRYPTION_KEY` (Fernet): resultados de escaneos y detalle de las correcciones
  en la base de datos, y la caché del triage en disco. Para rotar la clave: `DATA_ENCRYPTION_KEY=nueva,antigua`
  (cifra con la primera y descifra con todas). Las filas anteriores sin cifrar se siguen leyendo. Sin clave, el
  servicio arranca pero lo avisa en el log.
- **Contenedor efímero por escaneo** (`SCAN_RUNNER`, RF-4.4): cuando se define, cada escaneo corre en su
  propio contenedor en lugar de en un subproceso del worker, así que no comparte red ni sistema de ficheros
  con él. Es una plantilla de orden con cuatro marcadores que el worker sustituye: `{src}` (directorio a
  montar de solo lectura), `{out}` (fichero donde el contenedor deja el JSON del resultado), `{files_from}`
  (lista de ficheros en los escaneos incrementales; vacío si es completo) y `{engines}` (motores separados
  por comas). El contenedor monta `{src}` de solo lectura, sin red y sin secretos, corre `appsec-ai scan`
  dentro (la propia imagen del servicio ya lo trae) y escribe el resultado en `{out}`. Ejemplo con gVisor,
  reutilizando la imagen del servicio:

  ```
  SCAN_RUNNER=docker run --rm --runtime=runsc --network=none --read-only \
    -v {src}:/src:ro -v {out}:/out.json:rw --tmpfs /tmp \
    --memory=4g --cpus=2 --pids-limit=512 \
    appsec-ai:latest sh -c 'appsec-ai scan /src --format json --engines "{engines}" > /out.json'
  ```

  En Kubernetes, el mismo patrón es un Job efímero con `runtimeClassName: gvisor` por escaneo. Sin
  `SCAN_RUNNER`, sigue valiendo el subproceso aislado (`SCAN_SANDBOX`/`SCAN_SANDBOX_CMD`).

## 5. Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `DATABASE_URL` | Sí | Postgres en producción (SQLite por defecto en desarrollo) |
| `STAFF_LOGINS` | No | Logins de GitHub del equipo de seguridad (vista Equipo de pentests) |
| `REDTEAM_ENABLED` | No | Red teaming dinámico activado (por defecto sí; `0` para desactivarlo) |
| `REDTEAM_TIMEOUT` | No | Timeout por petición de red teaming, en segundos (por defecto 30) |
| `SCAN_RUNNER` | No | Contenedor efímero por escaneo: plantilla con `{src}` `{out}` `{files_from}` `{engines}` (RF-4.4) |
| `GITHUB_APP_ID` | Sí (worker) | ID de la GitHub App |
| `GITHUB_APP_PRIVATE_KEY` | Sí (worker) | Clave privada PEM |
| `GITHUB_WEBHOOK_SECRET` | Sí (API) | Secreto de los webhooks |
| `ANTHROPIC_API_KEY` | No | Activa el triage con Claude |
| `AI_MODEL` / `AI_EFFORT` | No | Modelo y esfuerzo del triage |
| `AI_MAX_REQUESTS_PR` / `AI_MAX_REQUESTS_FULL` | No | Presupuesto de peticiones de IA por escaneo |
| `AI_CACHE_DIR` | No | Directorio persistente para la caché del triage (una subcarpeta por repositorio). Sin él, cada escaneo vuelve a pagar todas las peticiones |
| `REPORT_LANGUAGE` | No | `es` o `en` |
| `FAIL_ON` | No | Severidad que hace fallar el check (por defecto `high`) |
| `MAX_REPO_MB` | No | Tamaño máximo del repositorio (por defecto 500) |
| `ADMIN_API_TOKEN` | No | Acceso de emergencia para operaciones (ve todas las instalaciones). Los clientes entran con GitHub |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Sí (panel) | Credenciales OAuth de la GitHub App, para el login del panel |
| `SESSION_SECRET` | Sí (panel) | Firma de las cookies de sesión (`openssl rand -hex 32`) |
| `PUBLIC_URL` | Sí (panel) | URL pública (`https://...`): callback de OAuth, cookies `Secure` y comprobación de `Origin` |
| `DATA_ENCRYPTION_KEY` | Sí en producción | Clave Fernet para cifrar resultados y caché. Genérala con `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SCAN_SANDBOX` | No | `subprocess` (por defecto) o `none` (solo desarrollo) |
| `SCAN_SANDBOX_CMD` | No | Envoltorio del escaneo aislado (bubblewrap, firejail...). `{src}` es el directorio del escaneo |
| `SCAN_TIMEOUT` | No | Segundos máximos por escaneo (por defecto 900) |
| `STRIPE_SECRET_KEY` | Sí (cobros) | Clave secreta de Stripe (`sk_live_...`; usa una *restricted key* con permisos de Checkout, Billing Portal y Subscriptions) |
| `STRIPE_WEBHOOK_SECRET` | Sí (cobros) | Secreto del endpoint de webhook (`whsec_...`) |
| `STRIPE_PRICE_STARTER` / `STRIPE_PRICE_TEAM` / `STRIPE_PRICE_BUSINESS` | Sí (cobros) | Id del precio mensual de cada plan (`price_...`) |

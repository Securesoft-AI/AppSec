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
- **Cifrado en reposo** con `DATA_ENCRYPTION_KEY` (Fernet): resultados de escaneos y detalle de las correcciones
  en la base de datos, y la caché del triage en disco. Para rotar la clave: `DATA_ENCRYPTION_KEY=nueva,antigua`
  (cifra con la primera y descifra con todas). Las filas anteriores sin cifrar se siguen leyendo. Sin clave, el
  servicio arranca pero lo avisa en el log.
- **Pendiente antes de abrir al público:**
  - un contenedor efímero por escaneo (gVisor/Firecracker, p. ej. un Job de Kubernetes o de Cloud Run con
    `runtimeClassName: gvisor`). El subproceso ya no tiene secretos, pero comparte red y sistema de ficheros
    con el worker. Como paso intermedio, ejecuta el worker con el runtime `runsc` de gVisor;
  - límites por plan.

## 5. Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `DATABASE_URL` | Sí | Postgres en producción (SQLite por defecto en desarrollo) |
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

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
   - **Permisos del repositorio:** Contents *Read*, Metadata *Read*, Pull requests *Read & write*, Checks *Read & write*.
   - **Eventos:** Pull request, Push, Check run.
3. Crea la App y apunta el **App ID** (`GITHUB_APP_ID`).
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
- Los secretos (`GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, `ANTHROPIC_API_KEY`, `ADMIN_API_TOKEN`) van en el gestor de secretos de la plataforma, **nunca** en el repositorio.

Coste orientativo para empezar: 20–50 $/mes más el uso de la API de Claude.

## 4. Seguridad del propio servicio

- Webhooks verificados con HMAC-SHA256. Sin secreto configurado se rechazan todos.
- Tokens de instalación de corta duración (1 hora). El token nunca aparece en URLs, argumentos ni logs.
- El código del cliente se clona en un directorio temporal que se borra siempre, también si hay errores. Se descartan el historial, los hooks, LFS y los enlaces simbólicos.
- El worker se ejecuta sin privilegios (`uid 10001`) y con límites de memoria, CPU y tamaño del repositorio.
- El triage con IA trata el código del cliente como datos no confiables (defensa frente a prompt injection).
- **Pendiente antes de abrir al público:**
  - aislar cada escaneo en su propio contenedor efímero (gVisor/Firecracker);
  - login con GitHub en el panel, que sustituya a `ADMIN_API_TOKEN`;
  - límites por plan;
  - cifrar en reposo los resultados de los escaneos y la caché del triage (`AI_CACHE_DIR`).

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
| `ADMIN_API_TOKEN` | No | Acceso provisional a la API REST |

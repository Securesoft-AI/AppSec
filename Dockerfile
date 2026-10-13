# Imagen única para la API y el worker. Los motores externos van en entornos aislados
# para que sus dependencias no choquen con las del servicio.

FROM golang:1.23-bookworm AS gotools
RUN go install github.com/zricethezav/gitleaks/v8@v8.21.2 \
 && go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.0.2

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /go/bin/gitleaks /go/bin/osv-scanner /usr/local/bin/

# SAST: Semgrep CE (LGPL) con nuestras reglas. Sustituible por el binario de Opengrep.
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install semgrep==1.180.0 \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep
# IaC: Checkov (Apache 2.0).
RUN python -m venv /opt/checkov && /opt/checkov/bin/pip install "checkov>=3.2,<4" \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY web ./web
RUN pip install ".[service]"

# Sin privilegios: el worker analiza código no confiable.
RUN useradd --create-home --uid 10001 appsec && mkdir -p /work /var/lib/appsec-ai/cache \
 && chown appsec /work /var/lib/appsec-ai/cache
USER appsec
ENV WORKDIR=/work SEMGREP_SEND_METRICS=off

EXPOSE 8000
CMD ["appsec-ai", "serve", "--port", "8000"]

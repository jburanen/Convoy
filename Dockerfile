# Convoy — container image for the orchestration web service.
# Pure-Python deps (paramiko/cryptography ship manylinux wheels), so no build
# toolchain is needed on slim.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first (better layer caching), then the package with the web extra.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[web]"

# Runtime data dir (config/inventory/reports); owned by uid 1001 so the container,
# run as 1001:1001, can write to a bind mount without leaving root-owned files.
RUN mkdir -p /data && chown 1001:1001 /data

EXPOSE 8080
USER 1001:1001

# Liveness probe used by compose; kept dependency-free (stdlib only). Follows
# CONVOY_SSL_CERTFILE to probe https:// (unverified — loopback, not a trust
# decision) when the optional native TLS listener is enabled.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,ssl,urllib.request,sys; tls=bool(os.environ.get('CONVOY_SSL_CERTFILE')); ctx=ssl._create_unverified_context() if tls else None; sys.exit(0 if urllib.request.urlopen(('https' if tls else 'http')+'://localhost:8080/health', context=ctx).status==200 else 1)"

CMD ["python", "-m", "convoy.web"]

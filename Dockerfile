# Convoy — container image for the orchestration web service.
# Pure-Python deps (paramiko/cryptography ship manylinux wheels), so no build
# toolchain is needed on slim.
#
# Published to ghcr.io/jburanen/convoy by .github/workflows/release.yml on every
# vX.Y.Z tag. End users pull it via docker-compose.yml and never build this.
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

# The image carries its own config template: a published image is started by
# people with no checkout to copy one from, and the entrypoint seeds the data
# volume from this on first run. Only *.example.* files — nothing sensitive.
COPY examples ./examples
COPY docker-entrypoint.sh /usr/local/bin/convoy-entrypoint
RUN chmod +x /usr/local/bin/convoy-entrypoint

# Runtime data dir (config/inventory/reports); owned by uid 1001 so the container,
# run as 1001:1001, can write to it without leaving root-owned files. A named
# volume mounted here inherits this ownership, which is what lets a bare
# `docker compose up -d` work on any host — see docker-compose.yml.
RUN mkdir -p /data && chown 1001:1001 /data

# Links the GHCR package to this repository, and lets `docker inspect` answer
# which release an image is. VERSION is passed by the release workflow.
ARG VERSION=dev
LABEL org.opencontainers.image.title="Convoy" \
      org.opencontainers.image.description="Orchestration layer for Check Point CDT/CPUSE — staged, health-gated patching across management servers and gateways." \
      org.opencontainers.image.source="https://github.com/jburanen/Convoy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

EXPOSE 8080
USER 1001:1001

# Liveness probe used by compose; kept dependency-free (stdlib only). Follows
# CONVOY_SSL_CERTFILE to probe https:// (unverified — loopback, not a trust
# decision) when the optional native TLS listener is enabled.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,ssl,urllib.request,sys; tls=bool(os.environ.get('CONVOY_SSL_CERTFILE')); ctx=ssl._create_unverified_context() if tls else None; sys.exit(0 if urllib.request.urlopen(('https' if tls else 'http')+'://localhost:8080/health', context=ctx).status==200 else 1)"

ENTRYPOINT ["convoy-entrypoint"]
CMD ["python", "-m", "convoy.web"]

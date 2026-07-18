# chkp-cpuse-orch — container image for the orchestration web service.
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

# Liveness probe used by compose; kept dependency-free (stdlib only).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health').status==200 else 1)"

CMD ["uvicorn", "chkp_cpuse_orch.web.app:app", "--host", "0.0.0.0", "--port", "8080"]

# No `# syntax=` directive on purpose. It makes BuildKit fetch the
# docker/dockerfile frontend from Docker Hub before parsing this file — a third
# rate-limited round-trip on a runner that shares its IP with every other
# GitHub Actions job. Nothing here needs a newer frontend than the daemon's
# built-in one: no RUN --mount, no COPY --link, no heredocs. Add the directive
# back only alongside a feature that actually requires it.
# ─────────────────────────────────────────────────────────────────────────────
# Kronagent container image.
#
# Two properties are deliberate and worth stating, because this is a security
# product and the image is part of the argument:
#
#   1. The cloud SDKs are NOT installed by default. Every provider adapter
#      imports its SDK lazily, so dry-run, the demo and the full test suite need
#      none of them. An image that does not contain boto3 cannot be argued into
#      touching AWS. Add capability explicitly:
#          docker build --build-arg EXTRAS=aws,k8s .
#
#   2. It runs as a non-root user with a read-only-friendly layout. A platform
#      that asks for permission to contain workloads has no business running as
#      root inside its own container.
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Empty = core only (dry-run, demo, tests). "aws,k8s" / "all" to add live
# containment. See note 1 above.
ARG EXTRAS=""

COPY pyproject.toml README.md LICENSE ./
COPY kronagent/ ./kronagent/
COPY *.py ./

# Build a wheel and install it into an isolated prefix we can copy wholesale,
# so the runtime stage carries no build toolchain.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && if [ -n "$EXTRAS" ]; then /opt/venv/bin/pip install ".[$EXTRAS]"; \
    else /opt/venv/bin/pip install "."; fi


FROM python:3.13-slim AS runtime

# Set by the release workflow; a local build reports "dev".
ARG VERSION=dev
LABEL org.opencontainers.image.title="Kronagent" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.source="https://github.com/Aditya-galaxy/kronagent" \
      org.opencontainers.image.description="Autonomous AI threat-defense with graduated autonomy and a tamper-evident audit log" \
      org.opencontainers.image.url="https://kronagent.com" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Noncommercial-1.0.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Safe defaults, restated at the image layer. config.py already defaults
    # dry_run to True; setting it here means an operator reading `docker
    # inspect` can see the posture without reading Python.
    KRONAGENT_DRY_RUN=true \
    KRONAGENT_STATE_DIR=/var/lib/kronagent

COPY --from=builder /opt/venv /opt/venv

# Samples let the image demonstrate itself with no cloud account attached.
WORKDIR /app
COPY samples/ ./samples/

# Non-root. State lives in a volume it owns; nothing else is writable.
RUN useradd --system --uid 10001 --home /var/lib/kronagent --shell /usr/sbin/nologin kronagent \
 && mkdir -p /var/lib/kronagent \
 && chown -R kronagent:kronagent /var/lib/kronagent /app
USER kronagent
VOLUME ["/var/lib/kronagent"]

EXPOSE 8000

# The console answers /api/status without touching a cloud provider, so this
# reports "the process is serving", not "a cloud is reachable" — which is what
# a container healthcheck should mean.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/status', timeout=4).status==200 else 1)"

# The agent loop and the console in one process (run_serve.py, installed as
# the kronagent-serve console script). With no live source configured the loop
# stays off and only the console serves; add --replay to demonstrate on the
# bundled samples.
CMD ["kronagent-serve", "--host", "0.0.0.0", "--port", "8000"]

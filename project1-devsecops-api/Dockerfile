# syntax=docker/dockerfile:1.7
#
# Multi-stage build:
#   deps     - hash-verified dependency install into a venv
#   test     - deps + dev tooling + source; runs the test suite
#   runtime  - minimal, non-root image with no build tools and no pip
#
# Pin the base image by digest in CI for reproducibility; Dependabot
# (docker ecosystem) keeps the tag/digest current.
ARG PYTHON_IMAGE=python:3.13-slim-trixie

FROM ${PYTHON_IMAGE} AS deps
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.txt

FROM deps AS test
COPY requirements-dev.txt .
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements-dev.txt
RUN useradd --system --uid 10002 --create-home tester && install -d -o tester -g tester /src
WORKDIR /src
COPY --chown=tester . .
ENV PATH=/opt/venv/bin:$PATH
# Tests run unprivileged too; nothing in the build needs root after install.
USER tester
CMD ["pytest", "-q"]

FROM deps AS venv-prod
# The runtime never installs packages, so remove pip from the venv.
RUN /opt/venv/bin/python -m pip uninstall -y pip

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="secure-invoice-api" \
      org.opencontainers.image.description="Security-hardened FastAPI reference service" \
      org.opencontainers.image.licenses="MIT"

# Apply pending OS security updates, then drop the system pip/setuptools
# (not needed at runtime and a common source of scanner findings).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
RUN python -m pip uninstall -y pip setuptools wheel || true

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin app \
 && install -d -o app -g app -m 0700 /data

COPY --from=venv-prod /opt/venv /opt/venv
WORKDIR /app
# Source is owned by root and read-only for the app user.
COPY --chown=root:root --chmod=0555 app ./app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_DATABASE_URL=sqlite:////data/app.db

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log"]

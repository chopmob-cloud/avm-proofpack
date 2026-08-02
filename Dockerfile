# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# avm-proofpack service image (design/grpc-rest-service-design.md §6-§7).
#
# Builds the OPTIONAL service layer only. The verification core
# (src/avm_proofpack/) stays zero-dependency; this image installs the package
# WITH the `[server]` extra (grpclib / betterproto / uvicorn) and runs both
# transports behind one ProofpackService via `python -m avm_proofpack_server`.
#
# Multi-stage: the builder compiles a wheel from a clean source tree (the
# design's build-hygiene rule, S6 caveat: build from a clean checkout/sdist so
# the experimental Falcon/state-proof tier is never globbed in); the runtime
# stage carries only the installed package and its `[server]` deps, no build
# tooling.
#
# No secrets, keys, or certs are baked in. TLS material and the API-key file are
# provided at run time via env vars pointing at mounted volumes (see
# docker-compose.yml and docs/service.md).
# ---------------------------------------------------------------------------

# --- build stage -----------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install the package plus the [server] extra into an isolated prefix. Copying
# only the files the build needs keeps the layer cache stable and avoids pulling
# local dev artefacts (dist/, build/, .venv/) into the wheel.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir --prefix=/install ".[server]"

# --- runtime stage ---------------------------------------------------------
FROM python:3.12-slim AS runtime

# Non-root runtime user (design §9: least privilege; nothing here needs root).
RUN groupadd --system proofpack \
    && useradd --system --gid proofpack --home-dir /app --no-create-home proofpack

WORKDIR /app

# Bring in the site-packages and console scripts built in the previous stage.
COPY --from=builder /install /usr/local

# Service configuration is env-driven (src/avm_proofpack_server/config.py).
# These are safe, non-secret defaults; bind to all interfaces inside the
# container and speak both transports. Override any of them at run time.
# Secrets (API key file, TLS cert/key) are NEVER set here; supply them via
# mounted volumes + the *_FILE env vars at run time.
ENV AVM_PROOFPACK_HOST=0.0.0.0 \
    AVM_PROOFPACK_GRPC_PORT=50051 \
    AVM_PROOFPACK_REST_PORT=8080 \
    AVM_PROOFPACK_TRANSPORTS=grpc,rest \
    PYTHONUNBUFFERED=1

USER proofpack

# gRPC (50051) and REST (8080). Match AVM_PROOFPACK_GRPC_PORT / _REST_PORT if
# you override them.
EXPOSE 50051 8080

# Runs both transports over the one ProofpackService (and the optional scheduler
# when AVM_PROOFPACK_SCHEDULER_ENABLED=1).
ENTRYPOINT ["python", "-m", "avm_proofpack_server"]

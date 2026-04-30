# ============================================================
# ca-radar — multi-stage distroless container
# ============================================================
# Stage 1: builder — install dependencies with uv into /app/.venv
# Stage 2: runtime — gcr.io/distroless/python3-debian12 (no shell,
#          no package manager, minimal attack surface)
#
# Build:
#   docker build -t ca-radar:latest .
#
# Run (interactive device-code scan):
#   docker run --rm -it \
#     -v "$(pwd)/snapshot:/snapshot" \
#     ca-radar:latest \
#     scan --tenant contoso.onmicrosoft.com --out /snapshot
#
# Run (app auth with cert):
#   docker run --rm \
#     -v "$(pwd)/snapshot:/snapshot" \
#     -v "$(pwd)/cert.pem:/certs/cert.pem:ro" \
#     -e CA_RADAR_CLIENT_ID="00000000-0000-0000-0000-000000000000" \
#     -e CA_RADAR_CERT_PATH="/certs/cert.pem" \
#     ca-radar:latest \
#     scan --tenant contoso.onmicrosoft.com --auth app --out /snapshot
# ============================================================

# ── Stage 1: builder ─────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv==0.5.26

# Copy only the manifest files first — install deps without the project itself.
# This layer is cached as long as pyproject.toml / uv.lock don't change.
COPY pyproject.toml uv.lock README.md ./

# Install runtime dependencies but NOT the project wheel yet
RUN uv sync --no-dev --no-install-project

# Copy the full source and install the package as a proper wheel
COPY ca_radar/ ca_radar/
RUN uv pip install --no-deps --no-cache-dir .

# ── Stage 2: distroless runtime ───────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot

LABEL org.opencontainers.image.title="ca-radar" \
      org.opencontainers.image.description="Conditional Access Gap Analyser for Microsoft 365 / Entra ID" \
      org.opencontainers.image.source="https://github.com/investwithdon7-rgb/ca-radar" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy only the installed site-packages from the builder venv.
# We deliberately do NOT copy the venv's bin/ scripts because their shebangs
# point to the builder's /usr/local/bin/python3.11, which does not exist in
# the distroless image (Python lives at /usr/bin/python3 in Debian packages).
COPY --from=builder /app/.venv/lib/python3.11/site-packages /app/site-packages

# distroless:nonroot already runs as uid 65532 (nonroot)
# No USER instruction needed — it's the default

# Snapshot output directory (mount a volume here)
VOLUME ["/snapshot"]

# Point distroless Python to the installed site-packages
ENV PYTHONPATH="/app/site-packages" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Use distroless Python to invoke ca_radar.__main__ (added for this entrypoint)
ENTRYPOINT ["/usr/bin/python3", "-m", "ca_radar"]
CMD ["--help"]

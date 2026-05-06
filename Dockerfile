# pentest-ai Dockerfile (multi-stage)
#
# Targets:
#   prod     — minimal runtime, only the installed package
#   dev      — full dev dependencies, source mounted at /workspace
#
# Build:
#   docker build --target prod -t pentest-ai:latest .
#   docker build --target dev  -t pentest-ai:dev .
#
# Run (prod):
#   docker run --rm -it -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY pentest-ai ptai mcp

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─── prod stage: install the package, no dev deps ──────────────────────
FROM base AS prod

COPY pyproject.toml README.md VERSION ./
COPY agents/ agents/
COPY api/ api/
COPY cli/ cli/
COPY engine/ engine/
COPY mcp_server/ mcp_server/
COPY config/ config/
COPY playbooks/ playbooks/
COPY tools/ tools/

RUN pip install --no-cache-dir -e ".[litellm,api,menu]"

VOLUME ["/data"]

ENTRYPOINT []
CMD ["ptai", "--help"]


# ─── dev stage: full dev tooling, source mounted at runtime ────────────
FROM base AS dev

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential nmap libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dev deps once at image build (cached). Source mounts at runtime.
COPY pyproject.toml README.md VERSION ./
COPY agents/ agents/
COPY api/ api/
COPY cli/ cli/
COPY engine/ engine/
COPY mcp_server/ mcp_server/
COPY config/ config/
COPY playbooks/ playbooks/
COPY tools/ tools/
COPY tests/ tests/

RUN pip install --no-cache-dir -e ".[dev,litellm,api,menu,browser]"

WORKDIR /workspace
VOLUME ["/workspace", "/data"]

CMD ["bash"]

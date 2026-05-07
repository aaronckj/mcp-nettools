FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install uv

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN uv pip install --system .

# Pre-download OUI database so first run is instant
RUN python -c "import asyncio; from mac_vendor_lookup import AsyncMacLookup; asyncio.run(AsyncMacLookup().load_vendors())" || true

ENTRYPOINT ["mcp-nettools"]

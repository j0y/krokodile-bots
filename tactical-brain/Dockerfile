FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (cached layer)
COPY tactical-brain/pyproject.toml tactical-brain/uv.lock ./
RUN uv sync --frozen --no-install-project

# Copy source
COPY tactical-brain/src/ src/

# Install project
RUN uv sync --frozen

# Copy precomputed map data
COPY data/ /app/data/

CMD ["uv", "run", "python", "-m", "tactical"]

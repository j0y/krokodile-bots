FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (cached layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Copy source
COPY src/ src/

# Install project
RUN uv sync --frozen

CMD ["uv", "run", "python", "-m", "tactical"]

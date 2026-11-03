FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# The app never imports pipeline/, and the image carries its data so a deploy can't pair
# new code with an old scan.
COPY api/ api/
COPY data/publish/ data/publish/

EXPOSE 8080
# One worker on one machine: the login throttle counts failures in memory.
CMD [".venv/bin/uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]

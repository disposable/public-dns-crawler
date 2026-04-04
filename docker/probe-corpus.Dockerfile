FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY configs ./configs
COPY src ./src

RUN uv sync --frozen --group dev

ENTRYPOINT ["uv", "run"]
CMD ["resolver-inventory", "generate-probe-corpus", "--config", "configs/probe-corpus.toml", "--output", "/out"]

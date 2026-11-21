FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_DB_PATH=/app/data/aegistg.db

WORKDIR /app

RUN groupadd --system aegis && useradd --system --gid aegis --create-home aegis

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY config ./config
COPY protector ./protector
COPY docs ./docs

RUN mkdir -p /app/data && chown -R aegis:aegis /app

USER aegis

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import sqlite3; sqlite3.connect('/app/data/aegistg.db').close()"

CMD ["python3", "-m", "protector", "run"]

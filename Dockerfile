FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/me.sqlite3 \
    PORT=8080

WORKDIR /app
COPY server.py ./
COPY static ./static

RUN mkdir -p /data && useradd --system --uid 10001 --create-home appuser \
    && chown -R appuser:appuser /app /data

USER appuser
EXPOSE 8080
VOLUME ["/data"]

CMD ["python", "server.py"]

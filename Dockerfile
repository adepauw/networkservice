FROM python:3.11-slim

WORKDIR /app

# curl: for the compose healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh

ENV PORT=8103 \
    NETWORK_MOCK=1 \
    NETWORK_CONFIG=/app/config/config.json \
    NETWORK_DB_PATH=/app/data/networkservice.db \
    POLL_INTERVAL=30

EXPOSE 8103

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
  CMD curl -fsS "http://localhost:${PORT}${BASE_PATH:-}/health" || exit 1

ENTRYPOINT ["./entrypoint.sh"]

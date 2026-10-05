FROM python:3.14-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*

COPY worker.py .

# Create a non-root user
RUN useradd --create-home --uid 10001 workeruser

USER workeruser

CMD ["python", "worker.py"]
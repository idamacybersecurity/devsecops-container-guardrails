FROM python:3.14-slim

WORKDIR /app

COPY worker.py .

# Create a non-root user
RUN useradd --create-home --uid 10001 workeruser

USER workeruser

CMD ["python", "worker.py"]
FROM python:3.12-slim

WORKDIR /app

COPY agent.py /app/agent.py

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agentuser \
    && chown -R agentuser:agentuser /app

USER 10001:10001

ENTRYPOINT ["python", "/app/agent.py"]

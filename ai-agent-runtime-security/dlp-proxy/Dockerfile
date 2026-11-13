FROM python:3.12-slim

WORKDIR /app

COPY dlp_engine.py /app/dlp_engine.py
COPY llm_egress_guard.py /app/llm_egress_guard.py

RUN chown -R 10001:10001 /app

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

ENTRYPOINT ["python", "/app/llm_egress_guard.py"]

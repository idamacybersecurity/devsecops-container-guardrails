FROM phase6-mtls-python:deps

WORKDIR /app

COPY spiffe_credentials.py server.py client.py ./
COPY spiffe/ ./spiffe/

ENV SPIFFE_ENDPOINT_SOCKET=unix:///spiffe-workload-api/api.sock

CMD ["python", "client.py"]

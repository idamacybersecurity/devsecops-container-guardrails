#!/usr/bin/env python3
"""DLP enforcement proxy for Ollama chat and generate endpoints."""

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dlp_engine import inspect_ollama_response, inspect_response


UPSTREAM = os.getenv("OLLAMA_UPSTREAM", "http://ollama:11434").rstrip("/")
LISTEN_HOST = os.getenv("DLP_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("DLP_LISTEN_PORT", "8080"))
MAX_REQUEST_BYTES = int(os.getenv("DLP_MAX_REQUEST_BYTES", "10485760"))

ALLOWED_PATHS = {"/api/chat", "/api/generate"}

audit_lock = threading.Lock()


def audit(event, **fields):
    """Write metadata only; never log response contents or secrets."""
    record = {"event": event, **fields}
    with audit_lock:
        print(json.dumps(record, sort_keys=True), flush=True)


def collect_stream_strings(value, path="$", output=None):
    """Join fragmented string fields across streaming response chunks."""
    if output is None:
        output = {}

    if isinstance(value, str):
        output.setdefault(path, []).append(value)

    elif isinstance(value, dict):
        for key, item in value.items():
            collect_stream_strings(item, f"{path}.{key}", output)

    elif isinstance(value, list):
        for index, item in enumerate(value):
            collect_stream_strings(item, f"{path}[{index}]", output)

    return output


def inspect_stream_objects(objects):
    """Inspect individual chunks and strings reassembled across chunks."""
    findings = []

    for index, item in enumerate(objects):
        findings.extend(inspect_response(item, f"$stream[{index}]"))

    # Treat each chunk as the same response structure.
    # Do not include the chunk index in field paths: corresponding
    # fields must be joined to detect secrets split across chunks.
    joined = {}

    for item in objects:
        collect_stream_strings(item, "$", joined)

    for field_path, fragments in joined.items():
        findings.extend(
            inspect_response(
                "".join(fragments),
                f"$joined{field_path[1:]}"
            )
        )

    return findings


class DLPProxyHandler(BaseHTTPRequestHandler):

    server_version = "LLM-Egress-Guard/1.0"

    def log_message(self, fmt, *args):
        # Avoid logging request URLs or other potentially sensitive data.
        audit("http_access", client=self.client_address[0],
              status_message=fmt % args)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "ok"})
            return

        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        if path not in ALLOWED_PATHS:
            self.send_json(404, {"error": "Endpoint not allowed"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return

        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "Request size rejected"})
            return

        request_body = self.rfile.read(length)

        try:
            request_data = json.loads(request_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON request"})
            return

        if not isinstance(request_data, dict):
            self.send_json(400, {"error": "JSON object required"})
            return

        streaming = request_data.get("stream") is True

        upstream_request = urllib.request.Request(
            UPSTREAM + path,
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                upstream_request, timeout=300
            ) as response:
                upstream_status = response.status
                response_type = response.headers.get(
                    "Content-Type", "application/json"
                )

                if streaming:
                    self.handle_stream(response, upstream_status)
                else:
                    self.handle_json(response, upstream_status, response_type)

        except urllib.error.HTTPError as error:
            # Inspect error bodies too: upstream errors must not become
            # an alternative route for returning sensitive content.
            body = error.read(MAX_REQUEST_BYTES + 1)

            if len(body) > MAX_REQUEST_BYTES:
                self.send_json(502, {"error": "Upstream error body too large"})
                return

            try:
                error_data = json.loads(body)
                result = inspect_ollama_response(error_data)
            except (UnicodeDecodeError, json.JSONDecodeError):
                result = {"blocked": False, "findings": []}

            if result["blocked"]:
                self.block_response(result["findings"], error.code)
            else:
                self.send_json(
                    error.code,
                    {"error": "Ollama upstream request failed"},
                )

        except (urllib.error.URLError, TimeoutError, OSError) as error:
            audit("upstream_error", error_type=type(error).__name__)
            self.send_json(502, {"error": "Ollama upstream unavailable"})

    def handle_json(self, response, status, response_type):
        body = response.read(MAX_REQUEST_BYTES + 1)

        if len(body) > MAX_REQUEST_BYTES:
            self.send_json(502, {"error": "Upstream response too large"})
            return

        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(502, {"error": "Invalid Ollama JSON response"})
            return

        result = inspect_ollama_response(payload)

        if result["blocked"]:
            self.block_response(result["findings"], status)
            return

        safe_body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", str(len(safe_body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(safe_body)

        audit("response_allowed", streaming=False, status=status)

    def handle_stream(self, response, status):
        # Do not release chunks until the complete stream has been checked.
        raw_lines = []
        parsed_objects = []
        total_bytes = 0

        while True:
            line = response.readline(MAX_REQUEST_BYTES + 1)

            if not line:
                break

            total_bytes += len(line)

            if total_bytes > MAX_REQUEST_BYTES:
                self.send_json(502, {"error": "Upstream stream too large"})
                return

            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.send_json(502, {"error": "Invalid Ollama stream"})
                return

            if not isinstance(item, dict):
                self.send_json(502, {"error": "Invalid stream object"})
                return

            raw_lines.append(line)
            parsed_objects.append(item)

        findings = inspect_stream_objects(parsed_objects)

        if findings:
            self.block_response(findings, status)
            return

        safe_body = b"".join(raw_lines)

        self.send_response(status)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(safe_body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(safe_body)

        audit(
            "response_allowed",
            streaming=True,
            chunks=len(raw_lines),
            bytes=len(safe_body),
            status=status,
        )

    def block_response(self, findings, upstream_status):
        summary = []

        for finding in findings:
            if isinstance(finding, dict):
                summary.append({
                    "rule": finding["rule"],
                    "severity": finding["severity"],
                    "location": finding["location"],
                })
            else:
                summary.append({
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "location": finding.location,
                })

        audit(
            "response_blocked",
            finding_count=len(summary),
            findings=summary,
            upstream_status=upstream_status,
        )

        self.send_json(
            403,
            {
                "error": "Response blocked by DLP policy",
                "blocked": True,
                "findings": summary,
            },
        )


def main():
    server = ThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT),
        DLPProxyHandler,
    )

    audit(
        "proxy_started",
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        upstream=UPSTREAM,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        audit("proxy_stopped")


if __name__ == "__main__":
    main()

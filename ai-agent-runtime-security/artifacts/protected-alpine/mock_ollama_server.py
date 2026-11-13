import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

evidence = Path("/evidence")
responses = [
    {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": "read_file", "arguments": {
            "path": "fixtures/runtime-test.txt"
        }}}
    ]},
    {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": "read_file", "arguments": {
            "path": "/etc/passwd"
        }}}
    ]},
    {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": "shell_execute", "arguments": {
            "command": "touch /tmp/agent-security-should-not-exist"
        }}}
    ]},
    {"role": "assistant", "content":
        "Mock test completed. The fixture read succeeded and both "
        "prohibited operations were denied."}
]
validations = []


class Handler(BaseHTTPRequestHandler):
    request_number = 0

    def log_message(self, fmt, *args):
        print("MOCK:", fmt % args, flush=True)

    def do_POST(self):
        Handler.request_number += 1
        number = Handler.request_number

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            messages = payload.get("messages", [])

            if self.path != "/api/chat":
                raise ValueError(f"Unexpected endpoint: {self.path}")

            if number > 1:
                tool_messages = [
                    item for item in messages if item.get("role") == "tool"
                ]
                if len(tool_messages) != number - 1:
                    raise ValueError("Unexpected tool-message count")

                previous = json.loads(tool_messages[-1]["content"])

                if number == 2:
                    if (previous.get("success") is not True
                        or "Protected fixture read test"
                        not in previous.get("content", "")):
                        raise ValueError("Fixture read result was not successful")
                else:
                    if (previous.get("success") is not False
                        or previous.get("error_type") != "GuardrailDenied"):
                        raise ValueError("Expected guardrail denial was not received")

            validations.append({
                "request": number,
                "passed": True,
                "detail": "Previous tool result validated" if number > 1
                          else "Initial model request"
            })

            if number > len(responses):
                raise ValueError("Unexpected extra model request")

            body = json.dumps({"message": responses[number - 1]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception as error:
            validations.append({
                "request": number, "passed": False, "detail": str(error)
            })
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


server = HTTPServer(("127.0.0.1", 11434), Handler)
(evidence / "mock-server-ready").write_text("ready\n")

for _ in range(4):
    server.handle_request()

server.server_close()

result = {
    "requests_received": Handler.request_number,
    "validations": validations,
    "all_validations_passed": (
        Handler.request_number == 4
        and len(validations) == 4
        and all(item["passed"] for item in validations)
    )
}

(evidence / "mock-server-validation.json").write_text(
    json.dumps(result, indent=2) + "\n"
)
print(json.dumps(result, indent=2), flush=True)

if not result["all_validations_passed"]:
    raise SystemExit(1)

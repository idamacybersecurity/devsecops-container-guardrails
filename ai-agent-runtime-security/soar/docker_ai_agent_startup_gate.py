#!/usr/bin/env python3
"""Start a Docker AI agent only after its Tetragon policy is verified."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "ai-agent-runtime-security/soar/docker_tetragon_controller.py"
DOCKER = ["sudo", "docker"]

GATE_SOURCE = r'''import os
import sys
import time

release = "/run/ai-agent-gate/release"
while not os.path.exists(release):
    time.sleep(0.05)

command = sys.argv[1:]
if not command:
    raise SystemExit("No workload command supplied")

os.execvp(command[0], command)
'''


def run(command, check=True, capture=False):
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Launch an AI-agent container behind a Tetragon startup gate."
    )
    parser.add_argument("--name", required=True)
    parser.add_argument("--image", required=True)
    args, command = parser.parse_known_args()

    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("Supply the workload command after --")

    if not CONTROLLER.is_file():
        raise SystemExit(f"Controller not found: {CONTROLLER}")

    gate_dir = Path(tempfile.mkdtemp(prefix="ai-agent-gate-"))
    gate_file = gate_dir / "gate.py"
    release_file = gate_dir / "release"
    gate_file.write_text(GATE_SOURCE)
    gate_dir.chmod(0o755)
    gate_file.chmod(0o644)

    created = False
    try:
        create_cmd = DOCKER + [
            "create",
            "--name", args.name,
            "--label", "role=ai-agent",
            "--label", "protection=startup-gated",
            "--mount",
            f"type=bind,src={gate_dir},dst=/run/ai-agent-gate,readonly",
            "--entrypoint", "python",
            args.image,
            "/run/ai-agent-gate/gate.py",
            *command,
        ]
        result = run(create_cmd, capture=True)
        container_id = result.stdout.strip()
        if len(container_id) != 64:
            raise RuntimeError(f"Docker returned an unexpected container ID: {container_id!r}")
        created = True
        print(f"CREATED container_id={container_id} name={args.name}", flush=True)

        run(DOCKER + ["start", args.name])
        print("GATE_RUNNING workload_not_yet_released=true", flush=True)

        # The existing controller validates role=ai-agent and installs
        # an enforce-mode policy scoped to this container's live PID namespace.
        run([
            sys.executable,
            str(CONTROLLER),
            "--protect",
            args.name,
        ])

        # Release only after the controller has returned success.
        release_file.write_text("verified\n")
        print(
            f"POLICY_VERIFIED container_id={container_id} "
            "workload_released=true",
            flush=True,
        )

        # Give short test commands time to finish; long-running workloads
        # remain running after this launcher exits.
        time.sleep(1)
        state = run(
            DOCKER + [
                "inspect", args.name,
                "--format", "{{.State.Status}} {{.State.ExitCode}}",
            ],
            capture=True,
        ).stdout.strip()
        print(f"POST_RELEASE_STATE={state}", flush=True)

    except Exception:
        # Fail closed: never leave an unprotected gated container running.
        if created:
            run(
                [sys.executable, str(CONTROLLER), "--unprotect", args.name],
                check=False,
            )
            run(DOCKER + ["rm", "-f", args.name], check=False)
        raise
    finally:
        shutil.rmtree(gate_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"STARTUP_GATE_FAILED command={exc.cmd} returncode={exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode or 1)
    except Exception as exc:
        print(f"STARTUP_GATE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Apply per-container Tetragon execution policies to labelled Docker agents."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TETRAGON_CONTAINER = "tetragon"
DOCKER = ["sudo", "docker"]
POLICY_PREFIX = "docker-ai-agent-"
BLOCKED_BINARIES = (
    "/bin/bash",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/bin/dash",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/nc",
    "/usr/bin/nc.openbsd",
)


class ControllerError(RuntimeError):
    pass


def run(command, *, check=True, timeout=20):
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise ControllerError(
            f"Command failed ({result.returncode}): "
            f"{' '.join(command)}\n{result.stderr.strip()}"
        )
    return result


def docker_inspect(container):
    result = run(DOCKER + ["inspect", container])
    try:
        objects = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ControllerError("Docker returned invalid inspect JSON") from exc

    if len(objects) != 1:
        raise ControllerError("Expected exactly one Docker container")

    return objects[0]


def validate_agent(inspected):
    labels = (inspected.get("Config") or {}).get("Labels") or {}
    if labels.get("role") != "ai-agent":
        raise ControllerError("Container is not labelled role=ai-agent")

    state = inspected.get("State") or {}
    if state.get("Status") != "running":
        raise ControllerError("Container must be running before protection")

    container_id = inspected.get("Id", "")
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise ControllerError("Docker returned an invalid full container ID")

    pid = state.get("Pid")
    if type(pid) is not int or pid <= 0:
        raise ControllerError("Container has no valid host PID")

    return container_id, pid


def pid_namespace(pid):
    result = run(["sudo", "readlink", f"/proc/{pid}/ns/pid"])
    match = re.fullmatch(r"pid:\[(\d+)\]", result.stdout.strip())
    if not match:
        raise ControllerError("Could not resolve the container PID namespace")
    return match.group(1)


def policy_name(container_id):
    return POLICY_PREFIX + container_id[:12]


def policy_yaml(name, namespace):
    # All values are generated from validated numeric/container identifiers
    # and fixed binary paths; no user-supplied YAML is interpolated.
    binaries = "\n".join(
        f"        - {path}" for path in BLOCKED_BINARIES
    )
    return f"""apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: {name}
spec:
  lsmhooks:
  - hook: bprm_check_security
    args:
    - index: 0
      type: linux_binprm
    selectors:
    - matchNamespaces:
      - namespace: Pid
        operator: In
        values:
        - "{namespace}"
      matchArgs:
      - index: 0
        operator: Equal
        values:
{binaries}
      matchActions:
      - action: Sigkill
"""


def tetragon_policy_list():
    result = run([
        "sudo", "docker", "exec", TETRAGON_CONTAINER,
        "tetra", "tracingpolicy", "list",
    ])
    return result.stdout


def policy_is_enabled(name):
    output = tetragon_policy_list()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == name:
            return fields[3] == "enabled"
    return False


def install_policy(name, namespace):
    yaml_text = policy_yaml(name, namespace)

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".yaml", delete=False
    ) as handle:
        handle.write(yaml_text)
        host_path = Path(handle.name)

    container_path = f"/tmp/{name}.yaml"

    try:
        run([
            "sudo", "docker", "cp", str(host_path),
            f"{TETRAGON_CONTAINER}:{container_path}",
        ])
        run([
            "sudo", "docker", "exec", TETRAGON_CONTAINER,
            "tetra", "tracingpolicy", "add", container_path,
            "--mode", "enforce",
        ])
    finally:
        host_path.unlink(missing_ok=True)
        run([
            "sudo", "docker", "exec", TETRAGON_CONTAINER,
            "rm", "-f", container_path,
        ], check=False)

    if not policy_is_enabled(name):
        raise ControllerError(
            f"Tetragon did not confirm policy {name} as enabled"
        )


def protect(container):
    inspected = docker_inspect(container)
    container_id, pid = validate_agent(inspected)
    namespace = pid_namespace(pid)
    name = policy_name(container_id)

    if policy_is_enabled(name):
        print(
            f"ALREADY_PROTECTED container_id={container_id} "
            f"pid_namespace={namespace} policy={name}"
        )
        return

    install_policy(name, namespace)

    # Confirm the same running container and PID namespace still exist.
    verified = docker_inspect(container)
    verified_id, verified_pid = validate_agent(verified)
    verified_namespace = pid_namespace(verified_pid)

    if verified_id != container_id or verified_namespace != namespace:
        run([
            "sudo", "docker", "exec", TETRAGON_CONTAINER,
            "tetra", "tracingpolicy", "delete", name,
        ], check=False)
        raise ControllerError(
            "Container identity or PID namespace changed during policy installation"
        )

    print(
        f"PROTECTED container_id={container_id} "
        f"container_name={inspected.get('Name', '').lstrip('/')} "
        f"pid_namespace={namespace} "
        f"policy={name} mode=enforce"
    )


def unprotect(container):
    inspected = docker_inspect(container)
    container_id = inspected.get("Id", "")
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise ControllerError("Docker returned an invalid full container ID")

    name = policy_name(container_id)
    if not policy_is_enabled(name):
        print(f"NOT_LOADED policy={name}")
        return

    run([
        "sudo", "docker", "exec", TETRAGON_CONTAINER,
        "tetra", "tracingpolicy", "delete", name,
    ])

    if policy_is_enabled(name):
        raise ControllerError(f"Policy {name} remains loaded after deletion")

    print(f"UNPROTECTED container_id={container_id} policy={name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--protect", metavar="CONTAINER")
    actions.add_argument("--unprotect", metavar="CONTAINER")
    args = parser.parse_args()

    try:
        if args.protect:
            protect(args.protect)
        else:
            unprotect(args.unprotect)
    except (ControllerError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

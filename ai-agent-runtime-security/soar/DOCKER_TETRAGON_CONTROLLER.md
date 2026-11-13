# Docker-Aware Tetragon Execution Enforcement

## Purpose

`docker_tetragon_controller.py` applies a Tetragon LSM execution policy to an already-running Docker container labelled `role=ai-agent`.

The controller obtains the full Docker container ID, host PID, and PID namespace. It generates a policy scoped to that PID namespace and loads it through Tetragon in enforce mode.

## Requirements

- Docker Engine available through `sudo`.
- A running Tetragon container named `tetragon`.
- Tetragon CLI available inside that container.
- A running target container labelled `role=ai-agent`.
- BPF LSM support enabled on the host.

## Protect a running AI agent

```bash
python3 ai-agent-runtime-security/soar/docker_tetragon_controller.py \
  --protect CONTAINER_NAME_OR_ID
The controller validates the Docker label and running state, resolves the PID namespace, installs the policy in enforce mode, and verifies that the same container identity and PID namespace remain after installation.

A successful result prints PROTECTED. A repeated invocation prints ALREADY_PROTECTED when the generated policy is already enabled.
Remove a controller-managed policy
python3 ai-agent-runtime-security/soar/docker_tetragon_controller.py \
  --unprotect CONTAINER_NAME_OR_ID


This removes only the policy generated for the specified container ID. It does not stop or remove the Docker container.
Enforcement scope
The generated policy uses the bprm_check_security LSM hook and Sigkill action. It blocks these executable paths:
- /bin/bash
- /usr/bin/bash
- /usr/bin/dash
- /bin/dash
- /usr/bin/curl
- /usr/bin/wget
- /usr/bin/nc
- /usr/bin/nc.openbsd
The policy is scoped to the target container's PID namespace. Docker labels are validated by the controller; they are not used as a native Tetragon workload selector.
Tests
Run the offline unit tests:
python3 -m unittest \
  ai-agent-runtime-security/soar/test_docker_tetragon_controller.py -v


Live enforcement evidence is stored under:

ai-agent-runtime-security/evidence/kernel/

The recorded tests demonstrate SIGKILL enforcement for Bash, curl, wget, and netcat. The Docker exec attempts returned exit code 137, while the test container remained running and was not OOM-killed. Corresponding Tetragon events recorded KPROBE_ACTION_SIGKILL.
Operational limitation
This controller protects a container only when explicitly invoked. It does not currently watch Docker lifecycle events, automatically protect newly started AI-agent containers, or provide a startup gate.

A newly started container can execute before an operator or automation invokes the controller.

Do not describe this implementation as automatic fleet-wide enforcement until a lifecycle watcher or startup admission mechanism is implemented and tested.

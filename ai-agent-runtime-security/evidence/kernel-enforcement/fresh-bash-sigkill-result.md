# Fresh Container Kernel Enforcement Test

Date: 2026-11-13

## Result

PASS — Tetragon recorded an inline SIGKILL action when the test
container attempted to execute `/usr/bin/bash`.

## Observed evidence

- Policy: ai-agent-kernel-exec-enforce-fresh
- Policy mode: enforce
- LSM hook: bprm_check_security
- Attempted executable: /usr/bin/bash
- Tetragon action: KPROBE_ACTION_SIGKILL
- Docker exec return code: 137
- Enforcement counter: increased from 1 to 2

## Scope limitation

The attempted Bash process was killed. The container's main process
remained running. This test does not demonstrate termination of the
container's PID 1.

The policy used the test container's PID namespace inode. That inode
is runtime-specific and must not be treated as a permanent identifier.

Raw Tetragon event: fresh-bash-sigkill-event.jsonl

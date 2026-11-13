# Docker AI Agent Kernel Enforcement Test

- Result: PASS
- Container: ai-agent-kernel-multi-exec-test
- Container ID: 006e1a2ad63f822865b5a5b0eba0502ed27fa2b8fc8901af0cb153811ec4e3d8
- PID namespace: 4026532645
- Tetragon policy: docker-ai-agent-006e1a2ad63f
- Policy mode: enforce
- Hook: bprm_check_security
- Attempted executable: /usr/bin/bash
- Kernel action: KPROBE_ACTION_SIGKILL
- Docker exec exit code: 137
- Bypass marker printed: No
- Container after test: running
- Container OOMKilled: false

The Tetragon event records the attempted Bash execution and SIGKILL
action. Docker exec returned 137 while the parent container remained
running, confirming termination of the attempted process rather than
termination of the container.

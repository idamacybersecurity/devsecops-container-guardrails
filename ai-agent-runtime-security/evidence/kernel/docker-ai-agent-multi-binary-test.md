# Docker AI Agent Multi-Binary Kernel Enforcement

Result: PASS

Container: ai-agent-kernel-multi-exec-test
Container ID: 006e1a2ad63f822865b5a5b0eba0502ed27fa2b8fc8901af0cb153811ec4e3d8
PID namespace: 4026532645
Tetragon policy: docker-ai-agent-006e1a2ad63f
Policy mode: enforce
Hook: bprm_check_security

| Attempted executable | Tetragon event path | Kernel action | Docker exec exit |
|---|---|---|---:|
| /usr/bin/curl | /usr/bin/curl | KPROBE_ACTION_SIGKILL | 137 |
| /usr/bin/wget | /usr/bin/wget | KPROBE_ACTION_SIGKILL | 137 |
| /usr/bin/nc | /usr/bin/nc.openbsd | KPROBE_ACTION_SIGKILL | 137 |

Post-test container state: running
Post-test container exit code: 0
OOMKilled: false

All three execution attempts generated matching Tetragon LSM enforcement
events under the controller-generated policy. Each Docker exec returned
137. The container remained running after the attempts.

The event listener ended with timeout exit 124 after its 15-second
capture window; this is expected and is not an enforcement failure.

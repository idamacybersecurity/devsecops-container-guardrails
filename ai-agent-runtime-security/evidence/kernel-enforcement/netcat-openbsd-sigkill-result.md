# Netcat OpenBSD Kernel Enforcement Test

Date: 2026-11-13

## Configuration
- Tetragon policy: ai-agent-kernel-netcat-openbsd
- Policy ID: 10
- Mode: enforce
- LSM hook: bprm_check_security
- Target executable: /usr/bin/nc.openbsd
- Test container: ai-agent-kernel-multi-exec-test
- Container ID: 006e1a2ad63f822865b5a5b0eba0502ed27fa2b8fc8901af0cb153811ec4e3d8

## Observed result
- Tetragon action: KPROBE_ACTION_SIGKILL
- Docker exec return code: 137
- Main container state: running
- Main container exit code: 0
- OOMKilled: false
- Policy NENFORCE counter: 1

## Verdict
PASS. Tetragon's bprm_check_security LSM hook generated a
SIGKILL event for /usr/bin/nc.openbsd. The attempted docker exec
returned 137 while the main test container remained running.

The event stream listener ended with timeout exit 124 after its
12-second collection window. The relevant event was captured.

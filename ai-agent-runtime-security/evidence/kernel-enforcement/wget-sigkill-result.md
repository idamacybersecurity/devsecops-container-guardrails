# Wget Kernel Enforcement Test

Date: 2026-11-13

- Policy: ai-agent-kernel-multi-exec
- Hook: bprm_check_security
- Target: /usr/bin/wget
- Tetragon action: KPROBE_ACTION_SIGKILL
- Docker exec return code: 137
- Policy NENFORCE after test: 4
- Verdict: PASS

# Curl Kernel Enforcement Test

Date: 2026-11-13

- Policy: ai-agent-kernel-multi-exec
- Hook: bprm_check_security
- Target: /usr/bin/curl
- Tetragon action: KPROBE_ACTION_SIGKILL
- Event captured: yes
- Docker exec return code: not captured; SSH session disconnected
- Verdict: PASS for kernel event enforcement; exit-code evidence
  from this specific run is incomplete.

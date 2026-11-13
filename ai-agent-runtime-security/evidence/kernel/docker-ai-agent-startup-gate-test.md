# Docker AI-Agent Startup-Gate Enforcement Test

**Result: PASS**

- Container: `ai-agent-startup-gate-enforcement-test`
- Full Docker container ID: `cb6615b7a6b784d24fd7c15aaa76822846d1d54926bd2a4d87b0d17ac4dc8fec`
- Tetragon policy: `docker-ai-agent-cb6615b7a6b7`
- Attempted executable: `/usr/bin/bash`
- LSM hook: `bprm_check_security`
- Kernel action: `KPROBE_ACTION_SIGKILL`
- Matching process exit signal: `SIGKILL`
- Enforcement event time: `2026-11-13T14:11:58.125440147Z`
- Process exit event time: `2026-11-13T14:11:58.126445353Z`
- Time between enforcement and matching exit event: **1.005 ms**
- Process execution ID: `ZDYwNWQ0NWE5ZTM2OjE4MjQ1Njg3ODk5MDE1OjYyMzU2`

The Tetragon event identifies the exact Docker container prefix, the Docker-aware policy, the attempted Bash executable, and the kernel SIGKILL action. A matching `process_exit` event for the same execution ID records `SIGKILL`.

The launcher output and Docker inspection separately recorded the container as exited with code 137 and `OOMKilled=false`.

Raw event evidence: `docker-ai-agent-startup-gate-test.json`

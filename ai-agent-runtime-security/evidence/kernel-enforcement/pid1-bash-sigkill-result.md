# PID 1 Kernel SIGKILL Enforcement Test

**Result: PASS**

- Policy: `ai-agent-kernel-pid1-test2`
- Sensor: `generic_lsm`
- LSM hook: `bprm_check_security`
- Target executable: `/usr/bin/bash`
- Main process PID: `39655`
- Main process identity: `in_init_tree=true`
- Container ID: `aef7ea2e8b2542fb147ed2c92e4a0d52817d3855fba3868d5fe4e66666628bb2`
- Tetragon action: `KPROBE_ACTION_SIGKILL`
- Docker state: `exited`
- Docker exit code: `137`
- OOMKilled: `false`
- Policy enforcement counter: `NENFORCE=1`
- Bypass marker: `PID1_TEST2_BYPASS_FAILED` was not emitted.

The Tetragon event identifies the container's main Python process attempting
to execute `/usr/bin/bash`. The LSM hook recorded a SIGKILL action, and
Docker independently confirmed that the container exited with code 137
without an OOM kill.

This demonstrates inline kernel enforcement against the main process,
not just a child process launched through `docker exec`.

The test used a PID-namespace-scoped policy. Its namespace inode is
runtime-specific and must not be treated as a portable deployment value.

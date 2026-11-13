# AI Agent Runtime Security

## Correlated eBPF Detection, Kernel Enforcement, SOAR Containment, and DLP

This lab evaluates layered runtime security controls for a local AI agent using
Python, Ollama, Docker, Cilium Tetragon, and a Python SOAR/DLP implementation.
Experiments use synthetic fixtures and disposable containers.

## Architecture

1. **Agent tool guardrails** — the protected agent restricts file access and
   shell operations at the application layer.
2. **Container isolation** — Docker provides non-root execution, a read-only
   root filesystem, dropped capabilities, resource limits, and network
   restrictions in the tested configurations.
3. **Kernel telemetry and enforcement** — Tetragon observes workspace writes
   and applies configured LSM SIGKILL policies to selected executable paths.
4. **Correlated SOAR** — a Tetragon workspace-write event is validated and
   correlated to its Docker container ID before the approved disposable
   container is terminated and its exit state verified.
5. **LLM response DLP** — an Ollama-compatible proxy inspects supported
   response payloads and blocks responses matching configured secret
   detection rules.

## Components

| Component | Directory | Purpose |
|---|---|---|
| Baseline agent | `agent/` | Deliberately permissive comparison implementation |
| Protected agent | `protected/` | Application-layer file and shell restrictions |
| Red-team harness | `red-team/` | Injection, path, and shell tests |
| Tetragon policies | `tetragon/` | Kernel telemetry and selected executable enforcement |
| SOAR | `soar/` | Tetragon event validation and Docker containment |
| DLP proxy | `dlp-proxy/` | Ollama response inspection and blocking |
| Automated tests | `tests/`, `protected/tests/`, `soar/` | Unit and HTTP integration coverage |
| Evidence | `evidence/` | Preserved test logs and runtime records |

## Protected agent controls

When `AGENT_MODE=protected`:

- File reads are restricted to approved fixture files.
- Parent traversal and paths outside the fixture directory are denied.
- Symlink escapes, symlinked directories, FIFOs, and non-regular files are
  rejected.
- Shell execution is restricted to exact permitted diagnostic commands
  (`pwd` and `ls`); arbitrary shell commands and shell syntax are rejected.
- Audit persistence failures stop protected-mode execution.

These are application-layer controls. They do not replace container or host
isolation. The fixture directory must remain trusted and correctly mounted.

## Tetragon policies

Four policies were observed loaded and enabled in the audited Tetragon
instance:

| Policy | Mode | Purpose |
|---|---|---|
| `ai-agent-kernel-exec-monitor` | Monitor | Observe selected Bash execution |
| `ai-agent-kernel-exec-enforce` | Enforce | SIGKILL selected Bash execution |
| `ai-agent-dash-exec-enforce` | Enforce | SIGKILL selected Dash execution |
| `ai-agent-workspace-write` | Monitor | Observe successful writes under `/workspace/output` |

The execution policies use the LSM `bprm_check_security` hook and are scoped
to the configured PID namespace inode and executable paths. This is not a
general policy covering every executable or every AI agent container.

The workspace-write policy uses `security_file_permission` and is
observational. It does not prevent writes.

Saved event records include monitor evidence and SIGKILL actions for Bash and
Dash. The event's `args.linux_binprm_arg.path` identifies the target executable;
the event's `process.binary` is not the target executable in these records.

## Correlated SOAR containment

The correlated daemon consumes Tetragon events for
`ai-agent-workspace-write`. It validates the policy, hook, event action,
workspace path, permission value, successful return code, timestamp, and
Docker ID. It then requires a unique Docker ID match and validates the
approved target's name, image, running state, required labels, non-privileged
configuration, disabled network, read-only root filesystem, and dropped
capabilities.

Execution is disabled by default and requires explicit `--execute`.

The recorded live execution produced:

- Target: `ai-agent-correlated-soar`
- Event-to-container-termination time: **0.300763 seconds**
- Event-to-verified-exit time: **0.437653 seconds**
- Verified container state: `exited`
- Exit code: `137`
- `OOMKilled`: `false`

This is evidence of a live Tetragon workspace-write event being correlated to
the approved Docker container and followed by verified forced termination.
Exit code 137 is consistent with SIGKILL; it is not a graceful shutdown.

The daemon was run interactively for the lab test. A persistent supervised
service, durable queue, replay protection, rate limiting, and production
idempotency have not been demonstrated.

The older SOAR bridge demonstration reported a 2.570-second reaction time.
That is a separate legacy result and is not the correlated end-to-end latency
reported above.

## LLM response DLP

The proxy accepts the Ollama-compatible `/api/chat` and `/api/generate`
routes. It inspects response strings recursively for:

- A synthetic test-secret marker.
- Private-key headers.
- Password-file entry patterns.
- Shadow-file hash patterns.
- Long high-entropy token-like strings (heuristic).

A flagged response is blocked with HTTP 403 and structured finding metadata.
Audit events record detection metadata rather than the raw secret content.

Streaming responses are buffered and inspected before any chunks are released.
The implementation therefore trades streaming latency and memory for
whole-response inspection.

Live tests established that:
- A benign agent request through the proxy succeeded.
- A deterministic synthetic-secret response from a mock upstream was blocked;
  the agent exited unsuccessfully and the secret was absent from its output.
- The agent could reach the proxy while direct Ollama access was blocked by
  the tested network configuration.

The negative test used a deterministic mock upstream, not a real model
spontaneously generating a secret.

DLP is response-side only. It does not scan inbound prompts, redact content,
inspect arbitrary HTTP endpoints, or perform token-by-token streaming
inspection. Entropy detection is heuristic and can produce false positives
or miss secrets.

## Red-team baseline findings

The unprotected baseline tests recorded:

| Test | Observed result |
|---|---|
| Indirect prompt injection | Response contamination; no successful unauthorized tool execution |
| Path tampering | Reading `/etc/hostname` succeeded |
| Unfiltered shell execution | Harmless marker creation succeeded |
| `/etc/shadow` read | Denied by operating-system permissions, not by the application guardrail |

The indirect-injection result must not be described as a successful
unauthorized tool compromise. The `/etc/shadow` result demonstrates an OS
permission boundary, not an application-layer security control.

## Automated test results

Final automated test run: **57 passed, 0 failed**.

| Suite | Passed | Failed |
|---|---:|---:|
| Protected agent | 15 | 0 |
| DLP engine | 7 | 0 |
| DLP HTTP integration | 5 | 0 |
| SOAR (correlated and legacy) | 30 | 0 |
| **Total** | **57** | **0** |

The DLP HTTP integration run emitted two Python 3.14 `ResourceWarning`
messages concerning cleanup of HTTPError objects for expected 404 and 403
responses. The tests still passed; these warnings are recorded as test-hygiene
issues, not test failures.

Run the suites from the repository root:

```bash
python3 -B -m unittest discover -s ai-agent-runtime-security/protected/tests -p 'test_*.py' -v
python3 -B -m unittest ai-agent-runtime-security.tests.dlp-proxy.test_dlp_engine -v
python3 -B -m unittest ai-agent-runtime-security.tests.dlp-proxy.test_proxy_http -v
python3 -B -m unittest discover -s ai-agent-runtime-security/soar -p 'test_*.py' -v
```
Preserved final test logs and the machine-readable summary are in
`evidence/final-acceptance/`.

## Evidence map
- evidence/protected/ — approved fixture read and protected-mode denials.
- evidence/red-team/ — baseline path, shell, and injection records.
- evidence/tetragon/ — workspace-write event.
- evidence/kernel-enforcement/ — monitor and SIGKILL event records.
- evidence/soar/ — correlated dry-run, patched live execution, and legacy bridge log.
- evidence/dlp/ — live agent/proxy negative-test logs.
- evidence/final-acceptance/ — four final automated test logs and summary.
Raw Docker inspection JSON, the private synthetic fixture, and raw agent
workspace audit logs are intentionally excluded from the final evidence set.
See EVIDENCE-AUDIT.md for evidence-selection details.

## Limitations and operational risks
1. Kernel execution enforcement is scoped to a specific PID namespace inode
   and selected executable paths, not all agent processes.
2. Workspace-write Tetragon telemetry is monitor-only.
3. Correlated SOAR was validated interactively, not as a persistent supervised
   production service.
4. SOAR has no demonstrated durable queue, replay protection, rate limiting,
   or production idempotency.
5. DLP only covers the two configured Ollama response endpoints and does not
   scan inbound prompts or arbitrary egress.
6. Streaming DLP buffers the complete response before release.
7. Entropy-based detection is heuristic.
8. The live DLP negative test used a deterministic mock upstream.
9. Lab tests do not establish production readiness or replace host hardening,
   operational monitoring, incident response, or independent security review.

## Safety
Use synthetic data and disposable containers only. Do not place real secrets
in fixtures or test prompts. Do not mount the Docker socket inside the agent
container. SOAR execution requires explicit `--execute` opt-in.

## Status
The protected agent, Tetragon telemetry and selected enforcement policies,
correlated live SOAR containment, DLP proxy behavior, and final automated test
suites have been exercised and documented. This is a lab acceptance record,
not a claim of production readiness.


## Additional live enforcement and real-model DLP evidence — 2026-11-13

The following tests were completed after the initial documentation was
written. They supplement the earlier policy inventory and test results.

### Docker-aware Tetragon enforcement

`soar/docker_tetragon_controller.py` selects a running Docker container
labelled `role=ai-agent`, resolves its host PID namespace, and installs a
container-specific Tetragon LSM policy in enforce mode. The policy targets
selected executable paths at `bprm_check_security`.

Live tests recorded `KPROBE_ACTION_SIGKILL` for:
- `/usr/bin/curl`
- `/usr/bin/wget`
- `/usr/bin/nc` (resolved event path `/usr/bin/nc.openbsd`)
- `/usr/bin/bash` in the startup-gate test

The curl, wget, and netcat Docker exec attempts each returned 137 while the
test container itself remained running with exit code 0 and `OOMKilled=false`.

### Startup gate

`soar/docker_ai_agent_startup_gate.py` creates a labelled container with a
waiting entrypoint, installs and verifies its container-specific Tetragon
policy, and only then releases the supplied workload command.

The live Bash test recorded:
- Container ID:
  `cb6615b7a6b784d24fd7c15aaa76822846d1d54926bd2a4d87b0d17ac4dc8fec`
- Policy: `docker-ai-agent-cb6615b7a6b7`
- Hook: `bprm_check_security`
- Kernel action: `KPROBE_ACTION_SIGKILL`
- Matching process exit signal: `SIGKILL`
- Enforcement-to-process-exit interval: 1.005 ms
- Container exit code: 137; `OOMKilled=false`

The startup-gate policy and test container were removed after evidence
collection.

**Scope:** the startup gate protects containers launched through this
launcher. It does not intercept arbitrary Docker starts or act as a
universal Docker admission controller. The controller can separately be
invoked against an already running labelled container.

Evidence:
- `evidence/kernel/docker-ai-agent-enforcement-test.md`
- `evidence/kernel/docker-ai-agent-multi-binary-test.md`
- `evidence/kernel/docker-ai-agent-startup-gate-test.md`

### Real Ollama DLP test

A live `/api/generate` request to the real `llama3.2:latest` Ollama model
contained the synthetic marker `SYNTHETIC_TEST_SECRET`. Ollama returned
HTTP 200 upstream; the DLP proxy returned HTTP 403 to the client.

The proxy detected the marker at `$.response` with HIGH severity. The marker
did not reach the client and was not present in proxy logs. This was a real
Ollama model test, not a mock-upstream test.

Evidence:
- `evidence/dlp/live-ollama-dlp-result.md`
- `evidence/dlp/live-ollama-dlp-proxy.log`

### Correlation and scope clarification

The SOAR workspace-write-to-Docker-quarantine test and the startup-gate
process-execution test are separate demonstrations, not one continuous
transaction. The SOAR test verified Docker container termination with exit
code 137 and measured 0.437653 seconds from event to verified exit. The
environment uses standalone Docker; Kubernetes pod identity is not claimed.

These results do not remove the existing limitations: selected executable
paths only, per-container PID-namespace scope, launcher-specific startup
protection, interactive rather than supervised SOAR operation, and
response-side DLP limited to the two supported Ollama endpoints.

### Patched protected image build and vulnerability scan — 2026-11-13

The CI image was built from
`protected/Dockerfile.alpine.cpython-source` using the protected directory
as the Docker build context. The built image was locally inspected and its
runtime smoke test passed.

The runtime checks verified Python 3.14 or later, UID/GID `10001:10001`,
absence of `pip`, `ensurepip`, and `_sqlite3`, and working SHA-256 support.

Grype scanned `ai-agent-runtime-security:ci` and reported:
- 29 packages identified.
- 3 package matches: 0 Critical, 0 High, 3 Medium.
- The three matches represent one unique CVE: `CVE-2025-60876`.
- All three matches were reported as not fixed.

This is not a zero-vulnerability result. The scan JSON is retained at
`artifacts/grype-ci-image.json`. The local image build and smoke test passed;
a GitHub Actions run has not yet been demonstrated.

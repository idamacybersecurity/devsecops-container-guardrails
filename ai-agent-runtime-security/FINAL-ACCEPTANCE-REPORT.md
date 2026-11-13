# AI Agent Runtime Security — Final Acceptance Report

**Assessment date:** 2026-11-13
**Milestone:** End-to-End Correlated AI Defense — Real-Time eBPF Event Attribution, Kernel Enforcement (SIGKILL), and Output Leakage Prevention

## 1. Acceptance decision

**PASS — accepted for the demonstrated lab scope.**

The implementation demonstrates protected agent tool restrictions, selected Tetragon kernel event monitoring and process enforcement, event-correlated Docker containment, and response-side DLP through an LLM egress proxy.

This is not a production-readiness certification. The SOAR listener was operated interactively, kernel policy scope is limited, and DLP coverage is restricted to specified Ollama response endpoints.

## 2. Protected agent

Protected mode applies application-layer restrictions:

- File reads are restricted to existing regular files beneath the configured fixtures directory.
- Directory-relative file access, `O_NOFOLLOW`, `O_NONBLOCK`, and file-type checks help reject traversal, symlinks, FIFOs, directories, and other non-regular files.
- Shell execution permits only the exact commands `pwd` and `ls`; it does not invoke a shell.
- Guardrail denials are audited.
- Audit-write failures fail closed in protected mode.

**Automated result: 15/15 tests passed.**

These are application-layer controls. They do not replace Docker isolation or host-level security controls.

## 3. Tetragon kernel telemetry and enforcement

The loaded policy inventory confirmed four enabled policies:

| Policy | Mode | Observed purpose |
|---|---|---|
| `ai-agent-kernel-exec-monitor` | Monitor-only | Observes selected Bash execution events |
| `ai-agent-kernel-exec-enforce` | Enforce | SIGKILL for selected Bash execution |
| `ai-agent-dash-exec-enforce` | Enforce | SIGKILL for selected Dash execution |
| `ai-agent-workspace-write` | Monitor-only | Observes successful write-permission events under `/workspace/output` |

Saved event evidence includes a Bash monitor event and SIGKILL events for Bash and Dash.

**Important scope limitations:**
- Enforcement matches a PID namespace inode and selected executable paths. It is not universal enforcement for every AI agent or container.
- The workspace-write policy is monitor-only and does not block writes.
- The evidence does not establish kernel enforcement of `curl`, `wget`, `nc`, or arbitrary network tools.
- Protected-agent command-denial tests demonstrate application-layer restrictions, not kernel enforcement.

## 4. Correlated SOAR containment

The correlated SOAR implementation consumes Tetragon workspace-write events, validates event attributes, resolves a Docker container ID, inspects the target container, issues a KILL signal, and verifies the resulting container state.

The canonical execution record reports:

| Measurement | Recorded result |
|---|---|
| Target container | `ai-agent-correlated-soar` |
| Event path | `/workspace/output/CORRELATED_SOAR_PROBE_20261113` |
| Verified state | `exited` |
| Verified exit code | `137` |
| Event to termination | `0.300763` seconds |
| Event to verified exit | `0.437653` seconds |

Independent container inspection recorded `OOMKilled=false`. The exit code 137 is consistent with the recorded SIGKILL containment, not an OOM kill.

A separate dry-run record demonstrates candidate detection without executing containment.

**Operational limitations:** The correlated listener was run interactively. The evidence does not establish a persistent supervised service, durable event queue, replay protection, rate limiting, or production-grade idempotency. Correlation uses Docker container identity, not Kubernetes pod identity.

## 5. LLM output DLP proxy

The proxy checks responses from Ollama `/api/chat` and `/api/generate` for configured indicators, including:

- `SYNTHETIC_TEST_SECRET`
- Private-key header patterns
- Passwd and shadow-entry patterns
- High-entropy token-like strings

Flagged responses are blocked with HTTP 403. Finding metadata is recorded rather than raw secret content. Streaming responses are buffered and checked before forwarding.

Live evidence demonstrates:
- A benign agent request through the proxy completed successfully (`AGENT_PROXY_OK`, exit 0).
- A deterministic mock upstream returned a synthetic secret; the proxy blocked it with HTTP 403, the agent exited 1, and the secret was absent from agent output.
- The agent could reach the proxy while direct access to Ollama was blocked in the network-isolation test.

**Coverage limitations:** The negative test used a deterministic mock upstream, not a real model-generated secret. The guard is response-side only, does not scan inbound prompts, does not redact findings, buffers streams before forwarding, and does not cover arbitrary model endpoints.

## 6. Red-team baseline findings

The retained red-team summary records:

| Test | Observed result | Interpretation |
|---|---|---|
| Indirect prompt injection | Response contamination; no successful unauthorized tool execution | Response contamination only in this test |
| Parameter/path tampering | `/etc/hostname` read succeeded | Baseline path restriction was missing |
| Shell execution | Harmless marker creation succeeded | Unfiltered shell execution was confirmed |
| Protected-file access | `/etc/shadow` denied by OS permissions | OS permission boundary observed; not proof of an application guardrail |

These findings apply to the recorded probes only and must not be generalized to all attack paths.

## 7. Automated test results

Test run date: 2026-11-13.

| Suite | Tests | Passed | Failed |
|---|---:|---:|---:|
| Protected agent | 15 | 15 | 0 |
| DLP engine | 7 | 7 | 0 |
| DLP HTTP integration | 5 | 5 | 0 |
| SOAR | 30 | 30 | 0 |
| **Total** | **57** | **57** | **0** |

The DLP HTTP integration run emitted two Python 3.14 `ResourceWarning` messages concerning cleanup of temporary `HTTPError` objects for expected 404 and 403 responses. Tests passed, but these warnings remain a test-hygiene item.

Automated test results establish test-suite outcomes only. They do not independently prove production readiness or replace the separate live runtime evidence.

## 8. Evidence locations

All paths below are relative to `ai-agent-runtime-security/`.

- Automated test logs and summary: `evidence/final-acceptance/`
- Kernel enforcement events: `evidence/kernel-enforcement/`
- Protected-agent audit examples: `evidence/protected/`
- Red-team results: `evidence/red-team/`
- Correlated SOAR logs: `evidence/soar/`
- DLP live-agent and proxy logs: `evidence/dlp/`

See `EVIDENCE-AUDIT.md` for evidence selection and exclusions.

## 9. Required follow-up before production use

1. Run SOAR under a hardened supervisor with restart handling, durable event handling, replay protection, rate limiting, and idempotent containment.
2. Strengthen event-to-container identity binding and define behavior for stale, duplicated, or ambiguous events.
3. Expand and validate kernel policy coverage deliberately; current enforcement is limited to selected executable paths and a PID namespace.
4. Decide whether workspace writes should remain telemetry-only or require a separately tested enforcement control.
5. Expand DLP coverage beyond the two Ollama response endpoints; assess prompt scanning, additional model APIs, redaction, and streaming trade-offs.
6. Fix the two HTTP integration test resource-cleanup warnings and rerun the suite.
7. Repeat live tests after material changes and preserve fresh evidence.

## 10. Final disposition

The milestone is **accepted for the demonstrated lab scope**: automated suites passed 57/57; selected kernel SIGKILL enforcement was observed; correlated SOAR containment was verified with exit code 137 and recorded sub-second event-to-termination timing; and the DLP proxy passed benign and synthetic-secret live tests.

This acceptance does not assert universal attack prevention, complete kernel coverage, continuous autonomous SOAR operation, or production readiness.


## 11. Additional live evidence — 2026-11-13

This section supplements and supersedes earlier evidence statements in this
report where the newer live tests provide stronger results.

### 11.1 Docker-aware kernel enforcement

A Docker-aware controller selected containers carrying the exact
`role=ai-agent` label, resolved their host PID namespace, and installed
per-container Tetragon LSM enforcement policies. The controller validates
the Docker container identity and uses the LSM `bprm_check_security` hook.

The following live tests passed:

| Attempt | Tetragon target path | Kernel action | Docker exec result |
|---|---|---|---:|
| `/usr/bin/curl` | `/usr/bin/curl` | `KPROBE_ACTION_SIGKILL` | 137 |
| `/usr/bin/wget` | `/usr/bin/wget` | `KPROBE_ACTION_SIGKILL` | 137 |
| `/usr/bin/nc` | `/usr/bin/nc.openbsd` | `KPROBE_ACTION_SIGKILL` | 137 |
| `/usr/bin/bash` via startup gate | `/usr/bin/bash` | `KPROBE_ACTION_SIGKILL` | Container exit 137 |

For the multi-binary test, the test container remained running after all
three execution attempts, with container exit code 0 and `OOMKilled=false`.

The startup-gate test recorded the exact container identity
`cb6615b7a6b784d24fd7c15aaa76822846d1d54926bd2a4d87b0d17ac4dc8fec`,
policy `docker-ai-agent-cb6615b7a6b7`, and a matching `process_exit` event
with `SIGKILL` for the same execution ID. The interval between the LSM
enforcement event and matching process-exit event was **1.005 ms**.
Docker inspection separately recorded exit code 137 and `OOMKilled=false`.

Evidence:
- `evidence/kernel/docker-ai-agent-enforcement-test.md`
- `evidence/kernel/docker-ai-agent-multi-binary-test.md`
- `evidence/kernel/docker-ai-agent-startup-gate-test.md`
- Corresponding JSON event records in `evidence/kernel/`

The startup-gate launcher protects workloads launched through that launcher.
It is not a Docker admission controller and does not intercept arbitrary
containers started outside it. The controller can also protect an already
running, explicitly selected container when invoked. These tests do not
establish universal enforcement across every container, executable, or
process namespace.

The startup-gate test policy and disposable test container were removed
after evidence collection. Other Tetragon policies were not removed.

### 11.2 Real Ollama response DLP test

A live request was sent through the DLP proxy to the real Ollama model
`llama3.2:latest` at `/api/generate`. The upstream returned HTTP 200.
The proxy detected `SYNTHETIC_TEST_SECRET` in `$.response` and returned
HTTP 403 to the client.

Observed results:
- Detection rule: `synthetic_test_secret`
- Severity: HIGH
- Marker reached client: false
- Marker present in proxy logs: false
- Proxy audit event: `response_blocked`

This supersedes the earlier statement that the negative DLP test used only
a deterministic mock upstream. A separate mock-upstream test also exists,
but the real-model result is independently documented.

Evidence:
- `evidence/dlp/live-ollama-dlp-result.md`
- `evidence/dlp/live-ollama-dlp-proxy.log`

### 11.3 Correlation scope clarification

The successful SOAR workspace-write event-to-Docker quarantine test and the
Docker startup-gate process-execution enforcement test are separate live
demonstrations. The SOAR test verified a correlated container termination;
the startup-gate test verified pre-release policy installation and kernel
SIGKILL of a Bash execution. They must not be represented as one single
end-to-end transaction.

The SOAR timing measurements remain:
- Event to termination: 0.300763 seconds
- Event to verified exit: 0.437653 seconds
- Verified exit code: 137
- `OOMKilled`: false

The environment is standalone Docker. No Kubernetes pod identity or
`pod_name` attribution is claimed.

### 11.4 Updated acceptance interpretation

The demonstrated lab scope now includes:
- Selected Docker-aware kernel SIGKILL enforcement for Bash, curl, wget,
  and netcat execution attempts.
- A tested startup gate that installs the container-specific policy before
  releasing the supplied workload command.
- A live Tetragon workspace-write event correlated by Docker container ID
  to SOAR quarantine and verified exit.
- A real Ollama synthetic-secret response blocked before reaching the client.

The existing limitations on policy scope, launcher coverage, interactive
SOAR operation, and DLP endpoint/response coverage remain in force.

### 11.5 Patched protected image build and scan

The replacement protected image was built locally using
`Dockerfile.alpine.cpython-source` with the protected directory as its build
context. Image inspection verified the non-root identity `10001:10001`.
The runtime smoke test passed its Python version, restricted-module, and
SHA-256 checks.

Grype identified 29 packages and three Medium package matches, with no
Critical or High matches. These three package records represent one unique
CVE, `CVE-2025-60876`, affecting BusyBox-related packages; all three were
reported as not fixed. The image must therefore not be described as
vulnerability-free.

The scan is retained at `artifacts/grype-ci-image.json`. These are local
build, inspection, runtime-test, and scan results; no successful GitHub
Actions run is claimed.

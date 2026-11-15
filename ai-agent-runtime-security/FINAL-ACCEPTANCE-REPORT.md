# AI Agent Runtime Security — Final Acceptance Report

**Assessment date:** 2026-11-13
**Milestone:** End-to-End Correlated AI Defense — Real-Time eBPF Event Attribution, Kernel Enforcement (SIGKILL), and Output Leakage Prevention

## 1. Acceptance decision

**PASS — accepted for the demonstrated lab scope.**

The implementation demonstrates protected agent tool restrictions, selected Tetragon kernel event monitoring and process enforcement, event-correlated Docker containment, and response-side DLP through an LLM egress proxy.

This is not a production-readiness certification. The SOAR listener was operated interactively, kernel policy scope is limited, and DLP coverage is restricted to specified Ollama response endpoints.

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

### 11.6 Additional evidence and corrections — 2026-11-14

#### Latency benchmark

The correlated SOAR test was repeated ten times on fresh disposable containers using `soar/soar_latency_benchmark.sh`. Each run restarted the daemon in `--execute` mode, started a container with the same configuration as the original test, and recorded the daemon timings with Docker's exit code. All ten containers were quarantined, all ten exited with code `137`, and all ten timing statuses were `valid`.

| Metric (10 runs) | Minimum | Median | Mean | Maximum |
|---|---|---|---|---|
| Event to termination | 0.2113 s | 0.2539 s | 0.2559 s | 0.3474 s |
| Event to verified exit | 0.3097 s | 0.3651 s | 0.3689 s | 0.4909 s |

Per-run results are in `evidence/soar/correlated-latency-benchmark.csv`; the daemon's raw output is in `evidence/soar/correlated-latency-benchmark-raw.log`. The interval starts at the Tetragon event timestamp, not an independently measured syscall time. The benchmark ran on one otherwise idle host and does not show behavior under load.

#### Unbroken Test A trace

One further run captured the Tetragon event stream, the daemon log, and Docker inspection output for the same container (`trace_run.sh`).

| Stage | Record |
|---|---|
| Tetragon event | `docker` field `55e63a434da5f32aae54aa2754000b0` (container ID prefix) |
| SOAR daemon | `QUARANTINED: container_id=55e63a434da5f32aae54aa2754000b0ccbcdb787b413ee218fbd473b78b79238`, verified state `exited`, verified exit code `137`, event to termination `0.298388` s (`valid`), event to verified exit `0.459225` s |
| Docker inspect | Same full ID, `exited`, `ExitCode=137`, `FinishedAt=2026-11-14T10:50:55.043988291Z` |

The recorded times agree: event time `10:50:54.7456Z` plus `0.2984` s gives `10:50:55.0440Z`. The files are `evidence/soar/unbroken-trace-*`. This closes the correlation qualification recorded in the previous milestone for the workspace-write test. Section 11.3 still applies: this test and the startup-gate enforcement test remain separate demonstrations.

#### Enforcement policy files added to `tetragon/`

`ai-agent-kernel-exec-enforce-fresh.yaml`, `ai-agent-kernel-pid1-test2.yaml`, `ai-agent-kernel-multi-exec.yaml` (`curl`, `wget`, `nc`) and `ai-agent-kernel-netcat-openbsd.yaml`. Each contains a fixed PID namespace value that belongs to the container used in its test and is not a permanent identifier.

#### Corrections from source-code review

- The correlated SOAR daemon acts only on a container named `ai-agent-correlated-soar` running `ai-agent-sandbox:baseline`, with the three required labels, non-privileged, network mode `none`, read-only root filesystem and all capabilities dropped. It consumes only events from `ai-agent-workspace-write`. The enforcing exec policies act in the kernel and are not routed to the daemon. It runs in dry-run mode unless `--execute` is given, and polls Docker for up to 5 seconds to verify the exited state.
- The DLP proxy accepts `POST /api/chat` and `POST /api/generate` and `GET /healthz`. Streamed responses are held until the whole stream is inspected, so clients receive no partial output. A request is treated as streaming only when `stream` is `true`; by code review, a request that omits it would be rejected with HTTP 502 (fail-closed, not tested). Only responses are inspected, not prompts. The audit log records metadata only. The proxy serves plain HTTP without authentication.
- The DLP engine applies four pattern rules and one entropy rule (32 or more characters, 4.2 bits per character or higher). The entropy rule cannot flag hexadecimal strings, and the private-key rule covers only the listed header forms.
- Ollama publishes no host port at the time of this review. It is reachable only from containers on the internal Docker network.

#### Acceptance interpretation

The correlated containment test is now supported by a ten-run benchmark and a single-container trace. The existing limitations on policy scope, launcher coverage, interactive SOAR operation, and DLP endpoint and response coverage remain in force. This is not a production-readiness certification.

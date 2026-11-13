# AI Agent Runtime Security — Evidence Audit

**Audit date:** 2026-11-13
**Scope:** Evidence supporting the final lab acceptance report.

## 1. Evidence handling principles

Evidence is retained when it supports a stated test or implementation claim. A file's presence alone is not proof that a control works. Automated test results, live runtime observations, and configuration inventories are treated as different evidence types.

Raw container inspection output and workspace-generated audit data may contain host paths, identifiers, environment details, or synthetic fixtures. They are not automatically suitable for source control.

## 2. Curated evidence inventory

All paths below are relative to `ai-agent-runtime-security/`.

| Evidence path | Purpose |
|---|---|
| `evidence/final-acceptance/protected-agent-tests.log` | Protected-agent tests: 15 passed |
| `evidence/final-acceptance/dlp-engine-tests.log` | DLP engine tests: 7 passed |
| `evidence/final-acceptance/dlp-http-integration-tests.log` | DLP HTTP tests: 5 passed; includes two ResourceWarnings |
| `evidence/final-acceptance/soar-tests.log` | SOAR tests: 30 passed |
| `evidence/final-acceptance/test-summary.json` | Machine-readable summary of 57 tests |
| `evidence/kernel-enforcement/bash-monitor-event.json` | Saved Bash monitor event |
| `evidence/kernel-enforcement/bash-sigkill-event.json` | Saved Bash SIGKILL event |
| `evidence/kernel-enforcement/bin-bash-sigkill-event.json` | Additional Bash SIGKILL event |
| `evidence/kernel-enforcement/dash-sigkill-event.json` | Saved Dash SIGKILL event |
| `evidence/protected/approved-fixture-read.jsonl` | Approved fixture-read audit |
| `evidence/protected/private-file-denial.jsonl` | Protected-mode private-file denial |
| `evidence/protected/shell-command-denial.jsonl` | Protected-mode shell-command denial |
| `evidence/red-team/red-team-summary.json` | Consolidated baseline red-team results |
| `evidence/red-team/redteam-indirect-audit.jsonl` | Indirect-injection audit |
| `evidence/red-team/redteam-path-audit.jsonl` | Path-tampering audit |
| `evidence/red-team/redteam-shadow-audit.jsonl` | Protected-file test audit |
| `evidence/red-team/redteam-shell-audit.jsonl` | Shell-execution audit |
| `evidence/soar/correlated-soar-dry-run.log` | Non-destructive SOAR candidate evidence |
| `evidence/soar/correlated-soar-execute-patched.log` | Canonical correlated containment and timing |
| `evidence/soar/live-quarantine-bridge.log` | Separate legacy live-quarantine bridge result |
| `evidence/tetragon/workspace-write-event.jsonl` | Workspace-write telemetry event |
| `evidence/dlp/live-agent-dlp-block-agent.log` | Agent-side DLP negative-test result |
| `evidence/dlp/live-agent-dlp-block-proxy.log` | Proxy-side DLP negative-test result |

The user also reports retaining three Slack alert screenshots from the earlier Tetragon ChatOps milestone. Those screenshots are not evidence for this AI-agent runtime-security acceptance.

## 3. SOAR log selection

The canonical timing claim uses `evidence/soar/correlated-soar-execute-patched.log`. It records:

- `verified_state=exited`
- `verified_exit_code=137`
- `event_to_termination_seconds=0.300763`
- `event_to_verified_exit_seconds=0.437653`

The dry-run log is retained as separate non-destructive candidate evidence.

`correlated-soar-execute.log` records an earlier execution involving a different container ID. It is historical and must not be combined with the patched run's timing measurements.

`correlated-soar-container.log` contains only `SOAR_PROBE_WRITE_OK` and adds little beyond the correlated dry-run and execution records. It is not required for the curated acceptance set.

## 4. Exclusion and review rules

Do not stage these categories indiscriminately:

- Raw `*inspect.json` files: review and sanitize first because inspection output can expose host paths, environment values, labels, mounts, and identifiers.
- Workspace output directories and raw agent audit files: these may contain transient probe data or synthetic secret fixtures. Prefer curated evidence copies.
- Private synthetic fixture files, including `agent/workspace/private/shadow.txt`: do not commit as general project artifacts.
- Historical or duplicate SOAR logs: retain the patched canonical execution and dry-run evidence; do not use older logs for the canonical latency claim.
- `__pycache__`, `.pyc`, temporary files, and generated mock outputs: exclude from source control.
- Mixed historical contents under `artifacts/`: inspect each file individually before deciding whether it belongs in the repository.

This audit does not claim that every currently untracked file has been reviewed or approved for commit.

## 5. Evidence limitations

- Automated test logs show test outcomes, not production readiness.
- Tetragon event files show selected monitor and enforcement events, not universal process enforcement.
- SOAR logs show a successful interactive correlated containment run, not durable, supervised, continuously available operation.
- DLP logs show a benign request and a synthetic-secret response block through the tested proxy path. The negative test used a deterministic mock upstream, not a real model-generated secret.
- Red-team results are limited to the recorded probes.

## 6. Pre-commit review checklist

- [ ] Confirm the test summary reports 57 total, 57 passed, and 0 failed.
- [ ] Confirm the four test logs correspond to the summary.
- [ ] Review curated Tetragon events for unrelated sensitive data.
- [ ] Review protected and red-team JSONL files for fixture secrets or host-specific data.
- [ ] Keep raw container inspection JSON out of the commit unless sanitized and explicitly approved.
- [ ] Exclude transient workspace outputs, private fixtures, bytecode, and temporary artifacts.
- [ ] Stage individual reviewed paths; do not use `git add .`.

## 7. Audit disposition

The curated evidence inventory supports the scoped claims in `FINAL-ACCEPTANCE-REPORT.md`. Exclusions and limitations are explicit. Any additional files found during repository review must be assessed individually rather than assumed safe or relevant.


## 8. Additional evidence recorded — 2026-11-13

The following live evidence was added after the original curated inventory.

| Evidence path | What it supports |
|---|---|
| `evidence/kernel/docker-ai-agent-enforcement-test.json` and `.md` | Docker-aware Bash enforcement evidence |
| `evidence/kernel/docker-ai-agent-multi-binary-test.jsonl` and `.md` | Live curl, wget, and netcat SIGKILL results |
| `evidence/kernel/docker-ai-agent-startup-gate-test.json` and `.md` | Startup-gate Bash SIGKILL, exact container identity, matching process-exit event, and 1.005 ms event interval |
| `evidence/dlp/live-ollama-dlp-result.md` | Real `llama3.2:latest` Ollama synthetic-secret response blocked with HTTP 403 |
| `evidence/dlp/live-ollama-dlp-proxy.log` | Proxy-side metadata-only audit evidence for the real Ollama test |

The real Ollama test supersedes the earlier limitation that the synthetic
secret negative test used only a mock upstream. The mock test remains a
separate test result.

The Docker-aware enforcement tests supersede the earlier statement that
there was no live kernel enforcement evidence for curl, wget, or netcat.

### Additional scope limitations

- The startup gate only controls containers launched through that launcher;
  it does not intercept arbitrary Docker container creation or startup.
- The startup-gate process-execution test and SOAR workspace-write
  quarantine test are separate demonstrations, not one continuous trace.
- The environment is standalone Docker; Kubernetes pod attribution is not
  demonstrated.
- The new kernel tests cover the listed executable paths and tested
  PID namespaces, not universal executable enforcement.

The startup-gate policy and disposable container were removed after the
test. The evidence files were retained.

The original inventory and exclusions above remain applicable. New evidence
must still be reviewed individually before staging.

## 9. Patched CI image evidence — 2026-11-13

| Evidence path | What it supports |
|---|---|
| `artifacts/grype-ci-image.json` | Grype JSON scan of `ai-agent-runtime-security:ci`: 29 packages, 3 Medium package matches, 0 Critical/High, and one unique CVE (`CVE-2025-60876`), with all matches reported as not fixed |

The local patched-image build and runtime smoke test passed. This does not
establish that the GitHub Actions workflow has run successfully. The scan
does not establish a vulnerability-free image.

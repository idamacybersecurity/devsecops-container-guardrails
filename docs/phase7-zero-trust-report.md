# Phase 7 — Zero Trust Service Mesh, Envoy L7 Telemetry & OPA Gatekeeper Guardrails

## 1. Objective

Implement and validate Kubernetes runtime security controls using Istio, Envoy, and OPA Gatekeeper. The objective is to enforce authenticated service-to-service communication, least-privilege access, observable L7 traffic, and admission-time security guardrails.

## 2. Lab Environment

- Platform: AWS EC2 running Ubuntu
- Kubernetes: k3s, single-node lab cluster
- Service mesh: Istio 1.31.1
- Admission policy engine: OPA Gatekeeper 3.23.1
- Workloads: curl client, writer client, and httpbin service
- Test namespaces: phase7-mtls and phase7-gatekeeper-test

## 3. Implemented Controls

### 3.1 Mutual TLS

Configured Istio PeerAuthentication in STRICT mode for the phase7-mtls namespace. Verified the effective policy and tested that plaintext traffic from a client outside the mesh was rejected.

### 3.2 Service Identity and Authorization

Configured Istio AuthorizationPolicy resources using Kubernetes service-account principals.

- curl identity: GET access to httpbin.
- writer identity: POST, PUT, and DELETE access to httpbin.
- Default-deny behavior: requests not permitted by an applicable ALLOW policy are denied.

Observed test results included HTTP 200 for authorized requests and HTTP 403 for unauthorized requests.

### 3.3 Envoy L7 Telemetry

Configured an Istio Telemetry resource to send Envoy access logs to stdout. Inspected logs to verify request outcomes, including authorization denials and response details.

### 3.4 Gatekeeper Admission Guardrails

Implemented and tested constraints for:

- Required Istio proxy sidecar, including native sidecar init containers.
- Container security context requirements: non-root execution, no privilege escalation, no privileged mode, and no added Linux capabilities.
- No-privilege-escalation baseline.

Negative tests demonstrated that noncompliant Pods were rejected. A compliant test Pod was admitted and reached Running status with two containers.

## 4. Validation Evidence

The lab produced the following observed results:

| Test | Observed result |
|---|---|
| Authorized curl GET | HTTP 200 |
| Unauthorized client GET | HTTP 403 |
| curl POST without writer permission | HTTP 403 |
| Authorized writer POST | HTTP 200 |
| writer GET without permission | HTTP 403 |
| Plaintext request outside the mesh | Rejected |
| Pod missing required istio-proxy | Admission denied |
| Pod with invalid security context | Admission denied |
| Pod requesting privileged mode or added capability | Admission denied |
| Compliant test Pod | Admitted; Running, 2/2 containers |

Gatekeeper constraint audit status showed zero violations after the test namespace was cleaned of the stale noncompliant Pod. This is an audit snapshot, not proof that every workload in the cluster is compliant.

## 5. Known Limitation

Gatekeeper reported that its Kubernetes-native validation engine was missing. Rego webhook enforcement and constraint audits were exercised, but native-validation deployment was not confirmed. This limitation is documented rather than represented as a successful native-validation configuration.

## 6. Scope

Validation was performed in a single-node k3s lab on AWS EC2. The results demonstrate the configured controls in this test environment; they do not establish production readiness, multi-node resilience, or cluster-wide enforcement beyond the namespaces and workloads covered by the policies.

## 7. Evidence and Supporting Files

Architecture diagram: `docs/phase7-zero-trust-architecture.md`

Istio authorization policies: `phase7/istio/authorization/`

Envoy telemetry configuration: `phase7/telemetry/access-logging.yaml`

Gatekeeper templates, constraints, and test manifests: `phase7/gatekeeper/`

Screenshots should be retained separately and referenced by their actual filenames when the final evidence package is assembled.

## 8. Conclusion

Phase 7 demonstrates STRICT mTLS, service-account-based authorization, Envoy L7 access logging, and Gatekeeper admission controls in a Kubernetes lab. Positive and negative tests provide evidence of the configured behavior. The Gatekeeper native-validation warning remains an explicit limitation.

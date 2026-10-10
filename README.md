# DevSecOps Container Guardrails

Enterprise-style DevSecOps pipeline for a containerized Python application (API and worker services), applying security controls from commit to cluster admission.

## Controls

- **Pre-commit:** Conftest/OPA policy checks (Kubernetes and Dockerfile) and a TruffleHog secret scan on staged content
- **CI (GitHub Actions):** Bandit SAST, full Git-history TruffleHog scan, Syft CycloneDX SBOMs, Grype vulnerability gate
- **Supply chain:** keyless Cosign signing, CycloneDX SBOM attestations bound to image digests, signature and attestation verification before deployment authorization
- **Cluster:** Kyverno ImageValidatingPolicy requiring Cosign-signed images (k3s lab cluster)
- **Cloud auth:** GitHub Actions OIDC to AWS IAM, with no long-lived access keys

## Status

- Phase 1: complete
- Phase 2: preparation (see `docs/architecture.md`)

## Known limitations

- The Kyverno policy was tested on a single-node k3s lab cluster. Signed images without a valid SBOM attestation are denied. Admission of a signed and attested image timed out against the 30-second webhook limit in this environment.
- The local TruffleHog pre-commit hook points to a Windows binary and is not yet portable.

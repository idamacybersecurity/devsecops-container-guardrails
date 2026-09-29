# Enterprise DevSecOps Pipeline Architecture

## Overview

This architecture implements security controls throughout the software delivery lifecycle. Security checks begin before code is committed and continue through source-code analysis, secret scanning, container creation, SBOM generation, vulnerability scanning, image signing, signature verification, and deployment authorization.

AWS authentication is performed using GitHub Actions OIDC and temporary AWS credentials instead of long-lived AWS access keys.

## Security Pipeline

```mermaid
flowchart TD
    A[Developer Changes Code] --> B[Pre-Commit Security Checks]

    B --> B1[OPA / Rego Policies]
    B1 --> B2[Dockerfile Policies]
    B1 --> B3[Kubernetes Policies]

    B2 --> C[Git Commit / Push]
    B3 --> C

    C --> D[GitHub Actions]

    D --> E[TruffleHog<br/>Full Git History Secret Scan]
    D --> F[OPA / Conftest<br/>Policy-as-Code Validation]
    D --> G[Bandit SAST<br/>Python Security Scan]

    E --> H{Security Checks Pass?}
    F --> H
    G --> H

    H -- No --> X[Pipeline Blocked]
    H -- Yes --> I[Build API and Worker<br/>Container Images]

    I --> J[Syft<br/>Generate CycloneDX SBOMs]

    J --> K[Python Dependencies]
    J --> L[Container Base-Image Packages]

    K --> M[Grype SBOM Vulnerability Scan]
    L --> M

    M --> N{HIGH / CRITICAL CVE<br/>with Known Fix?}

    N -- Yes --> X
    N -- No --> O[Publish Security-Approved<br/>Images to GHCR]

    O --> P[Resolve Immutable<br/>SHA-256 Image Digests]

    P --> Q[Cosign / Sigstore<br/>Keyless Image Signing]

    Q --> R[Cosign Signature Verification]

    R --> S{Valid Signature?}

    S -- No --> X
    S -- Yes --> T[Deployment Authorization Gate]

    T --> U[Deployment Authorized]

    D --> V[GitHub Actions OIDC Token]
    V --> W[AWS IAM OIDC Provider]
    W --> Y[Assume Dedicated IAM Role]
    Y --> Z[Temporary AWS Credentials]

    Z -. Authentication available for deployment .-> T
```

## Implemented Security Controls

- **Pre-commit:** Conftest executes OPA/Rego policies before relevant Dockerfile or Kubernetes changes are committed.
- **Secret scanning:** TruffleHog scans Git history for exposed credentials and secrets.
- **SAST:** Bandit scans Python source code and blocks qualifying security findings.
- **Policy as Code:** OPA/Rego enforces non-root containers, read-only filesystems, and restrictions against `latest` image tags.
- **SBOM:** Syft generates CycloneDX SBOMs containing Python application dependencies and container base-image packages.
- **SCA:** Grype scans the generated SBOMs and blocks HIGH or CRITICAL vulnerabilities when a known fix is available.
- **Container registry:** Images that pass the security gates are published to GitHub Container Registry.
- **Image integrity:** Container images are referenced by immutable SHA-256 digest before signing.
- **Signing:** Cosign/Sigstore performs keyless signing of approved container images.
- **Deployment gate:** Cosign verification must succeed before deployment authorization can execute.
- **Cloud authentication:** GitHub Actions uses OIDC to assume a dedicated AWS IAM role and obtain temporary credentials without storing long-lived AWS access keys.

## Verification

The pipeline was tested with both positive and negative security scenarios.

A security-approved container image successfully passed the vulnerability gates, was signed with Cosign, had its signature verified, and reached the deployment authorization gate.

A separate controlled test published an intentionally unsigned container image. Cosign returned `no signatures found`, and the deployment authorization step was skipped.

AWS OIDC authentication was also validated by successfully assuming the dedicated IAM role from GitHub Actions and obtaining temporary AWS credentials.

## Current Deployment Scope

This project validates the security controls required before deployment and demonstrates secure AWS authentication using OIDC. The current implementation does not claim that an application workload was deployed to an AWS or Kubernetes production environment.
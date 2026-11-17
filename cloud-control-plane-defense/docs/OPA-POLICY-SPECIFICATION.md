# OPA / Rego policy specification

## Purpose

The pre-deployment policy gate evaluates Terraform plan data using Conftest and
OPA. Its purpose is to reject infrastructure changes that violate the cloud
control-plane security baseline before deployment.

## Required policy controls

| Control | Expected rejection condition |
|---|---|
| Wildcard IAM permissions | IAM policy grants `Action: "*"` |
| Privilege-escalation combination | A policy grants `iam:PassRole` together with `ec2:RunInstances` or `lambda:CreateFunction` |
| S3 encryption | An S3 bucket is configured without the required server-side encryption |
| Secrets encryption | A Secrets Manager resource lacks the required encryption configuration |
| Public ingress | A security-group ingress rule exposes a port to `0.0.0.0/0` |

## Enforcement workflow

1. Generate a Terraform plan.
2. Convert the plan to JSON.
3. Evaluate the plan with Conftest and the Rego policy.
4. Reject the deployment when policy violations are reported.
5. Proceed only after the policy gate passes.

## Verification boundary

The policy specification describes the intended controls. The actual Rego
implementation and test fixtures are authoritative for the exact expressions
and resource coverage. Do not interpret this specification as proof that every
possible Terraform resource type or policy encoding is covered.

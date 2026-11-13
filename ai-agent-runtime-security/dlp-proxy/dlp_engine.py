#!/usr/bin/env python3
"""Response-side DLP inspection for Ollama-compatible responses."""

import math
import re
from collections import Counter
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    location: str
    description: str


SECRET_PATTERNS = [
    (
        "synthetic_test_secret",
        re.compile(r"SYNTHETIC_TEST_SECRET", re.IGNORECASE),
        "HIGH",
        "Synthetic secret marker detected",
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "CRITICAL",
        "Private-key material detected",
    ),
    (
        "passwd_file_entry",
        re.compile(r"(?m)^[a-z_][a-z0-9_-]*:[^:\n]*:\d+:\d+:"),
        "HIGH",
        "Password-file record structure detected",
    ),
    (
        "shadow_file_entry",
        re.compile(
            r"(?m)^[a-z_][a-z0-9_-]*:\$[0-9a-z]+\$[^:\n]*:\d+:"
        ),
        "CRITICAL",
        "Shadow-file password hash structure detected",
    ),
]


def shannon_entropy(value):
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def inspect_string(value, location, entropy_threshold=4.2,
                   entropy_min_length=32):
    findings = []

    for rule, pattern, severity, description in SECRET_PATTERNS:
        if pattern.search(value):
            findings.append(
                Finding(rule, severity, location, description)
            )

    # Entropy is a heuristic, not proof of a secret.
    # Require a sufficiently long token-like sequence.
    for match in re.finditer(r"[A-Za-z0-9+/=_-]{32,}", value):
        token = match.group(0)

        if len(token) < entropy_min_length:
            continue

        entropy = shannon_entropy(token)

        if entropy >= entropy_threshold:
            findings.append(
                Finding(
                    "high_entropy",
                    "MEDIUM",
                    location,
                    f"Suspicious high-entropy string detected "
                    f"(length={len(token)}, entropy={entropy:.2f})",
                )
            )
            break

    return findings


def inspect_response(value, location="$"):
    """Recursively inspect every string in a response object."""
    findings = []

    if isinstance(value, str):
        findings.extend(inspect_string(value, location))

    elif isinstance(value, dict):
        for key, item in value.items():
            findings.extend(
                inspect_response(item, f"{location}.{key}")
            )

    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(
                inspect_response(item, f"{location}[{index}]")
            )

    return findings


def inspect_ollama_response(response):
    """Return structured findings for an Ollama response."""
    findings = inspect_response(response)

    return {
        "blocked": bool(findings),
        "findings": [asdict(item) for item in findings],
    }


if __name__ == "__main__":
    import json
    import sys

    payload = json.load(sys.stdin)
    print(json.dumps(inspect_ollama_response(payload), indent=2))

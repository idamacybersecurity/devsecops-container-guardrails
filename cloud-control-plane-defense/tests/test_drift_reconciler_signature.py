import json
import subprocess
from pathlib import Path

import pytest

import drift.drift_reconciler as reconciler


IDENTITY = "ccpd-drift-baseline"
NAMESPACE = "ccpd-drift-baseline"


def make_keypair(directory, name):
    private_key = directory / name
    subprocess.run(
        [
            "ssh-keygen", "-q", "-t", "ed25519",
            "-N", "", "-f", str(private_key),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    public_parts = Path(f"{private_key}.pub").read_text().split()
    return private_key, public_parts


def configure_signed_baseline(tmp_path, monkeypatch):
    baseline = tmp_path / "approved-drift-baseline.json"
    signature = tmp_path / "approved-drift-baseline.json.sig"
    allowed_signers = tmp_path / "allowed-signers"

    document = {"schema_version": 1, "approved_resources": {}}
    baseline.write_text(json.dumps(document, sort_keys=True) + "\n")

    private_key, public_parts = make_keypair(tmp_path, "trusted-key")
    allowed_signers.write_text(
        f"{IDENTITY} {public_parts[0]} {public_parts[1]}\n"
    )

    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign",
            "-f", str(private_key),
            "-n", NAMESPACE,
            str(baseline),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    monkeypatch.setattr(reconciler, "BASELINE", baseline)
    monkeypatch.setattr(reconciler, "SIGNATURE", signature)
    monkeypatch.setattr(reconciler, "ALLOWED_SIGNERS", allowed_signers)

    for path in (baseline, signature, allowed_signers):
        path.chmod(0o600)

    return baseline, signature, allowed_signers, document


def test_valid_ed25519_signature_is_accepted(tmp_path, monkeypatch):
    _, _, _, expected = configure_signed_baseline(tmp_path, monkeypatch)

    assert reconciler.read_verified_baseline() == expected


def test_modified_baseline_is_rejected(tmp_path, monkeypatch):
    baseline, _, _, _ = configure_signed_baseline(tmp_path, monkeypatch)
    baseline.write_bytes(baseline.read_bytes() + b" ")

    with pytest.raises(RuntimeError, match="signature verification failed"):
        reconciler.read_verified_baseline()


def test_signature_from_untrusted_key_is_rejected(tmp_path, monkeypatch):
    _, _, allowed_signers, _ = configure_signed_baseline(
        tmp_path, monkeypatch
    )
    _, untrusted_public = make_keypair(tmp_path, "untrusted-key")
    allowed_signers.write_text(
        f"{IDENTITY} {untrusted_public[0]} {untrusted_public[1]}\n"
    )
    allowed_signers.chmod(0o600)

    with pytest.raises(RuntimeError, match="signature verification failed"):
        reconciler.read_verified_baseline()


@pytest.mark.parametrize("missing_name", ["signature", "allowed_signers"])
def test_missing_verification_file_is_rejected(
    tmp_path, monkeypatch, missing_name
):
    _, signature, allowed_signers, _ = configure_signed_baseline(
        tmp_path, monkeypatch
    )
    (signature if missing_name == "signature" else allowed_signers).unlink()

    with pytest.raises(RuntimeError, match="verification files are missing"):
        reconciler.read_verified_baseline()


def test_unsupported_signed_schema_is_rejected(tmp_path, monkeypatch):
    baseline, signature, _, _ = configure_signed_baseline(
        tmp_path, monkeypatch
    )

    document = {"schema_version": 999}
    baseline.write_text(json.dumps(document) + "\n")

    private_key = tmp_path / "trusted-key"

    # Remove the previous detached signature before signing new content.
    signature.unlink()

    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign",
            "-f", str(private_key),
            "-n", NAMESPACE,
            str(baseline),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    baseline.chmod(0o600)
    signature.chmod(0o600)

    with pytest.raises(RuntimeError, match="Unsupported baseline schema"):
        reconciler.read_verified_baseline()


def test_local_baseline_signing_is_disabled():
    with pytest.raises(RuntimeError, match="Local baseline signing is disabled"):
        reconciler.write_baseline()

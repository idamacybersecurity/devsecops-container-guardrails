import copy

import pytest

from drift.drift_reconciler import (
    approved_resources,
    compare,
    remediate_drift,
)


@pytest.fixture
def approved_state():
    state = approved_resources()
    assert "cloudtrail" in state
    return state


def changed_state(approved, mutate):
    observed = copy.deepcopy(approved)
    mutate(observed["cloudtrail"])
    return observed


def assert_cloudtrail_drift(approved, observed):
    findings = compare(approved, observed)
    assert (
        "CloudTrail destination, logging, or event-selector drift"
        in findings
    )
    return findings


def test_unchanged_cloudtrail_has_no_drift(approved_state):
    observed = copy.deepcopy(approved_state)
    findings = compare(approved_state, observed)
    assert (
        "CloudTrail destination, logging, or event-selector drift"
        not in findings
    )


def test_changed_s3_bucket_is_detected(approved_state):
    observed = changed_state(
        approved_state,
        lambda trail: trail.update(
            s3_bucket_name="unauthorized-audit-bucket"
        ),
    )
    assert_cloudtrail_drift(approved_state, observed)


def test_changed_s3_key_prefix_is_detected(approved_state):
    observed = changed_state(
        approved_state,
        lambda trail: trail.update(s3_key_prefix="unexpected-prefix"),
    )
    assert_cloudtrail_drift(approved_state, observed)


def test_changed_kms_key_is_detected(approved_state):
    observed = changed_state(
        approved_state,
        lambda trail: trail.update(
            kms_key_id="arn:aws:kms:eu-north-1:000000000000:key/unauthorized"
        ),
    )
    assert_cloudtrail_drift(approved_state, observed)


def test_stopped_logging_is_detected(approved_state):
    observed = changed_state(
        approved_state,
        lambda trail: trail.update(is_logging=False),
    )
    assert_cloudtrail_drift(approved_state, observed)


def test_weakened_event_selectors_are_detected(approved_state):
    def weaken(trail):
        trail["event_selectors"][0]["IncludeManagementEvents"] = False
        trail["event_selectors"][0]["ReadWriteType"] = "WriteOnly"

    observed = changed_state(approved_state, weaken)
    assert_cloudtrail_drift(approved_state, observed)


def test_cloudtrail_remediation_fails_closed(approved_state):
    observed = changed_state(
        approved_state,
        lambda trail: trail.update(s3_key_prefix="unauthorized-prefix"),
    )
    findings = assert_cloudtrail_drift(approved_state, observed)
    before = copy.deepcopy(observed)

    with pytest.raises(RuntimeError, match="CloudTrail"):
        remediate_drift(
            {"approved_resources": approved_state},
            {},
            observed,
            findings,
        )

    assert observed == before

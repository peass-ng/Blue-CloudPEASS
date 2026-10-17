"""An absent S3 detail cannot conflict with selected native field coverage."""
from copy import deepcopy

import pytest

from peaso.checks import claude_aws_a_s3 as s3
from peaso.checks.facts import Unavailable
from tests.test_peaso_s3_empty_payload_coherence import PUBLIC, READ, public_bucket, verdict


@pytest.mark.parametrize("entry", [
    {"status": "collected"}, {"status": "denied"}, {"status": "partial"},
    {"status": "unavailable"}, {}, None, "empty",
])
def test_missing_mapped_payload_requires_explicit_empty_coverage(entry):
    for detail, keys in s3._S3_DETAIL_PAYLOAD_KEYS.items():
        for key in keys:
            row = {detail: {**deepcopy(s3.ABSENT), "_coverage": {key: deepcopy(entry)}}}
            with pytest.raises(Unavailable):
                s3.section(row, detail)


def test_missing_collected_bucket_payload_cannot_prove_unmitigated_public_access():
    bucket = public_bucket()
    del bucket["PublicAccessBlock"]["PublicAccessBlockConfiguration"]
    bucket["PublicAccessBlock"]["_coverage"] = {
        "PublicAccessBlockConfiguration": {"status": "collected"}}
    assert verdict(PUBLIC, bucket)["status"] == "UNKNOWN"
    stored = verdict(READ, bucket)
    assert stored["status"] == "FAIL"
    assert stored["evidence"]["bucket_public_access_block"] is None
    assert stored["evidence"]["runtime_acl_ignored"] is None


def test_coherent_absence_with_empty_coverage_or_no_payload_coverage_stays_absent():
    for coverage in ({}, {"PublicAccessBlockConfiguration": {"status": "empty"}}):
        bucket = public_bucket()
        del bucket["PublicAccessBlock"]["PublicAccessBlockConfiguration"]
        bucket["PublicAccessBlock"]["_coverage"] = deepcopy(coverage)
        assert s3.section(bucket, "PublicAccessBlock") is None
        assert verdict(PUBLIC, bucket)["status"] == "FAIL"


def test_complete_account_mitigation_still_independently_passes():
    bucket = public_bucket()
    del bucket["PublicAccessBlock"]["PublicAccessBlockConfiguration"]
    bucket["PublicAccessBlock"]["_coverage"] = {
        "PublicAccessBlockConfiguration": {"status": "denied"}}
    account = {"PublicAccessBlockConfiguration": {key: True for key in s3.BLOCKS}}
    assert verdict(PUBLIC, bucket, account)["status"] == "PASS"

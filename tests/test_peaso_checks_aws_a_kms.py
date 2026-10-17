"""Read-only rotation semantics and complete source exclusions."""
import copy
import pytest

from peaso.checks import CHECKS, aws_a_kms as rules
from peaso.checks.fixtures import CASES

CHECK = next(c for c in CHECKS if c.id == rules.ID)


def test_real_rotation_states_purity_and_denied_metadata():
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("not_applicable", "NOT_APPLICABLE")):
        item = copy.deepcopy(CASES[rules.ID][name])
        before = copy.deepcopy(item)
        assert CHECK.evaluate(item, {})[0] == expected
        assert item == before
    assert CHECK.evaluate({"Metadata": {"collection_status": "denied"}}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("Origin", "EXTERNAL"), ("KeySpec", "RSA_2048"), ("KeyState", "Disabled"), ("KeyState", "PendingDeletion")])
def test_source_exclusions_do_not_require_unavailable_rotation_read(field, value):
    item = {"Metadata": {"KeyMetadata": {**rules.METADATA, field: value}}, "Rotation": {"collection_status": "denied"}}
    assert CHECK.evaluate(item, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("origin", ["AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"])
def test_custom_store_is_not_falsely_merged_with_aws_kms_only_existing_variant(origin):
    item = {"Metadata": {"KeyMetadata": {**rules.METADATA, "Origin": origin}}, "Rotation": {"KeyRotationEnabled": False}}
    assert CHECK.evaluate(item, {})[0] == "FAIL"
    item["Rotation"] = {"collection_status": "unknown"}
    assert CHECK.evaluate(item, {})[0] == "UNKNOWN"


def test_pending_replica_deletion_and_unsupported_states_are_distinct():
    item = {"Metadata": {"KeyMetadata": {**rules.METADATA, "KeyState": "PendingReplicaDeletion"}}, "Rotation": {"KeyRotationEnabled": False}}
    assert CHECK.evaluate(item, {})[0] == "FAIL"
    item["Metadata"]["KeyMetadata"]["KeyState"] = "future_state"
    assert CHECK.evaluate(item, {})[0] == "UNKNOWN"

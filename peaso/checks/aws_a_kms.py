"""KMS SQL rotation variant with explicit source eligibility exclusions."""
from . import register, result, unknown
from .facts import get
from .fixtures import CASES

ID = "aws.a.kms.rotation_source_eligibility"
NATIVE_IDS = [ID]
METADATA = {"KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled"}


@register(ID, "aws", "hardening", "kms_key", "Source-eligible customer-managed KMS key has rotation enabled",
    "medium", "SC-12", "Review rotation for eligible keys and distinguish unsupported, imported, disabled and pending-deletion key metadata.")
def rotation(item, index):
    metadata = get(item, "Metadata.KeyMetadata", dict)
    manager = get(metadata, "KeyManager", str)
    if manager == "AWS":
        return "NOT_APPLICABLE", {"reason": "Source customer-managed-key filter"}
    if manager != "CUSTOMER":
        return unknown("unrecognized KMS key manager")
    origin = get(metadata, "Origin", str)
    if origin == "EXTERNAL":
        return "NOT_APPLICABLE", {"reason": "Source imported-key exclusion"}
    if origin not in {"AWS_KMS", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"}:
        return unknown("unrecognized KMS key origin")
    spec = get(metadata, "KeySpec", str)
    if spec != "SYMMETRIC_DEFAULT":
        return "NOT_APPLICABLE", {"reason": "Source non-symmetric-key exclusion", "key_spec": spec}
    state = get(metadata, "KeyState", str)
    if state in {"PendingDeletion", "Disabled"}:
        return "NOT_APPLICABLE", {"reason": "Source disabled/pending-deletion exclusion", "key_state": state}
    if state not in {"Creating", "Enabled", "PendingImport", "PendingReplicaDeletion", "Unavailable", "Updating"}:
        return unknown("unrecognized KMS key state")
    enabled = get(item, "Rotation.KeyRotationEnabled", bool)
    return result(not enabled, rotation_enabled=enabled, key_origin=origin, key_state=state,
        semantics="Declared native rotation state under exact source eligibility, no resource change or rotation execution")
CASES[ID] = {"pass": {"Metadata": {"KeyMetadata": METADATA}, "Rotation": {"KeyRotationEnabled": True}},
    "fail": {"Metadata": {"KeyMetadata": METADATA}, "Rotation": {"KeyRotationEnabled": False}}, "missing": {}, "malformed": None,
    "not_applicable": {"Metadata": {"KeyMetadata": {"KeyManager": "AWS"}}}}

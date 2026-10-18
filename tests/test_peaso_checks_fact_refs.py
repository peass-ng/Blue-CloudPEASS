"""Authorized canonical metadata references never manufacture empty or safe facts."""
import copy
import pytest
from peaso.checks.facts import Unavailable, resolve_embedded_fact, azure_directory_join_authorized

PARENT = "/subscriptions/a/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/account"
CHILD = PARENT + "/providers/Microsoft.Insights/diagnosticSettings/audit"


def fixture():
    value = {"id": CHILD, "properties": {"logs": [{"category": "Audit", "enabled": True}]}}
    parent = {"native_id": PARENT, "provider": "azure", "type": "storage_account", "data": {"id": PARENT, "diagnosticSettings": [value], "_coverage": {"diagnosticSettings": {"status": "collected"}}}}
    child = {"id": CHILD, "parent_id": PARENT, "_embedded_ref": {"parent_id": PARENT, "field": "diagnosticSettings", "index": 0}}
    return child, parent, value


def test_reference_materializes_exact_observed_native_child_without_mutation():
    child, parent, value = fixture()
    before = copy.deepcopy((child, parent))
    output = resolve_embedded_fact(child, [parent])
    assert output == value and output is not value
    assert (child, parent) == before


@pytest.mark.parametrize("status", ["denied", "partial", "unknown", "malformed", "not_collected"])
def test_incomplete_child_inventory_never_resolves_to_empty_or_safe(status):
    child, parent, _ = fixture()
    with pytest.raises(Unavailable):
        resolve_embedded_fact(child, [parent], child_status=status)


def test_denied_parent_field_and_missing_parent_are_unknown():
    child, parent, _ = fixture()
    parent["data"]["_coverage"]["diagnosticSettings"]["status"] = "denied"
    with pytest.raises(Unavailable):
        resolve_embedded_fact(child, [parent])
    with pytest.raises(Unavailable):
        resolve_embedded_fact(child, [])


@pytest.mark.parametrize("index", [-1, 1, True, None, "0"])
def test_reference_index_requires_a_real_nonnegative_in_range_integer(index):
    child, parent, _ = fixture()
    child["_embedded_ref"]["index"] = index
    with pytest.raises(Unavailable):
        resolve_embedded_fact(child, [parent])


def test_reference_requires_exact_child_and_parent_identity_and_reviewed_path():
    child, parent, _ = fixture()
    for mutate in (
        lambda obj: obj.update(id=CHILD + "-other"),
        lambda obj: obj.update(parent_id=PARENT + "-other"),
        lambda obj: obj["_embedded_ref"].update(field="_credentials.token"),
    ):
        bad = copy.deepcopy(child); mutate(bad)
        with pytest.raises(Unavailable):
            resolve_embedded_fact(bad, [parent])


def test_complete_empty_parent_list_does_not_invent_a_child():
    child, parent, _ = fixture()
    parent["data"]["diagnosticSettings"] = []
    parent["data"]["_coverage"]["diagnosticSettings"]["status"] = "empty"
    with pytest.raises(Unavailable):
        resolve_embedded_fact(child, [parent])
    # No ref is needed for the valid observed empty parent fact itself.
    assert parent["data"]["diagnosticSettings"] == []


def tenant_fixture():
    metadata = {"tenant_id": "t1", "tenant_verified": True, "credential_context_id": "capture-a", "customer_context_id": "customer-a", "subscription_tenants": {"/subscriptions/a": "t1", "/subscriptions/b": "t2"}}
    proof = {key: metadata[key] for key in ("tenant_id", "tenant_verified", "credential_context_id", "customer_context_id")}
    collection = {"scope": "/tenants/t1/groups", "service": "Microsoft.Graph", "status": "collected", "_provenance": proof, "items": [{"id": "group", "_provenance": {"tenant_id": "t1", "tenant_verified": True}}]}
    return metadata, collection


def test_directory_join_same_tenant_capture_allowed_and_foreign_tenant_rejected():
    metadata, collection = tenant_fixture()
    assert azure_directory_join_authorized("/subscriptions/a", metadata, collection)
    assert not azure_directory_join_authorized("/subscriptions/b", metadata, collection)


def test_directory_join_unknown_or_foreign_capture_customer_and_item_proof_rejected():
    metadata, collection = tenant_fixture()
    for key in ("tenant_verified", "tenant_id", "credential_context_id", "customer_context_id", "subscription_tenants"):
        missing = copy.deepcopy(metadata); missing.pop(key)
        assert not azure_directory_join_authorized("/subscriptions/a", missing, collection)
    for key in ("credential_context_id", "customer_context_id"):
        foreign = copy.deepcopy(collection); foreign["_provenance"][key] = "another"
        assert not azure_directory_join_authorized("/subscriptions/a", metadata, foreign)
    collection["items"][0]["_provenance"]["tenant_id"] = "t2"
    assert not azure_directory_join_authorized("/subscriptions/a", metadata, collection)

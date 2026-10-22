"""A new Glue endpoint route needs a usable Region and a readable new endpoint."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc import versioned_catalog as catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-glue-passrole-createdevendpoint"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCOPE = "111111111111/us-east-1"
ENDPOINT_PREFIX = "arn:aws:glue:us-east-1:111111111111:devEndpoint/"


def _case(*, read_action="glue:GetDevEndpoints", read_resource="*", service="glue.amazonaws.com",
          trust="glue.amazonaws.com", status="empty", error=None, existing=(), create=True, passed=True,
          create_resource="*"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    statements = []
    if create:
        statements.append({"Effect": "Allow", "Action": "glue:CreateDevEndpoint", "Resource": create_resource})
    statements.append({"Effect": "Allow", "Action": read_action, "Resource": read_resource})
    if passed:
        statements.append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
                           "Condition": {"StringEquals": {"iam:PassedToService": service}}})
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"] = {"Statement": [
        {"Effect": "Allow", "Principal": {"Service": trust}, "Action": "sts:AssumeRole"}]}
    snapshot["collections"].append({"type": "glue_dev_endpoint", "scope": SCOPE,
        "service": "glue", "status": status,
        "items": [{"EndpointName": name} for name in existing] if status == "collected" else [],
        "error": error})
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_global_read_and_scoped_new_endpoint_read_reach_exact_role():
    assert _definite(_case()) == {TARGET: "conditional"}
    assert _definite(_case(read_action="glue:GetDevEndpoint",
                           read_resource=ENDPOINT_PREFIX + "audit-*")) == {TARGET: "conditional"}


def test_unrelated_permissions_and_role_do_not_reach():
    for kwargs in ({"read_resource": ENDPOINT_PREFIX + "other"}, {"create": False},
                   {"create_resource": ENDPOINT_PREFIX + "audit-*"},
                   {"passed": False}, {"service": "lambda.amazonaws.com"},
                   {"trust": "lambda.amazonaws.com"},
                   {"read_action": "glue:GetDevEndpoint", "read_resource": ENDPOINT_PREFIX + "used",
                    "status": "collected", "existing": ("used",)}):
        assert not _definite(_case(**kwargs)), kwargs


def test_disabled_region_and_denied_inventory_never_reach():
    for snapshot in (_case(error={"code": "operation_disabled_for_account"}),
                     _case(error={"code": "region_operation_unsupported"}),
                     _case(status="denied", error={"code": "AccessDeniedException"})):
        assert not _definite(snapshot)


def test_current_catalog_route_has_new_precondition():
    old_binding = {"schema": catalog.BINDING_SCHEMA,
                   "manifest_sha256": catalog.GLUE_690_PREVIOUS_MANIFEST,
                   "effective_tree_sha256": catalog.GLUE_690_PREVIOUS_TREE,
                   "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([ID], old_binding)
    assert old_status == "exact_previous_current" and ID in old
    assert "preconditions" not in old[ID]
    current, status = catalog.lookup_entries([ID], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ID]["preconditions"] == ["glue_new_public_dev_endpoint_role"]

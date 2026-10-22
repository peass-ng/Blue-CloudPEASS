"""Metastore self-grants require a usable gRPC service and a new permission."""
import sys
import types
from copy import deepcopy
from pathlib import Path

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SERVICE = PROJECT + "/locations/us-central1/services/s1"
SOURCE = "user:writer@example.com"
TECHNIQUE = "gcp-metastore-services-setiampolicy-metastore-service-self-grant"


def snapshot(*, write=True, prior=False, protocol="GRPC", state="ACTIVE",
             policy_status="collected"):
    def row(kind, data, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": data, "error": None}
    writer = PROJECT + "/roles/servicePolicyWriter"
    permissions = ["metastore.services.setIamPolicy"] if write else []
    if prior:
        permissions.append("metastore.services.use")
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "created_at": "2026-10-21T10:05:00Z", "collections": [
                row("project", [{"projectId": "p1", "name": "projects/123"}]),
                row("iam_role", [{"name": writer, "includedPermissions": permissions}]),
                row("iam_policy", [{"name": PROJECT,
                    "bindings": [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("metastore_service", [{"name": SERVICE, "state": state,
                    "hiveMetastoreConfig": {"endpointProtocol": protocol},
                    "iamPolicy": {"bindings": []},
                    "_coverage": {"iamPolicy": {"status": policy_status}}}]),
            ]}


def targets(snap, *, prefix="possible-metastore-service-self-grant"):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:" + prefix + ":")}


def test_active_grpc_service_has_exact_conditional_path():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-metastore-service-self-grant:" + SERVICE:
        "conditional"}
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "metastore_service")[
        "items"][0]["name"] = SERVICE.replace(PROJECT, "projects/123", 1)
    assert targets(snap) == {
        "gcp_verified_authority:possible-metastore-service-self-grant:" + SERVICE:
        "conditional"}


def test_no_write_prior_permission_or_unusable_protocol_does_not_claim_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=True))
    for protocol in ("THRIFT", "ENDPOINT_PROTOCOL_UNSPECIFIED"):
        assert not targets(snapshot(protocol=protocol))
    for state in ("SUSPENDED", "DELETING", "ERROR"):
        assert not targets(snapshot(state=state))


def test_missing_policy_or_state_remains_unresolved():
    assert "conditional" not in targets(snapshot(policy_status="denied")).values()
    assert "conditional" not in targets(snapshot(state="UPDATING")).values()
    assert "conditional" not in targets(snapshot(protocol=None)).values()
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "metastore_service")[
        "items"][0]["iamPolicy"]["bindings"] = "malformed"
    assert "conditional" not in targets(snap).values()
    snap = snapshot()
    snap["metadata"]["collector"] = "native-gcp"
    item = next(c for c in snap["collections"] if c["type"] == "metastore_service")["items"][0]
    assert "conditional" not in targets(snap).values()
    item["_coverage"]["network_detail"] = {"status": "collected"}
    assert targets(snap)["gcp_verified_authority:possible-metastore-service-self-grant:" + SERVICE] == "conditional"


def test_collector_reads_exact_service_and_iam_policy(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp
    assert "metastore.googleapis.com" in gcp.HOSTS

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url))
            if url.endswith("/services"):
                return {"services": [{"name": SERVICE, "state": "ACTIVE",
                    "hiveMetastoreConfig": {"endpointProtocol": "GRPC"}}]}, "services"
            if url.endswith("/services/s1"):
                return {"name": SERVICE, "state": "ACTIVE",
                    "hiveMetastoreConfig": {"endpointProtocol": "GRPC"}}, "details"
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["metastore_service"], "metastore_network_locations": ["us-central1"],
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "metastore_service"]
    result = collector.envelope(*job[:3], job[3])
    assert result["status"] == "collected"
    assert result["items"][0]["name"] == SERVICE
    assert result["items"][0]["_coverage"]["network_detail"]["status"] == "collected"
    assert result["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert transport.calls == [
        ("GET", "https://metastore.googleapis.com/v1/" + PROJECT + "/locations/us-central1/services"),
        ("GET", "https://metastore.googleapis.com/v1/" + SERVICE),
        ("GET", "https://metastore.googleapis.com/v1/" + SERVICE + ":getIamPolicy")]


def test_reviewed_mutation_requires_same_active_grpc_service_and_binding():
    record = {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
              "TargetResource": SERVICE, "GrantedResource": SERVICE,
              "AccessPermission": "metastore.services.setIamPolicy", "GrantedPrincipalId": SOURCE,
              "GrantedPermissions": ["metastore.services.use"],
              "PriorTestedPermission": "metastore.services.use",
              "AfterTestedPermission": "metastore.services.use",
              "PriorTestedResource": SERVICE, "AfterTestedResource": SERVICE,
              "AcceptedBindingMember": SOURCE,
              "AcceptedBindingRole": "roles/metastore.metadataViewer",
              "BindingPresentAtSnapshot": True,
              "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
              "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
              "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
              "BindingCheckedAt": "2026-10-21T10:03:00Z",
              "EvidenceObservedAt": "2026-10-21T10:04:00Z",
              "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
              "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
              "Status": "verified", "EvidenceRef": "reviewed-metastore-policy-1"}
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "metastore_service")[
        "items"][0]["iamPolicy"]["bindings"] = [
            {"role": "roles/metastore.metadataViewer", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [record], "error": None})
    assert len(targets(snap, prefix="self-grant")) == 1
    for field, value in (("TargetResource", PROJECT + "/locations/us-central1/services/other"),
                         ("GrantedResource", SERVICE + "/child"),
                         ("AcceptedBindingRole", "roles/metastore.metadataUser"),
                         ("AfterTestedResource", PROJECT + "/locations/us-central1/services/other")):
        changed = deepcopy(snap)
        next(c for c in changed["collections"] if c["type"] ==
             "gcp_resource_self_grant_evidence")["items"][0][field] = value
        assert not targets(changed, prefix="self-grant"), field
    changed = deepcopy(snap)
    next(c for c in changed["collections"] if c["type"] == "metastore_service")[
        "items"][0]["hiveMetastoreConfig"]["endpointProtocol"] = "THRIFT"
    assert not targets(changed, prefix="self-grant")

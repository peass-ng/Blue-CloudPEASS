# Historical archived-check predicate/collector contract; product selection rejects these IDs.
"""Native, offline project alias proof through the real GCP transport and registered historical predicate.

The fake session supplies inert HTTP responses; Transport.request, the collector,
its annotations, snapshot construction, and registered checks all run unchanged.
"""

import copy
from dataclasses import dataclass, field

import pytest

from peaso.checks.gcp_data_access import CHECK_SERVICES
from peaso.collectors import gcp
from tests.gcp_archived_native_contract import evaluate_historical_snapshot
from peaso.gcp_data_access_policy import OPTION
from peaso.snapshot import digest, make_snapshot, resource_id

SCOPE = "projects/fixture-project"
NUMBER = "12345"
CAI_NAME = f"//cloudresourcemanager.googleapis.com/projects/{NUMBER}"
PRINCIPAL = "user:auditor@example.test"
CRM = "https://cloudresourcemanager.googleapis.com"
CAI = "https://cloudasset.googleapis.com"
COMPUTE = "https://compute.googleapis.com"


def config(service, kind, exempt=()):
    return {"service": service, "auditLogConfigs": [{"logType": kind, "exemptedMembers": list(exempt)}]}


class Credentials:
    method = "inert-test"

    def headers(self):
        return {"Authorization": "Bearer inert-test-token"}


class InertTransport(gcp.Transport):
    def __init__(self, session):
        super().__init__(Credentials(), {"retries": 0, "timeout": 2})
        self.session = session

    def _session(self):
        return self.session


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code, self.headers = copy.deepcopy(data), status, {}

    def json(self):
        return copy.deepcopy(self.data)


@dataclass
class Scenario:
    direct: dict = field(default_factory=dict)
    cai_policy: dict | None = None
    cai_results: list | None = None
    cai_status: int = 200
    cai_warning: bool = False
    project_status: int = 200
    project_name: str = f"projects/{NUMBER}"
    ancestry: list = field(default_factory=lambda: [{"resourceId": {"type": "project", "id": NUMBER}}])
    ancestry_status: int = 200


class Session:
    def __init__(self, case):
        self.case = case
        self.calls = []

    def request(self, method, url, *, params, json, headers, timeout, allow_redirects):
        assert allow_redirects is False
        assert headers == {"Authorization": "Bearer inert-test-token"}
        assert timeout > 0
        self.calls.append((method, url, copy.deepcopy(params), copy.deepcopy(json)))
        case = self.case
        if url == f"{CRM}/v3/{SCOPE}" and method == "GET":
            return Response({"name": case.project_name, "projectId": SCOPE.split("/", 1)[1]}, case.project_status)
        if url == f"{COMPUTE}/compute/v1/{SCOPE}" and method == "GET":
            return Response({"name": SCOPE.split("/", 1)[1], "commonInstanceMetadata": {"fingerprint": "fixture"}})
        if url == f"{CRM}/v3/{SCOPE}:getIamPolicy" and method == "POST":
            assert json == {"options": {"requestedPolicyVersion": 3}}
            return Response(case.direct)
        if url == f"{CAI}/v1/{SCOPE}:searchAllIamPolicies" and method == "GET":
            results = case.cai_results
            if results is None:
                policy = case.cai_policy if case.cai_policy is not None else case.direct
                results = [{"resource": CAI_NAME,
                            "assetType": "cloudresourcemanager.googleapis.com/Project",
                            "project": f"projects/{NUMBER}", "policy": policy}]
            data = {"results": results}
            if case.cai_warning:
                data["warning"] = {"code": "PARTIAL_RESULTS"}
            return Response(data, case.cai_status)
        if url == f"{CRM}/v1/{SCOPE}:getAncestry" and method == "POST":
            assert json is None or json == {}
            return Response({"ancestor": case.ancestry}, case.ancestry_status)
        raise AssertionError(f"Unexpected native read: {method} {url}")

    def close(self):
        pass


def collect(case, *, owner_services=(), owner_rows=None):
    options = {"inventories": ["project", "iam_policy"], "concurrency": 1,
               "hydration_concurrency": 1, "metrics_scopes": False, "resource_iam": True}
    if owner_rows is None:
        owner_rows = [{"status": "approved", "scope": SCOPE, "service": service,
                       "source_ref": "reviewed-fixture-owner-input", "principals": [PRINCIPAL]}
                      for service in owner_services]
    options[OPTION] = owner_rows
    session = Session(case)
    transport = InertTransport(session)
    collector = gcp.GCPCollector({"auth": {}, "scopes": [SCOPE], "options": options},
                                 ["project", "iam_policy"], transport=transport)
    snapshot = collector.collect()
    assert transport.evidence == snapshot["metadata"]["source_requests"]
    return snapshot, session.calls


def findings(snapshot, check_id):
    return [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
            if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]


def status(snapshot, check_id):
    rows = findings(snapshot, check_id)
    assert rows, "A missing finding cannot establish a check outcome"
    return {row["status"] for row in rows if row["status"] != "NOT_APPLICABLE"}


def direct_finding(snapshot, check_id):
    envelope = next(row for row in snapshot["collections"] if row["type"] == "iam_policy" and row["scope"] == SCOPE)
    roots = [row for row in envelope["items"] if row.get("name") == SCOPE]
    assert len(roots) == 1
    native_id = resource_id("gcp", "iam_policy", SCOPE, roots[0])
    finding_id = digest(["gcp", SCOPE, "iam_policy", native_id])
    rows = [row for row in findings(snapshot, check_id) if row["resource_id"] == finding_id]
    assert len(rows) == 1
    return rows[0]


def complete_case(services=CHECK_SERVICES.values()):
    return Scenario(direct={"bindings": [], "auditConfigs": [config(service, kind)
                     for service in services for kind in ("DATA_READ", "DATA_WRITE")]})


def remake(snapshot, *, collections=None, metadata=None):
    return make_snapshot("gcp", snapshot["scopes"],
                         copy.deepcopy(snapshot["collections"] if collections is None else collections),
                         metadata=copy.deepcopy(snapshot["metadata"] if metadata is None else metadata))


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_verified_project_id_number_alias_passes_both_signed_checks(check_id):
    snapshot, calls = collect(complete_case(), owner_services=CHECK_SERVICES.values())
    assert ("GET", f"{CRM}/v3/{SCOPE}") in [(method, url) for method, url, _, _ in calls]
    assert ("POST", f"{CRM}/v3/{SCOPE}:getIamPolicy") in [(method, url) for method, url, _, _ in calls]
    assert ("GET", f"{CAI}/v1/{SCOPE}:searchAllIamPolicies") in [(method, url) for method, url, _, _ in calls]
    assert ("POST", f"{CRM}/v1/{SCOPE}:getAncestry") in [(method, url) for method, url, _, _ in calls]
    assert direct_finding(snapshot, check_id)["status"] == "PASS"
    assert len([row for row in findings(snapshot, check_id) if row["status"] == "NOT_APPLICABLE"]) == 1
    assert status(snapshot, check_id) == {"PASS"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("negative", ["missing_type", "exempt_principal"])
def test_verified_alias_preserves_real_failures(check_id, negative):
    service = CHECK_SERVICES[check_id]
    case = complete_case()
    if negative == "missing_type":
        case.direct["auditConfigs"] = [row for row in case.direct["auditConfigs"]
                                       if row["service"] != service or row["auditLogConfigs"][0]["logType"] != "DATA_WRITE"]
    else:
        for row in case.direct["auditConfigs"]:
            if row["service"] == service and row["auditLogConfigs"][0]["logType"] == "DATA_READ":
                row["auditLogConfigs"][0]["exemptedMembers"] = [PRINCIPAL]
    case.cai_policy = copy.deepcopy(case.direct)
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert direct_finding(snapshot, check_id)["status"] == "FAIL"
    assert status(snapshot, check_id) == {"FAIL"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_explicit_empty_cai_audit_configs_conflicts_with_direct(check_id):
    case = complete_case()
    case.cai_policy = {"bindings": [], "auditConfigs": []}
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_omitted_cai_policy_field_is_projection_without_assertion(check_id):
    case = complete_case()
    case.cai_policy = {}
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert status(snapshot, check_id) == {"PASS"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("change", ["denied_cai", "partial_cai", "malformed_cai", "missing_project_get",
                                     "ancestry_only", "missing_ancestry", "empty_ancestry", "missing_owner"])
def test_incomplete_native_authority_stays_unknown(check_id, change):
    case = complete_case()
    owner_services = tuple(CHECK_SERVICES.values())
    if change == "denied_cai":
        case.cai_status = 403
    elif change == "partial_cai":
        case.cai_warning = True
    elif change == "malformed_cai":
        case.cai_results = [{"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                             "project": f"projects/{NUMBER}", "policy": {"auditConfigs": "bad"}}]
    elif change in ("missing_project_get", "ancestry_only"):
        case.project_status = 403
    elif change == "missing_ancestry":
        case.ancestry_status = 403
    elif change == "empty_ancestry":
        case.ancestry = []
    elif change == "missing_owner":
        owner_services = ()
    snapshot, _ = collect(case, owner_services=owner_services)
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("change", ["wrong_method", "foreign_scope", "duplicate_request_id", "missing_request", "missing_metadata"])
def test_request_ledger_must_independently_bind_alias(check_id, change):
    snapshot, _ = collect(complete_case(), owner_services=CHECK_SERVICES.values())
    metadata = copy.deepcopy(snapshot["metadata"])
    ledger = metadata["source_requests"]
    project_get = next(row for row in ledger if row["url"] == f"{CRM}/v3/{SCOPE}")
    if change == "wrong_method":
        project_get["method"] = "POST"
    elif change == "foreign_scope":
        project_get["scope"] = "projects/foreign-project"
    elif change == "duplicate_request_id":
        ledger.append(copy.deepcopy(project_get))
    elif change == "missing_request":
        ledger.remove(project_get)
    else:
        metadata.pop("source_requests")
    assert status(remake(snapshot, metadata=metadata), check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_typed_resource_peer_does_not_claim_project_root(check_id):
    case = complete_case()
    case.cai_results = [{"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                         "project": f"projects/{NUMBER}", "policy": copy.deepcopy(case.direct)},
                        {"resource": "//storage.googleapis.com/projects/_/buckets/peer",
                         "assetType": "storage.googleapis.com/Bucket", "project": f"projects/{NUMBER}",
                         "policy": {"bindings": []}}]
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert status(snapshot, check_id) == {"PASS"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_uncertain_root_peer_prevents_certification(check_id):
    case = complete_case()
    case.cai_results = [{"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                         "project": f"projects/{NUMBER}", "policy": copy.deepcopy(case.direct)},
                        {"resource": "//mystery.googleapis.com/projects/12345/opaque",
                         "assetType": "unknown/Root", "project": f"projects/{NUMBER}",
                         "policy": {"bindings": []}}]
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("change", ["foreign_project_scope", "partial_project_collection",
                                     "missing_project_identity_field", "partial_policy_collection"])
def test_global_inventory_scope_and_field_gates(check_id, change):
    snapshot, _ = collect(complete_case(), owner_services=CHECK_SERVICES.values())
    collections = copy.deepcopy(snapshot["collections"])
    project = next(row for row in collections if row["type"] == "project")
    policy = next(row for row in collections if row["type"] == "iam_policy")
    if change == "foreign_project_scope":
        project["scope"] = "projects/foreign-project"
    elif change == "partial_project_collection":
        project["status"] = project["coverage_status"] = "partial"
    elif change == "missing_project_identity_field":
        project["items"][0].pop("projectId")
    else:
        policy["status"] = policy["coverage_status"] = "partial"
    assert status(remake(snapshot, collections=collections), check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_foreign_owner_principal_input_cannot_certify(check_id):
    rows = [{"status": "approved", "scope": SCOPE, "service": service,
             "source_ref": "reviewed-fixture-owner-input", "principals": [PRINCIPAL]}
            for service in CHECK_SERVICES.values()]
    for row in rows:
        if row["service"] == CHECK_SERVICES[check_id]:
            row["principals"] = ["group:auditors@example.test"]
    snapshot, _ = collect(complete_case(), owner_rows=rows)
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_conflicting_same_view_cai_duplicate_is_not_authoritative(check_id):
    case = complete_case()
    projection = {"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                  "project": f"projects/{NUMBER}", "policy": copy.deepcopy(case.direct)}
    contradictory = copy.deepcopy(projection)
    contradictory["policy"]["auditConfigs"] = []
    case.cai_results = [projection, contradictory]
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert status(snapshot, check_id) == {"UNKNOWN"}

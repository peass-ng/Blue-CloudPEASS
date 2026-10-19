# Historical archived-check predicate/collector contract; product selection rejects these IDs.
"""An inert root pair without a transport ledger stays conservatively UNKNOWN.

The real transport and verified alias path are covered by the separate project
alias pipeline tests. This fixture deliberately omits that authority.
"""

from threading import Lock

import pytest

from peaso.checks.gcp_data_access import CHECK_SERVICES
from peaso.collectors import gcp
from tests.gcp_archived_native_contract import evaluate_historical_snapshot
from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
from peaso.snapshot import make_snapshot
from test_peaso_gcp_data_access import config, owner


SCOPE = "projects/fixture-project"
NUMBER = "12345"
CAI_NAME = f"//cloudresourcemanager.googleapis.com/projects/{NUMBER}"


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_native_project_id_and_number_policy_views_are_currently_ambiguous(check_id):
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.lock = Lock()
    collector.max_items = None
    collector.seen_items = set()
    collector.total_items = 0
    collector.read_time = "2026-10-17T00:00:00Z"
    collector.needed = {"project", "iam_policy"}
    collector.options = {"metrics_scopes": False, "resource_iam": True}
    collector.api_key_alias_mode = False
    collector.allowed = None
    collector.ancestry = {SCOPE: [{"resourceId": {"type": "project", "id": NUMBER}}]}
    collector.ancestry_source_requests = {SCOPE: "ancestry-request"}
    collector.hydrate = lambda item, *_args, **_kwargs: item

    def pages(url, scope, **kwargs):
        assert scope == SCOPE
        if url.endswith(f"/v3/{SCOPE}"):
            assert kwargs["single"] is True
            yield ([{"name": f"projects/{NUMBER}", "projectId": "fixture-project"}], "project-request")
        elif url.endswith(f"/v3/{SCOPE}:getIamPolicy"):
            assert kwargs["method"] == "POST"
            yield ([{"auditConfigs": [config(service, "DATA_READ"), config(service, "DATA_WRITE")]}],
                   "direct-request")
        elif url.endswith(f"/v1/{SCOPE}:searchAllIamPolicies"):
            assert kwargs["key"] == "results"
            raw = {"resource": CAI_NAME, "assetType": "cloudresourcemanager.googleapis.com/Project",
                   "project": f"projects/{NUMBER}", "policy": {"bindings": []}}
            yield ([kwargs["transform"](raw)], "cai-request")
        else:
            raise AssertionError(url)

    collector.pages = pages
    jobs = {kind: (service_name, fetch) for kind, scope, service_name, fetch
            in collector.scope_jobs(SCOPE) if scope == SCOPE and kind in collector.needed}
    project = collector.envelope("project", SCOPE, *jobs["project"])
    policies = collector.envelope("iam_policy", SCOPE, *jobs["iam_policy"])
    collector.collections = {("project", SCOPE): project, ("iam_policy", SCOPE): policies}
    collector.annotate_effective_audit()

    assert project["status"] == "collected"
    assert project["items"][0]["projectId"] == "fixture-project"
    assert project["items"][0]["name"] == f"projects/{NUMBER}"
    assert project["items"][0]["_provenance"]["source_requests"] == ["project-request"]
    assert len(policies["items"]) == 2, policies
    direct = next(row for row in policies["items"] if row["name"] == SCOPE)
    cai = next(row for row in policies["items"] if row["name"] == CAI_NAME)
    assert direct["_provenance"]["source_requests"] == ["direct-request"]
    assert cai["_provenance"]["source_requests"] == ["cai-request"]
    assert direct["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"

    snapshot = make_snapshot("gcp", [SCOPE], [project, policies],
        metadata={OPTION: normalize_owner_policy([owner(service, SCOPE)], [SCOPE])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
                if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}, findings

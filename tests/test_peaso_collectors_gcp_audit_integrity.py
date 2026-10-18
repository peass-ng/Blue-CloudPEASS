"""Regression coverage for inherited GCP IAM audit-config collection integrity."""

from peaso.collectors import gcp


PROJECT = "projects/fixture"
FOLDER = "folders/12"
ORGANIZATION = "organizations/34"


def _policy(scope, configs=...):
    policy = {"name": scope, "_provenance": {"source_requests": [f"request:{scope}"]}}
    if configs is not ...:
        policy["auditConfigs"] = configs
    return policy


def _annotated_project(policies, ancestors):
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: [
        {"resourceId": {"type": kind, "id": identifier}}
        for kind, identifier in ancestors
    ]}
    collector.collections = {
        ("iam_policy", scope): {"items": [policy]}
        for scope, policy in policies.items()
    }
    collector.annotate_effective_audit()
    return collector.collections[("iam_policy", PROJECT)]["items"][0]


def test_complete_inherited_union_keeps_each_scope_and_request():
    project = [{"service": "spanner.googleapis.com", "auditLogConfigs": [{"logType": "DATA_WRITE"}]}]
    folder = [{"service": "pubsub.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
    organization = [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
    item = _annotated_project({
        PROJECT: _policy(PROJECT, project),
        FOLDER: _policy(FOLDER, folder),
        ORGANIZATION: _policy(ORGANIZATION, organization),
    }, [("folder", "12"), ("organization", "34")])

    assert item["effectiveAuditConfigs"] == [
        {"scope": scope, "auditConfigs": configs, "source_requests": [f"request:{scope}"]}
        for scope, configs in [(PROJECT, project), (FOLDER, folder), (ORGANIZATION, organization)]
    ]
    assert item["_coverage"]["effectiveAuditConfigs"] == {
        "status": "collected", "collection_status": "collected", "ancestry_known": True,
        "missing_scopes": [], "malformed_scopes": [],
        "ancestor_scopes": [FOLDER, ORGANIZATION], "ancestry_source_requests": [],
        "source_requests": sorted(f"request:{scope}" for scope in (PROJECT, FOLDER, ORGANIZATION)),
        "semantics": "Union of resource and ancestor auditConfigs (organization, folders, resource)",
    }


def test_malformed_ancestor_is_partial_and_raw_value_remains_visible():
    malformed = {"unexpected": "object"}
    item = _annotated_project({
        PROJECT: _policy(PROJECT, []),
        ORGANIZATION: _policy(ORGANIZATION, malformed),
    }, [("organization", "34")])

    coverage = item["_coverage"]["effectiveAuditConfigs"]
    assert coverage["status"] == coverage["collection_status"] == "partial"
    assert coverage["ancestry_known"] is True
    assert coverage["missing_scopes"] == []
    assert coverage["malformed_scopes"] == [ORGANIZATION]
    assert item["effectiveAuditConfigs"][1]["auditConfigs"] == malformed
    assert item["effectiveAuditConfigs"][1]["source_requests"] == [f"request:{ORGANIZATION}"]


def test_known_parentless_project_is_complete():
    configs = [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
    item = _annotated_project({PROJECT: _policy(PROJECT, configs)}, [])

    assert item["effectiveAuditConfigs"] == [
        {"scope": PROJECT, "auditConfigs": configs, "source_requests": [f"request:{PROJECT}"]}
    ]
    assert item["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"
    assert item["_coverage"]["effectiveAuditConfigs"]["malformed_scopes"] == []


def test_absent_audit_configs_is_legitimate_empty_policy():
    item = _annotated_project({PROJECT: _policy(PROJECT)}, [])

    assert item["effectiveAuditConfigs"][0]["auditConfigs"] == []
    coverage = item["_coverage"]["effectiveAuditConfigs"]
    assert coverage["status"] == "collected"
    assert coverage["missing_scopes"] == coverage["malformed_scopes"] == []


def test_denied_ancestor_stays_partial_with_missing_scope():
    item = _annotated_project({PROJECT: _policy(PROJECT, [])}, [("organization", "34")])

    assert [entry["scope"] for entry in item["effectiveAuditConfigs"]] == [PROJECT]
    coverage = item["_coverage"]["effectiveAuditConfigs"]
    assert coverage["status"] == "partial"
    assert coverage["ancestry_known"] is True
    assert coverage["missing_scopes"] == [ORGANIZATION]
    assert coverage["malformed_scopes"] == []

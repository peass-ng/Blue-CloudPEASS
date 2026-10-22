"""IAM optimizations retain full evidence, stable samples and scan isolation."""
import copy
import json

import pytest

from peaso.analysis import iam
from peaso.analysis.common import analysis_context
from peaso.snapshot import make_snapshot, resources


def snapshot(project="one", member="user:outside@example.com"):
    scope = f"projects/{project}"
    return make_snapshot("gcp", [scope], [{
        "type": "iam_policy", "scope": scope, "service": "iam", "status": "collected",
        "items": [{"name": f"{scope}/iamPolicy", "bindings": [
            {"role": "roles/viewer", "members": [member]},
            {"role": "roles/editor", "members": [member]},
        ]}],
    }], created_at="2026-01-01T00:00:00+00:00")


def test_trust_evidence_is_complete_shared_and_read_only_within_scan():
    snap = snapshot()
    rows = resources(snap)
    before = copy.deepcopy(snap)
    with analysis_context(snap):
        first = iam.review_findings(snap, rows)
        second = iam.review_findings(snap, rows)
        left = next(f["evidence"] for f in first if f["check_id"] == "analysis.principal_exposure")
        right = next(f["evidence"] for f in second if f["check_id"] == "analysis.principal_exposure")
        assert left["default_trusted_scopes"] == {"one": "scanned_scope"}
        assert left["default_trusted_scopes"] is right["default_trusted_scopes"]
        assert len(left["principals"]) == 2
        with pytest.raises(TypeError):
            left["default_trusted_scopes"]["injected"] = "scanned_scope"
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert snap == before


def test_trust_evidence_does_not_cross_scan_boundaries():
    results = []
    for project in ("one", "two"):
        snap = snapshot(project)
        with analysis_context(snap):
            results.append(next(f["evidence"]["default_trusted_scopes"]
                                for f in iam.review_findings(snap, resources(snap))
                                if f["check_id"] == "analysis.principal_exposure"))
    assert results == [{"one": "scanned_scope"}, {"two": "scanned_scope"}]


def test_policy_parsing_is_reused_across_grants_principals_and_graph(monkeypatch):
    scope = "111122223333/us-east-1"
    document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Principal": "*"}]}
    snap = make_snapshot("aws", [scope], [{
        "type": "iam_role", "scope": scope, "service": "iam", "status": "collected",
        "items": [{"RoleName": "reader", "Policy": json.dumps(document)}],
    }])
    rows = resources(snap)
    original, calls = iam.policy_documents, []

    def counted(data):
        calls.append(data)
        yield from original(data)

    monkeypatch.setattr(iam, "policy_documents", counted)
    with analysis_context(snap):
        expected = list(iam.principals(rows[0]))
        iam.grants(rows[0])
        graph = iam.build_iam(snap, rows)
        assert list(iam.principals(rows[0])) == expected
    assert len(calls) == 1
    assert any(e["type"] == "declared_grant" for e in graph["edges"])
    # Ad hoc callers still see mutations between calls outside an evaluation.
    row = copy.deepcopy(rows[0])
    assert list(iam.principals(row))
    row["data"]["Policy"] = {"Statement": []}
    assert list(iam.principals(row)) == []


def test_large_grant_sample_preserves_risk_order_and_ties():
    declared = [{"native_grant": i, "allowed_declaration": i % 4 != 0,
                 "severity": ("info", "low", "medium", "high", "critical")[i % 5],
                 "broad": i % 3 == 0, "conditional": i % 2 == 0}
                for i in range(1000)]
    card = iam.grant_card(declared, {"id": "role"})
    expected = sorted(declared, key=lambda g: (
        not g["allowed_declaration"], {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[g["severity"]],
        not g["broad"], g["conditional"]))[:iam.GRANT_SAMPLE]
    assert card["source_grants"] == expected
    assert card["grant_count"] == 1000
    assert sum(card["grant_summary"]["by_severity"].values()) == 1000
    assert card["grant_summary"]["allowed"] == 750
    assert card["grant_summary"]["broad"] == 334
    assert card["grant_summary"]["conditional"] == 500


def test_gcp_permissions_are_classified_once_without_losing_unknowns(monkeypatch):
    calls = []

    def classify(provider, permission):
        calls.append((provider, permission))
        return {"known": "high"}.get(permission)

    monkeypatch.setattr(iam, "permission_severity", classify)
    declared = iam.full_grants({"provider": "gcp", "data": {"includedPermissions": ["known", "unknown"]}})
    assert calls == [("gcp", "known"), ("gcp", "unknown")]
    assert [(g["severity"], g["criticality_state"]) for g in declared] == [("high", "rule_based"), ("info", "unknown")]

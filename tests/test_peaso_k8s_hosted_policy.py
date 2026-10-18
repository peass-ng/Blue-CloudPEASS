"""Private hosted intake contract for one explicit Kubernetes owner declaration."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from peaso.collectors.k8s import _owner_policy_metadata
from peaso.server.validation import validate_connector


SETTINGS = SimpleNamespace(auth_mode="cognito")
AUTH = {"method": "token", "server": "https://cluster.example.org", "token": "fixture-token",
        "cluster_id": "cluster-a"}
OBSERVED = "2026-10-13T10:00:00Z"
POLICY = {"cluster_id": "cluster-a", "observed_at": OBSERVED,
          "max_age_seconds": 300, "max_policy_items": 2,
          "system_namespaces": ["kube-system", "kube-public"]}


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr("peaso.collectors.k8s._public_server", lambda server: (server, "cluster.example.org"))


def validate(policy, provider="k8s", auth=None):
    options = {"compliance_policy": policy}
    validate_connector(provider, dict(AUTH if auth is None else auth), options, SETTINGS)
    return options


def test_exact_scoped_declaration_is_accepted_and_preserved():
    options = validate(deepcopy(POLICY))
    assert options["compliance_policy"] == POLICY
    metadata = _owner_policy_metadata(options, "cluster-a", OBSERVED)
    assert metadata["status"] == "collected"
    assert metadata["system_namespaces"] == POLICY["system_namespaces"]
    assert metadata["source"] == "operator-supplied"


def test_explicit_declaration_without_optional_expiry_is_accepted():
    policy = {key: deepcopy(value) for key, value in POLICY.items()
              if key not in {"observed_at", "max_age_seconds"}}
    options = validate(policy)
    assert options["compliance_policy"] == policy
    metadata = _owner_policy_metadata(options, "cluster-a", "2027-10-13T10:00:00Z")
    assert metadata["status"] == "collected"
    assert metadata["system_namespaces"] == policy["system_namespaces"]
    assert "observed_at" not in metadata and "max_age_seconds" not in metadata


def test_absent_policy_has_no_default_and_stale_policy_becomes_unknown():
    options = {}
    validate_connector("k8s", dict(AUTH), options, SETTINGS)
    assert options == {}
    assert _owner_policy_metadata(options, "cluster-a", OBSERVED)["status"] == "unknown"
    assert _owner_policy_metadata({"compliance_policy": POLICY}, "cluster-a", "2026-10-13T10:10:00Z")["status"] == "unknown"


@pytest.mark.parametrize("mutate", [
    lambda p: p.pop("cluster_id"),
    lambda p: p.update(cluster_id="cluster-b"),
    lambda p: p.pop("observed_at"),
    lambda p: p.pop("max_age_seconds"),
    lambda p: p.update(observed_at="2026-10-13"),
    lambda p: p.update(max_age_seconds=0),
    lambda p: p.update(max_age_seconds=31536001),
    lambda p: p.update(max_policy_items=1),
    lambda p: p.update(system_namespaces=[]),
    lambda p: p.update(system_namespaces=["kube-system", "kube-system"]),
    lambda p: p.update(system_namespaces=["bad_namespace"]),
    lambda p: p.update(unreviewed_owner_field=True),
])
def test_malformed_or_unbounded_declaration_is_rejected(mutate):
    policy = deepcopy(POLICY)
    mutate(policy)
    with pytest.raises(HTTPException) as error:
        validate(policy)
    assert error.value.status_code == 422


def test_foreign_provider_and_cluster_identity_are_rejected():
    with pytest.raises(HTTPException) as error:
        validate(deepcopy(POLICY), provider="gcp", auth={})
    assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        validate(deepcopy(POLICY), auth={**AUTH, "cluster_id": "cluster-b"})
    assert error.value.status_code == 422


def test_backup_policy_shape_remains_exact_for_aws():
    aws_auth = {"method": "access_keys", "aws_access_key_id": "fixture-key",
                "aws_secret_access_key": "fixture-secret"}
    backup = {"aws_backup_plan": {"applies_to": ["123456789012/us-east-1"],
                                  "required_frequency_hours": 24}}
    options = validate(backup, provider="aws", auth=aws_auth)
    assert options["compliance_policy"] == backup
    with pytest.raises(HTTPException) as error:
        validate({**backup, "system_namespaces": ["kube-system"]}, provider="aws", auth=aws_auth)
    assert error.value.status_code == 422

"""Hosted shared GCP identity must stay inside a customer's verified projects."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.gcp_platform import PLATFORM_EMAIL, PLATFORM_PROJECT, PROOF_VALUE, approved_project
from peaso.server.validation import auth_capabilities, validate_connector


LABEL = "hacktricks-cspm-0123456789abcdefabcd"
SETTINGS = SimpleNamespace(auth_mode="cognito", gcp_platform_sa_secret_arn="arn:aws:secretsmanager:us-east-1:202533532952:secret:fixture")


def project(ident, number, *, label=LABEL):
    return {"name": f"projects/{number}", "projectId": ident, "state": "ACTIVE",
            "labels": {label: PROOF_VALUE}}


def connector(scopes, *, discover=False):
    return {"provider": "gcp", "scopes": scopes,
            "auth": {"method": "platform-service-account", "project_proof_label": LABEL,
                     "sa_json": {"type": "service_account", "project_id": PLATFORM_PROJECT,
                                 "client_email": PLATFORM_EMAIL, "private_key": "fixture-only"}},
            "options": {"all_projects": discover, "inventories": ["project"]}}


def test_platform_mode_is_advertised_only_when_secret_is_configured():
    assert "platform-service-account" in auth_capabilities(SETTINGS)["gcp"]
    assert "platform-service-account" not in auth_capabilities(SimpleNamespace(auth_mode="cognito"))["gcp"]


def test_server_creates_proof_and_rejects_forgery_or_platform_project():
    auth = {"method": "platform-service-account"}
    validate_connector("gcp", auth, {"all_projects": True}, SETTINGS, scopes=["*"])
    assert auth["project_proof_label"].startswith("hacktricks-cspm-")
    with pytest.raises(HTTPException) as error:
        validate_connector("gcp", {"method": "platform-service-account", "project_proof_label": LABEL},
                           {"all_projects": True}, SETTINGS, scopes=["*"])
    assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        validate_connector("gcp", {"method": "platform-service-account"}, {}, SETTINGS,
                           scopes=[PLATFORM_PROJECT])
    assert error.value.status_code == 422
    with pytest.raises(HTTPException):
        validate_connector("gcp", {"method": "platform-service-account"}, {}, SETTINGS,
                           scopes=["folders/123456789"])


def test_platform_key_cannot_be_uploaded_as_a_customer_key():
    with pytest.raises(HTTPException) as error:
        validate_connector("gcp", {"method": "service-account", "sa_json": {
            "type": "service_account", "token_uri": "https://oauth2.googleapis.com/token",
            "client_email": PLATFORM_EMAIL}}, {}, SETTINGS, scopes=["customer-project"])
    assert error.value.status_code == 422


def test_discovery_keeps_only_projects_with_this_connectors_label():
    collector = GCPCollector(connector(["*"], discover=True), requirements=["project"], transport=object())
    own = project(PLATFORM_PROJECT, 100)
    customer = project("customer-project", 101)
    another_tenant = project("another-project", 102, label="hacktricks-cspm-11111111111111111111")
    collector.pages = lambda *args, **kwargs: iter([([own, customer, another_tenant], "request-1")])
    try:
        collector.discover()
        assert collector.scopes == ["projects/customer-project"]
        assert [item["projectId"] for item in collector.collections[("project", "discovery")]["items"]] == ["customer-project"]
        assert not collector.options["all_hierarchy"]
    finally:
        collector.hydration_pool.shutdown(wait=True)


def test_explicit_customer_project_requires_current_proof_before_collection():
    collector = GCPCollector(connector(["customer-project"]), requirements=["project"], transport=object())
    collector.read = lambda *args, **kwargs: (project("customer-project", 101, label="hacktricks-cspm-11111111111111111111"), "request-1")
    try:
        with pytest.raises(ReadError, match="selected_project_not_verified"):
            collector.discover()
    finally:
        collector.hydration_pool.shutdown(wait=True)


def test_platform_project_and_unverified_projects_are_never_approved():
    assert not approved_project(project(PLATFORM_PROJECT, 100), LABEL)
    assert not approved_project(project("another-project", 102, label="hacktricks-cspm-11111111111111111111"), LABEL)

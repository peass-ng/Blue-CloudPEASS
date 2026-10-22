"""Shared-flow escalation needs one runnable Apigee environment and hook."""

from types import SimpleNamespace

import pytest

from peaso.privesc.effective_permissions.gcp_apigee import sharedflow_hook_selector

PROJECT = "projects/p-one"
ORG = "organizations/own"
ENV = ORG + "/environments/standard"
TARGET = SimpleNamespace(scope=PROJECT, attrs={"email": "target@p-one.iam.gserviceaccount.com",
                                               "resource": PROJECT + "/serviceAccounts/target@p-one.iam.gserviceaccount.com"})


class Model:
    def __init__(self, *, deployment=True, deployment_state=None, runtime_type="CLOUD", env_type="PROXY", grants=None,
                 deployment_status="collected"):
        environment = {"name": ENV, "state": "ACTIVE", "deploymentType": env_type,
                       "_coverage": {"proxyDeployments": {"status": deployment_status}},
                       "_proxy_deployments": ([{"apiProxy": "customer-api", "environment": "standard",
                                                "revision": "1", "state": deployment_state}]
                                              if deployment else [])}
        self.snapshot = {"collections": [{"type": "apigee_organization", "scope": PROJECT,
                                          "status": "collected", "items": [{"name": ORG, "projectId": "p-one",
                                                                          "state": "ACTIVE", "runtimeType": runtime_type,
                                                                          "_coverage": {"apigee_environments": {"status": "collected"}},
                                                                          "_apigee_environments": [environment]}]}]}
        self.parents = {}
        self.project_alias = {"123": "p-one"}
        self.principals = {"serviceAccount:service-123@gcp-sa-apigee.iam.gserviceaccount.com": object()}
        self.grants = grants if grants is not None else {
            ("apigee.sharedflows.create", ORG),
            ("apigee.sharedflowrevisions.deploy", ORG + "/sharedflows/__new_sharedflow__/revisions/__new_revision__"),
            ("apigee.deployments.create", ENV),
            ("apigee.flowhooks.attachSharedFlow", ENV + "/flowhooks/PreProxyFlowHook"),
            ("iam.serviceAccounts.getAccessToken", TARGET.attrs["resource"]),
        }

    def _norm_scope(self, value):
        return value

    def check(self, principal, requirement, resource):
        if (requirement["action"], resource) in self.grants:
            return SimpleNamespace(confidence="derived")
        return None


def test_shared_flow_uses_one_standard_environment_with_deployed_proxy():
    result = sharedflow_hook_selector(Model(), True, {"target": TARGET}, object())
    assert result == {"target": ("conditional", "apigee_sharedflow_hook_on_deployed_proxy_environment")}


def test_empty_environment_is_unresolved_until_a_proxy_is_deployed():
    assert sharedflow_hook_selector(Model(deployment=False), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_denied_deployment_inventory_is_unresolved():
    assert sharedflow_hook_selector(Model(deployment_status="denied"), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_explicit_deployment_error_is_unresolved():
    assert sharedflow_hook_selector(Model(deployment_state="ERROR"), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_archive_environment_cannot_run_ordinary_shared_flow_deployment():
    assert sharedflow_hook_selector(Model(env_type="ARCHIVE"), True, {"target": TARGET}, object()) == {}


def test_hybrid_runtime_identity_must_not_be_invented():
    assert sharedflow_hook_selector(Model(runtime_type="HYBRID"), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_unrelated_hook_permission_cannot_attach_to_selected_environment():
    grants = Model().grants - {("apigee.flowhooks.attachSharedFlow", ENV + "/flowhooks/PreProxyFlowHook")}
    grants.add(("apigee.flowhooks.attachSharedFlow", ORG + "/environments/other/flowhooks/PreProxyFlowHook"))
    assert sharedflow_hook_selector(Model(grants=grants), True, {"target": TARGET}, object()) == {}


@pytest.mark.parametrize("environment_policy", [False, True])
def test_catalog_entry_joins_project_or_environment_hook_grants(environment_policy):
    from peaso import privesc
    from peaso.privesc.evaluator import Evaluator
    from peaso.privesc.effective_permissions.gcp import GcpModel

    user = "user:operator@example.com"
    agent = "serviceAccount:service-123@gcp-sa-apigee.iam.gserviceaccount.com"
    author_role = PROJECT + "/roles/sharedflowAuthor"
    env_role = PROJECT + "/roles/flowHookDeployer"
    author_permissions = ["apigee.sharedflows.create", "apigee.sharedflowrevisions.deploy",
                          "iam.serviceAccounts.actAs"]
    env_permissions = ["apigee.deployments.create", "apigee.flowhooks.attachSharedFlow"]
    if not environment_policy:
        author_permissions += env_permissions
    environment = {"name": ENV, "state": "ACTIVE", "deploymentType": "PROXY",
                   "_coverage": {"proxyDeployments": {"status": "collected"}},
                   "_proxy_deployments": [{"apiProxy": "customer-api", "environment": "standard", "revision": "1"}]}
    if environment_policy:
        environment["iamPolicy"] = {"bindings": [{"role": env_role, "members": [user]}]}
        environment["_coverage"]["iamPolicy"] = {"status": "collected"}
    collections = [
        ("project", [{"projectId": "p-one", "name": "projects/123"}]),
        ("iam_role", [{"name": author_role, "includedPermissions": author_permissions},
                      {"name": env_role, "includedPermissions": env_permissions}]),
        ("iam_policy", [{"name": PROJECT, "bindings": [{"role": author_role, "members": [user]}]}]),
        ("service_account", [{"email": TARGET.attrs["email"], "projectId": "p-one",
                              "iamPolicy": {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator",
                                                         "members": [agent]}]}}]),
        ("apigee_organization", [{"name": ORG, "projectId": "p-one", "state": "ACTIVE",
                                  "runtimeType": "CLOUD",
                                  "_coverage": {"apigee_environments": {"status": "collected"}},
                                  "_apigee_environments": [environment]}]),
        ("iam_deny_policy", []),
    ]
    snapshot = {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
                "collections": [{"type": kind, "scope": PROJECT, "status": "collected" if values else "empty",
                                 "items": values} for kind, values in collections], "metadata": {}}
    entry = next(row for row in privesc.catalog()["entries"]
                 if row["id"] == "gcp-apigee-sharedflow-flowhook-with-sa-actas")
    reaches = Evaluator(GcpModel(snapshot), [entry]).run()
    assert any(reach.source.id == user and "serviceAccount:" + TARGET.attrs["email"] in reach.targets
               and reach.targets["serviceAccount:" + TARGET.attrs["email"]].confidence == "conditional"
               for reach in reaches)

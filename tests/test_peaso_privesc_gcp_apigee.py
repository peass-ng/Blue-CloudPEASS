"""The Apigee proxy route must join one organization, environment, and runtime SA."""

from types import SimpleNamespace

import pytest

from peaso.privesc.effective_permissions.gcp_apigee import proxy_deploy_selector


PROJECT = "projects/p-one"
ORG = "organizations/own"
ENV = ORG + "/environments/standard"
TARGET = SimpleNamespace(scope=PROJECT, attrs={"email": "target@p-one.iam.gserviceaccount.com",
                                               "resource": PROJECT + "/serviceAccounts/target@p-one.iam.gserviceaccount.com"})


class Model:
    def __init__(self, *, deployment_type="PROXY", environment_status="collected", grants=None,
                 inventory="collected", runtime_type="CLOUD"):
        self.snapshot = {"collections": [{"type": "apigee_organization", "scope": PROJECT, "status": inventory,
                                          "items": [{"name": ORG, "projectId": "p-one", "state": "ACTIVE",
                                                     "runtimeType": runtime_type,
                                                     "_coverage": {"apigee_environments": {"status": environment_status}},
                                                     "_apigee_environments": [{"name": ENV, "state": "ACTIVE",
                                                                                "deploymentType": deployment_type}]}]}]}
        self.parents = {}
        self.project_alias = {"123": "p-one"}
        self.principals = {"serviceAccount:service-123@gcp-sa-apigee.iam.gserviceaccount.com": object()}
        self.grants = grants if grants is not None else {
            ("apigee.proxies.create", ORG),
            ("apigee.proxyrevisions.deploy", ORG + "/apis/__new_proxy__/revisions/__new_revision__"),
            ("apigee.deployments.create", ENV),
            ("iam.serviceAccounts.getAccessToken", TARGET.attrs["resource"]),
        }

    def _norm_scope(self, value):
        return value

    def check(self, principal, requirement, resource):
        if (requirement["action"], resource) in self.grants:
            return SimpleNamespace(confidence="derived")
        return None


def test_exact_standard_environment_and_runtime_delegation_produces_conditional_path():
    result = proxy_deploy_selector(Model(), True, {"target": TARGET}, object())
    assert result == {"target": ("conditional", "apigee_proxy_deploys_in_standard_environment_with_runtime_token_access")}


def test_archive_environment_does_not_produce_proxy_escalation_path():
    assert proxy_deploy_selector(Model(deployment_type="ARCHIVE"), True, {"target": TARGET}, object()) == {}


def test_missing_runtime_delegation_is_unresolved_instead_of_confirmed():
    grants = Model().grants - {("iam.serviceAccounts.getAccessToken", TARGET.attrs["resource"])}
    assert proxy_deploy_selector(Model(grants=grants), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_hybrid_runtime_is_unresolved_even_if_managed_agent_has_token_grant():
    assert proxy_deploy_selector(Model(runtime_type="HYBRID"), True, {"target": TARGET}, object())["target"][0] == "unknown"


def test_known_standard_environment_survives_other_environment_read_denial():
    assert proxy_deploy_selector(Model(environment_status="denied"), True, {"target": TARGET}, object())["target"][0] == "conditional"


def test_grants_on_other_environment_cannot_satisfy_deployment():
    grants = Model().grants - {("apigee.deployments.create", ENV)}
    grants.add(("apigee.deployments.create", ORG + "/environments/other"))
    assert proxy_deploy_selector(Model(grants=grants), True, {"target": TARGET}, object()) == {}


@pytest.mark.parametrize("mode", ["project", "environment", "update_only"])
def test_catalog_entry_uses_exact_apigee_grants_and_runtime_agent(mode):
    from peaso import privesc
    from peaso.privesc.evaluator import Evaluator
    from peaso.privesc.effective_permissions.gcp import GcpModel

    role = PROJECT + "/roles/apigeeDeployer"
    environment_role = PROJECT + "/roles/apigeeEnvironmentDeployer"
    user = "user:operator@example.com"
    agent = "serviceAccount:service-123@gcp-sa-apigee.iam.gserviceaccount.com"
    main_permissions = ["apigee.proxies.create" if mode != "update_only" else "apigee.proxies.update",
                        "apigee.proxyrevisions.deploy", "iam.serviceAccounts.actAs"]
    if mode != "environment":
        main_permissions.append("apigee.deployments.create")
    environment = {"name": ENV, "state": "ACTIVE", "deploymentType": "PROXY"}
    if mode == "environment":
        environment.update(iamPolicy={"bindings": [{"role": environment_role, "members": [user]}]},
                           _coverage={"iamPolicy": {"status": "collected"}})
    collections = [
        ("project", [{"projectId": "p-one", "name": "projects/123"}]),
        ("iam_role", [{"name": role, "includedPermissions": main_permissions},
                      {"name": environment_role, "includedPermissions": ["apigee.deployments.create"]}]),
        ("iam_policy", [{"name": PROJECT, "bindings": [{"role": role, "members": [user]}]}]),
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
                 if row["id"] == "gcp-apigee-proxy-deploy-with-sa-actas")
    model = GcpModel(snapshot)
    if mode == "environment":
        assert model.check(model.principals[user], {"action": "apigee.deployments.create"}, ENV), model.grants.get(user)
    reaches = Evaluator(model, [entry]).run()
    reached = [reach for reach in reaches if reach.source.id == user
               and "serviceAccount:" + TARGET.attrs["email"] in reach.targets]
    if mode == "update_only":
        assert not reached
    else:
        assert reached and reached[0].targets["serviceAccount:" + TARGET.attrs["email"]].confidence == "conditional"

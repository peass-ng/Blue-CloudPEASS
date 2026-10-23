"""Eventarc OAuth-token paths require a usable route and token-minting agent."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@example.com"
SA = "target@p1.iam.gserviceaccount.com"
AGENT = "serviceAccount:service-123@gcp-sa-eventarc.iam.gserviceaccount.com"
BUS = PROJECT + "/locations/us-central1/messageBuses/b1"
ENROLLMENT = PROJECT + "/locations/us-central1/enrollments/e1"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-eventarc-pipeline-oauth-token-actas")


def case(*, route="create", bus=True, bus_policy=True, enrollment=True,
         agent=True, pipeline=True, actas=True, publishing=True):
    role = PROJECT + "/roles/pipelineWriter"
    permissions = (["eventarc.pipelines.create"] if pipeline else []) + (
        ["iam.serviceAccounts.actAs"] if actas else [])
    if route == "create":
        permissions += ["eventarc.enrollments.create", "eventarc.messageBuses.use"]
    elif route == "update":
        permissions += ["eventarc.enrollments.update"]
    elif route == "new_bus":
        permissions += ["eventarc.enrollments.create", "eventarc.messageBuses.create",
                        "eventarc.messageBuses.use", "eventarc.messageBuses.publish"]
    buses = ([{"name": BUS, "iamPolicy": {"bindings": []} if bus_policy else {"collection_status": "denied"},
              "_coverage": {"iamPolicy": {"status": "collected" if bus_policy else "denied"}}}]
             if bus else [])
    enrollments = ([{"name": ENROLLMENT, "messageBus": BUS,
                     "destination": PROJECT + "/locations/us-central1/pipelines/old",
                     "iamPolicy": {"bindings": []},
                     "_coverage": {"iamPolicy": {"status": "collected"}}}]
                   if enrollment and route == "update" else [])
    collections = [
        ("project", PROJECT, [{"name": "projects/123", "projectId": "p1"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role, "members": [SOURCE]},
            *([{"role": "roles/eventarc.serviceAgent", "members": [AGENT]}] if agent else [])]}]),
        ("iam_role", PROJECT, [{"name": role, "includedPermissions": permissions}]),
        ("iam_role_builtin", PROJECT, [{"name": "roles/eventarc.serviceAgent",
                                        "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}]),
        ("service_account", PROJECT, [{"name": PROJECT + "/serviceAccounts/" + SA,
                                        "email": SA, "projectId": "p1"}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("eventarc_message_bus", PROJECT, buses, "collected" if buses else "empty"),
        ("eventarc_enrollment", PROJECT, enrollments, "collected" if enrollments else "empty"),
        ("service_usage", PROJECT, [{"name": PROJECT + "/services/eventarcpublishing.googleapis.com",
                                     "state": "ENABLED"}] if publishing else [], "collected" if publishing else "empty"),
    ]
    model = GcpModel(snapshot("gcp", collections))
    return {target: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()}


def test_existing_bus_and_enrollment_create_enable_conditional_token_path():
    assert case() == {"serviceAccount:" + SA: "conditional"}


def test_pipeline_and_actas_alone_cannot_route_an_event():
    assert case(route="none") == {}
    assert case(pipeline=False) == {}
    assert case(actas=False) == {}
    assert "conditional" not in case(agent=False).values()


def test_existing_enrollment_update_is_an_alternative_route():
    assert case(route="update") == {"serviceAccount:" + SA: "conditional"}
    assert case(route="update", enrollment=False) == {}
    assert case(route="update", bus=False) == {}


def test_new_bus_route_needs_publishing_service():
    assert case(route="new_bus", bus=False) == {"serviceAccount:" + SA: "conditional"}
    assert "conditional" not in case(route="new_bus", bus=False, publishing=False).values()


def test_unreadable_bus_policy_is_unresolved():
    assert "conditional" not in case(bus_policy=False).values()


def test_cross_project_sa_requires_explicit_source_and_agent_grants():
    other = "projects/p2"
    email = "target@p2.iam.gserviceaccount.com"
    role = PROJECT + "/roles/pipelineWriter"
    sa_policy = {"bindings": [
        {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]},
        {"role": "roles/iam.serviceAccountTokenCreator", "members": [AGENT]}]}
    collections = [
        ("project", PROJECT, [{"name": "projects/123", "projectId": "p1"}]),
        ("project", other, [{"name": "projects/456", "projectId": "p2"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role, "members": [SOURCE]},
            {"role": "roles/eventarc.serviceAgent", "members": [AGENT]}]}]),
        ("iam_policy", other, [{"name": other, "bindings": []}]),
        ("iam_role", PROJECT, [{"name": role, "includedPermissions": [
            "eventarc.pipelines.create", "eventarc.enrollments.create", "eventarc.messageBuses.use"]}]),
        ("iam_role", other, [], "empty"),
        ("iam_role_builtin", PROJECT, [
            {"name": "roles/eventarc.serviceAgent", "includedPermissions": ["iam.serviceAccounts.getAccessToken"]},
            {"name": "roles/iam.serviceAccountUser", "includedPermissions": ["iam.serviceAccounts.actAs"]},
            {"name": "roles/iam.serviceAccountTokenCreator", "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}]),
        ("service_account", other, [{"name": other + "/serviceAccounts/" + email,
                                     "email": email, "projectId": "p2", "iamPolicy": sa_policy}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("iam_deny_policy", other, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("org_policy_effective", other, [{"constraint": "iam.disableCrossProjectServiceAccountUsage",
                                          "spec": {"rules": [{"enforce": False}]}}]),
        ("eventarc_message_bus", PROJECT, [{"name": BUS, "iamPolicy": {"bindings": []},
                                             "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        ("eventarc_enrollment", PROJECT, [], "empty"),
    ]
    model = GcpModel(snapshot("gcp", collections))
    got = {target: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
           if reach.source.id == SOURCE for target, grant in reach.targets.items()}
    assert got == {"serviceAccount:" + email: "conditional"}
    sa_policy["bindings"].pop()
    model = GcpModel(snapshot("gcp", collections))
    assert "conditional" not in {grant.confidence for reach in Evaluator(model, [ENTRY]).run()
                                 if reach.source.id == SOURCE for grant in reach.targets.values()}
    sa_policy["bindings"].append({"role": "roles/iam.serviceAccountTokenCreator", "members": [AGENT]})
    next(rows for kind, scope, rows, *_ in collections
         if kind == "org_policy_effective" and scope == other)[0]["spec"]["rules"][0]["enforce"] = True
    model = GcpModel(snapshot("gcp", collections))
    assert "conditional" not in {grant.confidence for reach in Evaluator(model, [ENTRY]).run()
                                 if reach.source.id == SOURCE for grant in reach.targets.values()}

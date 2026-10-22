"""A new MIG pivot needs one feasible template, network, and service agent."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
AGENT = "serviceAccount:123@cloudservices.gserviceaccount.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instancetemplates-mig-actas")


def case(*, source_create=True, agent_actas=True, agent_metadata=True,
         images=True, subnets=True):
    common = ["compute.instanceTemplates.get", "compute.instances.create",
              "compute.instances.setMetadata", "compute.disks.create",
              "compute.images.useReadOnly", "compute.subnetworks.use",
              "compute.subnetworks.useExternalIp"]
    caller = {"name": PROJECT + "/roles/migCaller", "includedPermissions": common +
              (["compute.instanceTemplates.create", "compute.instanceGroupManagers.create"]
               if source_create else [])}
    agent = {"name": PROJECT + "/roles/migAgent", "includedPermissions":
             [p for p in common if agent_metadata or p != "compute.instances.setMetadata"] +
             ["compute.instances.setServiceAccount"]}
    bindings = [{"role": caller["name"], "members": [SOURCE]},
                {"role": agent["name"], "members": [AGENT]}]
    if agent_actas:
        bindings.append({"role": "roles/iam.serviceAccountUser", "members": [AGENT]})
    image = {"name": "boot", "selfLink": BASE + "projects/p1/global/images/boot", "status": "READY"}
    subnet = {"name": "default", "selfLink": BASE + "projects/p1/regions/us-central1/subnetworks/default",
              "purpose": "PRIVATE", "state": "READY"}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [caller, agent]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("image", PROJECT, [image] if images else [], "collected" if images else "empty"),
        ("subnetwork", PROJECT, [subnet] if subnets else [], "collected" if subnets else "empty"),
        ("iam_deny_policy", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_new_mig_path_needs_creator_agent_and_viable_boot_network():
    assert case() == [(TARGET, "conditional")]
    assert case(source_create=False) == []
    assert case(agent_actas=False) == []
    assert case(agent_metadata=False)[0][1] == "unknown"
    assert case(images=False)[0][1] == "unknown"
    assert case(subnets=False)[0][1] == "unknown"


def test_cross_project_mig_service_account_remains_unresolved():
    common = ["compute.instanceTemplates.create", "compute.instanceGroupManagers.create",
              "compute.instanceTemplates.get", "compute.instances.create",
              "compute.instances.setMetadata", "compute.disks.create",
              "compute.images.useReadOnly", "compute.subnetworks.use",
              "compute.subnetworks.useExternalIp"]
    role = {"name": PROJECT + "/roles/migCaller", "includedPermissions": common}
    other = "projects/p2"
    other_email = "target@p2.iam.gserviceaccount.com"
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("project", other, [{"projectId": "p2", "name": "projects/456"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role["name"], "members": [SOURCE]},
            {"role": "roles/compute.instanceGroupManagerServiceAgent", "members": [AGENT]}]}]),
        ("iam_policy", other, [{"name": other, "bindings": [
            {"role": "roles/iam.serviceAccountUser", "members": [AGENT]}]}]),
        ("iam_role", PROJECT, [role]),
        ("service_account", PROJECT, []),
        ("service_account", other, [{"email": other_email, "projectId": "p2"}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("iam_deny_policy", other, [], "empty")])
    result = [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
              if reach.source.id == SOURCE for tid, grant in reach.targets.items()]
    assert len(result) == 1
    assert result[0][0].startswith("unresolved:gcp_service_account:")
    assert result[0][0].endswith(":" + other)
    assert result[0][1] == "unknown"

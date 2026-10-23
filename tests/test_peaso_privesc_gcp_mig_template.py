"""A MIG template pivot needs a concrete group, runnable rollout, and service-agent grant."""

from __future__ import annotations

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
TARGET_EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + TARGET_EMAIL
AGENT = "serviceAccount:123@cloudservices.gserviceaccount.com"
BASE = "https://www.googleapis.com/compute/v1/"


def _case():
    role = {"name": "projects/p1/roles/migUpdater", "includedPermissions": [
        "compute.instanceGroupManagers.update", "compute.instanceTemplates.create",
        "compute.instanceTemplates.useReadOnly", "compute.instances.create",
        "compute.instances.setMetadata", "compute.disks.create",
        "compute.images.useReadOnly", "compute.subnetworks.use"]}
    policy = {"name": PROJECT, "bindings": [
        {"role": role["name"], "members": [SOURCE]},
        {"role": "roles/iam.serviceAccountUser", "members": [AGENT]}]}
    template = {"name": "base", "selfLink": BASE + "projects/p1/global/instanceTemplates/base",
                "properties": {"serviceAccounts": [{"email": TARGET_EMAIL}],
                               "disks": [{"initializeParams": {"sourceImage": BASE + "projects/p1/global/images/base"}}],
                               "networkInterfaces": [{"subnetwork": BASE + "projects/p1/regions/us-central1/subnetworks/default"}]}}
    mig = {"name": "production", "selfLink": BASE + "projects/p1/zones/us-central1-a/instanceGroupManagers/production",
           "instanceTemplate": template["selfLink"], "targetSize": 2,
           "updatePolicy": {"type": "PROACTIVE"}}
    return role, policy, template, mig


def test_existing_mig_template_pivot_requires_exact_runtime_and_permissions():
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-compute-instancegroupmanagers-update-template")
    role, policy, template, mig = _case()

    def result(migs=None):
        snap = snapshot("gcp", [
            ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
            ("iam_policy", PROJECT, [policy]), ("iam_role", PROJECT, [role]),
            ("service_account", PROJECT, [{"email": TARGET_EMAIL, "projectId": "p1"}]),
            ("instance_template", PROJECT, [template]),
            ("instance_group_manager", PROJECT, [mig] if migs is None else migs),
            ("iam_deny_policy", PROJECT, [], "empty")])
        return [(tid, g.confidence) for reach in Evaluator(GcpModel(snap), [entry]).run()
                if reach.source.id == SOURCE for tid, g in reach.targets.items()]

    assert result() == [(TARGET, "conditional")]
    assert result([]) == []
    mig.pop("instanceTemplate")
    mig["versions"] = [{"instanceTemplate": template["selfLink"]}]
    assert result() == [(TARGET, "conditional")]
    mig["instanceTemplate"] = template["selfLink"]
    mig.pop("versions")
    mig["targetSize"] = 0
    assert len(result()) == 1 and result()[0][1] == "unknown"
    mig["targetSize"] = 2
    mig["instanceTemplate"] = BASE + "projects/p1/global/instanceTemplates/missing"
    assert len(result()) == 1 and result()[0][1] == "unknown"
    mig["instanceTemplate"] = template["selfLink"]
    role["includedPermissions"].remove("compute.instances.setMetadata")
    assert len(result()) == 1 and result()[0][1] == "unknown"
    role["includedPermissions"].append("compute.instances.setMetadata")
    policy["bindings"][1]["role"] = "roles/viewer"
    assert result() == []
    policy["bindings"][1]["role"] = "roles/iam.serviceAccountUser"
    role["includedPermissions"].remove("compute.instanceGroupManagers.update")
    assert result() == []

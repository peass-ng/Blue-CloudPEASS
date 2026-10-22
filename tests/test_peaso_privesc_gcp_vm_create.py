"""A direct VM pivot needs a concrete boot and network configuration."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/projects/p1/"


def test_vm_create_needs_attachable_sa_and_concrete_image_and_subnet():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-create-actas")
    role = {"name": "projects/p1/roles/vmCreator", "includedPermissions": [
        "compute.instances.create", "compute.disks.create", "compute.instances.setMetadata",
        "compute.instances.setServiceAccount", "compute.subnetworks.use",
        "compute.subnetworks.useExternalIp", "compute.images.useReadOnly"]}
    policy = {"name": PROJECT, "bindings": [
        {"role": role["name"], "members": [SOURCE]},
        {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}]}
    image = {"name": "base", "status": "READY", "selfLink": BASE + "global/images/base",
             "_coverage": {"iamPolicy": {"status": "collected"}}, "iamPolicy": {"bindings": []}}
    subnet = {"name": "subnet", "purpose": "PRIVATE", "state": "READY",
              "selfLink": BASE + "regions/us-central1/subnetworks/subnet"}

    def result(images=None, subnets=None):
        snap = snapshot("gcp", [
            ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
            ("iam_policy", PROJECT, [policy]), ("iam_role", PROJECT, [role]),
            ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
            ("image", PROJECT, [image] if images is None else images),
            ("subnetwork", PROJECT, [subnet] if subnets is None else subnets),
            ("iam_deny_policy", PROJECT, [], "empty")])
        return [(tid, g.confidence) for reach in Evaluator(GcpModel(snap), [entry]).run()
                if reach.source.id == SOURCE for tid, g in reach.targets.items()]

    assert result() == [(TARGET, "conditional")]
    assert len(result(images=[])) == 1 and result(images=[])[0][1] == "unknown"
    assert len(result(subnets=[])) == 1 and result(subnets=[])[0][1] == "unknown"
    role["includedPermissions"].remove("compute.subnetworks.useExternalIp")
    assert len(result()) == 1 and result()[0][1] == "unknown"
    role["includedPermissions"].remove("compute.instances.create")
    assert result() == []

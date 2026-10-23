"""Captured GKE bare status.image format with exact immutable imageID binding."""
from copy import deepcopy

from peaso import k8s_image_source_association_20261020 as reviewed
from peaso import k8s_image_source_association_current_20261023 as current


DIGEST = "sha256:" + "a" * 64
IMAGE = "europe-west3-docker.pkg.dev/k8s-artifacts-prod/images/pause@" + DIGEST
LOCAL_HASH = "sha256:" + "b" * 64


def case():
    selection = {"cluster_id": "projects/test/locations/us-central1-a/clusters/owned",
                 "api_version": "v1", "kind": "Pod", "namespace": "owned", "name": "qa-image",
                 "uid": "pod-uid", "container_type": "regular", "container_name": "pause"}
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"namespace": "owned", "name": "qa-image", "uid": "pod-uid", "resourceVersion": "42"},
           "spec": {"containers": [{"name": "pause", "image": IMAGE}]},
           "status": {"containerStatuses": [{"name": "pause", "image": LOCAL_HASH,
               "imageID": IMAGE, "containerID": "containerd://owned-instance", "restartCount": 0,
               "ready": True, "state": {"running": {"startedAt": "2026-10-23T18:00:00Z"}}}]}}
    return selection, pod


def resolve(selection, pod):
    return current.resolve_image_source(selection, pod, cluster_id=selection["cluster_id"])


def test_bare_runtime_hash_uses_only_exact_immutable_spec_and_qualified_image_id():
    selected, pod = case()
    assert reviewed.resolve_image_source(selected, pod, cluster_id=selected["cluster_id"])["status"] == "mismatch"
    result = resolve(selected, pod)
    assert result["status"] == "associated"
    assert result["immutable_reference"] == IMAGE
    assert result["native_status_image"] == LOCAL_HASH
    assert result["status_image_binding"] == "exact_immutable_spec_and_qualified_image_id"
    assert pod["status"]["containerStatuses"][0]["image"] == LOCAL_HASH


def test_foreign_repository_with_same_digest_stays_mismatch():
    selected, pod = case()
    pod["status"]["containerStatuses"][0]["imageID"] = "foreign.example/team/pause@" + DIGEST
    assert resolve(selected, pod)["status"] == "mismatch"


def test_different_image_id_digest_stays_unresolved():
    selected, pod = case()
    pod["status"]["containerStatuses"][0]["imageID"] = IMAGE.replace(DIGEST, "sha256:" + "c" * 64)
    assert resolve(selected, pod)["status"] != "associated"


def test_tag_only_spec_and_foreign_uid_cannot_use_bare_hash():
    selected, pod = case()
    tagged = deepcopy(pod)
    tagged["spec"]["containers"][0]["image"] = IMAGE.split("@")[0] + ":3.9"
    assert resolve(selected, tagged)["status"] != "associated"
    selected["uid"] = "foreign-uid"
    assert resolve(selected, pod)["status"] == "mismatch"

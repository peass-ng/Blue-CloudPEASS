"""Current Pod image association for kubelet bare-digest status aliases.

The reviewed 20261020 association stays authoritative for identity, owner,
container state, repository, and digest checks. Some GKE runtimes report a
local ``sha256:...`` image identifier in status.image while imageID carries
the qualified immutable registry reference. The local hash does not identify
a repository; only an exact spec/imageID match permits the reviewed resolver
to consume the qualified reference.
"""
from copy import deepcopy
import re

from peaso import k8s_image_source_association_20261020 as reviewed


_BARE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATUS_FIELDS = {"regular": ("containers", "containerStatuses"),
                  "init": ("initContainers", "initContainerStatuses"),
                  "ephemeral": ("ephemeralContainers", "ephemeralContainerStatuses")}


def _unique_named(rows, name):
    if type(rows) is not list:
        return None
    matches = [row for row in rows if type(row) is dict and row.get("name") == name]
    return matches[0] if len(matches) == 1 else None


def resolve_image_source(selection, pod, *, cluster_id, **kwargs):
    result = reviewed.resolve_image_source(selection, pod, cluster_id=cluster_id, **kwargs)
    if (result.get("status") != "mismatch"
            or result.get("reason") != "registry_alias_or_repository_mismatch"
            or type(selection) is not dict or selection.get("kind") != "Pod"
            or type(pod) is not dict or type(pod.get("spec")) is not dict
            or type(pod.get("status")) is not dict
            or selection.get("container_type") not in _STATUS_FIELDS):
        return result
    spec_field, status_field = _STATUS_FIELDS[selection["container_type"]]
    declared = _unique_named(pod["spec"].get(spec_field), selection.get("container_name"))
    observed = _unique_named(pod["status"].get(status_field), selection.get("container_name"))
    if declared is None or observed is None:
        return result
    local_hash, image_id = observed.get("image"), observed.get("imageID")
    if type(local_hash) is not str or not _BARE_DIGEST.fullmatch(local_hash) or type(image_id) is not str:
        return result
    qualified = image_id.removeprefix("docker-pullable://")
    declared_ref = declared.get("image")
    if type(declared_ref) is not str or qualified != declared_ref:
        return result
    try:
        desired = reviewed.parse_image_reference(declared_ref)
    except ValueError:
        return result
    if not desired.explicit_registry or desired.digest is None or desired.immutable_reference != declared_ref:
        return result
    normalized = deepcopy(pod)
    row = _unique_named(normalized["status"].get(status_field), selection["container_name"])
    row["image"] = qualified
    accepted = reviewed.resolve_image_source(selection, normalized, cluster_id=cluster_id, **kwargs)
    if accepted.get("status") == "associated":
        accepted["native_status_image"] = local_hash
        accepted["status_image_binding"] = "exact_immutable_spec_and_qualified_image_id"
        return accepted
    return result

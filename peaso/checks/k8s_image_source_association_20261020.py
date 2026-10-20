"""Pure, bounded association of selected native declarations and Pod image status.

Accept decoded Kubernetes JSON, never sanitized inventory or SDK attributes. No
reader, credential provider, registry client, scanner, or registered control lives
here. A successful association reports what one Pod status said, not effective
deployment, registry authorization, verified manifest bytes, or secret coverage.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
import re


SCHEMA = "k8s-image-source-association-v1"
MAX_CONTAINERS = 128
MAX_OWNER_REFERENCES = 8
MAX_IMAGE_LENGTH = 1024
_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_REPOSITORY = re.compile(
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z"
)
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\Z")
_CONTAINER_ID = re.compile(r"[a-z][a-z0-9+.-]{0,31}://[A-Za-z0-9_.:-]{1,256}\Z")
_GROUPS = {
    "regular": ("containers", "containerStatuses"),
    "init": ("initContainers", "initContainerStatuses"),
    "ephemeral": ("ephemeralContainers", "ephemeralContainerStatuses"),
}
_PATHS = {
    ("v1", "Pod"): ("spec",),
    ("v1", "PodTemplate"): ("template", "spec"),
    ("v1", "ReplicationController"): ("spec", "template", "spec"),
    **{("apps/v1", k): ("spec", "template", "spec") for k in (
        "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet")},
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}
_SELECTOR_KEYS = {"cluster_id", "api_version", "kind", "namespace", "name", "uid",
                  "container_type", "container_name"}


class _Unresolved(ValueError):
    def __init__(self, reason, status="unknown"):
        self.reason, self.status = reason, status


@dataclass(frozen=True)
class ImageReference:
    registry: str
    repository: str
    tag: str | None
    digest: str | None
    explicit_registry: bool

    @property
    def repository_key(self):
        return self.registry + "/" + self.repository

    @property
    def immutable_reference(self):
        return self.repository_key + "@" + self.digest if self.digest else None


def _text(value, maximum=512):
    return (type(value) is str and 0 < len(value) <= maximum
            and value.isascii() and all(32 < ord(c) < 127 for c in value))


def parse_image_reference(value):
    """Conservative SHA256 Docker/OCI name subset; never resolve tags or DNS.

    Only the documented index.docker.io -> docker.io alias and Docker shorthand
    are normalized. Mirrors, custom runtime defaults, IPv6 and other algorithms
    need separate native evidence/support. These failures are not bad posture.
    """
    if (not _text(value, MAX_IMAGE_LENGTH) or any(c in value for c in "%?#\\")
            or "://" in value or value.count("@") > 1):
        raise _Unresolved("malformed_image_reference", "invalid")
    name, at, digest = value.partition("@")
    if at and not _DIGEST.fullmatch(digest):
        raise _Unresolved("unsupported_or_malformed_digest")
    digest = digest if at else None
    head, slash, tail = name.rpartition("/")
    leaf = tail if slash else name
    leaf, colon, tag = leaf.partition(":")
    if colon and not _TAG.fullmatch(tag):
        raise _Unresolved("malformed_image_tag", "invalid")
    name = head + "/" + leaf if slash else leaf
    first, sep, rest = name.partition("/")
    explicit = bool(sep and ("." in first or ":" in first or first == "localhost"))
    host, repository = (first.lower(), rest) if explicit else ("docker.io", name)
    if host == "index.docker.io":
        host = "docker.io"
    if (not _HOST.fullmatch(host) or ".." in host or host.endswith(".")
            or (":" in host and not 1 <= int(host.rsplit(":", 1)[1]) <= 65535)):
        raise _Unresolved("unsupported_or_malformed_registry", "invalid")
    if any(not _LABEL.fullmatch(part) for part in host.split(":", 1)[0].split(".")):
        raise _Unresolved("unsupported_or_malformed_registry", "invalid")
    if host == "docker.io" and "/" not in repository:
        repository = "library/" + repository
    if len(host + "/" + repository) > 255 or not _REPOSITORY.fullmatch(repository):
        raise _Unresolved("malformed_image_repository", "invalid")
    return ImageReference(host, repository, tag if colon else (None if digest else "latest"),
                          digest, explicit)


def _identity(resource):
    if type(resource) is not dict or type(resource.get("metadata")) is not dict:
        raise _Unresolved("missing_native_object_identity", "invalid")
    version, kind, meta = resource.get("apiVersion"), resource.get("kind"), resource["metadata"]
    if any(key in resource or key in meta for key in (
            "items", "continue", "nextLink", "remainingItemCount", "partial", "_partial",
            "hasMore", "continuationToken", "_coverage")):
        raise _Unresolved("partial_or_list_object_not_supported")
    if type(version) is not str or type(kind) is not str or (version, kind) not in _PATHS:
        raise _Unresolved("unsupported_native_kind_or_api_version")
    if (not _text(meta.get("namespace"), 63) or not _LABEL.fullmatch(meta["namespace"])
            or not _text(meta.get("name"), 253) or not _NAME.fullmatch(meta["name"])
            or any(not _LABEL.fullmatch(s) for s in meta["name"].split("."))
            or not _text(meta.get("uid"), 128) or not _TOKEN.fullmatch(meta["uid"])
            or not _text(meta.get("resourceVersion"), 128)):
        raise _Unresolved("missing_or_malformed_native_identity", "invalid")
    if meta.get("deletionTimestamp") is not None:
        raise _Unresolved("object_terminating")
    return {"api_version": version, "kind": kind, "namespace": meta["namespace"],
            "name": meta["name"], "uid": meta["uid"], "resource_version": meta["resourceVersion"]}


def _declarations(resource):
    identity = _identity(resource)
    path = _PATHS[(identity["api_version"], identity["kind"])]
    spec = resource
    for key in path:
        if type(spec) is not dict or type(spec.get(key)) is not dict:
            raise _Unresolved("missing_native_pod_spec")
        spec = spec[key]
    groups, names, count = {}, set(), 0
    for typ, (field, _) in _GROUPS.items():
        rows = spec.get(field, [])
        if type(rows) is not list or len(rows) > MAX_CONTAINERS:
            raise _Unresolved("invalid_or_unbounded_container_declarations", "invalid")
        count += len(rows)
        if count > MAX_CONTAINERS or (typ == "regular" and not rows):
            raise _Unresolved("invalid_or_unbounded_container_declarations", "invalid")
        if rows and typ == "ephemeral" and identity["kind"] != "Pod":
            raise _Unresolved("ephemeral_containers_require_selected_pod")
        groups[typ] = {}
        for index, row in enumerate(rows):
            if (type(row) is not dict or not _text(row.get("name"), 63)
                    or not _LABEL.fullmatch(row["name"])):
                raise _Unresolved("malformed_container_declaration", "invalid")
            if row["name"] in names:
                raise _Unresolved("ambiguous_container_declarations", "invalid")
            names.add(row["name"])
            groups[typ][row["name"]] = (row, "/" + "/".join(path) + f"/{field}/{index}/image")
    return groups


def _selected_image(resource, typ, name):
    groups = _declarations(resource)
    if name not in groups[typ]:
        raise _Unresolved("selected_container_missing")
    row, path = groups[typ][name]
    return parse_image_reference(row.get("image")), path


def _same_desired(left, right):
    return (left.repository_key == right.repository_key and left.digest == right.digest
            and (left.digest is not None or left.tag == right.tag))


def _owner_link(parent, child):
    parent_id, child_id = _identity(parent), _identity(child)
    if child_id["namespace"] != parent_id["namespace"]:
        raise _Unresolved("owner_namespace_mismatch", "mismatch")
    refs = child["metadata"].get("ownerReferences", [])
    if type(refs) is not list or len(refs) > MAX_OWNER_REFERENCES:
        raise _Unresolved("invalid_or_unbounded_owner_references", "invalid")
    controllers = []
    for ref in refs:
        if (type(ref) is not dict or any(not _text(ref.get(k), 128)
                for k in ("apiVersion", "kind", "name", "uid"))
                or ("controller" in ref and type(ref["controller"]) is not bool)):
            raise _Unresolved("malformed_owner_reference", "invalid")
        if ref.get("controller") is True:
            controllers.append(ref)
    if len(controllers) != 1:
        raise _Unresolved("missing_or_ambiguous_controller_owner")
    ref = controllers[0]
    if any(ref[k] != parent_id[target] for k, target in (
            ("apiVersion", "api_version"), ("kind", "kind"), ("name", "name"), ("uid", "uid"))):
        raise _Unresolved("controller_owner_identity_mismatch", "mismatch")


def _status(resource, typ, name):
    declarations = _declarations(resource)
    native = resource.get("status")
    if type(native) is not dict:
        raise _Unresolved("pod_status_missing")
    selected, seen, count = None, set(), 0
    for group, (_, field) in _GROUPS.items():
        rows = native.get(field, [])
        if type(rows) is not list or len(rows) > MAX_CONTAINERS:
            raise _Unresolved("invalid_or_unbounded_container_statuses", "invalid")
        count += len(rows)
        if count > MAX_CONTAINERS:
            raise _Unresolved("invalid_or_unbounded_container_statuses", "invalid")
        for index, row in enumerate(rows):
            if type(row) is not dict or not _text(row.get("name"), 63):
                raise _Unresolved("malformed_container_status", "invalid")
            if row["name"] in seen:
                raise _Unresolved("ambiguous_container_statuses", "invalid")
            seen.add(row["name"])
            if row["name"] not in declarations[group]:
                raise _Unresolved("status_declaration_name_or_type_mismatch", "mismatch")
            if group == typ and row["name"] == name:
                selected = row, f"/status/{field}/{index}"
    if selected is None:
        raise _Unresolved("selected_container_status_missing")
    return selected


def _observed_status(row):
    # Do not inspect lastState: it belongs to a different container instance.
    state = row.get("state", {})
    if type(state) is not dict or len(state) > 1:
        raise _Unresolved("malformed_container_state", "invalid")
    if not state or "waiting" in state:
        raise _Unresolved("container_waiting_or_state_missing")
    key = next(iter(state))
    if key not in ("running", "terminated") or type(state[key]) is not dict:
        raise _Unresolved("malformed_container_state", "invalid")
    state_id = state[key].get("containerID")
    instance = row.get("containerID", state_id)
    if not _text(instance, 300) or not _CONTAINER_ID.fullmatch(instance):
        raise _Unresolved("container_instance_id_missing_or_unsupported")
    if state_id is not None and instance != state_id:
        raise _Unresolved("terminated_container_instance_mismatch", "mismatch")
    if (type(row.get("restartCount")) is not int or row["restartCount"] < 0
            or type(row.get("ready")) is not bool):
        raise _Unresolved("malformed_container_status_counters", "invalid")
    if key == "terminated" and type(state[key].get("exitCode")) is not int:
        raise _Unresolved("malformed_terminated_container_state", "invalid")
    times = {}
    for field in (("startedAt",) if key == "running" else ("startedAt", "finishedAt")):
        value = state[key].get(field)
        try:
            if not _text(value, 64):
                raise ValueError
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except ValueError:
            raise _Unresolved("container_state_timestamp_missing_or_invalid") from None
        times[field] = value
    if key == "terminated" and datetime.fromisoformat(times["finishedAt"].replace("Z", "+00:00")) < datetime.fromisoformat(times["startedAt"].replace("Z", "+00:00")):
        raise _Unresolved("container_state_timestamp_order_invalid", "invalid")
    image = parse_image_reference(row.get("image"))
    raw_id = row.get("imageID")
    if not _text(raw_id, MAX_IMAGE_LENGTH + 20):
        raise _Unresolved("image_id_missing")
    if raw_id.startswith("docker-pullable://"):
        raw_id = raw_id[len("docker-pullable://"):]
    elif "://" in raw_id or _DIGEST.fullmatch(raw_id):
        # A runtime/config hash is not necessarily a registry manifest digest.
        raise _Unresolved("non_pullable_runtime_image_id")
    actual = parse_image_reference(raw_id)
    if actual.digest is None or not actual.explicit_registry:
        raise _Unresolved("image_id_not_qualified_immutable_reference")
    return image, actual, {"state": key, "container_id": instance,
                           "restart_count": row["restartCount"], "ready": row["ready"],
                           "state_timestamps": times}


def resolve_image_source(selection, declaration, *, cluster_id, pod_selection=None,
                         pod=None, owner_chain=()):
    """Resolve ONE exact container from caller-supplied bounded native objects.

    selection pins cluster, API version/kind, namespace/name/UID and container
    type/name. Optional pod_selection pins namespace/name/UID for a controller's
    one explicitly supplied Pod. owner_chain is [ReplicaSet] for Deployment,
    [Job] for CronJob, and empty for direct owning controllers. No discovery or
    label inference occurs. A declaration-only result never selects an observed
    image for a scanner; immutable_reference is populated only for association.
    """
    result = {"schema": SCHEMA, "status": "unknown", "reason": "unresolved",
              "claim": "none", "immutable_reference": None,
              "image_bytes_scanned": False, "effective_deployment_proven": False,
              "registry_access": "not_checked"}
    try:
        if (type(selection) is not dict or set(selection) != _SELECTOR_KEYS
                or not _text(cluster_id) or selection.get("cluster_id") != cluster_id
                or type(selection.get("container_type")) is not str
                or selection["container_type"] not in _GROUPS
                or not _text(selection.get("container_name"), 63)
                or not _LABEL.fullmatch(selection["container_name"])):
            raise _Unresolved("invalid_exact_selection_or_cluster_mismatch", "invalid")
        origin = _identity(declaration)
        if any(selection[k] != origin[k] for k in ("api_version", "kind", "namespace", "name", "uid")):
            raise _Unresolved("selected_declaration_identity_mismatch", "mismatch")
        if type(owner_chain) not in (tuple, list) or len(owner_chain) > 1:
            raise _Unresolved("unsupported_or_unbounded_owner_chain", "invalid")
        typ, name = selection["container_type"], selection["container_name"]
        desired, path = _selected_image(declaration, typ, name)
        result.update(cluster_id=cluster_id, declaration=origin, container_type=typ,
                      container_name=name, desired_image=asdict(desired), desired_image_path=path,
                      desired_immutable_reference=desired.immutable_reference)
        if origin["kind"] == "Pod":
            if pod is not None or pod_selection is not None or owner_chain:
                raise _Unresolved("unexpected_pod_or_owner_input", "invalid")
            observed = declaration
        elif pod is None:
            if pod_selection is not None or owner_chain:
                raise _Unresolved("missing_explicit_selected_pod")
            result.update(status="declaration_only" if desired.digest else "unknown",
                          reason="immutable_desired_declaration_only" if desired.digest else
                                 "mutable_declaration_without_pod_status",
                          claim="desired_image_declaration")
            return result
        else:
            if (type(pod_selection) is not dict or set(pod_selection) != {"namespace", "name", "uid"}):
                raise _Unresolved("explicit_pod_selection_required", "invalid")
            pod_id = _identity(pod)
            if pod_id["kind"] != "Pod" or any(pod_selection[k] != pod_id[k]
                    for k in ("namespace", "name", "uid")):
                raise _Unresolved("selected_pod_identity_mismatch", "mismatch")
            expected = {"Deployment": "ReplicaSet", "CronJob": "Job"}.get(origin["kind"])
            if origin["kind"] == "PodTemplate":
                raise _Unresolved("podtemplate_has_no_native_controller_ownership")
            if len(owner_chain) != (1 if expected else 0):
                raise _Unresolved("required_native_owner_chain_missing_or_unexpected")
            if expected and _identity(owner_chain[0])["kind"] != expected:
                raise _Unresolved("intermediate_controller_kind_mismatch", "mismatch")
            nodes = [declaration, *owner_chain, pod]
            if len({_identity(n)["uid"] for n in nodes}) != len(nodes):
                raise _Unresolved("ambiguous_or_cyclic_owner_chain", "invalid")
            for parent, child in zip(nodes, nodes[1:]):
                _owner_link(parent, child)
                child_desired, _ = _selected_image(child, typ, name)
                if not _same_desired(desired, child_desired):
                    raise _Unresolved("controller_pod_declaration_mismatch", "mismatch")
            result["owner_chain"] = [_identity(n) for n in nodes]
            observed = pod
        result["pod"] = _identity(observed)
        row, status_path = _status(observed, typ, name)
        status_image, actual, instance = _observed_status(row)
        result.update(status_image=asdict(status_image), status_image_id=actual.immutable_reference,
                      status_path=status_path, container_instance=instance)
        if desired.repository_key != actual.repository_key or status_image.repository_key != actual.repository_key:
            raise _Unresolved("registry_alias_or_repository_mismatch", "mismatch")
        if desired.digest and desired.digest != actual.digest:
            # An index and its platform manifest have different digests. Without
            # verified descriptor bytes neither equality nor contradiction follows.
            raise _Unresolved("desired_status_digest_relation_unverified")
        if status_image.digest and status_image.digest != actual.digest:
            raise _Unresolved("status_image_digest_relation_unverified")
        if (not desired.digest and not status_image.digest and desired.tag != status_image.tag):
            raise _Unresolved("desired_status_tag_disagreement")
        result.update(status="associated", reason="selected_pod_status_reported_immutable_image",
                      claim="pod_status_reported_digest", immutable_reference=actual.immutable_reference)
    except _Unresolved as exc:
        result.update(status=exc.status, reason=exc.reason, immutable_reference=None)
    return result

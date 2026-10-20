"""Pure, bounded Cloud Run v2 image *declaration* association; never a check.

Inputs are one decoded native GET body and an independent exact selector. The
caller owns request provenance, capture time, IAM and later image inspection.
Current Revision/Execution/Task REST contracts do not expose per-container
resolved-digest status: no v1 imageDigest, Kubernetes imageID or Instance status
is transplanted here. A digest declaration is not observed runtime evidence.
App Engine flexible runtime image association remains explicitly unsupported.
"""
import re


SCHEMA = "gcp-workload-image-source-association-v1"
MAX_CONTAINERS = 16  # Local work bound, not a claim about Cloud Run quotas.
MAX_IMAGE_LENGTH = 512
RUN_API = "run.googleapis.com/v2"
APPENGINE_API = "appengine.googleapis.com/v1"
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_RESOURCE_ID = r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_GENERATION = re.compile(r"[1-9][0-9]{0,18}\Z")
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_IMAGE_PATH = re.compile(_PATH_COMPONENT + r"(?:/" + _PATH_COMPONENT + r")*\Z")
_REPOSITORY_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
_SELECTOR_KEYS = {"api_version", "kind", "project_id", "resource_name", "resource_uid",
                  "container_name", "digest", "repository", "immutable_reference"}
_CONTAINER_PATHS = {
    "Service": ("template", "containers"),
    "Revision": ("containers",),
    "Job": ("template", "template", "containers"),
    "Execution": ("template", "containers"),
    "Task": ("containers",),
}
_SUFFIXES = {
    "Service": r"/services/" + _RESOURCE_ID,
    "Revision": r"/services/" + _RESOURCE_ID + r"/revisions/" + _RESOURCE_ID,
    "Job": r"/jobs/" + _RESOURCE_ID,
    "Execution": r"/jobs/" + _RESOURCE_ID + r"/executions/" + _RESOURCE_ID,
    "Task": r"/jobs/" + _RESOURCE_ID + r"/executions/" + _RESOURCE_ID + r"/tasks/" + _RESOURCE_ID,
}
_SYNTHETIC = {
    "apiVersion", "kind", "metadata", "spec", "status", "imageDigest", "imageID",
    "containerStatuses", "resolvedImages", "resolvedImage", "resolvedDigest",
    "items", "resources", "nextPageToken", "partial", "_partial", "_coverage",
    "coverage", "complete", "hasMore", "continuationToken", "services", "jobs",
    "revisions", "executions", "tasks",
}


class _Unknown(ValueError):
    pass


def _require(ok, reason):
    if not ok:
        raise _Unknown(reason)


def _text(value, maximum=512):
    return (type(value) is str and 0 < len(value) <= maximum
            and value.isascii() and all(32 < ord(char) < 127 for char in value))


def _native_node(value):
    _require(type(value) is dict, "missing_native_object")
    _require(not _SYNTHETIC.intersection(value), "synthetic_or_foreign_api_shape")


def _immutable(value):
    """Literal pkg.dev SHA256 pull reference; no schemes, aliases or tag lookup."""
    _require(_text(value, MAX_IMAGE_LENGTH), "missing_or_unbounded_image_reference")
    match = re.fullmatch(
        r"([a-z0-9-]+)-docker\.pkg\.dev/([^/]+)/([^/]+)/([^@]+)@(sha256:[0-9a-f]{64})", value)
    _require(match is not None, "immutable_artifact_registry_reference_required")
    location, project, repository, image, digest = match.groups()
    _require(_LABEL.fullmatch(location) is not None
             and _PROJECT.fullmatch(project) is not None
             and _REPOSITORY_ID.fullmatch(repository) is not None
             and _IMAGE_PATH.fullmatch(image) is not None,
             "unsupported_or_malformed_artifact_registry_path")
    return {"immutable_reference": value, "digest": digest, "project_id": project,
            "registry": location + "-docker.pkg.dev", "image_path": image,
            "repository": f"projects/{project}/locations/{location}/repositories/{repository}"}


def _identity(selection, resource, project_id, kind):
    _native_node(resource)
    expected_name = selection["resource_name"]
    _require(_text(expected_name) and re.fullmatch(
        r"projects/" + re.escape(project_id) + r"/locations/[a-z][a-z0-9-]{0,62}"
        + _SUFFIXES[kind], expected_name) is not None, "resource_project_or_name_mismatch")
    _require(resource.get("name") == expected_name, "selected_resource_name_mismatch")
    uid = resource.get("uid")
    _require(_text(uid, 36) and _UUID.fullmatch(uid) is not None
             and selection["resource_uid"] == uid, "selected_resource_uid_missing_or_mismatch")
    _require(_text(resource.get("etag"), 256), "native_etag_missing")
    _require(not resource.get("deleteTime") and not resource.get("expireTime"),
             "resource_deleted_or_expiring")
    generation, observed = resource.get("generation"), resource.get("observedGeneration")
    _require(type(generation) is str and _GENERATION.fullmatch(generation) is not None
             and type(observed) is str and _GENERATION.fullmatch(observed) is not None
             and observed == generation and resource.get("reconciling") is False,
             "native_status_missing_stale_or_reconciling")
    # These are output-only native full resource names. A separately supplied
    # parent template/latest pointer is never used to select or overwrite a child.
    if kind == "Revision":
        _require(resource.get("service") == expected_name.rsplit("/revisions/", 1)[0],
                 "native_service_parent_mismatch")
    elif kind in ("Execution", "Task"):
        _require(resource.get("job") == expected_name.split("/executions/", 1)[0],
                 "native_job_parent_mismatch")
        if kind == "Task":
            _require(resource.get("execution") == expected_name.rsplit("/tasks/", 1)[0],
                     "native_execution_parent_mismatch")


def _container(resource, kind, name):
    node = resource
    path = _CONTAINER_PATHS[kind]
    for field in path[:-1]:
        node = node.get(field)
        _native_node(node)
    rows = node.get(path[-1])
    _require(type(rows) is list and 1 <= len(rows) <= MAX_CONTAINERS,
             "missing_or_unbounded_native_containers")
    seen, selected = set(), None
    for index, row in enumerate(rows):
        _native_node(row)
        container_name = row.get("name")
        # Even a single unnamed container is UNKNOWN; never invent a name or
        # infer identity from list order. Every selected name must be unique.
        _require(_text(container_name, 63) and _LABEL.fullmatch(container_name) is not None,
                 "container_name_missing_or_invalid")
        _require(container_name not in seen, "duplicate_container_name")
        seen.add(container_name)
        if container_name == name:
            selected = row.get("image"), "/" + "/".join(path) + f"/{index}/image"
    _require(selected is not None, "selected_container_missing")
    return selected


def resolve_image_source(selection, resource, *, project_id):
    """Return one exact declaration hint or UNKNOWN, without I/O or mutation.

    Selection is closed and independently pins API, kind, project ID, resource
    name/UUID, container name, repository, digest and literal OCI reference.
    Service/Job templates report desired_digest_declaration; Revision/Execution/
    Task bodies report resource_snapshot_digest_declaration. Neither is a
    per-container runtime observation, current serving/active workload proof,
    authorization grant, DockerImage inventory binding or content evidence.
    Missing, stale, ambiguous, mutable or unsupported evidence is UNKNOWN.
    """
    result = {"schema": SCHEMA, "status": "UNKNOWN", "reason": None,
              "association_kind": None, "selected_artifact_image_hint": None,
              "runtime_association_status": "UNKNOWN", "observed_runtime_digest": None,
              "deployed_bytes_proven": False, "content_status": "not_inspected",
              "complete": False}
    try:
        _require(type(selection) is dict and set(selection) == _SELECTOR_KEYS,
                 "exact_closed_selector_required")
        if selection["api_version"] == APPENGINE_API and selection["kind"] == "AppEngineVersion":
            raise _Unknown("appengine_flexible_runtime_digest_association_unsupported")
        _require(_text(project_id, 30) and _PROJECT.fullmatch(project_id) is not None
                 and selection["project_id"] == project_id, "exact_project_id_required")
        kind = selection["kind"]
        _require(selection["api_version"] == RUN_API and type(kind) is str
                 and kind in _CONTAINER_PATHS, "unsupported_native_api_or_kind")
        container_name = selection["container_name"]
        _require(_text(container_name, 63) and _LABEL.fullmatch(container_name) is not None,
                 "exact_container_name_required")
        selected = _immutable(selection["immutable_reference"])
        _require(selected["project_id"] == project_id
                 and selection["repository"] == selected["repository"]
                 and selection["digest"] == selected["digest"],
                 "selected_project_repository_or_digest_mismatch")
        _identity(selection, resource, project_id, kind)
        value, pointer = _container(resource, kind, container_name)
        declared = _immutable(value)
        _require(declared == selected, "selected_container_image_identity_mismatch")
        association_kind = ("desired_digest_declaration" if kind in ("Service", "Job")
                            else "resource_snapshot_digest_declaration")
        result.update(status="ASSOCIATED_DECLARATION", reason="exact_named_digest_declaration",
                      association_kind=association_kind,
                      selected_artifact_image_hint={
                          "selected_artifact_images": [selected["immutable_reference"]],
                          "repository": selected["repository"], "digest": selected["digest"],
                          "registry": selected["registry"], "image_path": selected["image_path"],
                          "source": {"api_version": RUN_API, "kind": kind,
                                     "project_id": project_id, "name": resource["name"],
                                     "uid": resource["uid"], "etag": resource["etag"],
                                     "generation": resource["generation"],
                                     "container_name": container_name, "image_json_pointer": pointer},
                          "repository_access": {
                              "status": "not_evaluated", "independent_of_workload_metadata_read": True,
                              "resource": selected["repository"],
                              "required_pull_permission": "artifactregistry.repositories.downloadArtifacts",
                              "reader_role_example": "roles/artifactregistry.reader"},
                          "requires_independent_native_repository_and_dockerimage_binding": True,
                      })
    except _Unknown as exc:
        result["reason"] = str(exc)
    return result

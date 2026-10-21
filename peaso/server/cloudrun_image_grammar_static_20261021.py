"""Pure immutable image selector grammar; no collectors, registry or I/O.

Exact AST subset of the reviewed native source, checked by parity tests.
"""
import re

MAX_IMAGE_LENGTH = 512

RUN_API = "run.googleapis.com/v2"

_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

_RESOURCE_ID = r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")

_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"

_IMAGE_PATH = re.compile(_PATH_COMPONENT + r"(?:/" + _PATH_COMPONENT + r")*\Z")

_REPOSITORY_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")

_SELECTOR_KEYS = {"api_version", "kind", "project_id", "resource_name", "resource_uid",
                  "container_name", "digest", "repository", "immutable_reference"}

class _Unknown(ValueError):
    pass

def _require(ok, reason):
    if not ok:
        raise _Unknown(reason)

def _text(value, maximum=512):
    return (type(value) is str and 0 < len(value) <= maximum
            and value.isascii() and all(32 < ord(char) < 127 for char in value))

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

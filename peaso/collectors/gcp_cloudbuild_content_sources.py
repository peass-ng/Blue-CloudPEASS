"""Pure bounded Cloud Build source planning; deliberately unregistered.

Accepts native Build, CRM v3 Project, GCS Bucket and Artifact Registry Repository
metadata already collected by the caller. Performs no reads, substitutions,
enumeration or admission. Source inputs are separate from produced artifacts.
A plan is a candidate for existing selected readers, never scan/coverage proof.

Official schema: https://cloud.google.com/build/docs/api/reference/rest/v1/projects.locations.builds
See Build, SourceProvenance, StorageSource, StorageSourceManifest, Results,
BuiltImage and ArtifactObjects. A logsBucket determines a filename, not a
Cloud Storage generation. logUrl is a Console URL, never an object download.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = "gcp-cloudbuild-content-sources-v1"
MAX_SOURCES = 10
MAX_IMAGES = 4
MAX_BINDINGS = 1000
MAX_REFERENCE_BYTES = 2048
PROJECT = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
IMAGE = re.compile(
    r"([a-z0-9-]+)-docker\.pkg\.dev/([a-z][a-z0-9-]{0,62})/"
    r"([a-z0-9._-]+)/([a-z0-9._/-]+)(?::([a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})|@(sha256:[0-9a-f]{64}))?\Z"
)


class InvalidBuild(ValueError):
    """Static reason code only: caller must not mistake rejection for coverage."""


def _text(value, cap=MAX_REFERENCE_BYTES):
    return (isinstance(value, str) and 0 < len(value) <= cap
            and len(value.encode("utf-8")) <= cap
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _hash(value):
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()).hexdigest()


def _bindings(rows):
    if (not isinstance(rows, (list, tuple)) or len(rows) > MAX_BINDINGS
            or any(not isinstance(row, dict) for row in rows)):
        raise InvalidBuild("invalid_or_excessive_bindings")
    return rows


def plan_build_content_sources(build, *, project_scope, project, buckets=(), repositories=(), max_sources=MAX_SOURCES):
    """Return immutable reader targets and explicit unresolved native relations.

    project must be a native CRM v3 Project (name=projects/NUMBER, projectId=ID).
    Both project ID/number scope aliases are accepted only through that binding.
    Every Build requires native id/projectId; regional name, when present, must
    agree. Bucket projectNumber and repository name/DOCKER format independently
    bind destinations. Duplicate native bindings are ambiguous and rejected.
    Lists above hard caps fail closed rather than silently truncate coverage.
    Unknown source-union members fail closed, allowing forward schema evolution
    only after review. No manifest traversal or inferred log-generation lookup.
    """
    if type(max_sources) is not int or not 1 <= max_sources <= MAX_SOURCES:
        raise InvalidBuild("invalid_source_limit")
    if not isinstance(build, dict) or not isinstance(project, dict):
        raise InvalidBuild("native_build_or_project_missing")
    pid, pname = project.get("projectId"), project.get("name")
    if (not isinstance(pid, str) or not PROJECT.fullmatch(pid)
            or not isinstance(pname, str) or not pname.startswith("projects/")
            or not NUMBER.fullmatch(pname[9:])):
        raise InvalidBuild("native_project_identity_invalid")
    number = pname[9:]
    if (project_scope not in ("projects/" + pid, pname)
            or "projectNumber" in project and project["projectNumber"] != number):
        raise InvalidBuild("project_scope_mismatch")
    bid = build.get("id")
    if (not isinstance(bid, str) or not TOKEN.fullmatch(bid)
            or build.get("projectId") != pid):
        raise InvalidBuild("native_build_identity_mismatch")
    identity = {"project_scope": project_scope, "project_id": pid,
                "project_number": number, "build_id": bid}
    if "name" in build:
        name = build["name"]
        match = re.fullmatch(r"projects/([^/]+)/locations/([a-z0-9-]{1,63})/builds/([^/]+)", name) if _text(name) else None
        if not match or match[1] not in (pid, number) or match[3] != bid:
            raise InvalidBuild("native_build_name_mismatch")
        identity["build_name"] = name
    buckets, repositories = _bindings(buckets), _bindings(repositories)
    result = {"schema": SCHEMA, "build": identity, "source_plans": [],
              "artifact_plans": [], "log_plans": [], "unresolved": [],
              "coverage": "planning_only", "max_sources": max_sources}

    def issue(field, reason):
        result["unresolved"].append({"field": field, "reason": reason})

    def add(group, role, reader, target, field):
        count = sum(len(result[key]) for key in ("source_plans", "artifact_plans", "log_plans"))
        if count >= max_sources:
            raise InvalidBuild("source_limit_exceeded")
        plan = {"build": dict(identity), "role": role, "reader": reader,
                "target": target, "native_field": field}
        plan["plan_sha256"] = _hash(plan)
        result[group].append(plan)

    def storage(row, field, role):
        if not isinstance(row, dict):
            issue(field, "malformed_storage_source")
            return
        bucket, obj, gen = (row.get(k) for k in ("bucket", "object", "generation"))
        if (not _text(bucket, 222) or not BUCKET.fullmatch(bucket)
                or any(len(part) > 63 for part in bucket.split("."))
                or not _text(obj, 1024) or any(c in obj for c in "#?*[]\\")
                or any(part in ("", ".", "..") for part in obj.split("/"))):
            issue(field, "unsupported_storage_reference")
            return
        if not isinstance(gen, str) or not NUMBER.fullmatch(gen) or int(gen) > 9223372036854775807:
            issue(field, "missing_or_invalid_generation")
            return
        matches = [b for b in buckets if b.get("name") == bucket]
        if len(matches) != 1 or matches[0].get("projectNumber") != number:
            issue(field, "bucket_project_binding_missing_foreign_or_ambiguous")
            return
        target = {"project_scope": project_scope, "bucket": bucket,
                  "object": obj, "generation": gen}
        if role == "source_archive":
            format_name = "tar.gz" if obj.endswith(".tar.gz") else "zip" if obj.endswith(".zip") else None
            if format_name is None:
                issue(field, "unsupported_source_archive_format")
                return
            target["format"] = format_name
            reader = "gcs_selected_archive"
        else:
            if not obj.endswith(".json"):
                issue(field, "unsupported_source_manifest_format")
                return
            reader = "gcs_selected_object"
        add("source_plans", role, reader, target, field)
        if role == "source_manifest":
            issue(field, "manifest_children_not_planned")

    source, provenance = build.get("source", {}), build.get("sourceProvenance", {})
    if not isinstance(source, dict) or not isinstance(provenance, dict):
        issue("source", "malformed_source_or_provenance")
    elif len(source) > 1:
        issue("source", "ambiguous_source_union")
    elif source and next(iter(source)) not in ("storageSource", "storageSourceManifest"):
        issue("source", "unsupported_repository_or_source_kind")
    else:
        resolved_fields = [key for key in ("resolvedStorageSource", "resolvedStorageSourceManifest",
                           "resolvedGitSource", "resolvedRepoSource", "resolvedConnectedRepository") if key in provenance]
        selected = next(iter(source), None)
        expected = {"storageSource": "resolvedStorageSource", "storageSourceManifest": "resolvedStorageSourceManifest"}
        if len(resolved_fields) > 1 or (resolved_fields and selected and resolved_fields[0] != expected[selected]):
            issue("sourceProvenance", "ambiguous_or_conflicting_resolved_source")
        elif resolved_fields and resolved_fields[0] not in expected.values():
            issue("sourceProvenance", "unsupported_resolved_repository")
        else:
            resolved = resolved_fields[0] if resolved_fields else None
            key = selected or ({v: k for k, v in expected.items()}.get(resolved))
            if key:
                field = "sourceProvenance." + resolved if resolved else "source." + key
                row = provenance[resolved] if resolved else source[key]
                original = source.get(key)
                if resolved and original is not None and (not isinstance(original, dict) or not isinstance(row, dict)
                        or any(original.get(k) != row.get(k) for k in ("bucket", "object"))
                        or "generation" in original and original["generation"] != row.get("generation")):
                    issue(field, "source_provenance_conflict")
                else:
                    storage(row, field, "source_archive" if key == "storageSource" else "source_manifest")

    results = build.get("results", {})
    if not isinstance(results, dict):
        issue("results", "malformed_results")
    else:
        images = results.get("images", [])
        if not isinstance(images, list) or len(images) > MAX_IMAGES:
            raise InvalidBuild("invalid_or_excessive_result_images")
        seen = set()
        for i, image in enumerate(images):
            field = "results.images[" + str(i) + "]"
            if not isinstance(image, dict):
                issue(field, "malformed_built_image")
                continue
            if image.get("ociMediaType", "OCI_MEDIA_TYPE_UNSPECIFIED") not in (
                    "OCI_MEDIA_TYPE_UNSPECIFIED", "IMAGE_MANIFEST"):
                issue(field, "unsupported_image_index_or_media_type")
                continue
            if "artifactRegistryPackage" in image:
                issue(field, "artifact_registry_package_relationship_not_implemented")
                continue
            name, digest = image.get("name"), image.get("digest")
            match = IMAGE.fullmatch(name) if _text(name) else None
            if (not match or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                    or any(p in ("", ".", "..") for p in match[4].split("/"))
                    or match[3] in (".", "..") or match[6] and match[6] != digest):
                issue(field, "unsupported_or_unpinned_built_image")
                continue
            location, image_project, repo, path, _, _ = match.groups()
            repository = "projects/" + image_project + "/locations/" + location + "/repositories/" + repo
            matches = [r for r in repositories if r.get("name") == repository]
            if image_project != pid or len(matches) != 1 or matches[0].get("format") != "DOCKER":
                issue(field, "repository_project_binding_missing_foreign_or_ambiguous")
                continue
            uri = location + "-docker.pkg.dev/" + pid + "/" + repo + "/" + path + "@" + digest
            if uri in seen:
                issue(field, "duplicate_built_image")
                continue
            seen.add(uri)
            add("artifact_plans", "built_image", "artifact_image", {"uri": uri, "repository": repository,
                "digest": digest}, field)
        if "artifactManifest" in results:
            issue("results.artifactManifest", "manifest_path_has_no_separate_native_generation_or_traversal")
        for key in ("mavenArtifacts", "npmPackages", "pythonPackages", "goModules", "genericArtifacts", "buildStepImages"):
            if key in results:
                issue("results." + key, "unsupported_artifact_relationship")
    if "artifacts" in build or "images" in build:
        issue("artifacts", "upload_configuration_is_not_immutable_result_evidence")
    issue("logsBucket", "native_build_has_no_log_object_generation")
    if "logUrl" in build:
        issue("logUrl", "console_url_is_not_content_source")
    return result

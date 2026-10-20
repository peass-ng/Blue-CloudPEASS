"""Native-shaped synthetic examples, no cloud calls or detector dependencies."""
from copy import deepcopy

from peaso.collectors.gcp_cloudbuild_content_sources import (
    InvalidBuild, MAX_BINDINGS, plan_build_content_sources,
)

PROJECT = {"name": "projects/123456789", "projectId": "sample-project"}
BUCKET = {"name": "sample-source", "projectNumber": "123456789"}
REPO = {"name": "projects/sample-project/locations/europe-west1/repositories/builds", "format": "DOCKER"}
DIGEST = "sha256:" + "a" * 64
BUILD = {"id": "b123-456", "projectId": "sample-project",
         "name": "projects/sample-project/locations/europe-west1/builds/b123-456"}
SOURCE = {"bucket": "sample-source", "object": "sources/input.tar.gz", "generation": "1234567890123456"}
IMAGE = {"name": "europe-west1-docker.pkg.dev/sample-project/builds/app:release", "digest": DIGEST}


def plan(build=None, **kwargs):
    args = {"project_scope": "projects/sample-project", "project": deepcopy(PROJECT),
            "buckets": [deepcopy(BUCKET)], "repositories": [deepcopy(REPO)]}
    args.update(kwargs)
    return plan_build_content_sources(deepcopy(BUILD if build is None else build), **args)


def reasons(result):
    return {row["reason"] for row in result["unresolved"]}


def fails(build=None, **kwargs):
    try:
        plan(build, **kwargs)
    except InvalidBuild:
        return
    raise AssertionError("expected fail-closed identity/bounds rejection")


def test_resolved_archive_generation_is_exact_and_separate_from_artifacts():
    build = dict(BUILD, source={"storageSource": {k: v for k, v in SOURCE.items() if k != "generation"}},
                 sourceProvenance={"resolvedStorageSource": deepcopy(SOURCE)})
    result = plan(build)
    source = result["source_plans"][0]
    assert source["target"] == dict(SOURCE, project_scope="projects/sample-project", format="tar.gz")
    assert source["native_field"] == "sourceProvenance.resolvedStorageSource"
    assert source["build"]["build_id"] == BUILD["id"]
    assert source["reader"] == "gcs_selected_archive"
    assert result["artifact_plans"] == result["log_plans"] == []


def test_pinned_zip_input_and_resolved_only_source():
    source = dict(SOURCE, object="source.zip")
    assert plan(dict(BUILD, source={"storageSource": source}))["source_plans"][0]["target"]["format"] == "zip"
    assert plan(dict(BUILD, sourceProvenance={"resolvedStorageSource": source}))["source_plans"]


def test_source_generation_absent_or_malformed_never_means_latest():
    for generation in (None, "", "0", "01", "-1", 123, True, "1e4", "9223372036854775808"):
        source = dict(SOURCE, generation=generation)
        result = plan(dict(BUILD, source={"storageSource": source}))
        assert not result["source_plans"]
        assert "missing_or_invalid_generation" in reasons(result)


def test_source_conflicting_resolved_reference_or_generation():
    for key, value in (("bucket", "other-source"), ("object", "different.zip"), ("generation", "42")):
        result = plan(dict(BUILD, source={"storageSource": SOURCE},
                           sourceProvenance={"resolvedStorageSource": dict(SOURCE, **{key: value})}))
        assert not result["source_plans"]
        assert "source_provenance_conflict" in reasons(result)


def test_ambiguous_source_union_and_provenance_rejected():
    cases = [dict(BUILD, source={"storageSource": SOURCE, "gitSource": {}}),
             dict(BUILD, source={"storageSource": SOURCE}, sourceProvenance={"resolvedRepoSource": {}}),
             dict(BUILD, sourceProvenance={"resolvedStorageSource": SOURCE, "resolvedStorageSourceManifest": SOURCE})]
    for build in cases:
        assert not plan(build)["source_plans"]


def test_source_manifest_is_only_one_pinned_json_object():
    source = dict(SOURCE, object="sources/manifest.json")
    result = plan(dict(BUILD, source={"storageSourceManifest": source}))
    assert result["source_plans"][0]["reader"] == "gcs_selected_object"
    assert result["source_plans"][0]["role"] == "source_manifest"
    assert "manifest_children_not_planned" in reasons(result)
    assert not result["artifact_plans"]


def test_bucket_requires_unique_same_project_native_binding():
    for buckets in ([], [dict(BUCKET, projectNumber="999")], [BUCKET, BUCKET], [dict(BUCKET, projectNumber=123456789)]):
        result = plan(dict(BUILD, source={"storageSource": SOURCE}), buckets=buckets)
        assert not result["source_plans"]
        assert "bucket_project_binding_missing_foreign_or_ambiguous" in reasons(result)


def test_unsafe_or_unsupported_storage_names_rejected():
    for obj in ("*.zip", "a/../b.zip", "a//b.zip", "archive.tar", "x.zip#42", "x.zip?generation=2", "x\n.zip", "a" * 1025):
        assert not plan(dict(BUILD, source={"storageSource": dict(SOURCE, object=obj)}))["source_plans"]


def test_result_image_digest_replaces_tag_and_is_native_project_bound():
    result = plan(dict(BUILD, results={"images": [IMAGE]}))
    image = result["artifact_plans"][0]
    assert image["target"] == {"uri": IMAGE["name"].split(":")[0] + "@" + DIGEST,
                               "repository": REPO["name"], "digest": DIGEST}
    assert image["native_field"] == "results.images[0]"
    assert image["build"]["project_number"] == "123456789"


def test_matching_digest_name_and_untagged_name_supported():
    for name in (IMAGE["name"].split(":")[0], IMAGE["name"].split(":")[0] + "@" + DIGEST):
        assert plan(dict(BUILD, results={"images": [dict(IMAGE, name=name)]}))["artifact_plans"]


def test_unpinned_conflicting_external_and_foreign_images_rejected():
    for image in (dict(IMAGE, digest=None), dict(IMAGE, digest="sha256:abc"),
                  dict(IMAGE, name=IMAGE["name"].split(":")[0] + "@sha256:" + "b" * 64),
                  dict(IMAGE, name="gcr.io/sample-project/app:latest"),
                  dict(IMAGE, name=IMAGE["name"].replace("sample-project", "foreign-project")),
                  dict(IMAGE, name=IMAGE["name"].replace("/app", "/../app")),
                  dict(IMAGE, name="https://" + IMAGE["name"]), "not-a-built-image"):
        assert not plan(dict(BUILD, results={"images": [image]}))["artifact_plans"]


def test_images_require_repository_metadata_and_unique_binding():
    for repositories in ([], [REPO, REPO], [dict(REPO, format="MAVEN")]):
        assert not plan(dict(BUILD, results={"images": [IMAGE]}), repositories=repositories)["artifact_plans"]


def test_duplicate_images_are_not_repeated():
    result = plan(dict(BUILD, results={"images": [IMAGE, IMAGE]}))
    assert len(result["artifact_plans"]) == 1
    assert "duplicate_built_image" in reasons(result)


def test_logs_urls_and_upload_configuration_do_not_authorize_content():
    build = dict(BUILD, logsBucket="gs://sample-source", logUrl="https://console.cloud.google.com/cloud-build/builds/b123-456",
                 artifacts={"objects": {"location": "gs://sample-source/output/", "paths": ["**"]}, "images": [IMAGE["name"]]},
                 results={"artifactManifest": "gs://sample-source/artifacts-b123-456.json#123", "numArtifacts": "1"})
    result = plan(build)
    assert result["source_plans"] == result["artifact_plans"] == result["log_plans"] == []
    assert "native_build_has_no_log_object_generation" in reasons(result)
    assert "console_url_is_not_content_source" in reasons(result)
    assert "manifest_path_has_no_separate_native_generation_or_traversal" in reasons(result)
    assert "upload_configuration_is_not_immutable_result_evidence" in reasons(result)


def test_build_identity_and_scope_rejections():
    for build in (dict(BUILD, projectId="foreign-project"), dict(BUILD, id="other"), dict(BUILD, id=None),
                  dict(BUILD, name=BUILD["name"].replace("sample-project", "foreign-project")),
                  dict(BUILD, name=BUILD["name"].replace("b123-456", "other"))):
        fails(build)
    fails(project_scope="projects/foreign-project")
    fails(project={"name": "projects/sample-project", "projectId": "sample-project"})
    fails(project=dict(PROJECT, projectNumber="999"))


def test_native_legacy_build_and_numeric_scope_alias():
    build = {"id": BUILD["id"], "projectId": BUILD["projectId"], "source": {"storageSource": SOURCE}}
    result = plan(build, project_scope="projects/123456789")
    assert result["source_plans"][0]["target"]["project_scope"] == "projects/123456789"
    assert "build_name" not in result["build"]
    named = dict(BUILD, name=BUILD["name"].replace("sample-project", "123456789"))
    assert plan(named)["build"]["build_name"] == named["name"]


def test_bounds_fail_closed_without_truncating():
    fails(dict(BUILD, results={"images": [IMAGE] * 5}))
    fails(dict(BUILD, results={"images": {}}))
    fails(buckets=[BUCKET] * (MAX_BINDINGS + 1))
    for limit in (0, 11, True, "2"):
        fails(max_sources=limit)
    fails(dict(BUILD, source={"storageSource": SOURCE}, results={"images": [IMAGE]}), max_sources=1)


def test_unsupported_repositories_and_package_relationships_are_explicit():
    result = plan(dict(BUILD, source={"repoSource": {"repoName": "repo", "commitSha": "a" * 40}},
                       results={"mavenArtifacts": [], "buildStepImages": [DIGEST]}))
    assert "unsupported_repository_or_source_kind" in reasons(result)
    assert "unsupported_artifact_relationship" in reasons(result)
    assert result["source_plans"] == result["artifact_plans"] == []


def test_pure_deterministic_no_mutation_and_no_secret_fields_copied():
    build = dict(BUILD, source={"storageSource": deepcopy(SOURCE)}, results={"images": [deepcopy(IMAGE)]},
                 steps=[{"env": ["TOKEN=not-real-payload"]}], substitutions={"_PRIVATE": "not-real-payload"})
    original = deepcopy(build)
    result = plan(build)
    assert result == plan(build)
    assert build == original
    assert "not-real-payload" not in repr(result)
    result["source_plans"][0]["target"]["generation"] = "42"
    assert build == original


def test_malformed_optional_sections_do_not_create_plans():
    for value in (None, "malformed", []):
        result = plan(dict(BUILD, source=value, results=value))
        assert not result["source_plans"] and not result["artifact_plans"]
        assert "malformed_source_or_provenance" in reasons(result)
        assert "malformed_results" in reasons(result)


def test_image_indices_and_unimplemented_package_binding_rejected():
    for image in (dict(IMAGE, ociMediaType="IMAGE_INDEX"), dict(IMAGE, ociMediaType="UNKNOWN"),
                  dict(IMAGE, artifactRegistryPackage="projects/foreign/locations/us/repositories/x/packages/app")):
        assert not plan(dict(BUILD, results={"images": [image]}))["artifact_plans"]

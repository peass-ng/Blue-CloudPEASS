"""Regressions for native API spellings and proven optional-field omissions."""
import copy
import pytest
from peaso.checks import CHECKS
from peaso.checks import aws_b_core, aws_b_loadbalancing, aws_b_compute


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("algorithm,status", [("RSA-1024", "FAIL"), ("RSA_1024", "FAIL"),
    ("RSA-2048", "PASS"), ("RSA_2048", "PASS"), ("RSA-3072", "PASS"), ("RSA_3072", "PASS"),
    ("RSA-4096", "PASS"), ("RSA_4096", "PASS"), ("RSA-8192", "UNKNOWN"),
    ("EC_prime256v1", "NOT_APPLICABLE"), ("invented", "UNKNOWN")])
def test_acm_native_cli_spelling_and_enum_reference_without_fact_rewriting(algorithm, status):
    data = {"Certificate": {"collection_status": "collected", "Certificate": {"KeyAlgorithm": algorithm}}}
    before = copy.deepcopy(data)
    verdict, evidence = check("aws.b.acm.rsa_minimum_2048").evaluate(data, {})
    assert verdict == status
    assert data == before
    assert evidence["key_algorithm"] == algorithm


def test_lambda_missing_layers_requires_successful_detail_and_function_identity():
    c = check("aws.b.lambda.insights_layer")
    assert c.evaluate({"Configuration": {"collection_status": "collected", "FunctionName": "fixture"}}, {})[0] == "FAIL"
    for configuration in ({}, {"FunctionName": "fixture"}, {"collection_status": "collected"},
                          {"collection_status": "denied", "FunctionName": "fixture"},
                          {"collection_status": "collected", "FunctionName": "fixture", "_coverage": {"Layers": {"status": "denied"}}},
                          {"collection_status": "collected", "FunctionName": "fixture", "Layers": None}):
        assert c.evaluate({"Configuration": configuration}, {})[0] == "UNKNOWN"


def test_ecs_inherited_image_user_remains_unknown_and_explicit_root_fails():
    c = check("aws.b.ecs.declared_nonroot_users")
    base = {"Definition": {"collection_status": "collected", "taskDefinition": {"containerDefinitions": [{"name": "fixture"}]}}}
    assert c.evaluate(base, {})[0] == "UNKNOWN"
    base["Definition"]["taskDefinition"]["containerDefinitions"][0]["user"] = "0"
    assert c.evaluate(base, {})[0] == "FAIL"
    base["Definition"]["taskDefinition"]["containerDefinitions"][0]["user"] = "1000"
    assert c.evaluate(base, {})[0] == "PASS"


@pytest.mark.parametrize("field,cid,value", [
    ("privileged", "aws.b.ecs.no_privileged_containers", False),
    ("readonlyRootFilesystem", "aws.b.ecs.all_readonly_roots", True),
    ("user", "aws.b.ecs.declared_nonroot_users", "1000"),
    ("logConfiguration", "aws.b.ecs.some_logging_configuration", {"logDriver": "awslogs"}),
])
def test_explicit_container_field_denial_cannot_be_ignored_by_optional_defaults(field, cid, value):
    row = {"name": "fixture", field: value, "_coverage": {field: {"status": "denied"}}}
    data = {"Definition": {"taskDefinition": {"containerDefinitions": [row]}}}
    assert check(cid).evaluate(data, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("user,expected", [("00", "FAIL"), ("0000:1000", "FAIL"), (":1000", "UNKNOWN"), ("1000:1000:1000", "UNKNOWN")])
def test_declared_numeric_uid_zero_and_malformed_user_formats(user, expected):
    data = {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "fixture", "user": user}]}}}
    assert check("aws.b.ecs.declared_nonroot_users").evaluate(data, {})[0] == expected


def test_codebuild_identity_denial_cannot_prove_optional_encryption_defaults():
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "_coverage": {"name": {"status": "denied"}}, "artifacts": {"type": "S3"}}]}}
    assert check("aws.b.codebuild.s3_artifact_encryption").evaluate(data, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["NO_ARTIFACTS", "CODEPIPELINE"])
def test_codebuild_non_s3_type_is_na_only_in_separate_defensive_variant(kind):
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "artifacts": {"type": kind}}]}}
    assert check("aws.b.codebuild.s3_artifact_encryption").evaluate(data, {})[0] == "NOT_APPLICABLE"
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "FAIL"


def test_codebuild_s3_default_requires_positive_native_success_and_identity():
    c = check("aws.b.codebuild.s3_artifact_encryption")
    project = {"name": "fixture", "artifacts": {"type": "S3"}}
    data = {"Configuration": {"collection_status": "collected", "projects": [project]}}
    assert c.evaluate(data, {})[0] == "PASS"
    data["Configuration"].pop("collection_status")
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    data["Configuration"]["collection_status"] = "denied"
    assert c.evaluate(data, {})[0] == "UNKNOWN"


def test_codebuild_secondary_s3_failure_survives_non_s3_primary_and_missing_fields():
    c = check("aws.b.codebuild.s3_artifact_encryption")
    project = {"name": "fixture", "artifacts": {"type": "NO_ARTIFACTS"}, "secondaryArtifacts": [{"type": "S3", "encryptionDisabled": True}]}
    data = {"Configuration": {"collection_status": "collected", "projects": [project]}}
    assert c.evaluate(data, {})[0] == "FAIL"
    project["secondaryArtifacts"][0]["encryptionDisabled"] = "false"
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    project["secondaryArtifacts"] = [{"type": "S3", "_coverage": {"encryptionDisabled": {"status": "denied"}}}]
    assert c.evaluate(data, {})[0] == "UNKNOWN"


def test_codebuild_literal_secondary_absence_matches_source_true_only_condition():
    data = {"Configuration": {"collection_status": "collected", "projects": [{"name": "fixture", "artifacts": {"type": "S3", "encryptionDisabled": False}, "secondaryArtifacts": [{"type": "S3"}]}]}}
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "PASS"
    data["Configuration"]["projects"][0]["secondaryArtifacts"][0]["encryptionDisabled"] = True
    assert check("aws.b.codebuild.artifact_encryption").evaluate(data, {})[0] == "FAIL"

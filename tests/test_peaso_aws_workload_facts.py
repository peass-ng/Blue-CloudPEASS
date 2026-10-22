"""Offline fake-SDK collection and pure-normalization boundaries."""
import copy

import pytest
from peaso.collectors import aws, aws_facts_v4_holds as extension

ACCOUNT = "111111111111"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/build"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/runtime"
INSTANCE = "i-1234567890abcdef0"

class Denied(Exception):
    response = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
    operation_name = "GetPipeline"


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def can_paginate(self, operation):
        return False

    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((operation, kwargs))
            value = self.responses[operation]
            if isinstance(value, list):
                value = value.pop(0)
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        return call


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, service, **_):
        return self.clients[service]


def pipeline_response(*, repository="repo", role=ROLE):
    return {"pipeline": {"name": "pipe", "stages": [
        {"name": "Source", "actions": [{"name": "src", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "CodeCommit"},
            "configuration": {"RepositoryName": repository, "BranchName": "main", "OAuthToken": "must-not-cache"},
            "outputArtifacts": [{"name": "src-out"}]}]},
        {"name": "Build", "actions": [{"name": "build", "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild"},
            "configuration": {"ProjectName": "build", "ServiceRoleArnOverride": role,
                              "EnvironmentVariables": "secret", "BuildSpec": "must-not-cache-buildspec"},
            "inputArtifacts": [{"name": "src-out"}]}]}]}}


def sdk(responses=None):
    responses = responses or {}
    clients = {
        "codepipeline": FakeClient({"list_pipelines": {"pipelines": [{"name": "pipe"}]},
                                    "get_pipeline": pipeline_response()}),
        "codebuild": FakeClient({"list_projects": {"projects": ["build"]},
                                 "batch_get_projects": {"projects": [{"name": "build",
                                    "arn": f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/build", "serviceRole": ROLE}]}}),
        "ec2": FakeClient({"describe_instances": {"Reservations": [{"Instances": [{"InstanceId": INSTANCE,
                    "State": {"Name": "running"}, "IamInstanceProfile": {"Arn": PROFILE}}]}]},
             "describe_iam_instance_profile_associations": {"IamInstanceProfileAssociations": [{
                    "AssociationId": "iip-assoc-123", "InstanceId": INSTANCE, "State": "associated",
                    "IamInstanceProfile": {"Arn": PROFILE}}]}}),
    }
    for service, operations in responses.items():
        clients[service].responses.update(operations)
    return FakeSession(clients)


def collected(session):
    requests = aws.Requests({"retry_attempts": 1})
    pipeline = requests.pages(session, "codepipeline", REGION, "list_pipelines", "pipelines")
    pipeline.items = aws.ENRICHERS["codepipeline_pipeline"](requests, session, REGION, pipeline.items)
    projects = requests.pages(session, "codebuild", REGION, "list_projects", "projects")
    projects.items = aws.ENRICHERS["codebuild_project"](requests, session, REGION,
                                                          [{"name": name} for name in projects.items])
    instances = requests.pages(session, "ec2", REGION, "describe_instances", "Reservations[].Instances[]")
    associations = requests.pages(session, "ec2", REGION, "describe_iam_instance_profile_associations",
                                  "IamInstanceProfileAssociations")
    snapshot = {"collections": [
        {"type": "codepipeline_pipeline", "scope": f"{ACCOUNT}/{REGION}", "status": pipeline.status,
         "items": pipeline.items},
        {"type": "codebuild_project", "scope": f"{ACCOUNT}/{REGION}", "status": projects.status,
         "items": projects.items},
        {"type": "instance", "scope": f"{ACCOUNT}/{REGION}", "status": instances.status,
         "items": instances.items},
        {"type": "ec2_instance_profile_association", "scope": f"{ACCOUNT}/{REGION}",
         "status": associations.status, "items": associations.items},
        {"type": "iam_role", "scope": f"{ACCOUNT}/global", "status": "collected", "items": [
            {"Arn": ROLE, "InstanceProfileList": [{"Arn": PROFILE}]}]},
    ]}
    return requests, snapshot


def test_fake_sdk_collects_exact_joins_without_attestation():
    session = sdk()
    requests, snapshot = collected(session)
    calls_after_collection = requests.calls
    links = extension.codecommit_build_links(snapshot, ACCOUNT, REGION)["links"]
    assert len(links) == 1
    assert links[0]["Status"] == "configured"
    assert links[0]["RepositoryArn"] == f"arn:aws:codecommit:{REGION}:{ACCOUNT}:repo"
    assert links[0]["BuildRoleArn"] == ROLE
    assert links[0]["BuildRoleOrigin"] == "action_override"
    assert all(links[0][field] is None for field in ("BranchWritable", "BuildSpecUsesInput",
                                                    "ExecutionPathAvailable", "VerifiedPreconditions"))
    state = extension.ec2_profile_state(snapshot, ACCOUNT, REGION)["instances"][0]
    assert state["CurrentProfileState"] == "present" and state["CurrentProfileRoleArns"] == [ROLE]
    assert state["InstanceControlled"] is None and state["AssociationAction"] is None
    extension.codecommit_build_links(snapshot, ACCOUNT, REGION)
    extension.ec2_profile_state(snapshot, ACCOUNT, REGION)
    assert requests.calls == calls_after_collection
    assert session.clients["codepipeline"].calls[-1][0] == "get_pipeline"
    assert requests.calls >= 5
    cached_pipeline = [future.result() for key, future in requests._cache.items()
                       if key[1:4] == ("codepipeline", REGION, "get_pipeline")]
    assert len(cached_pipeline) == 1
    assert "must-not-cache" not in str(cached_pipeline) + str(snapshot)
    assert "EnvironmentVariables" not in str(snapshot)


@pytest.mark.parametrize("source_order,build_order,expected", [
    (1, 2, True), (None, 2, True), (1, 1, False), (1, 0, False), (1, True, False), (0, 2, False)])
def test_same_stage_codecommit_source_precedes_build_only_by_run_order(source_order, build_order, expected):
    response = pipeline_response()
    source_stage, build_stage = response["pipeline"]["stages"]
    source_stage["actions"][0]["runOrder"] = source_order
    build_stage["actions"][0]["runOrder"] = build_order
    source_stage["actions"].extend(build_stage["actions"])
    response["pipeline"]["stages"] = [source_stage]
    _, snapshot = collected(sdk({"codepipeline": {"get_pipeline": response}}))
    links = extension.codecommit_build_links(snapshot, ACCOUNT, REGION)["links"]
    assert bool(links) is expected


def test_denied_and_missing_reads_remain_unknown():
    _, snapshot = collected(sdk({"codepipeline": {"get_pipeline": Denied()},
                                 "ec2": {"describe_iam_instance_profile_associations": Denied()}}))
    assert snapshot["collections"][0]["items"][0]["ActionMetadata"]["collection_status"] == "denied"
    assert extension.codecommit_build_links(snapshot, ACCOUNT, REGION)["links"] == []
    assert extension.ec2_profile_state(snapshot, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "unknown"
    snapshot["collections"][1] = {"type": "codebuild_project", "scope": f"{ACCOUNT}/{REGION}",
                                  "status": "not_collected", "items": []}
    assert extension.codecommit_build_links(snapshot, ACCOUNT, REGION)["links"] == []


def test_partial_association_and_missing_project_do_not_claim_completeness():
    _, snapshot = collected(sdk({"codebuild": {"batch_get_projects": {"projects": []}}}))
    link = extension.codecommit_build_links(snapshot, ACCOUNT, REGION)["links"][0]
    assert link["Status"] == "partial" and link["BuildRoleArn"] is None
    partial_session = sdk({"ec2": {"describe_iam_instance_profile_associations": [
        {"IamInstanceProfileAssociations": [{"AssociationId": "iip-assoc-123", "InstanceId": INSTANCE,
            "State": "associated", "IamInstanceProfile": {"Arn": PROFILE}}], "NextToken": "page2"},
        Denied()]}})
    partial = aws.Requests({"retry_attempts": 1}).pages(
        partial_session, "ec2", REGION, "describe_iam_instance_profile_associations",
        "IamInstanceProfileAssociations", _tokens=("NextToken", "NextToken"))
    assert partial.status == "partial" and len(partial.items) == 1
    snapshot["collections"][3]["status"] = partial.status
    snapshot["collections"][3]["items"] = partial.items
    assert extension.ec2_profile_state(snapshot, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "unknown"
    snapshot["collections"][3]["status"] = "collected"
    snapshot["collections"][3]["items"] = []
    assert extension.ec2_profile_state(snapshot, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "unknown"
    snapshot["collections"][2]["items"][0].pop("IamInstanceProfile")
    assert extension.ec2_profile_state(snapshot, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "absent"


def test_wrong_account_role_repository_and_state_are_not_joins():
    _, snapshot = collected(sdk())
    wrong = copy.deepcopy(snapshot)
    wrong["collections"][1]["items"][0]["Configuration"]["projects"][0]["arn"] = \
        f"arn:aws:codebuild:{REGION}:222222222222:project/build"
    assert extension.codecommit_build_links(wrong, ACCOUNT, REGION)["links"][0]["BuildRoleArn"] is None
    wrong = copy.deepcopy(snapshot)
    wrong["collections"][0]["items"][0]["ActionMetadata"]["pipeline"]["stages"][0]["actions"][0]["configuration"]["RepositoryName"] = "other"
    assert extension.codecommit_build_links(wrong, ACCOUNT, REGION)["links"][0]["RepositoryArn"].endswith(":other")
    wrong = copy.deepcopy(snapshot)
    wrong["collections"][0]["items"][0]["ActionMetadata"]["pipeline"]["stages"][1]["actions"][0]["configuration"]["ServiceRoleArnOverride"] = \
        "arn:aws:iam::222222222222:role/build"
    assert extension.codecommit_build_links(wrong, ACCOUNT, REGION)["links"][0]["BuildRoleArn"] is None
    wrong = copy.deepcopy(snapshot)
    wrong["collections"][3]["items"][0]["IamInstanceProfile"]["Arn"] = \
        "arn:aws:iam::222222222222:instance-profile/runtime"
    assert extension.ec2_profile_state(wrong, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "unknown"
    wrong["collections"][3]["items"][0]["State"] = "disassociating"
    assert extension.ec2_profile_state(wrong, ACCOUNT, REGION)["instances"][0]["CurrentProfileState"] == "unknown"

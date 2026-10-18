"""Fake SDK and native-check regression for pre-cache CodeBuild projection."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import time

import pytest
from peaso.collectors import aws

ACCOUNT = "111111111111"
REGION = "us-east-1"
SECRET = "never_store_this_literal_9d6e"
BUILD_SPEC = "version: 0.2\nphases:\n  build:\n    commands: ['" + SECRET + "']"

class ProviderError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code, "Message": "redacted"}}
        self.operation_name = "BatchGetProjects"


class Client:
    def __init__(self, project, responses=None, delay=0):
        self.project = project
        self.responses = list(responses) if responses is not None else None
        self.delay = delay
        self.calls = 0

    def batch_get_projects(self, **kwargs):
        self.calls += 1
        assert kwargs == {"names": ["p1"]}
        if self.delay:
            time.sleep(self.delay)
        response = self.responses.pop(0) if self.responses is not None else {"projects": [self.project]}
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)

    def list_builds_for_project(self, **kwargs):
        return {"ids": []}


class Session:
    def __init__(self, client):
        self._client = client

    def client(self, service, **_):
        assert service == "codebuild"
        return self._client


def raw_project(*, buildspec=BUILD_SPEC, source_location=None):
    location = source_location or "https://x-token-auth:" + SECRET + "@bitbucket.org/org/private.git"
    return {"name": "p1", "arn": f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/p1",
        "serviceRole": f"arn:aws:iam::{ACCOUNT}:role/build", "projectVisibility": "PRIVATE",
        "encryptionKey": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/abc",
        "source": {"type": "BITBUCKET", "location": location, "buildspec": buildspec,
                   "auth": {"type": "SECRETS_MANAGER", "resource": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret/source"}},
        "secondarySources": [{"type": "GITHUB", "location": "https://github.com/org/secret-name",
                              "buildspec": "ci/buildspec.yml", "sourceIdentifier": "second"}],
        "environment": {"type": "LINUX_CONTAINER", "privilegedMode": False,
                        "imagePullCredentialsType": "SERVICE_ROLE",
                        "environmentVariables": [{"name": "DB_PASSWORD", "type": "SECRETS_MANAGER", "value": SECRET},
                                                 {"name": "STAGE", "type": "PLAINTEXT", "value": SECRET}]},
        "webhook": {"filterGroups": [[{"type": "HEAD_REF", "pattern": "refs/heads/" + SECRET}]]},
        "artifacts": {"type": "S3", "location": "bucket/path", "encryptionDisabled": False},
        "secondaryArtifacts": [{"type": "S3", "location": "bucket/other", "encryptionDisabled": False}],
        "logsConfig": {"cloudWatchLogs": {"status": "ENABLED", "groupName": "build-logs"},
                       "s3Logs": {"status": "ENABLED", "encryptionDisabled": False}},
        "vpcConfig": {"vpcId": "vpc-123", "subnets": ["subnet-123"], "securityGroupIds": ["sg-123"]}}


def collect(project=None, responses=None, delay=0, attempts=1):
    client = Client(project or raw_project(), responses, delay)
    session = Session(client)
    requests = aws.Requests({"retry_attempts": attempts}, sleep=lambda _: None)
    item = aws.ENRICHERS["codebuild_project"](requests, session, REGION, [{"name": "p1"}])[0]
    from peaso.snapshot import make_snapshot
    snapshot = make_snapshot("aws", [f"{ACCOUNT}/{REGION}"], [{"type": "codebuild_project",
        "scope": f"{ACCOUNT}/{REGION}", "service": "codebuild", "status": "collected",
        "items": [aws._safe(item)]}])
    return client, requests, item, snapshot


def status(function, item):
    return function(item, {})[0]


def test_fake_sdk_cache_snapshot_and_native_results():
    from peaso.checks import aws_b_compute as classic
    from peaso.checks import claude2_aws_b_devtools as native
    raw = {"name": "p1", "Configuration": {"collection_status": "collected", "projects": [raw_project()]}}
    client, requests, item, snapshot = collect()
    project = item["Configuration"]["projects"][0]
    assert project["source"]["auth"] == {"type": "SECRETS_MANAGER",
        "resource": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret/source", "ResourceReferenceKind": "arn"}
    assert project["source"]["BuildSpecPresent"] is True
    assert project["source"]["buildspec"] == "[buildspec redacted]"
    assert project["secondarySources"][0]["buildspec"] == "redacted.yml"
    assert project["environment"]["environmentVariables"] == [
        {"name": "DB_PASSWORD", "type": "SECRETS_MANAGER"}, {"name": "STAGE", "type": "PLAINTEXT"}]
    assert project["encryptionKey"].endswith(":key/abc") and project["artifacts"]["encryptionDisabled"] is False
    assert project["logsConfig"]["s3Logs"]["encryptionDisabled"] is False
    cached = [future.result() for key, future in requests._cache.items()
              if key[1:4] == ("codebuild", REGION, "batch_get_projects")]
    assert len(cached) == 1 and client.calls == 1 and requests.cache_hits >= 1
    assert SECRET not in json.dumps(cached, default=str) + json.dumps(snapshot, default=str)
    assert "version: 0.2" not in json.dumps(cached, default=str) + json.dumps(snapshot, default=str)
    for fn in (native.buildspec_prowler, native.buildspec_steampipe, native.source_url_credentials,
               native.webhook_anchored, native.env_names, native.project_private,
               classic.build_privileged, classic.build_logs, classic.artifacts, classic.build_s3):
        assert status(fn, raw) == status(fn, item), fn.__name__


def test_file_buildspec_and_clean_url_preserve_native_outcomes():
    from peaso.checks import claude2_aws_b_devtools as native
    project = raw_project(buildspec="ci/buildspec.yaml", source_location="https://bitbucket.org/org/private.git")
    raw = {"name": "p1", "Configuration": {"collection_status": "collected", "projects": [project]}}
    _, _, item, _ = collect(project)
    for fn in (native.buildspec_prowler, native.buildspec_steampipe, native.source_url_credentials):
        assert status(fn, raw) == status(fn, item), fn.__name__


def test_denied_missing_malformed_and_unclassified_remain_unknown():
    from peaso.checks import claude2_aws_b_devtools as native
    for response, expected in ((ProviderError("AccessDeniedException"), "denied"),
                               ({"projects": []}, "partial"),
                               ({"projects": [raw_project()], "projectsNotFound": ["p1"]}, "partial"),
                               ({"projects": [{"name": "p1", "source": {"buildspec": {"bad": SECRET}}}]}, "malformed")):
        _, requests, item, snapshot = collect(responses=[response])
        detail = item["Configuration"]
        assert detail["collection_status"] == expected
        assert SECRET not in json.dumps(snapshot, default=str)
        with pytest.raises(Exception):
            native.buildspec_prowler(item, {})
        if expected == "denied":
            cached = [future for key, future in requests._cache.items()
                      if key[1:4] == ("codebuild", REGION, "batch_get_projects")]
            assert len(cached) == 1 and cached[0].exception().status == "denied"
    _, _, item, _ = collect(raw_project(source_location="https://bitbucket.org/org/x?token=" + SECRET))
    assert item["Configuration"]["collection_status"] == "malformed"


def test_retry_readonly_guard_and_singleflight_cache():
    # One throttled attempt then success uses the existing retry scheduler.
    client = Client(raw_project(), [ProviderError("ThrottlingException"), {"projects": [raw_project()]}])
    session = Session(client)
    requests = aws.Requests({"retry_attempts": 2}, sleep=lambda _: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(requests.call, session, "codebuild", REGION, "batch_get_projects", names=["p1"])
                   for _ in range(2)]
        results = [future.result(timeout=2) for future in futures]
    assert client.calls == 2 and requests.cache_hits >= 1
    assert results[0] == results[1] and SECRET not in json.dumps(results)
    with pytest.raises(aws.ReadFailure) as denied:
        requests.call(session, "codebuild", REGION, "start_build", projectName="p1")
    assert denied.value.code == "non_read_operation" and client.calls == 2

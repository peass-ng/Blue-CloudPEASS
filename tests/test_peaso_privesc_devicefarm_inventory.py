"""Device Farm privesc inputs retain exact metadata without upload URLs."""
from types import SimpleNamespace

from peaso.collectors import aws_facts_ext
from peaso.collectors.aws_network_inventory import MetadataClient


ACCOUNT = "111111111111"
REGION = "us-west-2"
PROJECT = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:project:project-id"
UPLOAD = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:upload:project-id/upload-id"
POOL = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:devicepool:project-id/pool-id"


class Read:
    def __init__(self, items, status, error=None):
        self.items, self.status, self.error = items, status, error


class Requests:
    def __init__(self, child_operation, child_key, child):
        self.child_operation, self.child_key, self.child = child_operation, child_key, child

    def pages(self, session, service, region, operation, key, **kwargs):
        assert service == "devicefarm" and region == REGION
        if operation == "list_projects":
            assert key == "projects"
            return Read([{"arn": PROJECT}], "collected")
        assert operation == self.child_operation and key == self.child_key
        assert kwargs == {"arn": PROJECT}
        return self.child


def test_upload_inventory_keeps_binding_without_signed_url(monkeypatch):
    monkeypatch.setattr(aws_facts_ext, "_aws", lambda: SimpleNamespace(ReadResult=Read))
    child = Read([{"arn": UPLOAD, "name": "test.yml", "type": "APPIUM_NODE_TEST_SPEC",
                   "status": "SUCCEEDED", "url": "https://signed.example/private", "metadata": "private"}], "collected")
    read = aws_facts_ext.FETCHERS["devicefarm_upload"](Requests("list_uploads", "uploads", child), None, REGION, ACCOUNT)
    assert read.status == "collected"
    assert read.items == [{"arn": UPLOAD, "name": "test.yml", "type": "APPIUM_NODE_TEST_SPEC",
                           "status": "SUCCEEDED", "ProjectArn": PROJECT, "id": UPLOAD}]
    assert "signed.example" not in str(read.items)


def test_device_pool_inventory_keeps_exact_project(monkeypatch):
    monkeypatch.setattr(aws_facts_ext, "_aws", lambda: SimpleNamespace(ReadResult=Read))
    child = Read([{"arn": POOL, "type": "PRIVATE", "maxDevices": 2, "rules": [{"value": "private"}]}], "collected")
    read = aws_facts_ext.FETCHERS["devicefarm_device_pool"](
        Requests("list_device_pools", "devicePools", child), None, REGION, ACCOUNT)
    assert read.status == "collected"
    assert read.items == [{"arn": POOL, "type": "PRIVATE", "maxDevices": 2, "ProjectArn": PROJECT, "id": POOL}]


def test_wrong_project_child_and_denied_reads_are_not_complete(monkeypatch):
    monkeypatch.setattr(aws_facts_ext, "_aws", lambda: SimpleNamespace(ReadResult=Read))
    wrong = UPLOAD.replace("project-id/", "other-project/")
    malformed = aws_facts_ext.FETCHERS["devicefarm_upload"](
        Requests("list_uploads", "uploads", Read([{"arn": wrong}], "collected")), None, REGION, ACCOUNT)
    assert malformed.status == "malformed" and malformed.items == []
    denied = aws_facts_ext.FETCHERS["devicefarm_upload"](
        Requests("list_uploads", "uploads", Read([], "access_denied", {"code": "AccessDeniedException"})),
        None, REGION, ACCOUNT)
    assert denied.status == "access_denied" and denied.items == []


def test_run_projection_keeps_only_same_project_app_arn():
    run = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:run:project-id/run-id"

    class Native:
        def get_run(self, **kwargs):
            assert kwargs == {"arn": run}
            return {"run": {"arn": run, "appUpload": UPLOAD, "executionRoleArn":
                    f"arn:aws:iam::{ACCOUNT}:role/DeviceFarmRole", "testSpecArn": UPLOAD,
                    "parsingResultUrl": "https://signed.example/private",
                    "environmentVariables": [{"name": "SECRET", "value": "private"}]}}

    result = MetadataClient(Native(), "devicefarm").get_run(arn=run)["run"]
    assert result["appUpload"] == UPLOAD
    assert result["executionRoleArn"].endswith(":role/DeviceFarmRole")
    assert "signed.example" not in str(result) and "private" not in str(result)


def test_run_projection_rejects_another_projects_app():
    run = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:run:project-id/run-id"

    class Native:
        def get_run(self, **kwargs):
            return {"run": {"arn": run, "appUpload": UPLOAD.replace("project-id/", "other-project/")}}

    try:
        MetadataClient(Native(), "devicefarm").get_run(arn=run)
    except ValueError as exc:
        assert str(exc) == "malformed_devicefarm_run_app_upload"
    else:
        raise AssertionError("cross-project app upload was accepted")

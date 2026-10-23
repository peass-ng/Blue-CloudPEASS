"""Saved-plan and resolved binding for private content-addressed Lambda ZIPs."""
import json
from types import SimpleNamespace

import pytest

from scripts import peaso_deploy as deploy


def planned_delivery():
    bucket = f"hacktricks-cspm-artifacts-{deploy.ACCOUNT}"
    expected = {"api_zip": "/private/infra/aws/build/api.zip",
                "api_code_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "api_s3_delivery": True}
    key = deploy.api_package_key(expected["api_code_sha256"])
    object_after = {"bucket": bucket, "key": key, "source": expected["api_zip"],
                    "source_hash": expected["api_code_sha256"],
                    "metadata": {"sha256": "0" * 64}, "server_side_encryption": "aws:kms",
                    "kms_key_id": f"arn:aws:kms:us-east-1:{deploy.ACCOUNT}:key/00000000-0000-0000-0000-000000000001"}
    rows = [{"address": "aws_s3_object.api_zip", "mode": "managed",
             "change": {"after": object_after}}]
    for name in ("api", "scheduler"):
        rows.append({"address": f"aws_lambda_function.{name}", "mode": "managed",
                     "change": {"after": {"filename": None, "s3_bucket": bucket,
                                          "s3_key": key, "s3_object_version": None,
                                          "source_code_hash": expected["api_code_sha256"]},
                                "after_unknown": {}}})
    return {"resource_changes": rows}, expected


def test_exact_private_content_addressed_object_and_both_lambdas_are_accepted():
    plan, expected = planned_delivery()
    deploy.check_api_delivery_plan(plan, expected)


@pytest.mark.parametrize("mutate", [
    lambda rows: rows[0]["change"]["after"].update(key="runtime-packages/other.zip"),
    lambda rows: rows[0]["change"]["after"].update(server_side_encryption="AES256"),
    lambda rows: rows[0]["change"]["after"].update(metadata={"sha256": "f" * 64}),
    lambda rows: rows[1]["change"]["after"].update(s3_key="runtime-packages/other.zip"),
    lambda rows: rows[2]["change"]["after"].update(s3_object_version="unreviewed-version"),
    lambda rows: rows[2]["change"]["after"].update(filename="/tmp/api.zip"),
    lambda rows: rows.append({"address": "aws_s3_bucket_versioning.artifacts", "mode": "managed"}),
])
def test_delivery_refuses_unbound_or_weakened_package(mutate):
    plan, expected = planned_delivery()
    mutate(plan["resource_changes"])
    with pytest.raises(RuntimeError):
        deploy.check_api_delivery_plan(plan, expected)


def test_resolved_delivery_reads_content_addressed_object_and_rejects_other_key(monkeypatch, tmp_path):
    archive = tmp_path / "api.zip"
    archive.write_bytes(b"reviewed zip")
    plan, contract = planned_delivery()
    contract["api_zip"] = str(archive)
    bucket = plan["resource_changes"][0]["change"]["after"]["bucket"]
    key = deploy.api_package_key(contract["api_code_sha256"])
    values = {row["address"]: row["change"]["after"] for row in plan["resource_changes"]}
    state = {"values": {"root_module": {"resources": [{"address": address, "values": value}
                                                        for address, value in values.items()]}}}
    monkeypatch.setattr(deploy, "terraform", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(state)))
    response = {"Metadata": {"sha256": "0" * 64}, "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": values["aws_s3_object.api_zip"]["kms_key_id"],
                "ContentLength": archive.stat().st_size}
    class S3:
        def head_object(self, **kwargs):
            assert kwargs == {"Bucket": bucket, "Key": key, "ExpectedBucketOwner": deploy.ACCOUNT}
            return response
    session = SimpleNamespace(client=lambda name: S3() if name == "s3" else None)
    deploy.verify_resolved_api_delivery(session, contract)
    values["aws_lambda_function.scheduler"]["s3_key"] = "runtime-packages/other.zip"
    with pytest.raises(RuntimeError, match="different S3 package"):
        deploy.verify_resolved_api_delivery(session, contract)

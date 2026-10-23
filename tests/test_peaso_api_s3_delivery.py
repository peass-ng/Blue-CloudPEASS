"""Saved-plan binding for versioned private API Lambda packages."""
import pytest
from types import SimpleNamespace

from scripts import peaso_deploy as deploy


def planned_delivery():
    bucket = f"hacktricks-cspm-artifacts-{deploy.ACCOUNT}"
    expected = {"api_zip": "/private/infra/aws/build/api.zip",
                "api_code_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "api_s3_delivery": True}
    object_after = {"bucket": bucket, "key": deploy.API_PACKAGE_KEY,
                    "source": expected["api_zip"], "source_hash": expected["api_code_sha256"],
                    "metadata": {"sha256": "0" * 64}, "server_side_encryption": "aws:kms",
                    "kms_key_id": f"arn:aws:kms:us-east-1:{deploy.ACCOUNT}:key/00000000-0000-0000-0000-000000000001",
                    "version_id": None}
    rows = [{"address": "aws_s3_bucket_versioning.artifacts", "mode": "managed",
             "change": {"after": {"bucket": bucket, "versioning_configuration": [{"status": "Enabled"}]}}},
            {"address": "aws_s3_object.api_zip", "mode": "managed",
             "change": {"after": object_after, "after_unknown": {"version_id": True}}}]
    for name in ("api", "scheduler"):
        rows.append({"address": f"aws_lambda_function.{name}", "mode": "managed",
                     "change": {"after": {"filename": None, "s3_bucket": bucket,
                                          "s3_key": deploy.API_PACKAGE_KEY,
                                          "s3_object_version": None,
                                          "source_code_hash": expected["api_code_sha256"]},
                                "after_unknown": {"s3_object_version": True}}})
    return {"resource_changes": rows}, expected


def test_exact_versioned_private_object_and_both_lambdas_are_accepted():
    plan, expected = planned_delivery()
    deploy.check_api_delivery_plan(plan, expected)
    rows = plan["resource_changes"]
    rows[1]["change"]["after"]["version_id"] = "exact-version-1"
    rows[1]["change"]["after_unknown"].clear()
    for row in rows[2:]:
        row["change"]["after"]["s3_object_version"] = "exact-version-1"
        row["change"]["after_unknown"].clear()
    deploy.check_api_delivery_plan(plan, expected)


@pytest.mark.parametrize("mutate", [
    lambda rows: rows[1]["change"]["after"].update(key="public/api.zip"),
    lambda rows: rows[1]["change"]["after"].update(server_side_encryption="AES256"),
    lambda rows: rows[1]["change"]["after"].update(metadata={"sha256": "f" * 64}),
    lambda rows: rows[0]["change"]["after"].update(versioning_configuration=[{"status": "Suspended"}]),
    lambda rows: rows[2]["change"]["after"].update(s3_object_version="different-version"),
    lambda rows: rows[3]["change"]["after"].update(filename="/tmp/api.zip"),
    lambda rows: rows[1]["change"]["after_unknown"].clear(),
])
def test_delivery_refuses_unbound_or_weakened_package(mutate):
    plan, expected = planned_delivery()
    mutate(plan["resource_changes"])
    with pytest.raises(RuntimeError):
        deploy.check_api_delivery_plan(plan, expected)


def test_resolved_delivery_reads_exact_version_and_rejects_other_version(monkeypatch, tmp_path):
    archive = tmp_path / "api.zip"
    archive.write_bytes(b"reviewed zip")
    plan, contract = planned_delivery()
    contract["api_zip"] = str(archive)
    bucket = plan["resource_changes"][1]["change"]["after"]["bucket"]
    version = "reviewed-version"
    values = {"aws_s3_object.api_zip": dict(plan["resource_changes"][1]["change"]["after"], version_id=version),
              "aws_s3_bucket_versioning.artifacts": plan["resource_changes"][0]["change"]["after"]}
    for name in ("api", "scheduler"):
        values[f"aws_lambda_function.{name}"] = dict(plan["resource_changes"][2 if name == "api" else 3]["change"]["after"],
                                                      s3_object_version=version)
    state = {"values": {"root_module": {"resources": [{"address": key, "values": value}
                                                        for key, value in values.items()]}}}
    monkeypatch.setattr(deploy, "terraform", lambda *args, **kwargs: SimpleNamespace(stdout=__import__("json").dumps(state)))
    response = {"VersionId": version, "Metadata": {"sha256": "0" * 64},
                "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": values["aws_s3_object.api_zip"]["kms_key_id"],
                "ContentLength": archive.stat().st_size}
    class S3:
        def head_object(self, **kwargs):
            assert kwargs == {"Bucket": bucket, "Key": deploy.API_PACKAGE_KEY,
                              "VersionId": version, "ExpectedBucketOwner": deploy.ACCOUNT}
            return response
    session = SimpleNamespace(client=lambda name: S3() if name == "s3" else None)
    deploy.verify_resolved_api_delivery(session, contract)
    values["aws_lambda_function.scheduler"]["s3_object_version"] = "another-version"
    with pytest.raises(RuntimeError, match="different S3 version"):
        deploy.verify_resolved_api_delivery(session, contract)

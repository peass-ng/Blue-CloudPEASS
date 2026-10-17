"""Lossless hosted artifact compression retains tenant and download boundaries."""
import gzip
from io import BytesIO
import json

import pytest

from peaso.storage.artifacts import S3Artifacts


class MemoryS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **request):
        self.objects[request["Key"]] = request

    def get_object(self, Bucket, Key):
        stored = self.objects[Key]
        return {"Body": BytesIO(stored["Body"]), "ContentEncoding": stored.get("ContentEncoding")}

    def head_object(self, Bucket, Key):
        stored = self.objects[Key]
        return {"ContentLength": len(stored["Body"]), "ContentEncoding": stored.get("ContentEncoding"),
                "Metadata": stored.get("Metadata", {})}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        return f"https://fixture.invalid/{Params['Key']}?expiry={ExpiresIn}"


def test_large_unicode_report_is_lossless_smaller_and_private():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client, kms_key="fixture-key")
    value = {"findings": [{"id": str(i), "status": "UNKNOWN", "evidence": {"reason": "metadata unavailable · 数据"}} for i in range(2000)]}
    reference = artifacts.put("owner", "a" * 32, "report", value)
    obj = client.objects["artifacts/" + reference]
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    assert obj["ContentEncoding"] == "gzip" and obj["ContentType"] == "application/json"
    assert obj["ServerSideEncryption"] == "aws:kms" and obj["SSEKMSKeyId"] == "fixture-key"
    assert len(obj["Body"]) < len(encoded) / 5
    assert gzip.decompress(obj["Body"]) == encoded
    assert artifacts.get("owner", reference) == value
    assert artifacts.size("owner", reference) == len(encoded)
    assert "expiry=300" in artifacts.presign("owner", reference, "peaso-" + "a" * 32 + ".json")
    with pytest.raises(ValueError):
        artifacts.get("other", reference)
    with pytest.raises(ValueError):
        artifacts.presign("other", reference)


def test_markdown_compression_preserves_full_report_and_default_encryption():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    text = "# Full report\n\nUNKNOWN · review missing evidence\n" * 4000
    reference = artifacts.put_text("owner", "b" * 32, "markdown", text)
    obj = client.objects["artifacts/" + reference]
    assert obj["ContentEncoding"] == "gzip" and obj["ServerSideEncryption"] == "AES256"
    assert obj["ContentType"] == "text/markdown"
    assert artifacts.get_text("owner", reference) == text


def test_small_and_legacy_uncompressed_objects_remain_readable():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    reference = artifacts.put("owner", "c" * 32, "snapshot", {"schema_version": "1.0"})
    obj = client.objects["artifacts/" + reference]
    assert "ContentEncoding" not in obj
    assert artifacts.get("owner", reference) == {"schema_version": "1.0"}
    assert artifacts.size("owner", reference) == len(obj["Body"])


def test_missing_compressed_size_metadata_cannot_bypass_inline_limit():
    client = MemoryS3()
    artifacts = S3Artifacts("private", client=client)
    reference = artifacts.put("owner", "d" * 32, "report", {"data": "repeated metadata " * 10000})
    client.objects["artifacts/" + reference].pop("Metadata")
    assert artifacts.size("owner", reference) > 4 * 1024 * 1024
    assert artifacts.get("owner", reference)["data"].startswith("repeated metadata")

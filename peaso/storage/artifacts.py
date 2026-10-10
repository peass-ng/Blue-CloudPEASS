"""Private artifact storage interfaces. References are generated, never paths from HTTP."""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Protocol


class ArtifactStore(Protocol):
    def put(self, tenant: str, job_id: str, kind: str, value: dict) -> str: ...
    def get(self, tenant: str, reference: str) -> dict: ...


def prefix(tenant):
    return hashlib.sha256(tenant.encode()).hexdigest()


def check_reference(tenant, reference):
    if not re.fullmatch(r"[a-f0-9]{64}/[a-f0-9]{32}/(snapshot|report|manifest|findings|finding-index|coverage|graph-network|graph-iam|markdown|detail)-[a-f0-9]{32}\.(json|md)", reference) or not reference.startswith(prefix(tenant) + "/"):
        raise ValueError("Invalid artifact reference")


def reference_for(tenant, job_id, kind):
    reference = f"{prefix(tenant)}/{job_id}/{kind}-{uuid.uuid4().hex}.{'md' if kind == 'markdown' else 'json'}"
    check_reference(tenant, reference)
    return reference


class FileArtifacts:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def put(self, tenant, job_id, kind, value):
        return self._write(tenant, job_id, kind, json.dumps(value, separators=(",", ":"), allow_nan=False))

    def put_text(self, tenant, job_id, kind, value):
        return self._write(tenant, job_id, kind, value)

    def _write(self, tenant, job_id, kind, value):
        reference = reference_for(tenant, job_id, kind)
        path = self.root / reference
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return reference

    def get(self, tenant, reference):
        check_reference(tenant, reference)
        return json.loads((self.root / reference).read_text())

    def get_text(self, tenant, reference):
        check_reference(tenant, reference)
        return (self.root / reference).read_text()

    def size(self, tenant, reference):
        check_reference(tenant, reference)
        return (self.root / reference).stat().st_size


class S3Artifacts:
    """Optional hosted artifact adapter; bucket policy must block public access."""
    def __init__(self, bucket, client=None, kms_key=None):
        if client is None:
            import boto3
            client = boto3.client("s3")
        self.client, self.bucket, self.kms_key = client, bucket, kms_key

    def put(self, tenant, job_id, kind, value):
        reference = reference_for(tenant, job_id, kind)
        encryption = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key} if self.kms_key else {"ServerSideEncryption": "AES256"}
        self.client.put_object(Bucket=self.bucket, Key="artifacts/" + reference, Body=json.dumps(value, allow_nan=False).encode(), ContentType="application/json", **encryption)
        return reference

    def get(self, tenant, reference):
        check_reference(tenant, reference)
        return json.loads(self.client.get_object(Bucket=self.bucket, Key="artifacts/" + reference)["Body"].read())

    def put_text(self, tenant, job_id, kind, value):
        reference = reference_for(tenant, job_id, kind)
        encryption = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key} if self.kms_key else {"ServerSideEncryption": "AES256"}
        self.client.put_object(Bucket=self.bucket, Key="artifacts/" + reference, Body=value.encode(), ContentType="text/markdown", **encryption)
        return reference

    def get_text(self, tenant, reference):
        check_reference(tenant, reference)
        return self.client.get_object(Bucket=self.bucket, Key="artifacts/" + reference)["Body"].read().decode()

    def size(self, tenant, reference):
        check_reference(tenant, reference)
        return self.client.head_object(Bucket=self.bucket, Key="artifacts/" + reference)["ContentLength"]

    def presign(self, tenant, reference, filename=None):
        check_reference(tenant, reference)
        arguments = {"Bucket": self.bucket, "Key": "artifacts/" + reference}
        if filename:
            if not re.fullmatch(r"peaso-[a-f0-9]{32}\.(json|md)", filename):
                raise ValueError("Invalid download filename")
            arguments["ResponseContentDisposition"] = f'attachment; filename="{filename}"'
        return self.client.generate_presigned_url("get_object", Params=arguments, ExpiresIn=300)

"""Fail-closed review of one saved Source53-to-current CSPM update plan.

This module never plans, applies, publishes, or calls a provider. Its inputs are
the private state, saved plan JSON, and a coordinator-reviewed exact contract.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zlib


ACCOUNT = "202533532952"
BACKEND = {"bucket": "terraform-state-hacktricks-wiki", "key": "cspm/terraform.tfstate",
           "region": "us-east-1", "encrypt": True, "use_lockfile": True}
BASELINE_COUNT = 72
BASELINE_ADDRESSES_SHA256 = "bf637eafe4bcec3150881ce994869909007319457ab8095e17fd5b839d846341"
PRIOR_DATA_SOURCES = {
    "data.aws_acm_certificate.wiki": ("aws_acm_certificate", "wiki"),
    "data.aws_availability_zones.available": ("aws_availability_zones", "available"),
    "data.aws_caller_identity.current": ("aws_caller_identity", "current"),
    "data.aws_cloudfront_cache_policy.api": ("aws_cloudfront_cache_policy", "api"),
    "data.aws_cloudfront_cache_policy.frontend": ("aws_cloudfront_cache_policy", "frontend"),
    "data.aws_cloudfront_origin_request_policy.api": ("aws_cloudfront_origin_request_policy", "api"),
    "data.aws_route53_zone.wiki": ("aws_route53_zone", "wiki"),
}
TEMPLATE_HASHES = (
    "04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a",
    "25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17",
    "9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f",
)
TEMPLATE_ADDRESSES = {f'aws_s3_object.customer_role_template["{digest}"]': digest for digest in TEMPLATE_HASHES}
UPDATE_ACTIONS = {
    "aws_lambda_function.api": ["update"],
    "aws_lambda_function.scheduler": ["update"],
    'aws_ecs_task_definition.tasks["collector"]': ["delete", "create"],
    'aws_ecs_task_definition.tasks["analyzer"]': ["delete", "create"],
    "aws_sfn_state_machine.scan": ["update"],
    "aws_iam_role_policy.workflow": ["update"],
    "aws_iam_role_policy.api": ["update"],
    "aws_s3_object.customer_role_download": ["update"],
    "aws_s3_bucket_policy.templates[0]": ["update"],
    **{address: ["create"] for address in TEMPLATE_ADDRESSES},
}
RUNTIME_REQUIRED = {
    "aws_lambda_function.api", "aws_lambda_function.scheduler",
    'aws_ecs_task_definition.tasks["collector"]', 'aws_ecs_task_definition.tasks["analyzer"]',
}
# Exact provider refresh read-enrichments observed under pinned AWS provider
# 6.68.0 against Source53 state serial 23. Values are also independently
# reviewed in the private plan contract; a new drift row or changed value fails.
REVIEWED_DRIFT = {
    'aws_ecs_task_definition.tasks["analyzer"]': (
        "37181d917d871de8e5004c6647a7bc060d1b5e92bc83364f7cd2045587570d9c",
        "01d9c0f42a8ac5d85dca1b57f2373036ddf32fe6c6ced80f8d2cbb69044cfda1",
        "55aa1b7d453074b931337f00a34f540fa4f0317b5784114e3057391ecae2fd5c"),
    'aws_ecs_task_definition.tasks["collector"]': (
        "e82e88ab88cb6b2f19888aec69efcbfe6500913b960559b21d8583c30385fa0a",
        "1d2666cef245c9099f04f3f80d97e5802ed3718053553de355c605429808fd5b",
        "f5c80b490ecd55ed1fa19c41e278d866bc376ec290317618bb22e4e991a1978f"),
    "aws_iam_role.workflow": (
        "079f7fcabc1d958fe3aa788cf474b9a24c97dcb29fb90f2927f8d23edb0e02cd",
        "486e30ebb059474e48135c209b9991300f0504ec1e2ac305ea77304ba0218e92",
        "1fc88669c18168fabc75877000e1393e39379437f10a7d359ae7ab4ac46a3989"),
    "aws_s3_bucket.templates[0]": (
        "3a3eb44e2312da6f06cf07e48d6f0425f50ea40cf7c54887340140e48caa9e8d",
        "a39fc901681a0448370d98c2386d3636a2561ba10770ab6cff30d3f8a5b84a8b",
        "dca031f822b01f2120d543e8d78a5cb61d982f6fa5d1349b566b62f42d8f4b6d"),
    'aws_s3_object.customer_role_template["7e6fc610eee9021025ffd498c8dc924d740975a34c56f291bc7317a7db182dbe"]': (
        "5380cc280cc2ea9acf67a1fd5450947bfbb3370ee926ba896e64e89daf2dd133",
        "7f4a95fa0d3bdef7e02cdf7f149b40f00812f2c349ec01b85ef7517d4f1e3b6e",
        "f419561651c42b73d071630c24f7248404faf1bd1b539f1c1f8d2bdfb2e9bfcf"),
}
FIELDS = {
    "aws_lambda_function.api": {"filename", "source_code_hash", "source_code_size", "environment",
                                "last_modified", "version", "qualified_arn", "qualified_invoke_arn"},
    "aws_lambda_function.scheduler": {"filename", "source_code_hash", "source_code_size", "environment",
                                      "last_modified", "version", "qualified_arn", "qualified_invoke_arn"},
    'aws_ecs_task_definition.tasks["collector"]': {"container_definitions", "arn", "arn_without_revision", "id", "revision",
                                                     "enable_fault_injection", "ipc_mode", "pid_mode", "tags", "volume"},
    'aws_ecs_task_definition.tasks["analyzer"]': {"container_definitions", "arn", "arn_without_revision", "id", "revision",
                                                    "enable_fault_injection", "ipc_mode", "pid_mode", "tags", "volume"},
    "aws_sfn_state_machine.scan": {"definition"},
    "aws_iam_role_policy.workflow": {"policy"},
    "aws_iam_role_policy.api": {"policy"},
    "aws_s3_object.customer_role_download": {"etag", "version_id"},
    "aws_s3_bucket_policy.templates[0]": {"policy"},
}
UNKNOWN_FIELDS = {
    "aws_lambda_function.api": {"last_modified", "source_code_size", "version", "qualified_arn", "qualified_invoke_arn"},
    "aws_lambda_function.scheduler": {"last_modified", "source_code_size", "version", "qualified_arn", "qualified_invoke_arn"},
    'aws_ecs_task_definition.tasks["collector"]': {"arn", "arn_without_revision", "id", "revision",
                                                     "enable_fault_injection", "volume"},
    'aws_ecs_task_definition.tasks["analyzer"]': {"arn", "arn_without_revision", "id", "revision",
                                                    "enable_fault_injection", "volume"},
    "aws_sfn_state_machine.scan": {"definition"},
    "aws_iam_role_policy.workflow": {"policy"},
    "aws_s3_object.customer_role_download": {"version_id"},
    "aws_s3_bucket_policy.templates[0]": {"policy"},
}
TEMPLATE_UNKNOWN = {"acl", "arn", "bucket_key_enabled", "checksum_crc32", "checksum_crc32c",
                    "checksum_crc64nvme", "checksum_sha1", "checksum_sha256", "id", "kms_key_id",
                    "server_side_encryption", "storage_class", "version_id"}
TEMPLATE_MARKERS = {**{key: True for key in TEMPLATE_UNKNOWN},
                    "metadata": {}, "override_provider": [], "tags_all": {}}
OWNED_TASK_ARN = re.compile(
    rf"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/hacktricks-cspm-(collector|analyzer):[1-9][0-9]*")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def check_reviewed_object_checksum(response: dict, content: bytes, expected_sha256: str) -> None:
    """Bind resolved bytes and one supported full-object SDK/S3 checksum."""
    if not isinstance(content, bytes) or digest(content) != expected_sha256:
        raise RuntimeError('Resolved immutable object body differs from signed source')
    if (response.get('ServerSideEncryption') != 'AES256' or response.get('SSEKMSKeyId') or
            response.get('BucketKeyEnabled') not in (None, False) or
            response.get('StorageClass') not in (None, 'STANDARD') or
            response.get('ChecksumType') not in (None, 'FULL_OBJECT')):
        raise RuntimeError('Resolved immutable object encryption or storage differs')
    algorithms = {'ChecksumCRC32': lambda: zlib.crc32(content).to_bytes(4, 'big'),
                  'ChecksumSHA1': lambda: hashlib.sha1(content).digest(),
                  'ChecksumSHA256': lambda: hashlib.sha256(content).digest()}
    fields = (*algorithms, 'ChecksumCRC32C', 'ChecksumCRC64NVME')
    present = [key for key in fields if response.get(key)]
    if len(present) != 1 or present[0] == 'ChecksumCRC32C':
        raise RuntimeError('Resolved immutable object checksum algorithm differs')
    try:
        observed = base64.b64decode(response[present[0]], validate=True)
    except (ValueError, base64.binascii.Error):
        raise RuntimeError('Resolved immutable object checksum is malformed') from None
    if present[0] == 'ChecksumCRC64NVME':
        # S3 can supply this fallback checksum. The independent content check
        # above is SHA256; CRC64 is format-checked without claiming a recompute.
        if len(observed) != 8:
            raise RuntimeError('Resolved immutable object CRC64 checksum is malformed')
    elif observed != algorithms[present[0]]():
        raise RuntimeError('Resolved immutable object checksum differs from bytes')


def private_artifact(path: Path, expected_sha256: str) -> bytes:
    if not path.is_absolute() or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise RuntimeError("Current-update evidence must be an owned mode-0600 absolute file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise RuntimeError("Current-update evidence must be an owned mode-0600 absolute file") from None
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or
                metadata.st_size > 20_000_000):
            raise RuntimeError("Current-update evidence must be an owned mode-0600 absolute file")
        content = stream.read(20_000_001)
    if digest(content) != expected_sha256:
        raise RuntimeError("Current-update evidence digest changed")
    return content


def check_source_pins(release: dict, infra: Path) -> None:
    files = release.get('files')
    root = infra.parent.parent
    if not isinstance(files, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                              for key, value in files.items()):
        raise RuntimeError('Current-update frozen source manifest is malformed')
    selected = [name for name in files if name.startswith('infra/aws/') or
                name in {'scripts/peaso_deploy.py', 'scripts/peaso_deploy_current_update.py'}]
    required = {'infra/aws/versions.tf', 'infra/aws/storage.tf', 'infra/aws/.terraform.lock.hcl',
                'infra/aws/sdk-constraints.txt', 'scripts/peaso_deploy.py',
                'scripts/peaso_deploy_current_update.py'}
    if not required.issubset(selected):
        raise RuntimeError('Current-update frozen deployment source is incomplete')
    for name in selected:
        path = root / name
        if (not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or
                digest(path.read_bytes()) != files[name]):
            raise RuntimeError(f'Current-update frozen deployment source differs: {name}')


def active_owned_jobs_query(table: str, now_epoch: int) -> dict:
    """Count every unexpired owned job that can resume or block an update."""
    if table != 'hacktricks-cspm' or type(now_epoch) is not int or now_epoch < 0:
        raise RuntimeError('Current-update active-job query scope is malformed')
    return {'TableName': table, 'Select': 'COUNT',
            'FilterExpression': '#kind=:job AND #status IN (:queued,:collecting,:collected,:analyzing) AND deadline>:now',
            'ExpressionAttributeNames': {'#kind': 'kind', '#status': 'status'},
            'ExpressionAttributeValues': {':job': {'S': 'job'}, ':queued': {'S': 'queued'},
                                          ':collecting': {'S': 'collecting'},
                                          ':collected': {'S': 'collected'},
                                          ':analyzing': {'S': 'analyzing'},
                                          ':now': {'N': str(now_epoch)}},
            'ConsistentRead': True, 'Limit': 1000}


def state_resources(state: dict) -> dict:
    if state.get("lineage") != "07a58930-bf9f-7350-17e9-5e4d275a308a" or state.get("serial") != 23:
        raise RuntimeError("Current-update state epoch differs from Source53")
    resources: dict[str, dict] = {}
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        if resource.get("module"):
            raise RuntimeError("Current-update baseline contains a child module")
        for instance in resource.get("instances", []):
            address = f"{resource['type']}.{resource['name']}"
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            values = instance.get("attributes")
            if (address in resources or instance.get("deposed") or instance.get("status") == "tainted" or
                    not isinstance(values, dict)):
                raise RuntimeError("Current-update state has duplicate, tainted or malformed identity")
            if address == "random_bytes.credential_key":
                if values.get("length") != 32 or not isinstance(values.get("hex"), str) or len(values["hex"]) != 64:
                    raise RuntimeError("Current-update random credential identity is malformed")
            elif not isinstance(values.get("id"), str) or not values["id"]:
                raise RuntimeError("Current-update state identity is missing")
            resources[address] = values
    names = "\n".join(sorted(resources)) + "\n"
    if len(resources) != BASELINE_COUNT or digest(names.encode()) != BASELINE_ADDRESSES_SHA256:
        raise RuntimeError("Current-update state address inventory differs from Source53")
    return resources


def check_prior_data_sources(state: dict, prior_rows: list[dict]) -> None:
    """Bind Terraform's seven pinned data inputs to Source53 state and owned caller."""
    raw = {}
    for resource in state.get("resources", []):
        if resource.get("mode") != "data":
            continue
        address = f"data.{resource.get('type')}.{resource.get('name')}"
        instances = resource.get("instances")
        if (resource.get("module") or address not in PRIOR_DATA_SOURCES or
                (resource.get("type"), resource.get("name")) != PRIOR_DATA_SOURCES[address] or
                resource.get("provider") != 'provider["registry.terraform.io/hashicorp/aws"]' or
                not isinstance(instances, list) or len(instances) != 1 or
                instances[0].get("index_key") is not None or instances[0].get("deposed") or
                instances[0].get("status") == "tainted" or
                not isinstance(instances[0].get("attributes"), dict) or address in raw):
            raise RuntimeError("Current-update state data-source identity differs")
        raw[address] = instances[0]["attributes"]
    if set(raw) != set(PRIOR_DATA_SOURCES) or len(prior_rows) != len(PRIOR_DATA_SOURCES):
        raise RuntimeError("Current-update prior data-source inventory differs")
    seen = set()
    for row in prior_rows:
        if not isinstance(row, dict):
            raise RuntimeError("Current-update prior data-source row is malformed")
        address = row.get("address")
        if (address not in PRIOR_DATA_SOURCES or address in seen or row.get("mode") != "data" or
                (row.get("type"), row.get("name")) != PRIOR_DATA_SOURCES[address] or
                row.get("module_address") or
                row.get("provider_name") != "registry.terraform.io/hashicorp/aws" or
                row.get("schema_version") != 0 or
                not isinstance(row.get("sensitive_values"), dict) or
                unknown(row["sensitive_values"]) or not isinstance(row.get("values"), dict)):
            raise RuntimeError("Current-update prior data-source identity differs")
        seen.add(address)
        before, after = raw[address], row["values"]
        if address != "data.aws_caller_identity.current":
            if after != before:
                raise RuntimeError("Current-update prior data-source values differ from state")
            continue
        if (set(before) != {"account_id", "arn", "id", "user_id"} or
                set(after) != set(before) or
                before.get("account_id") != ACCOUNT or before.get("id") != ACCOUNT or
                after.get("account_id") != ACCOUNT or after.get("id") != ACCOUNT):
            raise RuntimeError("Current-update prior caller account differs")
        role_arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/LabManagementOutOfScope/"
        previous_arn, current_arn = before.get("arn"), after.get("arn")
        previous_id, current_id = before.get("user_id"), after.get("user_id")
        if (not all(isinstance(item, str) for item in
                    (previous_arn, current_arn, previous_id, current_id)) or
                not previous_arn.startswith(role_arn) or not current_arn.startswith(role_arn) or
                not re.fullmatch(r"gntd-[A-Za-z0-9]+", previous_arn[len(role_arn):]) or
                not re.fullmatch(r"gntd-[A-Za-z0-9]+", current_arn[len(role_arn):]) or
                ":" not in previous_id or ":" not in current_id or
                previous_id.split(":", 1)[0] != current_id.split(":", 1)[0] or
                previous_id.split(":", 1)[1] != previous_arn[len(role_arn):] or
                current_id.split(":", 1)[1] != current_arn[len(role_arn):]):
            raise RuntimeError("Current-update prior caller role or session differs")
    if seen != set(PRIOR_DATA_SOURCES):
        raise RuntimeError("Current-update prior data-source inventory differs")


def unknown(value: object) -> bool:
    if type(value) is bool:
        return value
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return any(unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(unknown(item) for item in value)
    raise RuntimeError("Current-update unknown marker is malformed")


def changed_fields(change: dict) -> list[str]:
    before, after, markers = change.get("before") or {}, change.get("after") or {}, change.get("after_unknown") or {}
    if not all(isinstance(item, dict) for item in (before, after, markers)):
        raise RuntimeError("Current-update change value shape is malformed")
    return sorted(key for key in set(before) | set(after) | set(markers)
                  if before.get(key) != after.get(key) or unknown(markers.get(key, False)))


def json_document(value: object, label: str) -> dict:
    try:
        document = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        raise RuntimeError(f"Current-update {label} JSON is malformed") from None
    if not isinstance(document, dict):
        raise RuntimeError(f"Current-update {label} JSON must be an object")
    return document


def reviewed_drift(rows: object, raw_resources: dict, approved: object) -> tuple[dict, list]:
    """Bind only the five Source53 read enrichments to state and child objects."""
    if not isinstance(rows, list) or not isinstance(approved, dict) or set(approved) != set(REVIEWED_DRIFT):
        raise RuntimeError("Current-update drift approval differs from the exact five rows")
    by_address = {row.get("address"): row for row in rows if isinstance(row, dict)}
    if len(by_address) != len(rows) or set(by_address) != set(REVIEWED_DRIFT):
        raise RuntimeError("Current-update provider drift differs from the exact reviewed rows")
    refreshed = dict(raw_resources)
    for address, row in by_address.items():
        change = row.get("change")
        if (row.get("mode") != "managed" or row.get("module_address") or
                not isinstance(change, dict) or change.get("actions") != ["update"] or
                change.get("before") != raw_resources[address] or
                not isinstance(change.get("after"), dict) or unknown(change.get("after_unknown") or {})):
            raise RuntimeError("Current-update drift identity or action differs")
        before, after = change["before"], change["after"]
        expected = dict(zip(("before_sha256", "after_sha256", "change_sha256"), REVIEWED_DRIFT[address]))
        observed = {"before_sha256": digest(canonical(before)), "after_sha256": digest(canonical(after)),
                    "change_sha256": digest(canonical(change))}
        if observed != expected or approved[address] != expected:
            raise RuntimeError("Current-update drift values differ from exact reviewed hashes")
        field = "inline_policy" if address == "aws_iam_role.workflow" else "policy" if address == "aws_s3_bucket.templates[0]" else "tags"
        if changed_fields(change) != [field]:
            raise RuntimeError("Current-update drift changed an unrelated field")
        if field == "tags":
            if before.get("tags") is not None or after.get("tags") != {}:
                raise RuntimeError("Current-update tag read enrichment differs")
        elif field == "inline_policy":
            prior, current = before.get(field), after.get(field)
            child = raw_resources["aws_iam_role_policy.workflow"]
            if (not isinstance(prior, list) or not isinstance(current, list) or len(prior) != len(current) or
                    len(current) != 1 or not isinstance(prior[0], dict) or not isinstance(current[0], dict) or
                    prior[0].get("name") != current[0].get("name") or
                    current[0].get("name") != child.get("name") or
                    json_document(current[0].get("policy"), "refreshed workflow role policy") !=
                    json_document(child.get("policy"), "owned workflow child policy")):
                raise RuntimeError("Current-update workflow role drift differs from owned child policy")
        else:
            child = raw_resources["aws_s3_bucket_policy.templates[0]"]
            if json_document(after.get("policy"), "refreshed template bucket policy") != json_document(
                    child.get("policy"), "owned template child policy"):
                raise RuntimeError("Current-update template bucket drift differs from owned child policy")
        refreshed[address] = after
    return refreshed, rows


def task_refs_equal(before: str, after: str) -> bool:
    if not isinstance(before, str) or not isinstance(after, str):
        return False
    old, new = OWNED_TASK_ARN.findall(before), OWNED_TASK_ARN.findall(after)
    if set(old) != {"collector", "analyzer"} or set(new) != {"collector", "analyzer"}:
        return False
    normalize = lambda value: json.loads(OWNED_TASK_ARN.sub(r"owned-task-\1", value))
    try:
        return normalize(before) == normalize(after)
    except (TypeError, ValueError):
        return False


def check_lambda(before: dict, after: dict) -> None:
    old = (before.get("environment") or [{}])[0].get("variables")
    new = (after.get("environment") or [{}])[0].get("variables")
    if not isinstance(old, dict) or not isinstance(new, dict) or set(old) != set(new):
        raise RuntimeError("Current-update Lambda environment shape changed")
    allowed = {"PEASO_SOURCE_VERSION", "PEASO_SOURCE_URL", "PEASO_PUBLIC_CUSTOMER_ROLE_TEMPLATE_URL"}
    if {key for key in old if old[key] != new[key]} - allowed:
        raise RuntimeError("Current-update Lambda environment changed unrelated values")


def check_task(before: dict, after: dict) -> None:
    try:
        old = json.loads(before["container_definitions"])
        new = json.loads(after["container_definitions"])
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("Current-update worker container definitions are malformed") from None
    if not isinstance(old, list) or not isinstance(new, list) or len(old) != 1 or len(new) != 1:
        raise RuntimeError("Current-update worker container count differs")
    old, new = dict(old[0]), dict(new[0])
    if not isinstance(old.get("image"), str) or not isinstance(new.get("image"), str):
        raise RuntimeError("Current-update worker image is missing")
    old.pop("image"); new.pop("image")
    old_env, new_env = old.pop("environment", None), new.pop("environment", None)
    if old != new or not isinstance(old_env, list) or not isinstance(new_env, list):
        raise RuntimeError("Current-update worker security or configuration changed")
    def environment(items: list) -> dict:
        if any(not isinstance(item, dict) or set(item) != {"name", "value"} or
               not isinstance(item["name"], str) or not isinstance(item["value"], str) for item in items):
            raise RuntimeError("Current-update worker environment is malformed")
        result = {item["name"]: item["value"] for item in items}
        if len(result) != len(items):
            raise RuntimeError("Current-update worker environment duplicates a name")
        return result
    prior, current = environment(old_env), environment(new_env)
    if set(prior) != set(current) or {key for key in prior if prior[key] != current[key]} - {"PEASO_SOURCE_VERSION"}:
        raise RuntimeError("Current-update worker environment changed unrelated values")


def check_ecs_defaults(before: dict, after: dict, markers: dict) -> None:
    """Accept only the observed provider re-encoding of safe task defaults."""
    scratch = [{"name": "scratch", "configure_at_launch": False, "host_path": "",
                "docker_volume_configuration": [], "efs_volume_configuration": [],
                "fsx_windows_file_server_volume_configuration": [], "s3files_volume_configuration": []}]
    expected_after = [dict(scratch[0])]
    expected_after[0].pop("configure_at_launch")
    tag_defaults = {"Application": "hacktricks-cspm", "ManagedBy": "Terraform"}
    if (before.get("enable_fault_injection") is not False or after.get("enable_fault_injection") is not None or
            markers.get("enable_fault_injection") is not True or
            before.get("ipc_mode") != "" or after.get("ipc_mode") is not None or markers.get("ipc_mode") or
            before.get("pid_mode") != "" or after.get("pid_mode") is not None or markers.get("pid_mode") or
            before.get("tags") != {} or after.get("tags") is not None or markers.get("tags") or
            before.get("tags_all") != tag_defaults or after.get("tags_all") != tag_defaults or
            before.get("volume") != scratch or after.get("volume") != expected_after or
            markers.get("volume") != [{"configure_at_launch": True, "docker_volume_configuration": [],
                                       "efs_volume_configuration": [], "fsx_windows_file_server_volume_configuration": [],
                                       "s3files_volume_configuration": []}]):
        raise RuntimeError("Current-update ECS default-false/scratch/IPC/PID/tag equivalence differs")


def check_api_policy(before: dict, after: dict) -> None:
    old = json_document(before.get("policy"), "API IAM policy")
    new = json_document(after.get("policy"), "API IAM policy")
    statements = new.get("Statement")
    if not isinstance(statements, list):
        raise RuntimeError("Current-update API IAM statements are malformed")
    pool = f"arn:aws:cognito-idp:us-east-1:{ACCOUNT}:userpool/us-east-1_7rbhezdKX"
    candidates = [item for item in statements if isinstance(item, dict) and item.get("Resource") == pool and
                  isinstance(item.get("Action"), list) and "cognito-idp:ListUserPoolClients" in item["Action"]]
    if len(candidates) != 1 or candidates[0]["Action"].count("cognito-idp:ListUserPoolClients") != 1:
        raise RuntimeError("Current-update API IAM addition is not uniquely scoped")
    candidates[0]["Action"].remove("cognito-idp:ListUserPoolClients")
    if new != old:
        raise RuntimeError("Current-update API IAM policy changed beyond the one read action")


def check_template_policy(before: dict, after: dict, resources: dict) -> None:
    old = json_document(before.get("policy"), "template bucket policy")
    new = json_document(after.get("policy"), "template bucket policy")
    statements = new.get("Statement")
    if not isinstance(statements, list):
        raise RuntimeError("Current-update template policy statements are malformed")
    candidates = [item for item in statements if isinstance(item, dict) and item.get("Sid") == "PublicReadOnlyCustomerRoleTemplate"]
    if len(candidates) != 1 or candidates[0].get("Action") != "s3:GetObject" or candidates[0].get("Principal") != "*":
        raise RuntimeError("Current-update template policy public read statement differs")
    bucket_arn = resources["aws_s3_bucket.templates[0]"].get("arn")
    expected = {f"{bucket_arn}/customer-role-{item}.json" for item in TEMPLATE_HASHES}
    values = candidates[0].get("Resource")
    if not isinstance(values, list) or len(values) != len(set(values)) or set(values) & expected != expected:
        raise RuntimeError("Current-update template policy lacks exact new resources")
    candidates[0]["Resource"] = [item for item in values if item not in expected]
    if new != old:
        raise RuntimeError("Current-update template policy changed unrelated permissions")


def check_template_bucket_controls(resources: dict, bucket: str) -> None:
    ownership = resources['aws_s3_bucket_ownership_controls.templates[0]']
    encryption = resources['aws_s3_bucket_server_side_encryption_configuration.templates[0]']
    versioning = resources['aws_s3_bucket_versioning.templates[0]']
    public = resources['aws_s3_bucket_public_access_block.templates[0]']
    if (any(item.get('bucket') != bucket for item in (ownership, encryption, versioning, public)) or
            ownership.get('rule') != [{'object_ownership': 'BucketOwnerEnforced'}] or
            encryption.get('rule') != [{'apply_server_side_encryption_by_default': [
                {'kms_master_key_id': '', 'sse_algorithm': 'AES256'}],
                'blocked_encryption_types': ['SSE-C'], 'bucket_key_enabled': False}] or
            versioning.get('versioning_configuration') != [{'mfa_delete': 'Disabled', 'status': 'Enabled'}] or
            any(public.get(key) is not value for key, value in {
                'block_public_acls': True, 'ignore_public_acls': True,
                'block_public_policy': False, 'restrict_public_buckets': False}.items())):
        raise RuntimeError('Current-update immutable template bucket controls differ')


def check_template_create(address: str, after: dict, resources: dict, infra: Path) -> None:
    template_hash = TEMPLATE_ADDRESSES[address]
    # storage.tf merges the current customer-role.json last, overriding the
    # historical filename for the same content hash.
    source_name = "customer-role.json" if template_hash == TEMPLATE_HASHES[-1] else f"customer-role-{template_hash}.json"
    source = infra / source_name
    content = source.read_bytes()
    if digest(content) != template_hash:
        raise RuntimeError("Current-update immutable customer-role source hash differs")
    expected = {"bucket": resources["aws_s3_bucket.templates[0]"].get("id"),
                "key": f"customer-role-{template_hash}.json",
                "source": f"./{source_name}",
                "etag": hashlib.md5(content).hexdigest(), "content_type": "application/json",
                "content_disposition": 'attachment; filename="customer-role.json"',
                "cache_control": "public,max-age=31536000,immutable", "metadata": {"sha256": template_hash}}
    for key, value in expected.items():
        if after.get(key) != value:
            raise RuntimeError(f"Current-update template object differs: {key}")
    # HashiCorp AWS provider v6.68.0's aws_s3_object schema has these optional
    # and computed fields. Reject any unexpected field and every nondefault
    # writable field beyond the pinned storage.tf configuration.
    defaults = {"acl": (None, "private"), "bucket_key_enabled": (None, False),
                "checksum_algorithm": (None, ""),
                "checksum_crc32": (None, ""), "checksum_crc32c": (None, ""),
                "checksum_crc64nvme": (None, ""), "checksum_sha1": (None, ""),
                "checksum_sha256": (None, ""), "content": (None, ""),
                "content_base64": (None, ""), "content_encoding": (None, ""),
                "content_language": (None, ""), "force_destroy": (None, False),
                "kms_key_id": (None, ""), "object_lock_legal_hold_status": (None, ""),
                "object_lock_mode": (None, ""), "object_lock_retain_until_date": (None, ""),
                "override_provider": (None, []), "region": (None, "us-east-1"),
                "server_side_encryption": (None, "AES256"), "source_hash": (None, ""),
                "storage_class": (None, "STANDARD"), "tags": (None, {}),
                "tags_all": ({"Application": "hacktricks-cspm", "ManagedBy": "Terraform"},),
                "website_redirect": (None, ""),
                "version_id": (None, "")}
    if set(after) - set(expected) - set(defaults) - {"id", "arn"}:
        raise RuntimeError("Current-update template object has unreviewed provider fields")
    for key, allowed in defaults.items():
        if after.get(key) not in allowed:
            raise RuntimeError(f"Current-update template object changes an unconfigured field: {key}")
    bucket, key = expected["bucket"], expected["key"]
    check_template_bucket_controls(resources, bucket)
    if after.get("id") not in (None, f"{bucket}/{key}") or after.get("arn") not in (
            None, f"arn:aws:s3:::{bucket}/{key}"):
        raise RuntimeError("Current-update template object identity differs")


def check_download(before: dict, after: dict, infra: Path) -> None:
    content = (infra / "customer-role.json").read_bytes()
    if digest(content) != TEMPLATE_HASHES[-1] or after.get("etag") != hashlib.md5(content).hexdigest():
        raise RuntimeError("Current-update download object is not the signed current role")
    if after.get("source") != "./customer-role.json" or before.get("source") != after.get("source"):
        raise RuntimeError("Current-update download source path changed")


def check_change(resource: dict, resources: dict, infra: Path) -> None:
    address, change = resource["address"], resource["change"]
    actions = change.get("actions")
    if actions != UPDATE_ACTIONS[address]:
        raise RuntimeError("Current-update action differs from its exact owned address")
    before, after, markers = change.get("before"), change.get("after"), change.get("after_unknown") or {}
    if not isinstance(after, dict) or not isinstance(markers, dict):
        raise RuntimeError("Current-update after/unknown shape is malformed")
    allowed_unknown = TEMPLATE_UNKNOWN if address in TEMPLATE_ADDRESSES else UNKNOWN_FIELDS.get(address, set())
    if {key for key, value in markers.items() if unknown(value)} - allowed_unknown:
        raise RuntimeError("Current-update plan defers a security or identity value")
    if address in TEMPLATE_ADDRESSES:
        if before is not None:
            raise RuntimeError("Current-update immutable template is not a create")
        if markers != TEMPLATE_MARKERS:
            raise RuntimeError("Current-update immutable template computed fields differ")
        check_template_create(address, after, resources, infra)
        return
    if before != resources.get(address) or not isinstance(before, dict):
        raise RuntimeError("Current-update prior resource values differ from state")
    if set(changed_fields(change)) - FIELDS[address]:
        raise RuntimeError("Current-update changed a field outside the exact address allowlist")
    if address.startswith("aws_lambda_function."):
        check_lambda(before, after)
    elif address.startswith("aws_ecs_task_definition."):
        check_task(before, after)
        check_ecs_defaults(before, after, markers)
    elif address == "aws_iam_role_policy.api":
        check_api_policy(before, after)
    elif address == "aws_s3_bucket_policy.templates[0]":
        if markers.get('policy') is True:
            if markers != {'policy': True} or after.get('policy') is not None:
                raise RuntimeError('Current-update template policy unknown shape differs')
        else:
            check_template_policy(before, after, resources)
    elif address == "aws_s3_object.customer_role_download":
        check_download(before, after, infra)
    elif address in {"aws_sfn_state_machine.scan", "aws_iam_role_policy.workflow"}:
        field = "definition" if address == "aws_sfn_state_machine.scan" else "policy"
        if unknown(markers.get(field, False)):
            if markers.get(field) is not True or not isinstance(before.get(field), str):
                raise RuntimeError("Current-update task references have malformed unknown marker")
        elif not task_refs_equal(before.get(field), after.get(field)):
            raise RuntimeError("Current-update task references changed beyond owned revisions")


def review(data: dict, contract: dict, state: dict, infra: Path) -> dict:
    if set(contract) != {"schema", "account", "backend", "state", "plan", "release", "approved_changes", "approved_drift"}:
        raise RuntimeError("Current-update contract has missing or unreviewed fields")
    if contract.get("schema") != "peaso-current-update-v1" or contract.get("account") != ACCOUNT or contract.get("backend") != BACKEND:
        raise RuntimeError("Current-update contract scope differs")
    raw_resources = state_resources(state)
    resources, drift_rows = reviewed_drift(data.get("resource_drift", []), raw_resources,
                                           contract.get("approved_drift"))
    state_meta = contract.get("state") or {}
    if set(state_meta) != {"path", "sha256", "lineage", "serial", "managed_address_sha256"}:
        raise RuntimeError("Current-update state contract has missing or unreviewed fields")
    if (state_meta.get("lineage") != state["lineage"] or state_meta.get("serial") != state["serial"] or
            state_meta.get("managed_address_sha256") != BASELINE_ADDRESSES_SHA256):
        raise RuntimeError("Current-update contract state identity differs")
    if data.get("prior_state", {}).get("values", {}).get("root_module", {}).get("child_modules"):
        raise RuntimeError("Current-update saved plan has child modules")
    prior = data.get("prior_state", {}).get("values", {}).get("root_module", {}).get("resources")
    if not isinstance(prior, list) or len(prior) != BASELINE_COUNT + len(PRIOR_DATA_SOURCES) or any(
            not isinstance(row, dict) or row.get("mode") not in {"managed", "data"} for row in prior):
        raise RuntimeError("Current-update saved plan prior inventory differs")
    prior_managed = [row for row in prior if row["mode"] == "managed"]
    check_prior_data_sources(state, [row for row in prior if row["mode"] == "data"])
    prior_values = {row["address"]: row.get("values") for row in prior_managed}
    if len(prior_values) != BASELINE_COUNT or prior_values != resources:
        raise RuntimeError("Current-update saved plan prior values differ from exact state")
    rows = data.get("resource_changes")
    if not isinstance(rows, list) or any(row.get("mode") != "managed" or row.get("module_address") for row in rows):
        raise RuntimeError("Current-update plan has unmanaged or child-module changes")
    by_address = {row["address"]: row for row in rows}
    if len(by_address) != len(rows) or set(by_address) != set(resources) | set(TEMPLATE_ADDRESSES):
        raise RuntimeError("Current-update changed the exact CSPM address inventory")
    approved = contract.get("approved_changes")
    if not isinstance(approved, dict) or not RUNTIME_REQUIRED.issubset(approved) or not set(TEMPLATE_ADDRESSES).issubset(approved):
        raise RuntimeError("Current-update contract omits the required runtime or immutable objects")
    observed = {}
    for address, row in by_address.items():
        change = row.get("change")
        if not isinstance(change, dict):
            raise RuntimeError("Current-update plan has a malformed resource change")
        if address not in approved:
            if (address not in resources or change.get("actions") != ["no-op"] or
                    change.get("before") != resources[address] or change.get("after") != resources[address] or
                    unknown(change.get("after_unknown") or {})):
                raise RuntimeError("Current-update unapproved address is not an exact no-op")
            continue
        if address not in UPDATE_ACTIONS:
            raise RuntimeError("Current-update contract approves an unrelated address")
        check_change(row, resources, infra)
        expected = {"actions": change["actions"], "changed_fields": changed_fields(change),
                    "change_sha256": digest(canonical(change))}
        if approved[address] != expected:
            raise RuntimeError("Current-update contract differs from reviewed action/fields/values")
        observed[address] = expected
    if set(observed) != set(approved):
        raise RuntimeError("Current-update contract contains unused approvals")
    return {"state": state, "resources": resources, "drift_rows": drift_rows,
            "approved_changes": observed,
            "lineage": state["lineage"], "serial": state["serial"]}


def load_context(plan: Path, raw_json: bytes, data: dict, contract_path: Path,
                 approved_sha256: str, infra: Path, build: Path) -> dict:
    contract_raw = private_artifact(contract_path, approved_sha256)
    contract = json_document(contract_raw.decode(), "approved contract")
    plan_meta = contract.get("plan") or {}
    if set(plan_meta) != {"sha256", "json_sha256", "json_path"}:
        raise RuntimeError("Current-update plan contract has missing or unreviewed fields")
    if plan_meta["sha256"] != digest(plan.read_bytes()) or plan_meta["json_sha256"] != digest(raw_json):
        raise RuntimeError("Current-update contract does not bind the saved binary and JSON")
    if private_artifact(Path(plan_meta["json_path"]), plan_meta["json_sha256"]) != raw_json:
        raise RuntimeError("Current-update saved JSON bytes differ from the reviewed binary")
    state_meta = contract.get("state") or {}
    state_raw = private_artifact(Path(state_meta.get("path", "")), state_meta.get("sha256", ""))
    state = json_document(state_raw.decode(), "private baseline state")
    release_meta = contract.get("release") or {}
    if set(release_meta) != {"source_version", "release_json_sha256", "source_zip_sha256",
                             "api_zip_sha256", "frontend_manifest_sha256", "worker_image"}:
        raise RuntimeError("Current-update release contract has missing or unreviewed fields")
    release_path = build / "release.json"
    if digest(release_path.read_bytes()) != release_meta.get("release_json_sha256"):
        raise RuntimeError("Current-update release manifest changed")
    release = json_document(release_path.read_text(), "frozen release")
    check_source_pins(release, infra)
    version = release.get("source_version")
    if not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{64}", version) or version != release_meta.get("source_version"):
        raise RuntimeError("Current-update release source version differs")
    artifacts = {
        "source_zip_sha256": build / f"peaso-source-{version}.zip",
        "api_zip_sha256": build / "api.zip",
        "frontend_manifest_sha256": build / "frontend-build.json",
    }
    for key, path in artifacts.items():
        if digest(path.read_bytes()) != release_meta.get(key):
            raise RuntimeError(f"Current-update {key} differs from reviewed package")
    variables = json_document((infra / "deployment.auto.tfvars.json").read_text(), "deployment variables")
    image = release_meta.get("worker_image")
    if (not isinstance(image, str) or not re.fullmatch(
            rf"{ACCOUNT}\.dkr\.ecr\.us-east-1\.amazonaws\.com/hacktricks-cspm-worker@sha256:[a-f0-9]{{64}}", image) or
            variables.get("worker_image") != image or Path(variables.get("api_zip", "")) != artifacts["api_zip_sha256"]):
        raise RuntimeError("Current-update image or API ZIP variables differ")
    context = review(data, contract, state, infra)
    context.update({"contract_path": str(contract_path), "contract_sha256": approved_sha256,
                    "state_sha256": state_meta["sha256"], "release": release_meta})
    if digest(private_artifact(contract_path, approved_sha256)) != approved_sha256 or digest(plan.read_bytes()) != plan_meta["sha256"]:
        raise RuntimeError("Current-update approval or saved plan changed during review")
    return context


def check_resolved_documents(resources: dict, planned_rows: dict, workflow: dict,
                             workflow_policy: dict, api_policy: dict, template_policy: dict,
                             revisions: dict) -> None:
    """Compare full resolved policies/workflow with approved before/after values."""
    if set(revisions) != {"collector", "analyzer"}:
        raise RuntimeError("Current-update resolved task revisions are incomplete")
    expected_arns = set(revisions.values())
    for address, actual in (("aws_sfn_state_machine.scan", workflow),
                            ("aws_iam_role_policy.workflow", workflow_policy)):
        field = "definition" if address == "aws_sfn_state_machine.scan" else "policy"
        before = resources[address].get(field)
        text = json.dumps(actual, sort_keys=True)
        if not task_refs_equal(before, text) or set(OWNED_TASK_ARN.findall(text)) != {"collector", "analyzer"}:
            raise RuntimeError("Current-update resolved workflow or policy changed beyond task revisions")
        found = list(OWNED_TASK_ARN.finditer(text))
        if {match.group(0) for match in found} != expected_arns:
            raise RuntimeError("Current-update resolved workflow or policy references another task revision")
    api_actual = {"policy": json.dumps(api_policy, sort_keys=True)}
    check_api_policy(resources["aws_iam_role_policy.api"], api_actual)
    api_planned = planned_rows["aws_iam_role_policy.api"]["change"]["after"]
    if json_document(api_actual["policy"], "resolved API IAM policy") != json_document(
            api_planned["policy"], "planned API IAM policy"):
        raise RuntimeError("Current-update resolved API IAM policy differs from the saved plan")
    template_actual = {"policy": json.dumps(template_policy, sort_keys=True)}
    check_template_policy(resources["aws_s3_bucket_policy.templates[0]"], template_actual, resources)
    template_change = planned_rows["aws_s3_bucket_policy.templates[0]"]["change"]
    if template_change.get("after_unknown", {}).get("policy") is not True and json_document(
            template_actual["policy"], "resolved template policy") != json_document(
            template_change["after"]["policy"], "planned template policy"):
        raise RuntimeError("Current-update resolved template policy differs from the saved plan")

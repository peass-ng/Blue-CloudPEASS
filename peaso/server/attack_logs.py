"""Bounded CloudTrail reads for the interactive attack-evidence preview."""
from __future__ import annotations

import gzip
import io
import json
import re
from datetime import datetime, timedelta, timezone

from botocore.config import Config

from peaso.collectors.aws import _session
from .validation import COLLECTOR_ROLE_ARN, PLATFORM_ACCOUNT_IDS


MAX_OBJECTS = 5
MAX_COMPRESSED_BYTES = 10_000_000
MAX_EVENTS = 2_000
MAX_LOOKUP_PAGES = 40
MAX_UNCOMPRESSED_OBJECT_BYTES = 5_000_000
_CONFIG = Config(connect_timeout=5, read_timeout=20, retries={"max_attempts": 1})


class LogAccessError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _assume(session, role_arn, external_id, region):
    import boto3
    params = {"RoleArn": role_arn, "RoleSessionName": "hacktricks-cspm-log-review", "DurationSeconds": 3600}
    if external_id:
        params["ExternalId"] = external_id
    creds = session.client("sts", region_name=region, config=_CONFIG).assume_role(**params)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                         aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"], region_name=region)


def _target_session(auth, options, role_arn, region, scopes=None):
    hosted = (auth.get("method") in {"assume_role", "task_role"}
              and str(auth.get("external_id", "")).startswith(("hacktricks-cspm-", "peaso-"))
              and not auth.get("aws_access_key_id"))
    source_auth = {**auth, "method": "access_keys" if auth.get("aws_access_key_id") else auth.get("method", "default")}
    if source_auth["method"] == "assume_role":
        source_auth["method"] = "profile" if auth.get("profile") else "default"
    session, _ = _session({"method": "default"} if hosted else source_auth, region)
    if hosted:
        session = _assume(session, COLLECTOR_ROLE_ARN, None, region)
    else:
        for step in auth.get("role_chain") or []:
            entry = {"role_arn": step} if isinstance(step, str) else step
            session = _assume(session, entry["role_arn"], entry.get("external_id") or auth.get("external_id"), region)
        if auth.get("role_arn"):
            session = _assume(session, auth["role_arn"], auth.get("external_id"), region)
    targets = list(auth.get("assume_roles") or [])
    if hosted and auth.get("role_arn"):
        targets.append({"role_arn": auth["role_arn"]})
    allowed = {t if isinstance(t, str) else t.get("role_arn") for t in targets}
    if role_arn:
        if role_arn not in allowed:
            raise LogAccessError("role_not_in_connector")
        if hosted and role_arn.split(":")[4] in PLATFORM_ACCOUNT_IDS:
            raise LogAccessError("platform_account_forbidden")
        entry = next(t for t in targets if (t if isinstance(t, str) else t.get("role_arn")) == role_arn)
        external = (entry.get("external_id") if isinstance(entry, dict) else None) or auth.get("external_id")
        session = _assume(session, role_arn, external, region)
    elif hosted or (allowed and not options.get("include_source_account", True)):
        raise LogAccessError("select_connector_role")
    identity = session.client("sts", region_name=region, config=_CONFIG).get_caller_identity()
    account = identity["Account"]
    if hosted and account in PLATFORM_ACCOUNT_IDS:
        raise LogAccessError("platform_account_forbidden")
    if role_arn and account != role_arn.split(":")[4]:
        raise LogAccessError("role_account_mismatch")
    account_scopes = {scope[:12] for scope in scopes or [] if isinstance(scope, str) and re.fullmatch(r"\d{12}(?:/[a-z0-9-]+)?", scope)}
    if account_scopes and account not in account_scopes:
        raise LogAccessError("account_outside_connector_scope")
    plain_account = account in (scopes or [])
    paired = {scope for scope in scopes or [] if isinstance(scope, str) and scope.startswith(account + "/")}
    if paired and not plain_account and f"{account}/{region}" not in paired:
        raise LogAccessError("region_outside_connector_scope")
    configured_regions = {item for item in options.get("regions") or [] if isinstance(item, str)}
    configured_regions.update(scope for scope in scopes or [] if isinstance(scope, str) and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", scope))
    if configured_regions and region not in configured_regions and f"{account}/{region}" not in paired:
        raise LogAccessError("region_outside_connector_scope")
    return session, account


def _objects(client, bucket, prefix, *, count):
    token = None
    found = []
    for _ in range(10):
        params = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            params["ContinuationToken"] = token
        page = client.list_objects_v2(**params)
        for item in page.get("Contents", []):
            if item.get("Key", "").endswith(".json.gz"):
                found.append(item)
                if len(found) >= count:
                    return found, False
        token = page.get("NextContinuationToken")
        if not token:
            return found, page.get("IsTruncated") is not True
    return found, False


def _day_prefix(source):
    if not source.day:
        raise LogAccessError("select_cloudtrail_day")
    try:
        day = datetime.strptime(source.day, "%Y-%m-%d").date()
    except ValueError:
        raise LogAccessError("invalid_cloudtrail_day") from None
    if day > datetime.now(timezone.utc).date():
        raise LogAccessError("future_cloudtrail_day")
    return f"{source.prefix}{source.region}/{day:%Y/%m/%d}/"


def check_aws_source(auth, options, source, scopes=None):
    session, account = _target_session(auth, options, source.role_arn, source.region, scopes)
    if source.kind == "aws_event_history":
        client = session.client("cloudtrail", region_name=source.region, config=_CONFIG)
        client.lookup_events(MaxResults=1)
        return {"account_id": account, "source_status": "accessible", "coverage": "Management events in this Region, up to 90 days; data events are absent."}
    if f"/{account}/CloudTrail/" not in "/" + source.prefix:
        raise LogAccessError("prefix_must_select_target_account_cloudtrail")
    client = session.client("s3", region_name=source.region, config=_CONFIG)
    found, listing_complete = _objects(client, source.bucket, _day_prefix(source), count=1)
    if not found:
        if not listing_complete:
            raise LogAccessError("log_prefix_listing_incomplete")
        return {"account_id": account, "source_status": "empty", "coverage": "The prefix is listable but contains no CloudTrail .json.gz object. Read permission and coverage remain unverified."}
    key = found[0]["Key"]
    response = client.get_object(Bucket=source.bucket, Key=key, Range="bytes=0-0")
    response["Body"].close()
    return {"account_id": account, "source_status": "accessible", "coverage": "S3 listing and GetObject succeeded for one CloudTrail object. KMS decrypt was exercised if the object uses SSE-KMS."}


def analyze_aws_source(auth, options, source, scopes=None):
    session, account = _target_session(auth, options, source.role_arn, source.region, scopes)
    events = []
    coverage = {"account_id": account, "objects_read": 0, "events_read": 0, "truncated": False,
                "source": source.kind, "region": source.region}
    if source.kind == "aws_event_history":
        client = session.client("cloudtrail", region_name=source.region, config=_CONFIG)
        token = None
        after = datetime.now(timezone.utc) - timedelta(days=90)
        for _ in range(MAX_LOOKUP_PAGES):
            params = {"StartTime": after, "MaxResults": 50}
            if token:
                params["NextToken"] = token
            page = client.lookup_events(**params)
            for item in page.get("Events", []):
                try:
                    event = json.loads(item["CloudTrailEvent"])
                except (KeyError, TypeError, ValueError):
                    continue
                if isinstance(event, dict):
                    identity = event.get("userIdentity")
                    identity = identity if isinstance(identity, dict) else {}
                    if str(event.get("recipientAccountId") or identity.get("accountId")) == account:
                        events.append(event)
                if len(events) >= MAX_EVENTS:
                    coverage["truncated"] = True
                    break
            if coverage["truncated"]:
                break
            token = page.get("NextToken")
            if not token:
                break
        if token:
            coverage["truncated"] = True
    else:
        if f"/{account}/CloudTrail/" not in "/" + source.prefix:
            raise LogAccessError("prefix_must_select_target_account_cloudtrail")
        client = session.client("s3", region_name=source.region, config=_CONFIG)
        objects, listing_complete = _objects(client, source.bucket, _day_prefix(source), count=MAX_OBJECTS + 1)
        if not listing_complete or len(objects) > MAX_OBJECTS:
            coverage["truncated"] = True
        total_bytes = 0
        for item in objects[:MAX_OBJECTS]:
            size = int(item.get("Size", 0))
            if size <= 0 or size > MAX_COMPRESSED_BYTES - total_bytes:
                coverage["truncated"] = True
                break
            response = client.get_object(Bucket=source.bucket, Key=item["Key"])
            try:
                raw = response["Body"].read(size + 1)
            finally:
                response["Body"].close()
            if len(raw) != size or len(raw) > MAX_COMPRESSED_BYTES - total_bytes:
                raise LogAccessError("object_size_changed")
            total_bytes += len(raw)
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                    expanded = stream.read(MAX_UNCOMPRESSED_OBJECT_BYTES + 1)
                if len(expanded) > MAX_UNCOMPRESSED_OBJECT_BYTES:
                    raise LogAccessError("decompressed_object_too_large")
                document = json.loads(expanded)
            except (OSError, ValueError, TypeError):
                raise LogAccessError("malformed_cloudtrail_object") from None
            records = document.get("Records") if isinstance(document, dict) else None
            if not isinstance(records, list):
                raise LogAccessError("malformed_cloudtrail_object")
            coverage["objects_read"] += 1
            for event in records:
                if not isinstance(event, dict):
                    continue
                identity = event.get("userIdentity")
                identity = identity if isinstance(identity, dict) else {}
                if str(event.get("recipientAccountId") or identity.get("accountId")) != account:
                    continue
                events.append(event)
                if len(events) >= MAX_EVENTS:
                    coverage["truncated"] = True
                    break
            if coverage["truncated"]:
                break
    coverage["events_read"] = len(events)
    from peaso.attack_detection import detect_aws_events
    detections = detect_aws_events(events)
    return {"coverage": coverage, "detections": [d.__dict__ for d in detections]}

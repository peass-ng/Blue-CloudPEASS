"""All-version launch-template IMDS declarations and unavailable facts."""
from __future__ import annotations

from peaso.checks import CHECKS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


CID = "aws.claude_a.ec2.launch_template_any_version_imdsv2"
DEFAULT_CID = "aws.claude_a.ec2.launch_template_default_imdsv2"
SCOPE = "123456789012/us-east-1"
SAFE = {"HttpEndpoint": "enabled", "HttpTokens": "required"}
DISABLED = {"HttpEndpoint": "disabled"}
UNSAFE = {"HttpEndpoint": "enabled", "HttpTokens": "optional"}


def _check(cid=CID):
    return next(check for check in CHECKS if check.id == cid)


def _version(number, metadata, *, default=False):
    data = {} if metadata is None else {"MetadataOptions": metadata}
    return {"VersionNumber": number, "DefaultVersion": default, "LaunchTemplateData": data}


def _item(*versions):
    return {"LaunchTemplateId": "lt-1", "LaunchTemplateName": "app", "DefaultVersionNumber": 1,
            "Versions": list(versions)}


def _status(item, cid=CID):
    return _check(cid).evaluate(item, {"context": {"Account": "123456789012", "scope": SCOPE}})[0]


def test_explicit_unsafe_version_fails_regardless_of_order_or_default():
    assert _status(_item(_version(1, UNSAFE, default=True), _version(2, SAFE))) == "FAIL"
    assert _status(_item(_version(2, SAFE), _version(1, UNSAFE, default=True))) == "FAIL"
    assert _status(_item(_version(1, SAFE, default=True), _version(2, UNSAFE))) == "FAIL"
    assert _status(_item(_version(1, None, default=True), _version(2, UNSAFE))) == "FAIL"


def test_complete_safe_versions_pass_and_default_check_remains_separate():
    complete = _item(_version(1, SAFE, default=True), _version(2, DISABLED))
    assert _status(complete) == "PASS"
    assert _status(_item(_version(1, UNSAFE, default=True), _version(2, SAFE)), DEFAULT_CID) == "FAIL"


def test_omission_unknown_enum_duplicate_identity_and_partial_facts_are_unknown():
    assert _status(_item(_version(1, None, default=True))) == "UNKNOWN"
    assert _status(_item(_version(1, {"HttpTokens": "required"}, default=True))) == "UNKNOWN"
    assert _status(_item(_version(1, {"HttpEndpoint": "enabled"}, default=True))) == "UNKNOWN"
    assert _status(_item(_version(1, {"HttpEndpoint": "enabled", "HttpTokens": "future"}, default=True))) == "UNKNOWN"
    assert _status(_item(_version(1, SAFE, default=True), _version(1, SAFE))) == "UNKNOWN"
    assert _status(_item(_version(True, SAFE, default=True))) == "UNKNOWN"
    assert _status(_item()) == "UNKNOWN"
    denied = _item(_version(1, SAFE, default=True))
    denied["_coverage"] = {"Versions": {"status": "denied"}}
    assert _status(denied) == "UNKNOWN"
    truncated = _item(_version(1, SAFE, default=True))
    truncated["_coverage"] = {"Versions": {"status": "partial", "error": {"code": "page_limit"}}}
    assert _status(truncated) == "UNKNOWN"


def test_production_snapshot_reports_unsafe_default_despite_safe_other_version():
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "ec2_launch_template", "scope": SCOPE,
        "service": "ec2", "status": "collected", "items": [
            _item(_version(1, UNSAFE, default=True), _version(2, SAFE))]}])
    report = evaluate_snapshot(snapshot, checks=[CID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CID]
    assert len(findings) == 1 and findings[0]["status"] == "FAIL"

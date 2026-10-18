"""Retained references reuse independently reviewed equivalent native predicates."""
import copy

import pytest

from peaso.checks import CHECKS, claude_aws_a_ec2, claude_aws_a_network
from peaso.checks.fixtures import CASES

IDS = {"aws.claude_a.ec2.ebs_encryption_by_default", "aws.claude_a.ec2.instance_imdsv2_applied",
    "aws.claude_a.ec2.instance_detailed_monitoring", "aws.claude_a.ebs.volume_in_use", "aws.claude_a.vpc.default_sg_no_rules", "aws.claude_a.vpc.flow_logs_active",
    "aws.claude_a.ec2.ami_not_public", "aws.claude_a.ec2.ami_ebs_encrypted", "aws.claude_a.ec2.ami_not_older_than_90_days",
    "aws.claude_a.ec2.instance_not_older_than_180_days", "aws.claude_a.ec2.stopped_instance_90_days", "aws.claude_a.ec2.instance_ebs_delete_on_termination",
    "aws.claude_a.ec2.eni_in_use", "aws.claude_a.ebs.snapshot_encrypted", "aws.claude_a.ebs.snapshot_not_public",
    "aws.claude_a.vpc.nacl_no_world_remote_admin", "aws.claude_a.vpc.sg_world_any_remote_admin", "aws.claude_a.vpc.sg_world_v6_remote_admin",
    "aws.claude_a.vpc.sg_world_any_cifs", "aws.claude_a.vpc.sg_world_v4_ssh", "aws.claude_a.vpc.sg_world_v4_rdp", "aws.cloudtrail.logging"}
REGISTRY = {c.id: c for c in CHECKS if c.id in IDS}


@pytest.mark.parametrize("cid", sorted(IDS))
def test_equivalent_references_real_states_and_purity(cid):
    assert cid in REGISTRY
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state]) if state in cases else ({} if state == "missing" else None)
        index = copy.deepcopy(cases.get("index", {}))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("tokens,state,expected", [("required", "applied", "PASS"), ("required", "pending", "FAIL"), ("optional", "applied", "FAIL")])
def test_applied_imdsv2_query_keeps_state_and_endpoint_disabled_difference(tokens, state, expected):
    check = REGISTRY["aws.claude_a.ec2.instance_imdsv2_applied"]
    item = {"MetadataOptions": {"HttpTokens": tokens, "State": state, "HttpEndpoint": "disabled"}}
    assert check.evaluate(item, {})[0] == expected


def test_default_security_group_only_and_no_any_traffic_in_either_direction():
    check = REGISTRY["aws.claude_a.vpc.default_sg_no_rules"]
    item = {"GroupName": "default", "IpPermissions": [], "IpPermissionsEgress": []}
    assert check.evaluate(item, {})[0] == "PASS"
    item["IpPermissionsEgress"] = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
    assert check.evaluate(item, {})[0] == "FAIL"
    item["GroupName"] = "application"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"


def test_readonly_ec2_settings_independent_denial_coverage_and_cache(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("ec2", region_name="us-east-1")
    stub = Stubber(client)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    stub.add_response("get_ebs_encryption_by_default", {"EbsEncryptionByDefault": True}, {})
    stub.add_client_error("get_snapshot_block_public_access_state", "UnauthorizedOperation", expected_params={})
    stub.add_response("get_image_block_public_access_state", {"ImageBlockPublicAccessState": "block-new-sharing"}, {})
    stub.add_response("get_instance_metadata_defaults", {"AccountLevel": {"HttpTokens": "required"}}, {})
    with stub:
        requests = aws.Requests({})
        first = aws._ec2_regional_settings(requests, session, "us-east-1")
        second = aws._ec2_regional_settings(requests, session, "us-east-1")
        assert first.status == "collected" and first.items == second.items and requests.calls == 4
        item = first.items[0]
        assert item["EbsEncryptionByDefault"] is True
        assert item["_coverage"]["SnapshotBlockPublicAccessState"]["status"] == "denied"
        assert REGISTRY["aws.claude_a.ec2.ebs_encryption_by_default"].evaluate(item, {})[0] == "PASS"
        assert item["InstanceMetadataDefaults"] == {"HttpTokens": "required"}
        stub.assert_no_pending_responses()


def test_flow_log_alias_requires_owned_vpc_and_preserves_every_nonactive_join_row():
    from peaso.checks.claude_aws_a_common import idx, ACCOUNT
    check = REGISTRY["aws.claude_a.vpc.flow_logs_active"]
    vpc = {"VpcId": "vpc-1", "OwnerId": ACCOUNT}
    flow = {"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}
    assert check.evaluate(vpc, idx(flow_log=[flow]))[0] == "PASS"
    assert check.evaluate(vpc, idx(flow_log=[flow, {"ResourceId": "vpc-1", "FlowLogStatus": "INACTIVE"}]))[0] == "FAIL"
    assert check.evaluate(vpc, idx(flow_log=[]))[0] == "FAIL"
    assert check.evaluate(vpc, idx(flow_log=None))[0] == "UNKNOWN"
    assert check.evaluate({**vpc, "OwnerId": "210987654321"}, idx(flow_log=None))[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("cid,field,days", [("aws.claude_a.ec2.ami_not_older_than_90_days", "CreationDate", 90), ("aws.claude_a.ec2.instance_not_older_than_180_days", "LaunchTime", 180)])
def test_age_alias_preserves_midnight_inclusive_cutoff_without_rolling_time(cid, field, days):
    from datetime import datetime, timedelta, timezone
    cutoff = datetime(2026, 10, 10, tzinfo=timezone.utc) - timedelta(days=days)
    index = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}
    assert REGISTRY[cid].evaluate({field: cutoff.isoformat()}, index)[0] == "PASS"
    assert REGISTRY[cid].evaluate({field: (cutoff - timedelta(seconds=1)).isoformat()}, index)[0] == "FAIL"


def test_stopped_and_stopping_source_inclusive_90day_cutoff_and_running_skip():
    cid = "aws.claude_a.ec2.stopped_instance_90_days";check = REGISTRY[cid]
    from datetime import datetime, timedelta, timezone
    cutoff = datetime(2026, 10, 10, tzinfo=timezone.utc) - timedelta(days=90)
    index = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}
    for state in ("stopped", "stopping"):
        assert check.evaluate({"State": {"Name": state}, "StateTransitionReason": "User initiated ("+cutoff.strftime("%Y-%m-%d %H:%M:%S")+" GMT)"}, index)[0] == "FAIL"
    assert check.evaluate({"State": {"Name": "running"}}, index)[0] == "NOT_APPLICABLE"


def test_snapshot_permission_read_denial_does_not_contaminate_encryption_metadata(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("ec2", region_name="us-east-1");stub = Stubber(client)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    stub.add_client_error("describe_snapshot_attribute", "UnauthorizedOperation", expected_params={"SnapshotId": "snap-inert", "Attribute": "createVolumePermission"})
    with stub:
        rows = aws._enrich(aws.Requests({}), session, "us-east-1", "ebs_snapshot", [{"SnapshotId": "snap-inert", "Encrypted": True}])
        assert REGISTRY["aws.claude_a.ebs.snapshot_encrypted"].evaluate(rows[0], {})[0] == "PASS"
        assert REGISTRY["aws.claude_a.ebs.snapshot_not_public"].evaluate(rows[0], {})[0] == "UNKNOWN"
        stub.assert_no_pending_responses()


def test_owned_image_and_snapshot_selection_use_self_owner_pagination(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    clients = {service: session.client(service, region_name="us-east-1") for service in ("sts", "ec2")}
    monkeypatch.setattr(aws.Requests, "client", lambda self, context, service, region: clients[service])
    monkeypatch.setattr(aws, "_session", lambda *args: (session, "inert"))
    sts,ec2 = Stubber(clients["sts"]),Stubber(clients["ec2"])
    sts.add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/inert", "UserId": "INERT"}, {})
    ec2.add_response("describe_snapshots", {"Snapshots": [{"SnapshotId": "snap-inert", "Encrypted": True}]}, {"OwnerIds": ["self"]})
    ec2.add_response("describe_snapshot_attribute", {"SnapshotId": "snap-inert"}, {"SnapshotId": "snap-inert", "Attribute": "createVolumePermission"})
    ec2.add_response("describe_images", {"Images": []}, {"Owners": ["self"], "IncludeDeprecated": True, "IncludeDisabled": True})
    with sts,ec2:
        snapshot = aws.collect({"provider": "aws", "scopes": ["us-east-1"], "options": {"service_concurrency": 1}}, ["ec2_image", "ebs_snapshot"])
        assert next(c for c in snapshot["collections"] if c["type"] == "ec2_image")["status"] == "empty"
        row = next(c for c in snapshot["collections"] if c["type"] == "ebs_snapshot")["items"][0]
        assert row["CreateVolumePermissions"] == [] and row["_coverage"]["CreateVolumePermissions"]["status"] == "empty"
        assert snapshot["metadata"]["calls"] == 4
        sts.assert_no_pending_responses();ec2.assert_no_pending_responses()


@pytest.mark.parametrize("cid,port,v4,v6", [
    ("aws.claude_a.vpc.sg_world_any_remote_admin", 22, True, True),
    ("aws.claude_a.vpc.sg_world_v6_remote_admin", 3389, False, True),
    ("aws.claude_a.vpc.sg_world_any_cifs", 445, True, True),
    ("aws.claude_a.vpc.sg_world_v4_ssh", 22, True, False),
    ("aws.claude_a.vpc.sg_world_v4_rdp", 3389, True, False)])
def test_sg_exact_source_cidr_ip_family_range_and_all_protocol_literals(cid, port, v4, v6):
    from peaso.checks.claude_aws_a_common import idx
    check = REGISTRY[cid]
    for cidr, expected in (("0.0.0.0/0", "FAIL" if v4 else "PASS"), ("::/0", "FAIL" if v6 else "PASS"), ("10.0.0.0/8", "PASS")):
        field, key = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
        permission = {"IpProtocol": "udp", "FromPort": port, "ToPort": port, "IpRanges": [], "Ipv6Ranges": [], field: [{key: cidr}]}
        item = {"GroupId": "sg-inert", "IpPermissions": [permission]}
        index = idx(security_group=[item]) if cid == "aws.claude_a.vpc.sg_world_v4_ssh" else {}
        udp_expected = "PASS" if cid == "aws.claude_a.vpc.sg_world_v4_ssh" else expected
        assert check.evaluate(item, index)[0] == udp_expected
        permission.update(IpProtocol="-1");permission.pop("FromPort");permission.pop("ToPort")
        assert check.evaluate(item, index)[0] == expected


def test_nacl_source_is_declared_allow_lint_independent_of_preceding_deny_rule():
    check = REGISTRY["aws.claude_a.vpc.nacl_no_world_remote_admin"]
    deny = {"RuleNumber": 50, "Egress": False, "Protocol": "6", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}}
    allow = {**deny, "RuleNumber": 100, "RuleAction": "allow"}
    assert check.evaluate({"Entries": [deny, allow]}, {})[0] == "FAIL"
    allow["Egress"] = True
    assert check.evaluate({"Entries": [deny, allow]}, {})[0] == "PASS"
    allow.update(Egress=False, Protocol="1")
    assert check.evaluate({"Entries": [allow]}, {})[0] == "PASS"

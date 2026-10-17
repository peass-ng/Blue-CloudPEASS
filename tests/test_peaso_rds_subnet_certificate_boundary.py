"""RDS subnet route and CA expiry boundaries from captured, API-shaped facts."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_aws_b_common import indexes, inventory


REGISTRY = {check.id: check for check in CHECKS}
SUBNET = REGISTRY["aws.cb.rds.instance_no_public_subnet"]
CERT = REGISTRY["aws.cb.rds.ca_certificate_not_expiring_7_days"]
EXPOSURE = REGISTRY["aws.cb.rds.instance_internet_exposed"]
INSTANCE_ARN = "arn:aws:rds:us-east-1:111111111111:db:db1"
CAPTURED = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def db_instance(*subnets):
    return {"DBInstanceArn": INSTANCE_ARN, "Engine": "postgres",
            "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": subnet, "SubnetStatus": "Active"} for subnet in subnets]}}


def routes(*rows, explicit=True, status="collected"):
    associations = [{"SubnetId": "subnet-a"}] if explicit else [{"Main": True}]
    return indexes(inventory("subnet", [{"SubnetId": "subnet-a", "VpcId": "vpc-1"}]),
                   inventory("route_table", [{"VpcId": "vpc-1", "Associations": associations,
                                               "Routes": list(rows)}], status=status))


LOCAL = {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}
DIRECT = {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}
NAT = {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-123"}


@pytest.mark.parametrize("default_route,expected", [(DIRECT, "FAIL"), (NAT, "PASS")])
@pytest.mark.parametrize("explicit", [True, False])
def test_effective_explicit_or_main_route_classifies_direct_igw_only(default_route, expected, explicit):
    item = db_instance("subnet-a")
    before = deepcopy(item)
    status, evidence = SUBNET.evaluate(item, routes(LOCAL, default_route, explicit=explicit))
    assert status == expected
    assert evidence["public_subnets"] == (["subnet-a"] if expected == "FAIL" else [])
    assert item == before


def test_private_local_only_and_unrelated_exposure_check():
    item = db_instance("subnet-a")
    assert SUBNET.evaluate(item, routes(LOCAL))[0] == "PASS"
    assert EXPOSURE.evaluate({**item, "PubliclyAccessible": False}, {})[0] == "PASS"


@pytest.mark.parametrize("item,index", [
    (db_instance(), routes(LOCAL)),
    ({"DBInstanceArn": INSTANCE_ARN, "Engine": "postgres"}, routes(LOCAL)),
    (db_instance("subnet-a"), indexes(inventory("subnet", []), inventory("route_table", []))),
    (db_instance("subnet-a"), routes(LOCAL, status="partial")),
    (db_instance("subnet-a"), routes()),
    (db_instance("subnet-a"), routes({"DestinationCidrBlock": "0.0.0.0/0"})),
    (db_instance("subnet-a"), routes({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": 3})),
    (db_instance("subnet-a"), routes({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123",
                                       "_coverage": {"GatewayId": {"status": "denied"}}})),
    ({**db_instance("subnet-a"), "collection_status": "denied"}, routes(DIRECT)),
])
def test_missing_partial_malformed_or_denied_subnet_evidence_is_unknown(item, index):
    assert SUBNET.evaluate(item, index)[0] == "UNKNOWN"


def certificate_index(valid_till, *, captured=CAPTURED, status="collected"):
    index = inventory("rds_certificate", [{"CertificateIdentifier": "rds-ca-rsa2048-g1",
                                           "ValidTill": valid_till}], status=status)
    index["context"]["created_at"] = captured.isoformat()
    return index


def cert_instance():
    return {"DBInstanceArn": INSTANCE_ARN, "Engine": "postgres",
            "CACertificateIdentifier": "rds-ca-rsa2048-g1"}


@pytest.mark.parametrize("offset,expected", [
    (timedelta(days=7, seconds=1), "PASS"),
    (timedelta(days=7), "FAIL"),
    (timedelta(days=6, hours=23), "FAIL"),
    (timedelta(seconds=-1), "FAIL"),
])
def test_ca_expiry_uses_exact_seven_day_interval(offset, expected):
    valid = CAPTURED + offset
    status, evidence = CERT.evaluate(cert_instance(), certificate_index(valid.isoformat()))
    assert status == expected
    assert evidence["seconds_remaining"] == offset.total_seconds()


def test_ca_expiry_normalizes_aware_offsets_and_uses_historical_capture():
    valid = (CAPTURED + timedelta(days=7, seconds=1)).astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert CERT.evaluate(cert_instance(), certificate_index(valid.isoformat()))[0] == "PASS"
    later = CAPTURED + timedelta(days=1)
    assert CERT.evaluate(cert_instance(), certificate_index(valid.isoformat(), captured=later))[0] == "FAIL"


@pytest.mark.parametrize("item,index", [
    (cert_instance(), certificate_index("bad timestamp")),
    (cert_instance(), certificate_index("2026-10-19T12:00:00")),
    (cert_instance(), certificate_index("2026-10-19T12:00:00Z", status="denied")),
    (cert_instance(), inventory("rds_certificate", [{"CertificateIdentifier": "other",
                                                       "ValidTill": "2026-10-19T12:00:00Z"}])),
    ({"DBInstanceArn": INSTANCE_ARN}, certificate_index("2026-10-19T12:00:00Z")),
    ({**cert_instance(), "collection_status": "denied"}, certificate_index("2026-10-19T12:00:00Z")),
])
def test_unavailable_certificate_or_capture_is_unknown(item, index):
    assert CERT.evaluate(item, index)[0] == "UNKNOWN"

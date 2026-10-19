"""Cloud SQL native IP declarations: inbound and outbound addresses are distinct."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, gcp_ports_metadata  # noqa: F401 - register checks


CHECK = {check.id: check for check in CHECKS}
CID = "gcp.ports.sql_private_ip_assignments"


def evaluate(types=None, **config):
    item = dict(config)
    if types is not None:
        item["ipAddresses"] = [{"type": value} for value in types]
    before = copy.deepcopy(item)
    result = CHECK[CID].evaluate(item, {})
    assert item == before
    return result


@pytest.mark.parametrize("types,expected", [
    (["PRIVATE", "OUTGOING"], "PASS"),
    (["OUTGOING"], "PASS"),
    (["PRIMARY", "PRIVATE"], "FAIL"),
    (["MIGRATED_1ST_GEN"], "FAIL"),
    (["PRIVATE", "OUTGOING", "MIGRATED_1ST_GEN"], "FAIL"),
    (["PRIVATE"], "PASS"),
    ([], "PASS"),
    (["SQL_IP_ADDRESS_TYPE_UNSPECIFIED"], "UNKNOWN"),
    (["FUTURE_TYPE"], "UNKNOWN"),
])
def test_incoming_address_classification(types, expected):
    assert evaluate(types)[0] == expected


def test_outgoing_only_has_no_private_inbound_claim():
    status, evidence = evaluate(["OUTGOING"])
    assert status == "PASS"
    assert evidence["private_incoming_present"] is False
    assert evidence["outgoing_source_present"] is True
    assert evidence["public_incoming_types"] == []
    assert "Incoming public/private and outgoing source address declarations" in evidence["semantics"]
    from peaso.finding_observation import evidence_summary
    observation = evidence_summary({"provider": "gcp", "check_id": CID,
                                    "status": status, "evidence": evidence})
    assert "OUTGOING is an outbound source" in observation
    assert "does not establish a private incoming endpoint" in observation


def test_native_address_type_governs_result_across_address_strings():
    private_and_outgoing = {"ipAddresses": [
        {"type": "PRIVATE", "ipAddress": "10.1.2.3"},
        {"type": "OUTGOING", "ipAddress": "198.51.100.8"},
    ]}
    assert CHECK[CID].evaluate(private_and_outgoing, {})[0] == "PASS"
    public_ipv4 = {"ipAddresses": [{"type": "PRIMARY", "ipAddress": "203.0.113.9"}]}
    assert CHECK[CID].evaluate(public_ipv4, {})[0] == "FAIL"
    # The native type remains authoritative if a provider returns an IPv6 literal.
    public_ipv6 = {"ipAddresses": [{"type": "PRIMARY", "ipAddress": "2001:db8::9"}]}
    assert CHECK[CID].evaluate(public_ipv6, {})[0] == "FAIL"


def test_psc_and_private_network_do_not_override_address_evidence():
    psc = {"settings": {"ipConfiguration": {"pscConfig": {"pscEnabled": True}}}}
    private_network = {"settings": {"ipConfiguration": {"privateNetwork": "projects/p/global/networks/v"}}}
    assert evaluate([], **psc)[0] == "PASS"
    assert evaluate(["OUTGOING"], **psc)[0] == "PASS"
    assert evaluate(["OUTGOING"], **private_network)[0] == "PASS"
    assert evaluate(["PRIMARY"], **psc)[0] == "FAIL"
    assert evaluate(["PRIMARY", "PRIVATE"], **private_network)[0] == "FAIL"
    # A PSC/private-network declaration cannot establish an unread IP list.
    assert evaluate(**psc)[0] == "UNKNOWN"
    assert evaluate(**private_network)[0] == "UNKNOWN"


def test_missing_and_malformed_address_facts_are_unknown():
    assert evaluate()[0] == "UNKNOWN"
    assert CHECK[CID].evaluate({"ipAddresses": [{"ipAddress": "192.0.2.1"}]}, {})[0] == "UNKNOWN"
    assert CHECK[CID].evaluate({"ipAddresses": [{"type": 23}]}, {})[0] == "UNKNOWN"
    assert CHECK[CID].evaluate({"ipAddresses": {"type": "PRIVATE"}}, {})[0] == "UNKNOWN"
    assert CHECK[CID].evaluate({"ipAddresses": [{"type": "PRIVATE"}],
                               "_coverage": {"ipAddresses": {"status": "denied"}}}, {})[0] == "UNKNOWN"


def test_legacy_address_is_not_silently_safe_in_other_source_variants():
    for cid in ("gcp.ports.sql_instance_with_no_public_ips", "gcp.ports.sql_instance_not_publicly_accessible",
                "gcp.ports.sql_no_primary_address"):
        assert CHECK[cid].evaluate({"ipAddresses": [{"type": "MIGRATED_1ST_GEN"}]}, {})[0] == "UNKNOWN"

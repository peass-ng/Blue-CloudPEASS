"""Pinned IANA row lifecycle semantics through the registered NSG evaluator."""
from tests.test_peaso_iana_service_assignments import evaluate, SOURCE_SHA


def test_deregistered_udp_sua_never_passes_as_active_assignment():
    status, evidence = evaluate(protocol='Udp', port=14001, measured='sua', claim='sua')
    assert status == 'UNKNOWN'
    assert evidence['reason'] == 'one or more required facts unresolved'
    assert evidence['iana_source_sha256'] == SOURCE_SHA


def test_same_name_remains_assigned_to_tcp_14001():
    status, evidence = evaluate(protocol='Tcp', port=14001, measured='sua', claim='sua')
    assert status == 'PASS'
    assert evidence['iana_source_sha256'] == SOURCE_SHA


def test_reserved_udp_alias_excluded_while_active_alias_remains():
    reserved, evidence = evaluate(protocol='Udp', port=5349,
                                  measured='stun-behaviors', claim='stun-behaviors')
    assert reserved == 'FAIL'
    assert evidence['iana_source_sha256'] == SOURCE_SHA
    active, evidence = evaluate(protocol='Udp', port=5349, measured='stuns', claim='stuns')
    assert active == 'PASS'
    assert evidence['iana_source_sha256'] == SOURCE_SHA


def test_description_word_unassigned_does_not_retire_named_remoteware():
    for protocol in ('Tcp', 'Udp'):
        status, evidence = evaluate(protocol=protocol, port=2999,
                                    measured='remoteware-un', claim='remoteware-un')
        assert status == 'PASS'
        assert evidence['iana_source_sha256'] == SOURCE_SHA

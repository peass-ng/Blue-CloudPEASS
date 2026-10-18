"""Directed TermService report consistency cases for the registered SW17 check."""
from tests.compliance_draft_isolation import staged_registry


with staged_registry(('compliance_new_sw17',)):
    from test_peaso_compliance_new_sw17 import case, native, run


SUFFIX = 'rdp_service_disabled'


def _term_service(machine, index):
    report = native(index, 'guest_configuration_report')
    return report['properties']['details']['resources'][0]


def test_disabled_compliant_term_service_passes():
    machine, index = case(SUFFIX)
    assert run(SUFFIX, machine, index)[0] == 'PASS'


def test_disabled_noncompliant_term_service_cannot_pass():
    machine, index = case(SUFFIX)
    _term_service(machine, index)['complianceStatus'] = 'NonCompliant'
    assert run(SUFFIX, machine, index)[0] == 'UNKNOWN'


def test_disabled_term_service_without_measured_compliance_cannot_pass():
    machine, index = case(SUFFIX)
    del _term_service(machine, index)['complianceStatus']
    assert run(SUFFIX, machine, index)[0] == 'UNKNOWN'


def test_enabled_unapproved_term_service_remains_fail():
    machine, index = case(SUFFIX)
    _term_service(machine, index)['properties']['state'] = 'Enabled'
    from test_peaso_compliance_new_sw17 import collection
    collection(index, 'vm_rdp_exception', [])
    assert run(SUFFIX, machine, index)[0] == 'FAIL'

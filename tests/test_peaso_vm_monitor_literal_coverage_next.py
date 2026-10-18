"""Literal policy lookups must honor explicit coverage on accepted fixtures."""
from __future__ import annotations

import pytest

from tests.compliance_draft_isolation import staged_registry

with staged_registry(('compliance_new_sw17', 'compliance_new_sw25')):
    import test_peaso_compliance_new_sw17 as vm
    import test_peaso_compliance_new_sw25 as monitor


@pytest.mark.parametrize('marker', [None, {}, {'status': 'denied'}, {'status': 'empty'}])
def test_vm_policy_literal_coverage(marker):
    suffix = 'system_updates_installed'
    machine, index = vm.case(suffix)
    assert vm.run(suffix, machine, index)[0] == 'PASS'
    check_id = vm.sw.PREFIX + suffix
    index['context']['metadata']['compliance_policy']['checks']['_coverage'] = {check_id: marker}
    assert vm.run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('marker', [None, {}, {'status': 'denied'}, {'status': 'empty'}])
def test_monitor_policy_literal_coverage(marker):
    cid = monitor.sw.REPORT_ID
    index = monitor.monitoring(cid)
    assert monitor.evaluate(cid, index)[0] == 'PASS'
    index['context']['metadata']['sw25_policy']['_coverage'] = {cid: marker}
    assert monitor.evaluate(cid, index)[0] == 'UNKNOWN'


def test_collected_literal_coverage_remains_accepted():
    suffix = 'system_updates_installed'
    machine, index = vm.case(suffix)
    check_id = vm.sw.PREFIX + suffix
    index['context']['metadata']['compliance_policy']['checks']['_coverage'] = {check_id: {'status': 'collected'}}
    assert vm.run(suffix, machine, index)[0] == 'PASS'

    cid = monitor.sw.REPORT_ID
    index = monitor.monitoring(cid)
    index['context']['metadata']['sw25_policy']['_coverage'] = {cid: {'status': 'collected'}}
    assert monitor.evaluate(cid, index)[0] == 'PASS'

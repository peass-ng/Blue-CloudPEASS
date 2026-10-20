"""Standalone tests of the actual new pure scalar helper, without app imports."""
import importlib.util
import json
from pathlib import Path

import pytest

PATH = Path('peaso/collectors/gcp_workbench_head3_projection_20261020.py')
SPEC = importlib.util.spec_from_file_location('workbench_head3_scalar_under_test', PATH)
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)


@pytest.mark.parametrize('value', [
    '', '00 19 * * MON', '0 0 1 * *', '59 23 31 12 7',
    '0 0 * JAN-MAR MON,FRI', '*/15 0-23/2 1,15 * 0-6',
    '0 0 * jan-mar mon-fri', '0 0 * * SUN',
])
def test_native_cron_supported_scalar_retained(value):
    assert projection.supported_schedule(value) == value
    assert projection.project_upgrade_schedule({projection.KEY: value}, {})[projection.KEY] == value


@pytest.mark.parametrize('value', [
    None, True, 7, [], {}, ' ', '\t', '0 0 * * *\n', '@weekly', '0 0 * * * command',
    '60 0 * * *', '0 24 * * *', '0 0 0 * *', '0 0 32 * *', '0 0 * 0 *',
    '0 0 * 13 *', '0 0 * * 8', '*/0 * * * *', '0-59/61 * * * *',
    '5-1 * * * *', '0 0 * * FRI-MON', '0 0 * FOO MON', '0 0 * * MONDAY',
    '0 0 * * 1/2', '0,,1 0 * * *', '0/2 0 * * *', '0 0 * * * #secret',
    '0 0 * * *;echo untrusted', 'CRON_TZ=UTC 0 0 * * *', '0 0 * * ?',
    '0 0 L * *', '0 0 * * 1#2', '0 0 * * ~', '0 0 * * МON', '0 0 * * MON' + ' ' * 129,
])
def test_unsupported_scalar_is_not_retained_or_defaulted(value):
    assert projection.supported_schedule(value) is None
    result = projection.project_upgrade_schedule({projection.KEY: value}, {})
    assert result[projection.KEY] is None
    assert result['_coverage'][projection.KEY]['status'] == 'unknown'
    assert 'untrusted' not in json.dumps(result) and 'secret' not in json.dumps(result)


@pytest.mark.parametrize('marker', [None, {}, 'collected', {'status': 'denied'},
                                  {'status': 'partial'}, {'status': 'empty'}])
def test_native_coverage_cannot_be_upgraded(marker):
    raw = {projection.KEY: '00 19 * * MON', '_coverage': {projection.KEY: marker}}
    result = projection.project_upgrade_schedule(raw, {})
    assert result[projection.KEY] is None
    assert result['_coverage'][projection.KEY]['status'] == 'unknown'


def test_native_absence_and_empty_and_malformed_remain_distinct():
    assert projection.project_upgrade_schedule({}, {}) == {}
    assert projection.project_upgrade_schedule({projection.KEY: ''}, {}) == {projection.KEY: ''}
    assert projection.project_upgrade_schedule({projection.KEY: 'garbage'}, {})[projection.KEY] is None


def test_scalar_projection_is_pure_and_preserves_other_scrubbed_leaves():
    raw = {projection.KEY: '00 19 * * MON', 'private': 'never copy this'}
    scrubbed = {projection.KEY: None, 'private': None, 'notebook-disable-terminal': 'true'}
    result = projection.project_upgrade_schedule(raw, scrubbed)
    assert result['private'] is None and result['notebook-disable-terminal'] == 'true'
    assert scrubbed[projection.KEY] is None
    assert raw['private'] == 'never copy this'

"""Brief copy consumes actual normal-engine Workbench setting evidence."""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from peaso.checks.gcp_workbench_head3_observed_20261020 import observation
from peaso.checks.gcp_evidence_explanations import evidence_summary


CAPTURE = Path('tests/fixtures/gcp-workbench-head3-brief-native-20261020.json')
SAMPLES = [pytest.param(f, id=r['case'] + '-' + f['check_id'].rsplit('.', 1)[-1])
           for r in json.loads(CAPTURE.read_text())['records'] for f in r['findings']]


@pytest.mark.parametrize('finding', SAMPLES)
def test_native_observation_and_provider_copy_are_specific_brief_and_immutable(finding):
    before = deepcopy(finding)
    text = observation(finding)
    if finding['status'] in ('PASS', 'FAIL'):
        assert text and len(text.split()) <= 17
        assert 'Workbench' in text
        rendered = evidence_summary(finding)
        assert text in rendered and len(re.split(r'[.!?] +', rendered)) <= 3
        if finding['check_id'].endswith('auto_upgrade_schedule_declared'):
            assert 'patch status' in rendered
        elif finding['check_id'].endswith('terminal_access_disabled'):
            assert 'terminal' in text and 'Kernel execution' in rendered
        else:
            assert 'file downloads' in text and 'DLP' in rendered
    else:
        assert text is None
    assert finding == before


@pytest.mark.parametrize('cid', [p.values[0]['check_id'] for p in SAMPLES[:3]])
@pytest.mark.parametrize('fault', ['provider', 'status', 'truth', 'setting', 'instance', 'scope'])
def test_copy_rejects_unbound_or_contradictory_setting_facts(cid, fault):
    f = next(deepcopy(p.values[0]) for p in SAMPLES
             if p.values[0]['check_id'] == cid and p.values[0]['status'] == 'PASS')
    assert observation(f)
    if fault == 'provider':
        f['provider'] = 'azure'
    elif fault == 'status':
        f['status'] = 'FAIL'
    elif fault == 'truth':
        f['evidence']['schedule_declared' if cid.endswith('schedule_declared') else 'disabled'] = 'true'
    elif fault == 'setting':
        f['evidence']['setting'] = 'unrelated.setting'
    elif fault == 'instance':
        f['evidence']['instance'] = 'foreign'
    else:
        f['scope'] = 'projects/other'
    assert observation(f) is None

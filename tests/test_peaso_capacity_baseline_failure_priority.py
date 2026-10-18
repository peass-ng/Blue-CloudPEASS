"""A fully measured baseline contradiction survives unresolved forecasts."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS

CID = 'azure.gap.capacity_usage_alerts'


def fixture():
    case = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[CID]
    return deepcopy(case['pass']), deepcopy(case['pass_index'])


def record(index):
    row = index['collections']['capacity_record'][0]['items'][0]
    index['capacity_record'][0]['data'] = row
    return row


def verdict(item, index):
    return next(check for check in CHECKS if check.id == CID).evaluate(item, index)[0]


@pytest.mark.parametrize('missing', ['forecast', 'failureScenarios', 'capacity'])
def test_measured_baseline_contradiction_survives_unresolved_forecast(missing):
    item, index = fixture()
    row = record(index)
    row['baseline']['average'] += 1
    if missing == 'forecast':
        row.pop('forecast')
    else:
        row['forecast'].pop(missing)
    assert verdict(item, index) == 'FAIL'


def test_unresolved_forecast_without_baseline_contradiction_is_unknown():
    item, index = fixture()
    record(index).pop('forecast')
    assert verdict(item, index) == 'UNKNOWN'


@pytest.mark.parametrize('invalid', ['samples', 'approval', 'window'])
def test_unverified_baseline_cannot_supply_failure_witness(invalid):
    item, index = fixture()
    row = record(index)
    row['baseline']['average'] += 1
    row.pop('forecast')
    if invalid == 'samples':
        row['_coverage']['samples']['status'] = 'partial'
    elif invalid == 'approval':
        row['baseline']['approvedAt'] = '2099-01-01T00:00:00Z'
    else:
        row['windowStart'] = '2000-01-01T00:00:00Z'
    assert verdict(item, index) == 'UNKNOWN'

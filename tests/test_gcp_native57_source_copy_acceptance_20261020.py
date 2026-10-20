"""Accept exact reviewed helpers and concise native successor observations."""
import ast
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks.gcp_remaining_finding_summary import evidence_summary

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'docs/gcp-review/recheck-20261020'


def function_source(path, symbol):
    text = path.read_text()
    parts = symbol.split('.')
    node = ast.parse(text)
    for part in parts:
        matches = [n for n in ast.walk(node) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == part]
        assert len(matches) == 1, (path, symbol)
        node = matches[0]
    start = min([node.lineno] + [n.lineno for n in node.decorator_list])
    return ''.join(text.splitlines(keepends=True)[start - 1:node.end_lineno])


def test_reviewed_helper_sources_and_origin_reports_are_exact():
    proof = json.loads((REVIEW / 'native57-predicate-successors.json').read_text())
    for name, expected in proof['origin_reports'].items():
        assert hashlib.sha256((REVIEW / name).read_bytes()).hexdigest() == expected
    iam = json.loads((REVIEW / 'native57-iam-kms-fixes.json').read_text())
    for row in iam['changed_functions']:
        actual = function_source(ROOT / row['path'], row['symbol'])
        assert actual == row['after']['source']
        assert hashlib.sha256(actual.encode()).hexdigest() == row['after']['sha256']
    data = json.loads((REVIEW / 'native57-data-fixes.json').read_text())
    checked = 0
    for path, row in data['source_changes'].items():
        for change in row['functions']:
            actual = function_source(ROOT / path, change['symbol'])
            assert hashlib.sha256(actual.encode()).hexdigest() == change['after_sha256'], (path, change['symbol'])
            checked += 1
    assert checked == 18


@pytest.mark.parametrize('seconds,period,expected', [
    ('8640000.000000001', '8640000.000000001s', True),
    ('8640000.999999999', '8640000.999999999s', True),
    ('8640000', '8640000s', False),
    ('8639999.999999999', '8639999.999999999s', False),
    ('8640000.000000001', '8640000s', False),
    ('8640000.000000001', None, False),
    ('NaN', 'NaNs', False),
    ('8640000.0000000010', '8640000.000000001s', False),
])
def test_fractional_rotation_copy_preserves_exact_boundary(seconds, period, expected):
    finding = {'provider': 'gcp', 'check_id': 'gcp.claude.kms_key.rotation_100_days', 'status': 'FAIL',
               'evidence': {'rotation_seconds': seconds, 'rotation_period': period}}
    text = evidence_summary(finding)
    assert bool(text) == expected
    if expected:
        assert seconds in text and '100 days' in text
    finding['status'] = 'PASS'
    assert evidence_summary(finding) is None


@pytest.mark.parametrize('cid', ['gcp.ports.function_logging_mutation_declarations',
                                'gcp.ports.function_legacy_deployment_role_declarations'])
@pytest.mark.parametrize('records,expected', [
    ([{'role': 'projects/native-project/roles/selected', 'policy': 'projects/native-project', 'condition': None}], True),
    ([], False), ([{}], False), ([{'role': '', 'policy': 'projects/native-project'}], False),
    ([{'role': 'roles/editor', 'policy': None}], False),
])
def test_filtered_function_role_declarations_need_named_role_and_policy(cid, records, expected):
    finding = {'provider': 'gcp', 'check_id': cid, 'status': 'FAIL',
               'evidence': {'role_assignment_declarations': records}}
    assert bool(evidence_summary(finding)) == expected

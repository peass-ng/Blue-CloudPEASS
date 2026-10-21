from copy import deepcopy
import pytest
from peaso import checks
from storage_immutability_native_successor import (
    CHECK_ID, TITLE, DESCRIPTION, REMEDIATION, observation, proposed_registry,
)

BASE = {
    'check_id': CHECK_ID, 'status': 'PASS',
    'evidence': {
        'containers_without_effective_default_retention': [],
        'observed_default_policies': [
            {'container_id': '/account/blobServices/default/containers/example',
             'state': 'Locked', 'retention_days': 30, 'new_writes_inherit': True},
        ],
    },
}


def test_registry_presentation_preserves_identity_groups_and_requirements():
    old = next(c for c in checks.CHECKS if c.id == CHECK_ID)
    new = next(c for c in proposed_registry(checks.CHECKS) if c.id == CHECK_ID)
    assert new.title == TITLE
    assert new.remediation == REMEDIATION
    assert 'locked' not in new.title.lower()
    assert 'Unlocked' in DESCRIPTION
    for field in ('id', 'provider', 'kind', 'target', 'category', 'control', 'severity',
                  'declared_dependencies', 'allow_incomplete_failure',
                  'empty_applicability_dependencies'):
        assert getattr(new, field) == getattr(old, field), field
    assert new.framework_ids == old.framework_ids
    assert new.mapping == old.mapping


def test_locked_observation_is_brief_and_makes_only_default_configuration_claim():
    result = observation(BASE)
    assert result == 'New writes inherit a positive default retention period in all 1 observed Blob containers.'
    assert 'every blob' not in result.lower()
    assert 'compliant' not in result.lower()


def test_unlocked_pass_discloses_mutability_without_changing_verdict():
    row = deepcopy(BASE)
    row['evidence']['observed_default_policies'][0]['state'] = 'Unlocked'
    assert observation(row).endswith('At least one default policy is unlocked and can still be changed.')
    assert row['status'] == 'PASS'


def test_failure_names_exactly_the_affected_containers():
    row = deepcopy(BASE)
    rows = row['evidence']['observed_default_policies']
    rows.append({'container_id': '/account/blobServices/default/containers/no-retention',
                 'state': 'Absent', 'retention_days': 0, 'new_writes_inherit': False})
    row['evidence']['containers_without_effective_default_retention'] = [rows[-1]['container_id']]
    row['status'] = 'FAIL'
    summary = observation(row)
    assert summary == ('New writes lack a positive inherited default retention policy in: '
                       '/account/blobServices/default/containers/no-retention.')
    assert 'containers/example' not in summary


@pytest.mark.parametrize('mutation', [
    lambda row: row.update(check_id='other'),
    lambda row: row.update(status='UNKNOWN'),
    lambda row: row.update(status='FAIL'),
    lambda row: row.update(evidence=None),
    lambda row: row['evidence'].update(observed_default_policies=[]),
    lambda row: row['evidence']['observed_default_policies'][0].update(state='unexpected'),
    lambda row: row['evidence']['observed_default_policies'][0].update(retention_days=True),
    lambda row: row['evidence']['observed_default_policies'][0].update(new_writes_inherit=None),
    lambda row: row['evidence']['observed_default_policies'].append(
        dict(row['evidence']['observed_default_policies'][0])),
    lambda row: row['evidence'].update(containers_without_effective_default_retention=['foreign']),
])
def test_inconsistent_or_unrecognized_evidence_is_not_rendered_as_success(mutation):
    row = deepcopy(BASE)
    mutation(row)
    assert observation(row) is None

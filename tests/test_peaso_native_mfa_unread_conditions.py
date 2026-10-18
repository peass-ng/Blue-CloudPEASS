"""An unreadable optional CA condition is not an unrestricted condition."""
import pytest
from peaso.snapshot import validate
from tests.test_peaso_mfa_native_direct_user_partitions import collect, row, assert_status


@pytest.mark.parametrize('field', ['locations', 'platforms', 'excludeUsers', 'excludeGroups',
                                 'grant:customAuthenticationFactors', 'app:applicationFilter'])
def test_native_all_mfa_does_not_ignore_unreadable_condition(monkeypatch, field):
    snap = collect(monkeypatch, [row('unread-scope', ['All'])])
    env = next(e for e in snap['collections'] if e['type'] == 'conditional_access_policy')
    conditions = env['items'][0]['conditions']
    container = conditions['users'] if field.startswith('exclude') else conditions
    if field.startswith('grant:'):
        container = env['items'][0]['grantControls']
        field = field.split(':', 1)[1]
    elif field.startswith('app:'):
        container = conditions['applications']
        field = field.split(':', 1)[1]
    container.setdefault('_coverage', {})[field] = {'status': 'denied'}
    snap.pop('snapshot_id')
    assert_status(validate(snap), 'UNKNOWN')

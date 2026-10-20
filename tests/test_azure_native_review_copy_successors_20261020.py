"""Native semantic corrections keep the prior guidance and signed base pins."""
from copy import deepcopy

import pytest

from peaso.checks.azure_finding_clarity_reviewed import ROWS as NATIVE_ROWS
from peaso.checks.azure_bulk_clarity_reviewed import ROWS as BULK_ROWS
ROWS = {**BULK_ROWS, **NATIVE_ROWS}
from peaso.checks.azure_native_review_copy_20261020 import SUCCESSORS, reviewed_fields


@pytest.mark.parametrize('cid,kind', SUCCESSORS)
def test_each_successor_is_bound_to_unmodified_predecessor_and_rejects_drift(cid, kind):
    prior = deepcopy(ROWS[cid][kind + '_fields'])
    preserved = deepcopy(prior)
    current = reviewed_fields(cid, kind, prior)
    assert prior == preserved
    assert current != prior
    corrupted = {**prior, 'unreviewed': 'source drift'}
    with pytest.raises(ValueError, match='guidance predecessor changed'):
        reviewed_fields(cid, kind, corrupted)
    current['unreviewed'] = True
    assert 'unreviewed' not in reviewed_fields(cid, kind, prior)


def test_current_guidance_rejects_old_unprovable_compliance_paths():
    def fields(cid, kind='description'):
        return reviewed_fields(cid, kind, ROWS[cid][kind + '_fields'])
    key = 'azure.claude.storage_access_keys_rotated_90'
    assert 'Both key1 and key2' in fields(key)['pass_when']
    assert 'UNKNOWN' in fields(key)['not_applicable_when']
    assert 'not applicable' in ROWS[key]['remediation_fields']['caveats'][0]
    assert 'Missing or future dates remain unresolved' in fields(key, 'remediation')['caveats'][0]
    nsg = fields('azure.claude2.nsg_flow_log_configured')
    assert 'enabled native NSG flow log' in nsg['pass_when']
    assert 'reference alone cannot satisfy' in nsg['description']
    windows = fields('azure.claude.vm_windows_secure_boot')
    assert 'SQL and custom images' in windows['description']
    assert 'offer' not in windows['not_applicable_when']

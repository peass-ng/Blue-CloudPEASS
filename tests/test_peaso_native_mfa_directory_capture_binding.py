"""Native user partitions must use directory evidence from the same capture."""
import pytest
from peaso.snapshot import validate
from tests.test_peaso_mfa_native_direct_user_partitions import collect, row, assert_status, U1, U2


@pytest.mark.parametrize('mutation', ['envelope-capture', 'row-customer', 'row-readonly'])
def test_native_partition_directory_authority_cannot_be_reused(monkeypatch, mutation):
    snap = collect(monkeypatch, [row('mfa-a', [U1]), row('mfa-b', [U2])])
    env = next(e for e in snap['collections'] if e['type'] == 'directory_user')
    if mutation == 'envelope-capture':
        env['_provenance']['credential_context_id'] = 'previous-scan-capture'
    elif mutation == 'row-customer':
        env['items'][0]['_provenance']['customer_context_id'] = 'another-customer'
    else:
        env['items'][0]['_provenance']['read_only'] = False
    snap.pop('snapshot_id')
    assert_status(validate(snap), 'UNKNOWN')

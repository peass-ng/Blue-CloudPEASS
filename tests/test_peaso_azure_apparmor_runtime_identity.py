"""Measured AppArmor profile joins require a real running container identity."""
import pytest

from test_peaso_azure_apparmor_effective_runtime import measured_snapshot, sealed, finding


@pytest.mark.parametrize('status_id,evidence_id', [
    ('', ''), ('   ', '   '), ('containerd://main', ''),
])
def test_empty_or_blank_container_identity_is_unknown(status_id, evidence_id):
    collections, metadata, created_at = measured_snapshot()
    pod = next(c for c in collections if c['type'] == 'pod')['items'][0]
    runtime = next(c for c in collections if c['type'] == 'pod_runtime')['items'][0]
    pod['status']['containerStatuses'][0]['containerID'] = status_id
    runtime['appArmorProfiles'][0]['containerId'] = evidence_id
    observed = finding(sealed(collections, metadata, created_at))
    assert observed['status'] == 'UNKNOWN', observed


def test_nonempty_joined_container_identity_still_passes():
    assert finding(sealed(*measured_snapshot()))['status'] == 'PASS'

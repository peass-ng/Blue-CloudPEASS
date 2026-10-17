"""Directed Localhost AppArmor kernel-profile authority checks."""
from test_peaso_azure_apparmor_effective_runtime import measured_snapshot, sealed, finding, CHECK


def _localhost_snapshot(applied_name):
    collections, metadata, created_at = measured_snapshot()
    pod = next(c for c in collections if c['type'] == 'pod')['items'][0]
    runtime = next(c for c in collections if c['type'] == 'pod_runtime')['items'][0]
    pod['spec']['containers'][0]['securityContext']['appArmorProfile'] = {
        'type': 'Localhost', 'localhostProfile': 'approved-local'}
    metadata['sw25_policy'][CHECK]['allowedProfiles'].append(
        {'type': 'Localhost', 'localhostProfile': 'approved-local'})
    runtime['appArmorProfiles'][0].update(
        profileType='Localhost', resolvedLocalhostProfile='approved-local',
        appliedProfileName=applied_name)
    return sealed(collections, metadata, created_at)


def test_matching_localhost_kernel_profile_passes():
    assert finding(_localhost_snapshot('approved-local'))['status'] == 'PASS'


def test_different_localhost_kernel_profile_fails():
    observed = finding(_localhost_snapshot('other-loaded-profile'))
    assert observed['status'] == 'FAIL', observed

"""An independently authorized service mismatch survives another unavailable path."""
from copy import deepcopy
import pytest
from tests.nsg_service_observation_fixture import fixture,digest
from tests.test_peaso_nsg_service_measurement_authority import status

@pytest.mark.parametrize('reverse',[False,True])
@pytest.mark.parametrize('actual,expected',[('ssh','FAIL'),('https','UNKNOWN')])
def test_service_counterexample_is_independent_of_other_path_observation(reverse,actual,expected):
    c,p=fixture(actual=actual)
    nsg=c['nsg'][0][1][0]
    path=deepcopy(c['nsg_effective_internet_path'][0][1][0]);path['id']+='-unavailable'
    measurement=deepcopy(c['nsg_service_measurement'][0][1][0]);measurement['id']+='-unavailable';measurement['path_id']=path['id']
    observation=measurement['properties']['observation'];observation['pathId']=path['id'];observation['readOnly']=False
    observation['snapshotSha256']=digest({'nsg':nsg,'path':path,'capture':observation['capture']})
    c['nsg_effective_internet_path'][0][1].append(path);c['nsg_service_measurement'][0][1].append(measurement)
    authority=p['serviceObservationAuthority'];authority['approvedSnapshotSha256s'].append(observation['snapshotSha256']);authority['approvedObservationSha256s'].append(digest(observation))
    if reverse:c['nsg_effective_internet_path'][0][1].reverse()
    assert status(c,p)==expected,status.last

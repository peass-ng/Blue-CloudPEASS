"""Independent container violations survive unrelated unavailable values."""
import pytest
from tests.test_peaso_pod_quantity_continuation import fixture
from peaso.checks import evaluate_check
from peaso.checks.compliance_new_sw25_facts import LIMITS_ID

@pytest.mark.parametrize('malformed_kind,bad_kind', [('containers','initContainers'), ('initContainers','containers')])
def test_container_violation_does_not_depend_on_order(malformed_kind,bad_kind):
    module=fixture();index=module.fixture(LIMITS_ID);pod=module.data(index,'pod')
    pod['spec'][malformed_kind][0]['resources']['limits']['cpu']='malformed'
    pod['spec'][bad_kind][0]['resources']['limits']['cpu']='2'
    assert evaluate_check(LIMITS_ID, {'scope':module.SCOPE}, index)[0]=='FAIL'

@pytest.mark.parametrize('admission', [True,False])
def test_incomplete_values_never_establish_compliance(admission):
    module=fixture();index=module.fixture(LIMITS_ID);pod=module.data(index,'pod')
    pod['spec']['containers'][0]['resources']['limits']['cpu']='malformed'
    module.data(index,'pod_runtime')['admissionEffectsResolved']=admission
    assert evaluate_check(LIMITS_ID, {'scope':module.SCOPE}, index)[0]=='UNKNOWN'

def test_unresolved_global_admission_does_not_authenticate_overlimit():
    module=fixture();index=module.fixture(LIMITS_ID);pod=module.data(index,'pod')
    pod['spec']['containers'][0]['resources']['limits']['cpu']='2'
    module.data(index,'pod_runtime')['admissionEffectsResolved']=False
    assert evaluate_check(LIMITS_ID, {'scope':module.SCOPE}, index)[0]=='UNKNOWN'

def test_ambiguous_container_identity_does_not_authenticate_violation():
    module=fixture();index=module.fixture(LIMITS_ID);pod=module.data(index,'pod')
    pod['spec']['containers'][0]['resources']['limits']['cpu']='2'
    pod['spec']['initContainers'][0]['name']=pod['spec']['containers'][0]['name']
    assert evaluate_check(LIMITS_ID, {'scope':module.SCOPE}, index)[0]=='UNKNOWN'

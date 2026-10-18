"""An empty native findings read still requires independent full coverage evidence."""
import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
SCOPE='123456789012/eu-west-1'
BUCKET='arn:aws:s3:::authorized-bucket'
CHECK='aws.pci.s3.sensitive_auth_data_findings'

def verdict(state='empty',coverage='valid',rows=None):
    collections=[{'type':'macie_finding','scope':SCOPE,'service':'macie2','status':state,'items':rows or []}]
    if coverage!='missing':
        item={'authorized':True,'complete':coverage!='incomplete','bucketArns':[BUCKET if coverage!='foreign' else 'arn:aws:s3:::foreign-bucket']}
        collections.append({'type':'macie_scan_coverage','scope':SCOPE,'status':'denied' if coverage=='denied' else 'collected','items':[] if coverage=='denied' else [item]})
    snapshot=make_snapshot('aws',[SCOPE],collections,metadata={'parameters':{'prohibited_auth_identifier_names':['CVV'],'authorized_macie_bucket_arns':[BUCKET]}})
    results=evaluate_snapshot(snapshot,checks=[CHECK])['findings']
    assert len(results)==1
    return results[0]

@pytest.mark.parametrize('state',['empty','collected'])
def test_native_empty_findings_accept_existing_independent_coverage_contract(state):
    assert verdict(state)['status']=='PASS'

@pytest.mark.parametrize('coverage',['missing','incomplete','denied','foreign'])
def test_empty_native_findings_never_substitute_for_coverage(coverage):
    assert verdict(coverage=coverage)['status'] in {'UNKNOWN','DENIED'}

def test_contradictory_empty_native_inventory_cannot_publish_evidence():
    with pytest.raises(ValueError,match='unavailable/empty collection cannot contain items'):
        verdict(rows=[{'id':'retained-unverified-row'}])

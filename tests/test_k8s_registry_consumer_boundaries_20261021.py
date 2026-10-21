"""Recorded image findings cannot turn missing scan evidence into PASS."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.collectors import k8s_selected_registry_image_20261021 as source
from peaso.checks import k8s_selected_registry_image_review_20261021 as review
CASES=None

def cases():
    return CASES if CASES is not None else json.loads(Path(review.__file__).with_name('k8s_selected_registry_image_review_20261021_cases.json').read_text())

def sample(kind,branch='pass'):
    ident=source.SECRET_CHECK if kind==source.SECRET_KIND else source.VULN_CHECK
    row=cases()[ident];item=deepcopy(row[branch]);index=deepcopy(row[branch+'_index'])
    index['collections'][kind][0]['items']=[item]
    return item,index

@pytest.mark.parametrize('mutation',['empty_parts','missing_config_and_layers','unavailable_receipt','reused_receipt_id','zero_bytes','missing_engine_version'])
def test_incomplete_secret_scan_cannot_pass(mutation):
    item,index=sample(source.SECRET_KIND);marker=item['SelectedRegistryImage']
    if mutation=='empty_parts':marker['parts']=[]
    if mutation=='missing_config_and_layers':marker['registry_receipts']=marker['registry_receipts'][:1]
    if mutation=='unavailable_receipt':marker['registry_receipts'][1]['status']='unavailable'
    if mutation=='reused_receipt_id':marker['registry_receipts'][1]['id']=marker['registry_receipts'][0]['id']
    if mutation=='zero_bytes':marker['registry_receipts'][1]['bytes']=0
    if mutation=='missing_engine_version':marker['parts'][0]['engines'][0].pop('version',None)
    assert review.evaluate(item,index,source.SECRET_KIND)[0]=='UNKNOWN'

@pytest.mark.parametrize('value',[None,False,'true',1])
def test_scan_complete_is_typed_and_required(value):
    item,index=sample(source.VULN_KIND)
    item['SelectedRegistryImage']['vulnerability']['scan_complete']=value
    assert review.evaluate(item,index,source.VULN_KIND)[0]=='UNKNOWN'

@pytest.mark.parametrize('kind',[source.SECRET_KIND,source.VULN_KIND])
@pytest.mark.parametrize('branch,expected',[('pass','PASS'),('fail','FAIL'),('unknown','UNKNOWN'),('missing','UNKNOWN')])
def test_native_captured_verdicts_preserved(kind,branch,expected):
    item,index=sample(kind,branch)
    assert review.evaluate(item,index,kind)[0]==expected

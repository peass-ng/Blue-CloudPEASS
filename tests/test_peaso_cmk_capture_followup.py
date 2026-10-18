"""Original CMK assessment must reject explicit foreign observation captures."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID='azure.gap.recovery_service_vault_encrypted_with_cmk'
DATA=json.loads((Path(__file__).parent/'fixtures/bulk_pending_behavior.json').read_text())[CID]

def verdict(kind,field,foreign=False,unsupported=False):
    index=deepcopy(DATA['pass_index']);context=index['context']
    context['metadata'][field]='accepted-context'
    row=index['collections'][kind][0]['items'][0]
    row['_provenance'][field]='foreign-context' if foreign else 'accepted-context'
    if unsupported:row['cmkSupported']=False
    snapshot=make_snapshot('azure',[context['scope']], [batch for batches in index['collections'].values() for batch in batches],metadata=context['metadata'],created_at=context['created_at'])
    findings=[r for r in evaluate_snapshot(snapshot,checks=[CID])['findings'] if r['check_id']==CID]
    assert len(findings)==1
    return findings[0]['status']

@pytest.mark.parametrize('kind',['recovery_vault_capability','key_authorization_evidence'])
@pytest.mark.parametrize('field',['credential_context_id','customer_context_id','tenant_id'])
def test_foreign_cmk_observation_is_unknown(kind,field):
    assert verdict(kind,field,foreign=True)=='UNKNOWN'

@pytest.mark.parametrize('kind',['recovery_vault_capability','key_authorization_evidence'])
@pytest.mark.parametrize('field',['credential_context_id','customer_context_id','tenant_id'])
def test_matching_explicit_capture_keeps_original_pass(kind,field):
    assert verdict(kind,field)=='PASS'

def test_foreign_capability_cannot_prove_inapplicability():
    assert verdict('recovery_vault_capability','customer_context_id',foreign=True,unsupported=True)=='UNKNOWN'

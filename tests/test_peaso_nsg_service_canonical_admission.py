"""Exact canonical service fixture admission; supplied evidence only."""
import copy,json
from pathlib import Path
from peaso.checks import evaluate_check
CID='azure.other.nsg_port_protocol_assignment'
FIXTURE=Path(__file__).parent/'fixtures/bulk_pending_behavior.json'

def test_original_bare_matching_labels_remain_unknown():
    case=json.loads(FIXTURE.read_text())[CID]
    index=copy.deepcopy(case['unknown_index'])
    assert 'serviceObservationAuthority' not in index['context']['metadata']['compliance_policy']['sw31']
    assert 'observation' not in index['nsg_service_measurement'][0]['data']['properties']
    assert evaluate_check(CID,case['unknown'],index)[0]=='UNKNOWN'

def test_canonical_external_inventory_rejects_foreign_source():
    case=json.loads(FIXTURE.read_text())[CID];index=copy.deepcopy(case['pass_index'])
    for row in [index['nsg_service_measurement'][0]['data'],index['collections']['nsg_service_measurement'][0]['items'][0]]:
        row['properties']['observation']['sourceId']='foreign-unapproved-inventory'
    assert evaluate_check(CID,case['pass'],index)[0]=='UNKNOWN'

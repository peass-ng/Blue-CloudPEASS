"""A canonical fixture repair must not weaken AWS native OU identity checks."""
import json,copy
from pathlib import Path
from peaso.checks import evaluate_check
CID='aws_cis_organization_units_environment_sensitivity'

def test_malformed_old_ou_identifiers_still_remain_unknown():
    case=copy.deepcopy(json.loads((Path(__file__).parent/'fixtures/bulk_pending_behavior.json').read_text())[CID])
    legacy=json.loads(json.dumps(case['pass_index']).replace('ou-abcd-12345678','ou-a-prod').replace('ou-abcd-87654321','ou-a-sensitive'))
    status,evidence=evaluate_check(CID,case['pass'],legacy)
    assert status=='UNKNOWN'
    assert 'parent identity/type' in evidence['reason']

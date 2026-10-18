"""IAM condition map keys are literal JSON fields, not dot-separated object paths."""
from copy import deepcopy
import pytest
from tests.test_peaso_aws_public_policy_field_authority import PUBLIC,observed,TRUST


@pytest.mark.parametrize("key",["aws:PrincipalTag/team.email","aws:RequestTag/release.version"])
@pytest.mark.parametrize("restricted",[False,True])
def test_literal_period_in_condition_key_keeps_frozen_classification(key,restricted):
    row=deepcopy(PUBLIC)
    block={key:"ops"}
    if restricted:block["aws:SourceAccount"]="123456789012"
    row["Condition"]={"StringEquals":block}
    assert observed([row],TRUST)==("PASS" if restricted else "FAIL")


def test_literal_condition_key_still_honors_explicit_unavailable_fact():
    row=deepcopy(PUBLIC)
    row["Condition"]={"StringEquals":{"aws:PrincipalTag/team.email":"ops","_coverage":{"aws:PrincipalTag/team.email":{"status":"denied"}}}}
    assert observed([row],TRUST)=="UNKNOWN"

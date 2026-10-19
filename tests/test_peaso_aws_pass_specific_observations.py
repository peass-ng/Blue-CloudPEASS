"""Native positive/multifield witnesses remain meaningful and strictly typed."""
from copy import deepcopy
from pathlib import Path
import gzip
import json
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_pass_specific_observations import REVIEWED_IDS, evidence_summary

CHECK_BY_ID = {c.id:c for c in CHECKS}
BULK = json.loads(gzip.decompress((Path(__file__).parent/'fixtures/aws_bulk_clarity_reviewed.json.gz').read_bytes()))


def actual(cid, branch='pass'):
    if cid in CASES:
        case=CASES[cid]
        return CHECK_BY_ID[cid].evaluate(deepcopy(case[branch]),deepcopy(case.get(branch+'_index',case.get('index',{}))))
    case=BULK[cid][branch.upper()]
    return CHECK_BY_ID[cid].evaluate(deepcopy(case['item']),deepcopy(case['index']))


@pytest.mark.parametrize('cid', sorted(REVIEWED_IDS))
def test_every_claimed_id_uses_real_positive_callback_and_decisive_fields(cid):
    status,evidence=actual(cid)
    assert status=='PASS'
    finding={'provider':'aws','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    text=evidence_summary(finding)
    assert text and len(text)<240
    assert ':' not in text and 'entries are recorded' not in text and 'Recorded resource state' not in text
    assert finding==before


@pytest.mark.parametrize('cid', sorted(REVIEWED_IDS))
def test_empty_malformed_and_opposite_native_evidence_do_not_create_success_facts(cid):
    for value in ({},None,[],False):
        assert evidence_summary({'provider':'aws','check_id':cid,'status':'PASS','evidence':value}) is None
    status,negative=actual(cid,'fail')
    assert status=='FAIL'
    assert evidence_summary({'provider':'aws','check_id':cid,'status':'PASS','evidence':negative}) is None
    status,evidence=actual(cid)
    wrong={key:([None] if isinstance(value,dict) else {}) for key,value in evidence.items()}
    assert evidence_summary({'provider':'aws','check_id':cid,'status':'PASS','evidence':wrong}) is None
    for status in ('FAIL','UNKNOWN','DENIED','NOT_APPLICABLE'):
        assert evidence_summary({'provider':'aws','check_id':cid,'status':status,'evidence':evidence}) is None


def summary(cid,e):
    return evidence_summary({'provider':'aws','check_id':cid,'status':'PASS','evidence':e})


def test_cognito_disabled_does_not_hide_saml_enabled():
    cid='aws.cb.opensearch.cognito_or_saml_dashboards_auth'
    assert summary(cid,{'cognito':False,'saml':True})=='OpenSearch Dashboards authentication enables SAML.'
    assert summary(cid,{'cognito':True,'saml':True})=='OpenSearch Dashboards authentication enables both Cognito and SAML.'
    assert summary(cid,{'cognito':False,'saml':False}) is None


def test_certificate_days_are_values_not_arn_count_or_assumed_acm_type():
    cid='aws.c2b.elbv2.listener_certificate_30_days'
    text=summary(cid,{'remaining_days':{'arn:aws:iam::1:server-certificate/c1':59,'arn:aws:acm:r:1:certificate/c2':45},'minimum_days':30})
    assert '45 calendar days' in text and 'ACM' not in text
    assert summary(cid,{'remaining_days':{'cert':True},'minimum_days':30}) is None


def test_real_time_and_version_two_logging_are_not_reported_as_disabled():
    cid='aws.c2b.cloudfront.logging_any';case=CASES[cid]
    for branch,needle in [('realtime_pass','real-time'),('v2_pass','version-2')]:
        status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(case[branch]),{})
        assert status=='PASS'
        assert needle in summary(cid,evidence)


def test_legacy_glue_job_s3_argument_is_supported_without_invented_config():
    text=summary('aws.cb.glue.job_s3_encryption_first_mode',{'security_configuration':None,'encryption_type_argument':'sse-s3'})
    assert 'SSE-S3' in text and 'without an attached' in text


def test_advanced_cloudtrail_selector_uses_actual_coverage_parser():
    cid='aws.cloudtrail.management_events'
    item={'EventSelectors':{'AdvancedEventSelectors':[{'Name':'management','FieldSelectors':[{'Field':'eventCategory','Equals':['Management']}]}]}}
    status,evidence=CHECK_BY_ID[cid].evaluate(item,{})
    assert status=='PASS'
    assert 'read and write' in summary(cid,evidence)
    evidence['advanced_event_selectors'][0]['FieldSelectors'].append({'Field':'readOnly','Equals':['true']})
    assert summary(cid,evidence) is None


def test_non_root_task_observation_requires_both_privilege_and_identity_witnesses():
    cid='aws.b.ecs.host_network_nonprivileged';_,evidence=actual(cid)
    assert summary(cid,{**evidence,'proven_numeric_uid_containers':[]}) is None
    assert summary(cid,{**evidence,'privileged_containers':['other']}) is None

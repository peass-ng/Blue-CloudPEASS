"""Actual core and signed native fixtures, without mutating the global fixture registry."""
import ast
from copy import deepcopy
import json
from pathlib import Path
import pytest

from peaso.checks import CHECKS
from peaso.checks.aws_core_observed_evidence import IDS, evidence_summary
from peaso.finding_observation import evidence_summary as displayed_summary

ROOT=Path(__file__).resolve().parents[1]
CHECKS_BY_ID={c.id:c for c in CHECKS}


def _cases():
    source=ast.parse((ROOT/'tests/test_peaso_checks.py').read_text())
    statements=[n for n in source.body if isinstance(n,ast.Assign) and
                any(isinstance(t,ast.Name) and t.id in {'PAB','BASE'} for t in n.targets)]
    constants={}
    exec(compile(ast.Module(body=statements,type_ignores=[]),'core-literal-fixtures','exec'),constants)
    cases=json.loads((ROOT/'tests/fixtures/aws_compute_storage_signed_cases.json').read_text())
    for cid,(passing,failing) in constants['BASE'].items():
        if cid in IDS:cases[cid]={'pass':passing,'fail':failing}
    cases['aws.s3.public_access_block']['fail_index']={'collections':{'s3_account_public_access_block':[{'scope':'a/r','status':'empty','items':[]}]}}
    cases['aws.s3.default_encryption']={'pass':{'Encryption':{'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]}}},'unknown':{'Encryption':{'absent':True}}}
    return {cid:cases[cid] for cid in IDS}

CASES=_cases()

@pytest.mark.parametrize('cid',sorted(IDS))
def test_every_core_id_projects_actual_native_observations(cid):
    cases=CASES[cid]
    for state in ('pass','fail','unknown'):
        if state not in cases:continue
        status,evidence=CHECKS_BY_ID[cid].evaluate(deepcopy(cases[state]),deepcopy(cases.get(state+'_index',cases.get('index',{}))))
        assert status==state.upper(),(cid,state,status,evidence)
        finding={'provider':'aws','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
        text=displayed_summary(finding)
        if status in ('PASS','FAIL'):
            assert isinstance(text,str) and text.strip(),(cid,status,evidence)
            assert len(text.split())<=40
            assert not text.startswith(('Observed evidence:','No observed evidence'))
        assert finding==before

@pytest.mark.parametrize('cid',sorted(IDS))
def test_empty_and_uncertain_evidence_cannot_create_configuration_claim(cid):
    for status in ('PASS','FAIL','UNKNOWN','DENIED','MANUAL'):
        assert evidence_summary({'provider':'aws','check_id':cid,'status':status,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','check_id':cid,'status':'PASS','evidence':CASES[cid]['pass']}) is None


def test_positive_fields_relabelled_fail_still_describe_the_observed_values():
    for cid,evidence,expected in [
        ('aws.iam.console_mfa',{'console_login':True,'mfa_device_count':1},'with 1 MFA device'),
        ('aws.ec2.imdsv2',{'metadata_options':{'HttpEndpoint':'enabled','HttpTokens':'required'}},'requires IMDSv2'),
        ('aws_cis_lambda_execution_role_no_admin',{'unconditional_admin':False},'no unconditional administrator'),
    ]:
        assert expected in evidence_summary({'provider':'aws','check_id':cid,'status':'FAIL','evidence':evidence})


def test_boolean_counts_are_not_mfa_device_counts():
    assert evidence_summary({'provider':'aws','check_id':'aws.iam.console_mfa','status':'PASS','evidence':{'console_login':True,'mfa_device_count':True}}) is None

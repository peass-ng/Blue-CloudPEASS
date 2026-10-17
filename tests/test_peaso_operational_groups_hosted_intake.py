"""The existing hosted option carries normative grouping, never observations."""
import copy,json
import pytest
from fastapi import HTTPException
from peaso.server.config import Settings
from peaso.server.validation import validate_connector
from peaso.collectors.aws_operational_groups_native import normalize

SCOPE='123456789012/us-east-1'
SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='/tenants/22222222-2222-2222-2222-222222222222'
ASG='arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:11111111-1111-1111-1111-111111111111:autoScalingGroupName/workers'

def options():
    return {'compliance_parameters':{'operational_groups':{
        'capacity_groups':[{'scope':SCOPE,'id':'workers','autoscaling_group_arn':ASG,'minimum_capacity':2,'capacity_unit':'units'}],
        'recovery_groups':[{'scope':SCOPE,'id':'critical','members':[{'kind':'instance','id':'i-11111111111111111'}]}]}}}

def validate(provider,value):
    auth={'method':'access_keys','aws_access_key_id':'fixture','aws_secret_access_key':'fixture'}if provider=='aws'else{'method':'token','arm_token':'fixture'}
    validate_connector(provider,auth,value,Settings(auth_mode='cognito'))

def test_aws_hosted_json_roundtrip_retains_only_normative_intent():
    value=json.loads(json.dumps(options()));before=copy.deepcopy(value)
    validate('aws',value)
    assert value==before
    assert normalize(value)==before['compliance_parameters']['operational_groups']

@pytest.mark.parametrize('field,value',[
    ('ConfiguredCapacity',100),('AvailabilityZones',['us-east-1a','us-east-1b']),
    ('state','running'),('observed_at','2026-10-15T00:00:00Z'),
    ('minimum_capacity',True),('minimum_capacity',0)])
def test_hosted_rejects_measured_capacity_and_invalid_thresholds(field,value):
    data=options();data['compliance_parameters']['operational_groups']['capacity_groups'][0][field]=value
    with pytest.raises(HTTPException)as error:validate('aws',data)
    assert error.value.status_code==422

@pytest.mark.parametrize('field,value',[('availability_zone','us-east-1a'),('state','running')])
def test_hosted_rejects_measured_recovery_member_fields(field,value):
    data=options();data['compliance_parameters']['operational_groups']['recovery_groups'][0]['members'][0][field]=value
    with pytest.raises(HTTPException)as error:validate('aws',data)
    assert error.value.status_code==422

@pytest.mark.parametrize('provider',['azure','gcp'])
def test_operational_groups_is_aws_only(provider):
    with pytest.raises(HTTPException)as error:validate(provider,options())
    assert error.value.status_code==422

def test_v5_existing_intune_and_patch_owner_policies_need_no_new_option():
    intune='azure.cis.intune_logs_captured_sent_log_analytics'
    patch='azure.gap.compute_vm_system_updates_installed'
    value={'compliance_policy':{'status':'collected','scope':SUB,
        'checks':{patch:{'maxReportAgeSeconds':3600,'requirePciCompliance':False}},
        'sw16':{intune:{'status':'collected','scope':TENANT,'requiredIntuneCategories':['AuditLogs'],
            'approvedWorkspaceIds':[SUB+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/audit']}}}}
    before=copy.deepcopy(value);validate('azure',json.loads(json.dumps(value)))
    assert value==before

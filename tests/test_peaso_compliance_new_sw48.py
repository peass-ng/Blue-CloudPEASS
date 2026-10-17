"""Isolated signed sw48 AWS evaluator tests; run this file alone with --noconftest."""
import copy
import json

from peaso.checks import CHECKS, evaluate_check
import sys
sw = sys.modules['peaso.checks._bulk_pending_compliance_new_sw48']
from scripts.peaso_compliance_compile import spec_digest

SCOPE = '123456789012/us-east-1'


def index(collections, parameters=None):
    result = {'context': {'provider':'aws','scope':SCOPE,'created_at':'2026-10-12T00:00:00+00:00',
              'metadata':{'parameters': parameters or {}}}, 'collections':{}}
    for kind, rows in collections.items():
        result['collections'][kind] = [{'type':kind,'scope':SCOPE,'status':'collected' if rows else 'empty','items':rows}]
        result[kind] = [{'type':kind,'scope':SCOPE,'data':row} for row in rows]
    return result


def evaluate(identifier, subject, facts):
    return evaluate_check(identifier, subject, facts)[0]


def test_signed_metadata_and_no_duplicate_ids():
    ledger = json.load(open('docs/compliance-ledgers/new-checks-aws.json'))
    entries = {e['id']:e for e in ledger}
    for identifier,(kind,category,severity,title,sha,_) in sw.SPECS.items():
        entry = entries[identifier]
        assert sha == spec_digest(entry)
        matches = [c for c in CHECKS if c.id == identifier]
        assert len(matches) == 1
        check = matches[0]
        assert (check.provider,check.kind,check.category,check.severity,check.title) == ('aws',kind,category,severity,title)


def test_config_recorder():
    identifier = 'aws_nist_config_enabled_all_regions'
    subject = {'scope':SCOPE}
    rec = {'name':'default','Status':{'collection_status':'collected','ConfigurationRecordersStatus':[{'name':'default','recording':True}]},
           'recordingGroup':{'allSupported':True,'includeGlobalResourceTypes':True}}
    facts = index({'config_recorder':[rec],'config_delivery_channel':[{'name':'default'}]},
                  {'enabled_regions':['us-east-1'],'global_resource_regions':['us-east-1']})
    assert evaluate(identifier,subject,facts) == 'PASS'
    bad = copy.deepcopy(facts)
    bad['config_recorder'][0]['data']['Status']['ConfigurationRecordersStatus'][0]['recording'] = False
    bad['collections']['config_recorder'][0]['items'][0]['Status']['ConfigurationRecordersStatus'][0]['recording'] = False
    assert evaluate(identifier,subject,bad) == 'FAIL'
    assert evaluate(identifier,subject,index({'config_recorder':[rec],'config_delivery_channel':[{'name':'default'}]})) == 'UNKNOWN'


def test_secret_kms_and_rotation():
    secret = {'ARN':'arn:aws:secretsmanager:us-east-1:123456789012:secret:abc','KmsKeyId':'key-1',
              'RotationEnabled':True,'RotationRules':{'AutomaticallyAfterDays':30},
              'RotationLambdaRequired':True,'RotationLambdaARN':'arn:lambda'}
    key = {'KeyId':'key-1','Metadata':{'KeyMetadata':{'KeyManager':'CUSTOMER','KeyState':'Enabled'}}}
    facts = index({'secret':[secret],'kms_key':[key]})
    for identifier in ('aws.pci.secretsmanager.kms_encryption_any','aws_nist_secretsmanager_secret_automatic_rotation_enabled'):
        assert evaluate(identifier,secret,facts) == 'PASS'
    bad = copy.deepcopy(secret); bad['KmsKeyId'] = ''
    assert evaluate('aws.pci.secretsmanager.kms_encryption_any',bad,index({'secret':[bad],'kms_key':[key]})) == 'UNKNOWN'
    bad = copy.deepcopy(key); bad['Metadata']['KeyMetadata']['KeyState'] = 'Disabled'
    assert evaluate('aws.pci.secretsmanager.kms_encryption_any',secret,index({'secret':[secret],'kms_key':[bad]})) == 'FAIL'
    bad = copy.deepcopy(secret); bad['RotationEnabled'] = False
    assert evaluate('aws_nist_secretsmanager_secret_automatic_rotation_enabled',bad,index({'secret':[bad]})) == 'FAIL'
    bad = copy.deepcopy(secret); bad['RotationRules'] = {'AutomaticallyAfterDays':'thirty'}
    assert evaluate('aws_nist_secretsmanager_secret_automatic_rotation_enabled',bad,index({'secret':[bad]})) == 'UNKNOWN'


def test_redshift_expected_settings():
    identifier = 'aws.pci.redshift.expected_settings'
    row = {'ClusterIdentifier':'cluster','ClusterParameterGroups':[{'ParameterGroupName':'pg'}],
           'ClusterParameterValues':{'pg':{'require_ssl':'true'}},'Encrypted':True}
    params = {'redshift_expected_settings':{'cluster_fields':{'Encrypted':True},'parameters':{'require_ssl':'true'}}}
    assert evaluate(identifier,row,index({'redshift_cluster':[row]},params)) == 'PASS'
    bad = copy.deepcopy(row); bad['Encrypted'] = False
    assert evaluate(identifier,bad,index({'redshift_cluster':[bad]},params)) == 'FAIL'
    assert evaluate(identifier,row,index({'redshift_cluster':[row]})) == 'UNKNOWN'


def test_classic_elb_policies():
    from elb_native_policy_fixture import bind_policy_sources
    custom, predefined = 'aws.pci.classic_elb.custom_ssl_policy','aws.pci.classic_elb.predefined_ssl_policy'
    row = bind_policy_sources({'LoadBalancerName':'elb','ListenerDescriptions':[{'Listener':{'Protocol':'HTTPS','LoadBalancerPort':443},'PolicyNames':['p']}],
           'PolicyDescriptions':[{'PolicyName':'p','PolicyTypeName':'SSLNegotiationPolicyType',
                                 'PolicyAttributeDescriptions':[{'AttributeName':'Protocol-TLSv1.2','AttributeValue':'true'}]}]})
    params = {'classic_elb_custom_ssl_policy':{'Protocol-TLSv1.2':'true'}}
    assert evaluate(custom,row,index({'classic_elb':[row]},params)) == 'PASS'
    assert evaluate(predefined,row,index({'classic_elb':[row]},params)) == 'PASS'
    bad = copy.deepcopy(row); bad['SSLPolicyCatalog']['PolicyDescriptions'][0]['PolicyAttributeDescriptions'][0]['AttributeValue'] = 'false'
    assert evaluate(predefined,bad,index({'classic_elb':[bad]},params)) == 'FAIL'
    bad = copy.deepcopy(row); bad['SSLPolicyDetails']['PolicyDescriptions'][0]['PolicyAttributeDescriptions'][0]['AttributeValue'] = 'false'
    assert evaluate(custom,bad,index({'classic_elb':[bad]},params)) == 'FAIL'
    assert evaluate(custom,row,index({'classic_elb':[row]})) == 'UNKNOWN'
    http = copy.deepcopy(row); http['ListenerDescriptions'][0]['Listener']['Protocol'] = 'HTTP'
    assert evaluate(custom,http,index({'classic_elb':[http]},params)) == 'NOT_APPLICABLE'
    assert evaluate(predefined,http,index({'classic_elb':[http]})) == 'NOT_APPLICABLE'

def test_vpn():
    identifier = 'aws_vpn_tunnel_encryption_configuration'
    subject = {'scope':SCOPE}
    tunnel = {'Phase1EncryptionAlgorithms':[{'Value':'AES256'}],'Phase2EncryptionAlgorithms':[{'Value':'AES256'}]}
    row = {'VpnConnectionId':'vpn-1','State':'available','Options':{'TunnelOptions':[tunnel,copy.deepcopy(tunnel)]}}
    client = {'ClientVpnEndpointId':'cvpn-1','Status':{'Code':'available'},'ServerCertificateArn':'arn:cert','TransportProtocol':'udp'}
    assert evaluate(identifier,subject,index({'vpn_connection':[row],'client_vpn_endpoint':[client]})) == 'PASS'
    bad = copy.deepcopy(row); bad['Options']['TunnelOptions'][0]['Phase1EncryptionAlgorithms'][0]['Value'] = 'AES128'
    assert evaluate(identifier,subject,index({'vpn_connection':[bad],'client_vpn_endpoint':[client]})) == 'FAIL'
    bad_client = copy.deepcopy(client); bad_client['ServerCertificateArn'] = ''
    assert evaluate(identifier,subject,index({'vpn_connection':[row],'client_vpn_endpoint':[bad_client]})) == 'FAIL'
    assert evaluate(identifier,subject,index({'vpn_connection':[row]})) == 'UNKNOWN'
    inactive = copy.deepcopy(row); inactive['State'] = 'deleted'
    assert evaluate(identifier,subject,index({'vpn_connection':[inactive],'client_vpn_endpoint':[]})) == 'NOT_APPLICABLE'


def test_environment_separation():
    identifier = 'aws_organizations_environment_account_separation'
    subject = {'AccountId':'123456789012'}
    resources = [{'Environment':'production','BoundaryId':'vpc-prod'},{'Environment':'development','BoundaryId':'vpc-dev'}]
    params = {'environment_boundaries':{'production':['vpc-prod'],'development':['vpc-dev']}}
    facts = index({'aws_organization_account':[subject],'environment_workload_resource':resources,'environment_boundary_link':[]},params)
    assert evaluate(identifier,subject,facts) == 'PASS'
    bad = copy.deepcopy(resources); bad[1]['BoundaryId'] = 'vpc-prod'
    assert evaluate(identifier,subject,index({'aws_organization_account':[subject],'environment_workload_resource':bad,'environment_boundary_link':[]},params)) == 'FAIL'
    assert evaluate(identifier,subject,index({'aws_organization_account':[subject],'environment_workload_resource':resources},params)) == 'UNKNOWN'


def test_recovery_group():
    identifier = 'aws.nist.sc_36_coverage'
    group = {'GroupId':'g1','Members':[{'Kind':'instance','Id':'i1'},{'Kind':'instance','Id':'i2'}]}
    instances = [{'InstanceId':'i1','State':{'Name':'running'},'Placement':{'AvailabilityZone':'us-east-1a'}},
                 {'InstanceId':'i2','State':{'Name':'running'},'Placement':{'AvailabilityZone':'us-east-1b'}}]
    facts = index({'recovery_group':[group],'instance':instances,'rds_instance':[]})
    assert evaluate(identifier,group,facts) == 'PASS'
    bad = copy.deepcopy(instances); bad[1]['Placement']['AvailabilityZone'] = 'us-east-1a'
    assert evaluate(identifier,group,index({'recovery_group':[group],'instance':bad,'rds_instance':[]})) == 'FAIL'
    assert evaluate(identifier,group,index({'recovery_group':[group],'instance':instances})) == 'UNKNOWN'


def test_rds_monitoring():
    identifier = 'aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled'
    row = {'DBInstanceIdentifier':'db1','MonitoringInterval':60,'MonitoringRoleArn':'arn:role','EnhancedMonitoringResourceArn':'arn:resource'}
    cluster = {'DBClusterMembers':[{'DBInstanceIdentifier':'db1'}]}
    assert evaluate(identifier,row,index({'rds_instance':[row],'rds_cluster':[cluster]})) == 'PASS'
    bad = copy.deepcopy(row); bad['MonitoringInterval'] = 0
    assert evaluate(identifier,bad,index({'rds_instance':[bad],'rds_cluster':[cluster]})) == 'FAIL'
    missing = {'DBClusterMembers':[{'DBInstanceIdentifier':'db2'}]}
    assert evaluate(identifier,row,index({'rds_instance':[row],'rds_cluster':[missing]})) == 'UNKNOWN'


def test_cloudformation_drift():
    identifier = 'aws_nist_cloudformation_stack_drift_detection_check'
    row = {'StackName':'stack','DriftDetection':{'DetectionStatus':'DETECTION_COMPLETE','DetectionTime':'2026-10-10T00:00:00Z','StackDriftStatus':'IN_SYNC'}}
    params = {'cloudformation_max_drift_age_days':7}
    assert evaluate(identifier,row,index({'cloudformation_stack':[row]},params)) == 'PASS'
    bad = copy.deepcopy(row); bad['DriftDetection']['StackDriftStatus'] = 'DRIFTED'
    assert evaluate(identifier,bad,index({'cloudformation_stack':[bad]},params)) == 'FAIL'
    assert evaluate(identifier,row,index({'cloudformation_stack':[row]})) == 'UNKNOWN'


def test_ecs_external_volumes():
    identifier = 'aws_g6_ecs_fargate_storage_encryption'
    cluster = {'clusterArn':'arn:aws:ecs:us-east-1:123456789012:cluster/c'}
    service = {'clusterArn':cluster['clusterArn'],'serviceArn':'arn:aws:ecs:us-east-1:123456789012:service/s',
               'volumeConfigurations':[{'managedEBSVolume':{'encrypted':True}}],'taskDefinition':'td1'}
    definition = {'taskDefinitionArn':'td1','Definition':{'taskDefinition':{'volumes':[{'efsVolumeConfiguration':{'fileSystemId':'fs1'}}]}}}
    fs = {'FileSystemId':'fs1','Encrypted':True}
    collections = {'ecs_cluster':[cluster],'ecs_service':[service],'ecs_task_definition':[definition],'efs_file_system':[fs]}
    assert evaluate(identifier,cluster,index(collections)) == 'PASS'
    bad = copy.deepcopy(fs); bad['Encrypted'] = False
    assert evaluate(identifier,cluster,index({**collections,'efs_file_system':[bad]})) == 'FAIL'
    assert evaluate(identifier,cluster,index({k:v for k,v in collections.items() if k != 'efs_file_system'})) == 'UNKNOWN'


def test_autoscaling_userdata_indicator():
    identifier = 'aws_autoscaling_userdata_plaintext_aws_key'
    row = {'LaunchConfigurationName':'lc','UserDataIndicators':{'InspectionStatus':'collected','HasAwsKeyPair':False}}
    assert evaluate(identifier,row,index({'autoscaling_launch_configuration':[row]})) == 'PASS'
    bad = copy.deepcopy(row); bad['UserDataIndicators']['HasAwsKeyPair'] = True
    assert evaluate(identifier,bad,index({'autoscaling_launch_configuration':[bad]})) == 'FAIL'
    bad = copy.deepcopy(row); bad['UserDataIndicators']['InspectionStatus'] = 'decode_failed'
    assert evaluate(identifier,bad,index({'autoscaling_launch_configuration':[bad]})) == 'UNKNOWN'


def test_sagemaker_clarify():
    identifier = 'aws_sagemaker_model_clarify_bias_job'
    subject = {'scope':SCOPE}
    job = {'ProcessingJobName':'j','EndpointName':'ep','ProcessingJobStatus':'Completed',
           'AppSpecification':{'ImageUri':'registry/clarify:latest'},'EndpointLinkedInput':True,'CreationTime':'2026-10-10T00:00:00Z'}
    endpoint = {'EndpointName':'ep','ModelLinkageStatus':'verified'}
    schedule = {'EndpointName':'ep','MonitoringScheduleStatus':'Scheduled'}
    collections = {'sagemaker_processing_job':[job],'sagemaker_endpoint':[endpoint],'sagemaker_monitoring_schedule':[schedule]}
    params = {'clarify_monitoring_interval_days':7}
    assert evaluate(identifier,subject,index(collections,params)) == 'PASS'
    bad = copy.deepcopy(schedule); bad['MonitoringScheduleStatus'] = 'Stopped'
    assert evaluate(identifier,subject,index({**collections,'sagemaker_monitoring_schedule':[bad]},params)) == 'FAIL'
    assert evaluate(identifier,subject,index(collections)) == 'UNKNOWN'
    assert evaluate(identifier,subject,index({**collections,'sagemaker_processing_job':[]},params)) == 'FAIL'
    assert evaluate(identifier,subject,index({**collections,'sagemaker_endpoint':[]},params)) == 'NOT_APPLICABLE'


def test_ecr_retention():
    identifier = 'aws_ecr_repository_lifecycle_retention'
    def policy(days):
        return json.dumps({'rules':[{'selection':{'tagStatus':'any','countType':'sinceImagePushed','countUnit':'days','countNumber':days},'action':{'type':'expire'}}]})
    row = {'repositoryName':'repo','LifecyclePolicy':{'lifecyclePolicyText':policy(7)}}
    params = {'ecr_retention_days':30}
    assert evaluate(identifier,row,index({'ecr_repository':[row]},params)) == 'PASS'
    bad = copy.deepcopy(row); bad['LifecyclePolicy']['lifecyclePolicyText'] = policy(60)
    assert evaluate(identifier,bad,index({'ecr_repository':[bad]},params)) == 'FAIL'
    assert evaluate(identifier,row,index({'ecr_repository':[row]})) == 'UNKNOWN'


def test_every_check_rejects_incomplete_malformed_and_missing_inventory():
    for identifier,(kind,*_) in sw.SPECS.items():
        subject = {'scope':SCOPE} if identifier in ('aws_nist_config_enabled_all_regions','aws_vpn_tunnel_encryption_configuration','aws_sagemaker_model_clarify_bias_job') else {'id':'subject'}
        facts = index({kind:[subject]})
        assert evaluate(identifier,subject,facts) == 'UNKNOWN'
        partial = copy.deepcopy(facts)
        partial['collections'][kind][0]['status'] = 'partial'
        assert evaluate(identifier,subject,partial) == 'UNKNOWN'
        malformed = copy.deepcopy(facts)
        malformed['collections'][kind][0]['items'] = 'not a list'
        assert evaluate(identifier,subject,malformed) == 'UNKNOWN'
        assert evaluate(identifier,subject,index({})) == 'UNKNOWN'
        foreign = copy.deepcopy(facts)
        foreign['context']['scope'] = '999999999999/eu-west-1'
        assert evaluate(identifier,subject,foreign) == 'UNKNOWN'


def teardown_module(module):
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]

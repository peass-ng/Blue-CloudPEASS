import copy,fnmatch,hashlib,json
from pathlib import Path
import pytest

from scripts import peaso_deploy_customer_policy as builder

ROOT=Path(builder.__file__).resolve().parents[1]
NEW_ROLE_SHA='1d8b49e45753dc7cba7069d772ad5286b5d033b294dacf6bea3a4ffd1c2aa2b1'
DELTA={'new_role_sha256':NEW_ROLE_SHA,'new_archive':'customer-role-'+NEW_ROLE_SHA+'.json'}
BASE=json.loads((ROOT/'infra/aws/customer-role-0484deedf711ac855f691e08531561c5b29abff7e46fa16320b79a32465eb6b2.json').read_text())
ROLE=json.loads((ROOT/'infra/aws/customer-role.json').read_text())
OPS={('outposts','list_outposts'):'outposts:ListOutposts',('s3control','list_regional_buckets'):'s3-outposts:ListRegionalBuckets',('s3tables','list_table_buckets'):'s3tables:ListTableBuckets',('s3vectors','list_vector_buckets'):'s3vectors:ListVectorBuckets',('dynamodb','list_backups'):'dynamodb:ListBackups',('rds','describe_db_instance_automated_backups'):'rds:DescribeDBInstanceAutomatedBackups',('rds','describe_db_cluster_automated_backups'):'rds:DescribeDBClusterAutomatedBackups',('redshift-serverless','list_snapshots'):'redshift-serverless:ListSnapshots',('redshift-serverless','list_recovery_points'):'redshift-serverless:ListRecoveryPoints'}

def added():
 before=BASE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 after=ROLE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 assert after[:len(before)]==before
 return after[len(before):-1]

def test_transit_gateway_route_evidence_grant_is_read_only_and_archived():
 row=ROLE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'][-1]
 assert row=={'Sid':'NativeTransitGatewayRouteEvidenceRead','Effect':'Allow',
  'Action':['ec2:DescribeTransitGatewayVpcAttachments','ec2:GetTransitGatewayRouteTableAssociations','ec2:SearchTransitGatewayRoutes'],
  'Resource':'*'}
 operations={('ec2','describe_transit_gateway_vpc_attachments'),
  ('ec2','get_transit_gateway_route_table_associations'),('ec2','search_transit_gateway_routes')}
 policy=builder.build_policy(operations,include_credential_report_generation=False)
 assert set(policy['Statement'][0]['Action'])==set(row['Action'])
 assert (ROOT/'infra/aws'/DELTA['new_archive']).read_bytes()==(ROOT/'infra/aws/customer-role.json').read_bytes()

@pytest.mark.parametrize('operation,expected',list(OPS.items()))
def test_new_action_has_verified_alias_and_exact_grant(operation,expected):
 assert builder.iam_action(*operation)==expected
 native=builder.NATIVE_METADATA_STATEMENTS[operation]
 assert native in added()
 policy=builder.build_policy({operation},include_credential_report_generation=False)
 assert policy['Statement']==[native]
 assert native['Action']==expected and '*'not in expected

@pytest.mark.parametrize('service,operation',[
 ('s3vectors','create_vector_bucket'),('s3vectors','put_vectors'),('s3vectors','delete_vectors'),
 ('s3tables','create_table_bucket'),('outposts','create_outpost'),
 ('rds','delete_db_cluster_automated_backup'),('redshift-serverless','restore_from_snapshot'),
 ('redshift-serverless','get_credentials'),('s3','get_object'),('secretsmanager','get_secret_value')])
def test_added_delta_cannot_authorize_mutation_or_content(service,operation):
 with pytest.raises(ValueError):builder.iam_action(service,operation)

@pytest.mark.parametrize('action,types',[
 ('rds:DescribeDBInstanceAutomatedBackups',{'auto-backup:*','db:*'}),
 ('rds:DescribeDBClusterAutomatedBackups',{'cluster:*','cluster-auto-backup:*'}),
 ('redshift-serverless:ListSnapshots',{'snapshot/*'}),
 ('redshift-serverless:ListRecoveryPoints',{'recoverypoint/*'})])
def test_resource_supported_metadata_grants_are_customer_scoped(action,types):
 row=next(r for r in added()if r['Action']==action)
 resources=row['Resource']if isinstance(row['Resource'],list)else[row['Resource']]
 assert {r['Fn::Sub'].split('${AWS::AccountId}:',1)[1]for r in resources}==types
 assert all('${AWS::Partition}'in r['Fn::Sub']and ':*:${AWS::AccountId}:'in r['Fn::Sub']for r in resources)
 # Concrete ARN matching proves added action does not match another account.
 for resource in resources:
  pattern=resource['Fn::Sub'].replace('${AWS::Partition}','aws').replace('${AWS::AccountId}','123456789012')
  actual=pattern.replace(':*:',':eu-west-1:').replace('*','owned')
  assert fnmatch.fnmatchcase(actual,pattern)
  assert not fnmatch.fnmatchcase(actual.replace('123456789012','999999999999'),pattern)

def test_only_nine_enumerations_added_originals_and_limits_preserved():
 assert len(added())==9 and {r['Action']for r in added()}==set(OPS.values())
 for row in added():
  assert set(row)=={'Sid','Effect','Action','Resource'}and row['Effect']=='Allow'
  assert row['Action'].split(':')[1].startswith(('List','Describe'))
 for n in ['AuditRole','CspmConfigurationReadOnly1','CspmConfigurationReadOnly2','CspmConfigurationReadOnly3']:
  assert BASE['Resources'][n]==ROLE['Resources'][n]
 assert set(BASE['Resources'])==set(ROLE['Resources'])
 assert BASE['Parameters']==ROLE['Parameters']and BASE['Outputs']==ROLE['Outputs']
 for r in ROLE['Resources'].values():
  if r['Type']=='AWS::IAM::ManagedPolicy':assert len(json.dumps(r['Properties']['PolicyDocument'],separators=(',',':')))<=6144
 assert len((ROOT/'infra/aws/customer-role.json').read_bytes())<=51200
 assert hashlib.sha256((ROOT/'infra/aws/customer-role.json').read_bytes()).hexdigest()==DELTA['new_role_sha256']
 assert (ROOT/'infra/aws'/DELTA['new_archive']).read_bytes()==(ROOT/'infra/aws/customer-role.json').read_bytes()
 assert builder.iam_action('sts','get_caller_identity')is None

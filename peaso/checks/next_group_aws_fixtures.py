"""Inert scoped native inputs; no SDK, collector, evaluator, or cloud calls."""
from copy import deepcopy
ACCOUNT='123456789012'
REGION='us-east-1'
SCOPE=ACCOUNT+'/'+REGION
CALLER={'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer'}
CLUSTER=f'arn:aws:rds:{REGION}:{ACCOUNT}:cluster:db-a'
MEMBER=f'arn:aws:rds:{REGION}:{ACCOUNT}:db:member-a'
ROLE=f'arn:aws:iam::{ACCOUNT}:role/RDSMonitor'
TASK=f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/web:1'
SECRET=f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:fixture-abcdef'
KEY_ID='11111111-1111-1111-1111-111111111111'
KEY=f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}'
def index(data):
 result={'context':{'provider':'aws','scope':SCOPE,'metadata':{'caller_identities':[deepcopy(CALLER)]}},'collections':{}}
 for kind,rows in data.items():
  result['collections'][kind]=[{'type':kind,'scope':SCOPE,'account_id':ACCOUNT,'global':False,'status':'collected' if rows else 'empty','items':deepcopy(rows)}]
  result[kind]=[{'type':kind,'scope':SCOPE,'provider':'aws','data':deepcopy(row)} for row in rows]
 return result
def case(item,passing,failing,unknown):
 return {'pass':deepcopy(item),'pass_index':index(passing),'fail':deepcopy(item),'fail_index':index(failing),
         'unknown':deepcopy(item),'unknown_index':index(unknown),'missing':{},'malformed':None}
cluster={'DBClusterArn':CLUSTER,'DBClusterIdentifier':'db-a','DBClusterMembers':[{'DBInstanceIdentifier':'member-a'}],'AccountId':ACCOUNT,'Region':REGION}
member={'DBInstanceArn':MEMBER,'DBInstanceIdentifier':'member-a','DBClusterIdentifier':'db-a','MonitoringInterval':60,'MonitoringRoleArn':ROLE,'AccountId':ACCOUNT,'Region':REGION}
rds_pass={'rds_cluster':[cluster],'rds_instance':[member]};rds_fail=deepcopy(rds_pass);rds_fail['rds_instance'][0]['MonitoringInterval']=0
rds_unknown=deepcopy(rds_pass);rds_unknown['rds_instance'][0]['MonitoringInterval']='malformed'
task={'taskDefinitionArn':TASK,'AccountId':ACCOUNT,'Region':REGION,'Definition':{'collection_status':'collected','taskDefinition':{'taskDefinitionArn':TASK,'containerDefinitions':[{'name':'web','environment':[{'name':'OTHER'}]}]}}}
ecs_pass={'ecs_task_definition':[task]};ecs_fail=deepcopy(ecs_pass);ecs_fail['ecs_task_definition'][0]['Definition']['taskDefinition']['containerDefinitions'][0]['environment']=[{'name':'AWS_ACCESS_KEY_ID'}]
ecs_unknown=deepcopy(ecs_pass);ecs_unknown['ecs_task_definition'][0]['Definition']['taskDefinition']['containerDefinitions'][0].pop('environment')
secret={'ARN':SECRET,'Name':'fixture','AccountId':ACCOUNT,'Region':REGION,'KmsKeyId':KEY,'_coverage':{'KmsKeyId':{'status':'collected','source_operation':'secretsmanager:DescribeSecret'}}}
key={'KeyArn':KEY,'KeyId':KEY_ID,'AccountId':ACCOUNT,'Region':REGION,'Metadata':{'collection_status':'collected','KeyMetadata':{'Arn':KEY,'KeyId':KEY_ID,'KeyManager':'CUSTOMER','KeyState':'Enabled'}}}
kms_pass={'secret':[secret],'kms_key':[key]};kms_fail=deepcopy(kms_pass);kms_fail['kms_key'][0]['Metadata']['KeyMetadata']['KeyState']='Disabled'
kms_unknown=deepcopy(kms_pass);kms_unknown['kms_key'][0]['Metadata']={'collection_status':'denied'}
CASES_FRAGMENT={'aws.nist.rds_cluster_member_enhanced_monitoring':case(cluster,rds_pass,rds_fail,rds_unknown),
                'aws_ecs_task_definition_credential_environment_names':case(task,ecs_pass,ecs_fail,ecs_unknown),
                'aws.pci.secretsmanager.kms_encryption_any':case(secret,kms_pass,kms_fail,kms_unknown)}
# Changing the assessed item's own ECS environment requires matching the index view.
CASES_FRAGMENT['aws_ecs_task_definition_credential_environment_names']['fail']=deepcopy(ecs_fail['ecs_task_definition'][0])
CASES_FRAGMENT['aws_ecs_task_definition_credential_environment_names']['unknown']=deepcopy(ecs_unknown['ecs_task_definition'][0])

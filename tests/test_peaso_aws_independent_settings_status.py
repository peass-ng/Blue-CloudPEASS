"""Independent SSM setting enrichment must not invalidate a limited scan."""
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.snapshot import validate
from peaso.engine import evaluate_snapshot
KIND='ssm_service_settings'
AUTOMATION='/ssm/automation/customer-script-log-destination'
PRIMARY=f'arn:aws:ssm:{REGION}:{ACCOUNT}:servicesetting/ssm/documents/console/public-sharing-permission'

def capture(sdk,monkeypatch,mode):
 session,add=sdk;sts=add('sts');ssm=add('ssm')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'}, {})
 if mode!='call_limit':
  ssm.add_client_error('get_service_setting','AccessDeniedException',expected_params={'SettingId':PRIMARY})
  if mode=='independent_success':ssm.add_response('get_service_setting',{'ServiceSetting':{'SettingId':AUTOMATION,'SettingValue':'CloudWatch','Status':'Customized'}},{'SettingId':AUTOMATION})
  else:ssm.add_client_error('get_service_setting','AccessDeniedException',expected_params={'SettingId':AUTOMATION})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'explicit-fixture'))
 options={'regions':[REGION],'service_concurrency':1,'retry_attempts':1,**({'max_calls':1}if mode=='call_limit'else{})}
 snapshot=collect_live({'provider':'aws','scopes':[ACCOUNT+'/'+REGION],'options':options},[KIND]);sts.assert_no_pending_responses();ssm.assert_no_pending_responses();validate(snapshot)
 return snapshot,next(c for c in snapshot['collections']if c['type']==KIND)

@pytest.mark.parametrize('mode,cause,code',[('both_denied','denied','AccessDeniedException'),('call_limit','not_collected','call_limit')])
def test_unavailable_parent_and_independent_setting_remain_explicit_unknown(sdk,monkeypatch,mode,cause,code):
 snapshot,collection=capture(sdk,monkeypatch,mode)
 assert collection['status']=='partial'and collection['error']=={'code':code,'cause_status':cause}
 assert len(collection['items'])==1
 assert collection['items'][0]['RequestedSettingId']==AUTOMATION
 assert collection['items'][0]['collection_status']==cause
 findings=evaluate_snapshot(snapshot,checks=['aws.cb.ssm.automation_logs_to_cloudwatch'])['findings']
 assert findings and all(f['status']=='UNKNOWN'for f in findings)


def test_successful_independent_setting_is_retained_without_promoting_failed_parent(sdk,monkeypatch):
 _,collection=capture(sdk,monkeypatch,'independent_success')
 assert collection['status']=='partial'and collection['error']=={'code':'AccessDeniedException','cause_status':'denied'}
 assert collection['items'][0]['ServiceSetting']['SettingValue']=='CloudWatch'


def test_snapshot_still_rejects_unavailable_collections_with_items():
 with pytest.raises(ValueError,match='unavailable/empty collection cannot contain items'):
  from peaso.snapshot import make_snapshot
  make_snapshot('aws',[ACCOUNT+'/'+REGION],[{'type':KIND,'scope':ACCOUNT+'/'+REGION,'status':'not_collected','items':[{'id':'not-native-proof'}]}])

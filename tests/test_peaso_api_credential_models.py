"""No-network botocore credential model witness for API packaging."""
"""No-network botocore 1.43.38 credential provider model witness."""
import contextlib,datetime,json,os,pathlib,tempfile,copy,socket
from unittest.mock import patch
import botocore.session
from botocore.stub import Stubber
from botocore.credentials import ContainerProvider,InstanceMetadataProvider,SSOCredentialFetcher
from botocore.tokens import SSOTokenProvider
from botocore.utils import SSOTokenLoader



def test_credential_provider_models_without_network():
    import botocore
    assert botocore.__version__ == '1.43.38'
    UTC=datetime.timezone.utc
    expiration=datetime.datetime.now(UTC)+datetime.timedelta(hours=2)
    assumed={'Credentials':{'AccessKeyId':'ASIA'+'A'*16,'SecretAccessKey':'s'*40,'SessionToken':'t'*60,'Expiration':expiration},'AssumedRoleUser':{'AssumedRoleId':'AROATEST:probe','Arn':'arn:aws:sts::123456789012:assumed-role/Probe/probe'}}
    seen=[];stack=contextlib.ExitStack();original=botocore.session.Session.create_client

    def intercepted(self,service_name,*args,**kwargs):
        assert service_name in {'sts','sso','sso-oidc'},service_name
        seen.append(service_name)
        client=original(self,service_name,*args,**kwargs)
        stub=stack.enter_context(Stubber(client))
        if service_name=='sts':
            op='assume_role' if seen.count('sts')==1 else 'assume_role_with_web_identity'
            stub.add_response(op,copy.deepcopy(assumed))
        elif service_name=='sso':
            stub.add_response('get_role_credentials',{'roleCredentials':{'accessKeyId':'ASIA'+'B'*16,'secretAccessKey':'s'*40,'sessionToken':'t'*60,'expiration':int(expiration.timestamp()*1000)}})
        else:
            stub.add_response('create_token',{'accessToken':'refreshed','expiresIn':3600,'tokenType':'Bearer','refreshToken':'refresh2'})
        return client

    with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{'AWS_EC2_METADATA_DISABLED':'true','AWS_CONFIG_FILE':temp+'/config','AWS_SHARED_CREDENTIALS_FILE':temp+'/credentials','AWS_DEFAULT_REGION':'us-east-1','AWS_ACCESS_KEY_ID':'','AWS_SECRET_ACCESS_KEY':''}),patch.object(botocore.session.Session,'create_client',intercepted),patch.object(socket.socket,'connect',side_effect=AssertionError('network attempted')):
        pathlib.Path(temp+'/credentials').write_text('[source]\naws_access_key_id = AKIA'+'A'*16+'\naws_secret_access_key = '+'s'*40+'\n')
        pathlib.Path(temp+'/token').write_text('synthetic-token')
        pathlib.Path(temp+'/config').write_text('[profile assume]\nrole_arn = arn:aws:iam::123456789012:role/Probe\nsource_profile = source\nrole_session_name = probe\n[profile sso]\nsso_session = test\nsso_account_id = 123456789012\nsso_role_name = Reader\n[sso-session test]\nsso_start_url = https://example.invalid/start\nsso_region = us-east-1\n')
        with stack:
            profile=botocore.session.Session(profile='source').get_credentials().get_frozen_credentials()
            assert profile.access_key.startswith('AKIA') and not seen
            assumed_profile=botocore.session.Session(profile='assume').get_credentials().get_frozen_credentials()
            assert assumed_profile.access_key.startswith('ASIA') and seen==['sts']
            with patch.dict(os.environ,{'AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/Probe','AWS_WEB_IDENTITY_TOKEN_FILE':temp+'/token'},clear=False):
                web=botocore.session.Session().get_component('credential_provider').get_provider('assume-role-with-web-identity').load().get_frozen_credentials()
                assert web.access_key.startswith('ASIA') and seen[-1]=='sts'
            fetcher=SSOCredentialFetcher('https://example.invalid/start','us-east-1','Reader','123456789012',lambda service,**kw: botocore.session.Session().create_client(service,**kw),token_loader=lambda *a,**kw:{'accessToken':'synthetic','expiresAt':expiration.isoformat()})
            role=fetcher.fetch_credentials()
            assert role['access_key'].startswith('ASIA') and seen[-1]=='sso'
            cache={}
            loader=SSOTokenLoader(cache=cache)
            old={'accessToken':'old','expiresAt':(datetime.datetime.now(UTC)-datetime.timedelta(minutes=1)).isoformat(),'refreshToken':'refresh','clientId':'client','clientSecret':'secret','registrationExpiresAt':(datetime.datetime.now(UTC)+datetime.timedelta(days=1)).isoformat()}
            loader.save_token('https://example.invalid/start',old,session_name='test')
            token=SSOTokenProvider(botocore.session.Session(profile='sso'),cache=cache).load_token().get_frozen_token()
            assert token.token=='refreshed' and seen[-1]=='sso-oidc'
            # Metadata providers use HTTP fetchers, with no modeled AWS service.
            class ContainerFetch:
                def full_url(self,relative):return 'http://127.0.0.1/fake'
                def retrieve_full_uri(self,url,headers=None):return {'AccessKeyId':'ASIA'+'C'*16,'SecretAccessKey':'s'*40,'Token':'t'*60,'Expiration':expiration.isoformat()}
            before=list(seen)
            with patch.dict(os.environ,{'AWS_ACCESS_KEY_ID':'AKIA'+'E'*16,'AWS_SECRET_ACCESS_KEY':'s'*40,'AWS_SESSION_TOKEN':'t'*60}):
                task=botocore.session.Session().get_credentials().get_frozen_credentials()
                assert task.token and seen==before
            container=ContainerProvider(environ={'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI':'/fake'},fetcher=ContainerFetch()).load().get_frozen_credentials()
            assert container.access_key.startswith('ASIA') and seen==before
            class IMDSFetch:
                def retrieve_iam_role_credentials(self):return {'access_key':'ASIA'+'D'*16,'secret_key':'s'*40,'token':'t'*60,'expiry_time':expiration.isoformat(),'role_name':'Probe'}
            instance=InstanceMetadataProvider(iam_role_fetcher=IMDSFetch()).load().get_frozen_credentials()
            assert instance.access_key.startswith('ASIA') and seen==before
    print(json.dumps({'botocore':'1.43.38','modeled_services':sorted(set(seen)),'service_construction_sequence':seen,'credential_paths':['explicit','task_role_env','profile','profile_assume_role','web_identity','sso_role','sso_oidc_refresh','container_http','instance_http'],'network_calls':0},sort_keys=True))


if __name__ == '__main__':
    test_credential_provider_models_without_network()

"""Selected AWS image intake stays credential-free and independent of secret scans."""
from copy import deepcopy
import importlib.abc
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector

SCOPE='111111111111/eu-west-1'
OPTION='selected_aws_image_vulnerabilities'
TARGET={'scope':SCOPE,'repository_name':'sample/app','image_digest':'sha256:'+'a'*64}
AUTH={'method':'access_keys','aws_access_key_id':'synthetic-offline','aws_secret_access_key':'synthetic-offline'}

@pytest.mark.parametrize('mode', ['local','cognito'])
@pytest.mark.parametrize('secret', [False,True])
@pytest.mark.parametrize('kind', ['ecr','lambda'])
def test_valid_selected_aws_intake_preserves_input(mode,secret,kind):
    target=deepcopy(TARGET) if kind=='ecr' else {'scope':SCOPE,'function_arn':'arn:aws:lambda:eu-west-1:111111111111:function:sample'}
    options={'image_vulnerability_scans':True,'content_secret_scans':secret,OPTION:[target]}
    original=deepcopy(options)
    validate_connector('aws',AUTH,options,SimpleNamespace(auth_mode=mode),scopes=[SCOPE])
    assert options==original

@pytest.mark.parametrize('case', ['no_targets','wrong_account','tag','extra_key','duplicate','foreign_provider','bad_bool','discovery','disabled_bad_target'])
def test_invalid_selection_rejected_even_when_disabled(case):
    options={'image_vulnerability_scans':True,OPTION:[deepcopy(TARGET)]};provider='aws'
    if case=='no_targets':options.pop(OPTION)
    elif case=='wrong_account':options[OPTION][0]['scope']='222222222222/eu-west-1'
    elif case=='tag':options[OPTION][0]['image_digest']='latest'
    elif case=='extra_key':options[OPTION][0]['token']='synthetic-never-used'
    elif case=='duplicate':options[OPTION]*=2
    elif case=='foreign_provider':provider='gcp'
    elif case=='bad_bool':options['image_vulnerability_scans']='true'
    elif case=='discovery':options['all_regions']=True
    elif case=='disabled_bad_target':options['image_vulnerability_scans']=False;options[OPTION][0]['image_digest']='latest'
    original=deepcopy(options)
    with pytest.raises(HTTPException) as caught:
        validate_connector(provider,AUTH,options,SimpleNamespace(auth_mode='local'),scopes=[SCOPE])
    assert caught.value.status_code==422 and options==original


def test_disabled_aws_without_targets_is_accepted():
    validate_connector('aws',AUTH,{'image_vulnerability_scans':False},SimpleNamespace(auth_mode='cognito'),scopes=[])


def test_cold_valid_aws_connector_cannot_import_native_or_use_network():
    root=Path(__file__).resolve().parents[1]
    script='''
import importlib.abc,socket,sys
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self,name,path=None,target=None):
  if name in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis') or name.startswith(('peaso.collectors.','peaso.checks.','peaso.analysis.')):
   raise ImportError('unexpected native import: '+name)
sys.meta_path.insert(0,Block())
def denied(*args,**kwargs):raise AssertionError('unexpected network')
socket.socket.connect=denied
socket.socket.connect_ex=denied
socket.create_connection=denied
from peaso.server.validation import validate_connector
from types import SimpleNamespace
for mode in ('local','cognito'):
 validate_connector('aws',AUTH,OPTIONS,SimpleNamespace(auth_mode=mode),scopes=SCOPES)
assert not any(name in sys.modules for name in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis'))
'''
    prefix='AUTH='+repr(AUTH)+'\nOPTIONS='+repr({'image_vulnerability_scans':True,OPTION:[TARGET]})+'\nSCOPES='+repr([SCOPE])+'\n'
    result=subprocess.run([sys.executable,'-c',prefix+script],cwd=root,text=True,capture_output=True,
        env={**os.environ,'PYTHONPATH':str(root),'PYTHONDONTWRITEBYTECODE':'1'},timeout=30)
    assert result.returncode==0,result.stderr


def test_full_metadata_regions_do_not_expand_selected_image_reads():
    regions=['eu-west-1','eu-west-2','eu-west-3','us-east-1','us-east-2','us-west-1','us-west-2',
             'eu-central-1','eu-north-1','ap-south-1','ap-northeast-1','ap-northeast-2',
             'ap-northeast-3','ap-southeast-1','ap-southeast-2','ca-central-1','sa-east-1']
    scopes=['111111111111/'+region for region in regions]
    options={'image_vulnerability_scans':True,OPTION:[deepcopy(TARGET)]}
    before=deepcopy(options)
    validate_connector('aws',AUTH,options,SimpleNamespace(auth_mode='cognito'),scopes=scopes)
    assert options==before and len(options[OPTION])==1

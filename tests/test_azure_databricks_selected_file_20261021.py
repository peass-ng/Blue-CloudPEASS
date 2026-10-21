"""Native selected content: normal package imports and bounded fake HTTP."""
import base64
import io
import json
import time
import unittest
import types
from copy import deepcopy
from unittest.mock import patch
from pathlib import Path
import pytest
from peaso import secret_scanning
from peaso import secret_evidence
from peaso.collectors import azure_selected_secret_integration_20261020 as integration
from peaso.collectors import azure_databricks_notebook_secret_indicators as source
from peaso.checks import azure_databricks_notebook_secret_review_20261020 as check

TENANT='11111111-1111-1111-1111-111111111111'
SUB='/subscriptions/'+TENANT
RID=SUB+'/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected'
HOST='adb-12345.12.azuredatabricks.net'
PATH='/Shared/config/example.txt'
TARGET={'workspace_resource_id':RID,'path':PATH,'object_type':'FILE'}
CONTENT=b'key=clear text\n'

def jwt(audience):
    claims={'tid':TENANT,'oid':'22222222-2222-2222-2222-222222222222','appid':'33333333-3333-3333-3333-333333333333','aud':audience,'exp':int(time.time())+3600}
    return 'x.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.x'

class Transport:
    tenant=verified_tenant=TENANT
    auth={}
    def __init__(self):self.audiences=[]
    def token(self,audience):self.audiences.append(audience);return jwt(audience)

class Response:
    def __init__(self,status,body,headers=None):
        self.status=status;self.body=json.dumps(body).encode() if isinstance(body,dict) else body;self.offset=0
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.body)),**(headers or {})}
    def getheader(self,name):return self.headers.get(name)
    def read(self,n):part=self.body[self.offset:self.offset+n];self.offset+=len(part);return part
    def close(self):pass

class HTTP:
    plan=[];seen=[]
    def __init__(self,host,timeout):self.host=host;self.sock=None
    def set_debuglevel(self,n):assert n==0
    def request(self,method,path,body,headers):
        assert method=='GET' and body is None and headers['Authorization'].startswith('Bearer ')
        assert headers['Authorization']!= 'Bearer '+jwt(source.ARM) or self.host=='management.azure.com'
        self.seen.append((self.host,path))
    def getresponse(self):
        if not self.plan:raise AssertionError('unexpected_request')
        return self.plan.pop(0)
    def close(self):pass

class Reader:
    def check_cancelled(self):pass
    def __init__(self):self.collections=[]
    def call(self,fn,*args):return fn(*args)
    def run(self,tasks):
        for kind,scope,service,fetch in tasks:
            items=[item for page in fetch() for item in page]
            self.collections.append({'kind':kind,'scope':scope,'service':service,'status':'collected','items':items,'_provenance':{'credential_context_id':'cred','customer_context_id':'cust'}})

class Cases(unittest.TestCase):
    def setUp(self):
        HTTP.plan=[];HTTP.seen=[];secret_scanning._RESULTS.clear()
    def plan(self,content=CONTENT,*,change=False,denied=False,truncated=False,foreign=False):
        status={'path':PATH,'object_type':'FILE','object_id':44,'resource_id':'file-id','created_at':1,'modified_at':10,'size':len(content)}
        after={**status,'modified_at':11} if change else status
        workspace={'id':RID,'name':'selected','type':'Microsoft.Databricks/workspaces','properties':{'workspaceId':'12345','workspaceUrl':'other.example.com' if foreign else HOST,'provisioningState':'Succeeded'}}
        export={'content':base64.b64encode(content).decode()}
        HTTP.plan=[Response(200,{'id':SUB,'subscriptionId':TENANT,'tenantId':TENANT,'state':'Enabled'}),Response(200,workspace),Response(200,status),Response(403,{'error_code':'DENIED'}) if denied else Response(200,export,{'Content-Length':'9999999'} if truncated else None),Response(200,after)]
    def collect(self,*,secret=None,other_unavailable=False):
        reader=Reader();transport=Transport();opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.FILE_OPTION:[TARGET]}
        def detector(payload,path,timeout):return [(secret,'Rule',1)] if secret else []
        def other(payload,path,timeout):
            if other_unavailable:raise RuntimeError('offline detector unavailable')
            return detector(payload,path,timeout)
        with patch.object(source.http.client,'HTTPSConnection',HTTP),patch.object(secret_scanning,'_scan_kingfisher',detector),patch.object(secret_scanning,'_scan_trufflehog',other):
            source.collect(reader,transport,[SUB],[source.KIND],opts)
        item=reader.collections[0]['items'][0]
        meta={**reader.databricks_notebook_secret_metadata,'context_binding':'scan_local','tenant_verified':True,'tenant_id':TENANT,'credential_context_id':'cred','customer_context_id':'cust'}
        item['_provenance'].update(credential_context_id='cred',customer_context_id='cust')
        index={'context':{'provider':'azure','scope':SUB,'metadata':meta},'collections':{source.KIND:reader.collections}}
        return reader,transport,item,check.evaluate(item,index)
    def test_clean_file_and_native_sequence(self):
        self.plan();reader,transport,item,(status,result)=self.collect()
        self.assertEqual(status,'PASS');self.assertTrue(result['complete'])
        self.assertEqual(transport.audiences,[source.ARM]*2+[source.DATABRICKS]*3)
        self.assertEqual(HTTP.seen,[( 'management.azure.com',SUB+'?api-version=2022-12-01'),('management.azure.com',RID+'?api-version='+source.API),
            (HOST,'/api/2.0/workspace/get-status?path=%2FShared%2Fconfig%2Fexample.txt'),
            (HOST,'/api/2.0/workspace/export?path=%2FShared%2Fconfig%2Fexample.txt&format=RAW&direct_download=false'),
            (HOST,'/api/2.0/workspace/get-status?path=%2FShared%2Fconfig%2Fexample.txt')])
        self.assertNotIn('key=clear',json.dumps(item));self.assertNotIn(PATH,json.dumps(item))
    def test_positive_hmac_union(self):
        self.plan(b'token=example-secret\n');_,_,item,(status,result)=self.collect(secret='example-secret')
        self.assertEqual(status,'FAIL');self.assertEqual(len(result['secret_leaks']),1)
        self.assertEqual({d['engine'] for d in result['secret_leaks'][0]['detectors']},{'kingfisher','trufflehog'})
        self.assertNotIn('example-secret',json.dumps(item)+json.dumps(result))
    def test_partial_positive_remains_fail_and_clean_unknown(self):
        self.plan(b'token=partial-secret\n');_,_,_,(status,result)=self.collect(secret='partial-secret',other_unavailable=True)
        self.assertEqual(status,'FAIL');self.assertFalse(result['complete'])
        self.assertEqual([d['engine'] for d in result['secret_leaks'][0]['detectors']],['kingfisher'])
        self.plan();_,_,_,(status,result)=self.collect(other_unavailable=True)
        self.assertEqual(status,'UNKNOWN');self.assertFalse(result['complete'])
    def test_unknown_denied_truncated_head_change_foreign(self):
        for kwargs in ({'denied':True},{'truncated':True},{'change':True},{'foreign':True}):
            with self.subTest(kwargs=kwargs):
                self.plan(**kwargs);HTTP.seen=[];_,_,item,(status,result)=self.collect()
                self.assertEqual(status,'UNKNOWN');self.assertFalse(item[source.MARKER]['complete'])
                self.assertFalse(result['complete'])
                if kwargs.get('foreign'):self.assertEqual(len(HTTP.seen),2)
    def test_selector_rejects_repo_traversal_and_nonexplicit_file(self):
        options={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.FILE_OPTION:[TARGET]}
        self.assertEqual(source.selected_targets(options,[SUB]),[TARGET])
        for path in ('/Repos/user/repo/file.txt','/Workspace/Repos/u/r/f','/Shared/../file.txt','/Shared//file.txt'):
            with self.subTest(path=path),self.assertRaises(ValueError):source.selected_targets({**options,source.FILE_OPTION:[{**TARGET,'path':path}]},[SUB])
        with self.assertRaises(ValueError):source.selected_targets({**options,source.FILE_OPTION:[{**TARGET,'object_type':'NOTEBOOK'}]},[SUB])
        with self.assertRaises(ValueError):source.selected_targets({**options,source.FILE_OPTION:[TARGET]*5},[SUB])
    def test_file_size_and_export_bytes_bind(self):
        self.plan();HTTP.plan[2].body=json.dumps({'path':PATH,'object_type':'FILE','object_id':44,'modified_at':10,'size':len(CONTENT)+1}).encode()
        HTTP.plan[2].headers['Content-Length']=str(len(HTTP.plan[2].body))
        _,_,item,(status,_)=self.collect();self.assertEqual(status,'UNKNOWN')
        self.assertFalse(item[source.MARKER]['complete'])

if __name__=='__main__':unittest.main(verbosity=2)

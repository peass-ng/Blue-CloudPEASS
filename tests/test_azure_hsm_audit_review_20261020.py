"""Archived HSM contract replay; never re-admits the control to product scans."""
from copy import deepcopy
import io
import json
import socket
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
import pytest
from peaso import checks
from peaso.checks import azure_hsm_audit_review_20261020 as review
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

SUB='11111111-1111-1111-1111-111111111111'
OTHER='99999999-9999-9999-9999-999999999999'
SCOPE='/subscriptions/'+SUB
HSM=SCOPE+'/resourceGroups/review/providers/Microsoft.KeyVault/managedHSMs/reviewhsm'
DIAG=HSM+'/providers/Microsoft.Insights/diagnosticSettings/audit'
DEST=SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/archive'
CHECK=review.CHECK


class NativeHTTP:
    def __init__(self,mode):
        self.mode=mode;self.calls=[];self.unexpected=[]
        self.hsm={'id':HSM,'name':'reviewhsm','type':'Microsoft.KeyVault/managedHSMs','location':'eastus',
            'sku':{'family':'B','name':'Standard_B1'},'properties':{'provisioningState':'Succeeded','enablePurgeProtection':True}}
        self.setting={'id':DIAG,'name':'audit','type':'Microsoft.Insights/diagnosticSettings','properties':{
            'storageAccountId':DEST,'logs':[{'category':'AuditEvent','enabled':True}]}}
        p=self.setting['properties'];log=p['logs'][0]
        if mode=='no_storage':p.pop('storageAccountId')
        if mode=='workspace_only':
            p.pop('storageAccountId')
            p['workspaceId']=SCOPE+'/resourceGroups/review/providers/Microsoft.OperationalInsights/workspaces/audit'
        if mode=='disabled':log['enabled']=False
        if mode=='other_category':log['category']='OtherCategory'
        if mode in ('allLogs','audit_group'):log.pop('category');log['categoryGroup']='allLogs'if mode=='allLogs'else'audit'
        if mode=='malformed_enabled':log['enabled']='true'
        if mode=='missing_enabled':log.pop('enabled')
        if mode=='no_selector':log.pop('category')
        if mode=='both_selectors':log['categoryGroup']='allLogs'
        if mode=='malformed_storage':p['storageAccountId']='https://archive.blob.core.windows.net/'
        if mode=='wrong_storage_provider':p['storageAccountId']=DEST.replace('Microsoft.Storage','MicrosoftXStorage')
        if mode=='cross_subscription_storage':p['storageAccountId']=DEST.replace(SUB,OTHER)
        if mode=='malformed_logs':p['logs']={}
        if mode=='missing_logs':p.pop('logs')
        if mode=='foreign_parent':self.hsm['id']=HSM.replace(SUB,OTHER)
        if mode=='wrong_hsm_type':self.hsm['type']='Microsoft.KeyVault/vaults'
        if mode=='wrong_diag_type':self.setting['type']='Microsoft.KeyVault/managedHSMs'
        if mode=='foreign_diag':self.setting['id']=DIAG.replace('reviewhsm','otherhsm')
        if mode=='wrong_diag_route':self.setting['id']=HSM+'/config/audit'
        if mode=='uppercase_identity':
            self.hsm['id']=HSM.upper();self.hsm['type']=self.hsm['type'].upper();self.setting['id']=DIAG.upper();self.setting['type']=self.setting['type'].upper()
    def open(self,request,timeout):
        try:
            response=self._open(request,timeout)
            response.status=200
            return response
        except AssertionError as e:self.unexpected.append((request.full_url,str(e)));raise
    def _open(self,request,timeout):
        p=urlsplit(request.full_url);q=parse_qs(p.query);path=p.path
        assert p.scheme=='https'and p.netloc=='management.azure.com'and timeout==20
        assert set(q)<={'api-version','page','$top'}and len(q.get('api-version',[]))==1
        method=request.get_method();self.calls.append({'method':method,'host':p.netloc,'path':path,'query':q})
        def deny():raise HTTPError(request.full_url,403,'denied',{},io.BytesIO(b'{}'))
        if method=='POST':
            assert path=='/providers/Microsoft.ResourceGraph/resources'and q['api-version']==['2022-10-01']
            assert json.loads(request.data)['subscriptions']==[SUB]
            value={'data':[self.hsm],'resultTruncated':False}
        else:
            assert method=='GET'and request.data is None
            if path.casefold()==(SCOPE+'/providers/Microsoft.KeyVault/managedHSMs').casefold():
                assert q['api-version']==['2023-07-01']
                if self.mode=='denied' or 'page'in q:deny()
                value={'value':[]if self.mode=='empty'else[self.hsm]}
                if self.mode=='parent_partial':value['nextLink']=azure.ARM+path+'?api-version=2023-07-01&page=2'
            elif path.casefold()==(SCOPE+'/resources').casefold():
                assert q=={'api-version':['2021-04-01'],'$top':['1000']};value={'value':[self.hsm]}
            elif path.casefold() in {(SCOPE+'/providers/'+ep).casefold() for ep,version in azure.ENDPOINTS.values()} or path.casefold()==(SCOPE+'/resourcegroups').casefold():
                versions={version for ep,version in azure.ENDPOINTS.values()if (SCOPE+'/providers/'+ep).casefold()==path.casefold()}
                if path.casefold()==(SCOPE+'/resourcegroups').casefold():versions.add('2021-04-01')
                assert q['api-version'][0]in versions;value={'value':[]}
            elif path.casefold()==(SCOPE+'/providers/Microsoft.Insights/diagnosticSettings').casefold():
                assert q['api-version']==['2021-05-01-preview'];value={'value':[]}
            else:
                assert path.casefold()==(HSM+'/providers/Microsoft.Insights/diagnosticSettings').casefold()
                assert q['api-version']==['2021-05-01-preview']
                if self.mode=='diag_denied'or 'page'in q:deny()
                values=[]if self.mode=='diag_empty'else[deepcopy(self.setting)]
                if self.mode in ('identical_repeat','conflicting_repeat'):
                    extra=deepcopy(self.setting)
                    if self.mode=='conflicting_repeat':extra['properties']['logs'][0]['enabled']=False
                    values.append(extra)
                value={'value':values}
                if self.mode=='diag_partial':value['nextLink']=azure.ARM+path+'?api-version=2021-05-01-preview&page=2'
        return io.BytesIO(json.dumps(value).encode())


@pytest.fixture(autouse=True)
def offline_temporary_registry(monkeypatch):
    def blocked(*a,**kw):raise AssertionError('Network/DNS/auth forbidden')
    for obj,names in ((socket,('create_connection','getaddrinfo')),(socket.socket,('connect','connect_ex')),(azure,('credential_for',))):
        for name in names:monkeypatch.setattr(obj,name,blocked)
    before=list(checks.CHECKS)
    if not any(c.id==CHECK for c in before):
        review.install(checks.register)
    try:yield
    finally:checks.CHECKS[:]=before


def capture(monkeypatch,mode='good',reuse_diagnostics=False):
    http=NativeHTTP(mode);monkeypatch.setattr(azure,'build_opener',lambda *a:http)
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture-inert'},'options':{'concurrency':1,'retries':0}}
    required=plan_collection({'connector':connector,'checks':[CHECK]})
    assert required==['managed_hsm']
    snapshot=azure.collect(connector,required+(['diagnostic_setting']if reuse_diagnostics else []))
    findings=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings']
    assert not http.unexpected,http.unexpected
    assert all('Microsoft.Storage/storageAccounts/'not in c['path']and '/logs'not in c['path'] for c in http.calls)
    return findings,snapshot,http


NATIVE_BRANCHES=(('good','PASS'),('no_storage','FAIL'),('disabled','FAIL'),('other_category','FAIL'),
 ('allLogs','UNKNOWN'),('audit_group','UNKNOWN'),('malformed_enabled','UNKNOWN'),('missing_enabled','UNKNOWN'),
 ('no_selector','UNKNOWN'),('both_selectors','UNKNOWN'),('malformed_storage','UNKNOWN'),('wrong_storage_provider','UNKNOWN'),
 ('cross_subscription_storage','PASS'),('malformed_logs','UNKNOWN'),('missing_logs','UNKNOWN'),('foreign_parent','UNKNOWN'),
 ('wrong_hsm_type','UNKNOWN'),('wrong_diag_type','UNKNOWN'),('foreign_diag','UNKNOWN'),('wrong_diag_route','UNKNOWN'),
 ('uppercase_identity','PASS'),('denied','DENIED'),('empty','EMPTY'),('diag_denied','UNKNOWN'),('diag_empty','FAIL'),
 ('parent_partial','UNKNOWN'),('diag_partial','UNKNOWN'),('identical_repeat','PASS'),('conflicting_repeat','UNKNOWN'))

@pytest.mark.parametrize('mode,want',NATIVE_BRANCHES)
def test_native_hsm_declaration(monkeypatch,mode,want,record_property):
    findings,snapshot,http=capture(monkeypatch,mode)
    actual={f['status']for f in findings}
    record_property('check_id',CHECK);record_property('mode',mode);record_property('actual',','.join(sorted(actual)));record_property('expected',want)
    assert actual=={want},findings

@pytest.mark.parametrize('field',('source_operation','read_only','api_version','scope','request_path','credential_context_id','customer_context_id'))
def test_missing_native_child_provenance_is_unresolved(monkeypatch,field):
    findings,snapshot,http=capture(monkeypatch)
    collections=deepcopy(snapshot['collections'])
    item=next(c['items'][0]for c in collections if c['type']=='managed_hsm')
    item['diagnosticSettings'][0]['_provenance'].pop(field,None)
    changed=make_snapshot('azure',snapshot['scopes'],collections,metadata=snapshot['metadata'],created_at=snapshot['created_at'])
    findings=evaluate_snapshot(changed,checks=[CHECK],include_not_applicable=True)['findings']
    assert {f['status']for f in findings}=={'UNKNOWN'}


def test_reuses_actual_native_diagnostic_collection(monkeypatch):
    findings,snapshot,http=capture(monkeypatch,reuse_diagnostics=True)
    assert {f['status']for f in findings}=={'PASS'},findings
    assert sum(c['path'].casefold()==(HSM+'/providers/Microsoft.Insights/diagnosticSettings').casefold()for c in http.calls)==1


def test_ordinary_import_never_registers_an_additional_id():
    assert sum(c.id==CHECK for c in checks.CHECKS)==1
    assert review.DECLARATIONS[0]['finding_type']=='logging'
    assert review.DECLARATIONS[0]['requirements']==[]


def test_supported_log_analytics_only_is_currently_storage_specific_failure(monkeypatch,record_property):
    """Preserve scope-decision witness: this is supported HSM logging, no Storage declaration."""
    findings,snapshot,http=capture(monkeypatch,'workspace_only')
    record_property('check_id',CHECK);record_property('mode','workspace_only')
    record_property('source','https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/logging')
    assert {f['status']for f in findings}=={'FAIL'},findings


def test_archived_hsm_is_still_rejected_by_product_planning():
    from peaso import engine
    from peaso.checks import native_only
    assert CHECK in native_only.exclusions()
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.plan_collection({'connector':{'provider':'azure','scopes':[SUB]},'checks':[CHECK]})
    assert CHECK in native_only.exclusions()

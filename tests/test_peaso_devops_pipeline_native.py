"""Directed private native DevOps metadata contracts; no network or pipeline runs."""
import copy
import io
import json
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso.collectors import azure_devops_pipeline_native as native
PROJECT = '11111111-1111-1111-1111-111111111111'
REPO = '22222222-2222-2222-2222-222222222222'
SECRET = 'DO-NOT-PERSIST-actual-sensitive-value'
TOKEN = 'DO-NOT-PERSIST-credential'


def definition():
    return {'id': 1, 'revision': 3, 'project': {'id': PROJECT},
            'repository': {'id': REPO, 'type': 'TfsGit'}, 'process': {'type': 2},
            'variables': {'AZURE_CLIENT_SECRET': {'value': SECRET, 'isSecret': True}},
            'variableGroups': [7], 'authorization': SECRET, 'url': 'https://user:'+SECRET+'@evil.invalid'}


def test_definition_projection_retains_only_metadata_and_never_mutates():
    raw = definition(); before = copy.deepcopy(raw)
    result = native.project(raw, 'definition', PROJECT, 1)
    assert result['variables'] == [{'name':'AZURE_CLIENT_SECRET','source':'pipeline','scopeId':'1','isSecret':True}]
    assert SECRET not in json.dumps(result) and raw == before
    assert 'url' not in result and 'authorization' not in result


@pytest.mark.parametrize('change', ['wrong-project', 'wrong-id', 'bool-id', 'bool-revision', 'missing-repository', 'foreign-repository', 'duplicate-groups'])
def test_definition_identity_and_revision_fail_closed(change):
    raw = definition()
    if change == 'wrong-project':raw['project']['id'] = REPO
    if change == 'wrong-id':raw['id'] = 2
    if change == 'bool-id':raw['id'] = True
    if change == 'bool-revision':raw['revision'] = True
    if change == 'missing-repository':raw.pop('repository')
    if change == 'foreign-repository':raw['repository']['type'] = 'GitHub'
    if change == 'duplicate-groups':raw['variableGroups'] = [7,7]
    with pytest.raises(ValueError):native.project(raw, 'definition', PROJECT, 1)


@pytest.mark.parametrize('flag', [None, 'true', 1, [], {}])
def test_ambiguous_secret_flag_is_unresolved_not_invented_false(flag):
    result = native.variables({'AZURE_CLIENT_SECRET':{'value':SECRET,'isSecret':flag}},'pipeline','1')
    assert 'isSecret' not in result[0] and SECRET not in json.dumps(result)


def test_groups_drop_every_value_and_provider_credential():
    raw = {'id':7,'name':'group','type':'AzureKeyVault','providerData':{'credentials':SECRET},
           'variables':{'AZURE_CLIENT_SECRET':{'value':SECRET,'isSecret':True}}}
    result = native.project(raw, 'group', PROJECT)
    assert result['variables'][0]['source'] == 'keyVault'
    assert SECRET not in json.dumps(result) and 'providerData' not in result


def test_preview_only_keeps_literal_variable_metadata():
    text = 'variables:\n  AZURE_CLIENT_SECRET: '+SECRET+'\nsteps:\n- script: echo '+SECRET+'\n'
    result = native.expanded_yaml(text, '1')
    assert result['variables'] == [{'name':'AZURE_CLIENT_SECRET','source':'yamlLiteral','scopeId':'1','isSecret':False}]
    assert SECRET not in json.dumps(result) and result['templates_resolved']


@pytest.mark.parametrize('text', [
 'variables:\n  AZURE_CLIENT_SECRET: $(secret)\n',
 'variables:\n- template: vars.yml\n',
 'variables:\n- group: ${{ parameters.group }}\n',
 'resources:\n  repositories:\n  - repository: foreign\nvariables: {}\n'])
def test_dynamic_or_external_template_variables_cannot_prove_complete(text):
    assert native.expanded_yaml(text, '1')['templates_resolved'] is False


@pytest.mark.parametrize('text', [
 'variables:\n  A: x\n  A: y\n',
 'variables: &x {A: secret}\nother: *x\n',
 'variables: !!python/object:module {}\n',
 '- not-a-pipeline\n'])
def test_yaml_ambiguous_or_executable_graph_rejected(text):
    with pytest.raises(ValueError):native.expanded_yaml(text, '1')


class Response(io.BytesIO):
    headers = {}
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class Opener:
    def __init__(self, payload):self.payload=payload;self.requests=[]
    def open(self, request, timeout):
        self.requests.append(request)
        return Response(json.dumps(self.payload).encode())


def api(payload):
    opener = Opener(payload)
    return native.MetadataAPI('owned',{'server':'https://dev.azure.com/owned','method':'pat','token':TOKEN},opener),opener


def test_only_dedicated_preview_POST_is_permitted_and_pinned():
    client, opener = api({'finalYaml':'variables: {}'})
    client.call(PROJECT,'preview',pipeline_id=1,revision=3,commit='a'*40)
    req, = opener.requests;url=urlsplit(req.full_url)
    assert req.method == 'POST' and url.netloc=='dev.azure.com' and url.path.endswith('/pipelines/1/preview')
    assert parse_qs(url.query)=={'api-version':['7.1'],'pipelineVersion':['3']}
    assert json.loads(req.data)=={'previewRun':True,'resources':{'repositories':{'self':{'version':'a'*40}}}}
    assert '/runs' not in req.full_url
    with pytest.raises(ValueError):client.call(PROJECT,'runs',pipeline_id=1)


@pytest.mark.parametrize('commit',[None,'main','a'*39,'a'*41,'a'*39+'g'])
def test_no_preview_without_immutable_commit(commit):
    client,opener=api({})
    with pytest.raises(ValueError):client.call(PROJECT,'preview',pipeline_id=1,revision=3,commit=commit)
    assert not opener.requests


def test_successful_build_metadata_does_not_claim_security_process_or_review():
    result=native.project({'id':1,'definition':{'id':1},'status':'completed','result':'succeeded',
                           'parameters':SECRET,'logs':SECRET},'build',PROJECT,1)
    assert SECRET not in json.dumps(result) and 'securityTestingEvidence' not in result
    assert not {'process','reviews','category','noAdverseSecurityEffect'} & result.keys()

SUB = '/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT = '44444444-4444-4444-4444-444444444444'


def captured_snapshot(secret=True, yaml='variables: {}', unrelated=False, public=False, *,
                      group_rows=None, definition_group_ids=None):
    from types import SimpleNamespace
    from peaso.collectors.azure import _Reader
    from peaso.snapshot import make_snapshot
    options = {'compliance_parameters': {
        'azure_devops_git': {'subscriptions': [{'scope':SUB,'organization':'owned','project_ids':[PROJECT]}]},
        'azure_devops_pipelines': {'credentialVariableNames':['AZURE_CLIENT_SECRET'],
            'requiredVariableNames':['AZURE_CLIENT_SECRET'],
            'pipelines':[{'project_id':PROJECT,'pipeline_id':1,'definition_revision':3,'commit':'a'*40}]}}}
    class InertAPI:
        def __init__(self,*args):pass
        def call(self, project_id, operation, **kwargs):
            assert project_id == PROJECT
            if operation == 'definition':
                raw=definition();raw['variables']['AZURE_CLIENT_SECRET']['isSecret']=secret
                if definition_group_ids is not None:raw['variableGroups']=definition_group_ids
                return native.project(raw, operation, project_id, 1)
            assert operation == 'preview'
            return native.project({'finalYaml':yaml},operation,project_id,1)
        def pages(self, project_id, operation, **kwargs):
            assert operation == 'groups'
            groups=copy.deepcopy(group_rows) if group_rows is not None else [{'id':7,'name':'used','type':'Vsts','variables':{}}]
            if unrelated:groups.append({'id':8,'name':'unused','type':'Vsts','variables':{
                'AZURE_CLIENT_SECRET':{'isSecret':False,'value':SECRET}}})
            return [native.project(g,'group',project_id) for g in groups]
    reader=_Reader({'concurrency':1,'retries':0})
    def arm_request(url):
        assert url.startswith('https://management.azure.com'+SUB+'?')
        return {'id':SUB,'tenantId':TENANT}
    if public:
        from unittest.mock import patch
        from peaso.collectors.azure import collect
        class Transport:
            verified_tenant=TENANT
            def request(self,url,**kwargs):return arm_request(url)
        with patch.object(native,'MetadataAPI',InertAPI):
            return collect({'scopes':[SUB],'options':options,'auth':{
                'devops_credentials':[{'server':'https://dev.azure.com/owned','method':'pat','token':TOKEN}]}},
                requirements=[native.KIND],transport=Transport())
    native.collect(reader,arm_request,SimpleNamespace(verified_tenant=TENANT),[SUB],{native.KIND},options,
        {'devops_credentials':[{'server':'https://dev.azure.com/owned','method':'pat','token':TOKEN}]},api_factory=InertAPI)
    assert reader.collections[0]['status']=='collected',reader.collections
    snapshot=make_snapshot('azure',[SUB,'/devops/owned'],reader.collections,
        created_at='2026-10-15T20:00:00Z',metadata={
            'native_devops_pipeline_capture':reader.native_devops_pipeline_capture,
            'sw14Policy':reader.native_devops_pipeline_policy})
    return native.bind_snapshot(snapshot)


def status(snapshot,check=native.SECRET_CHECK):
    from tests.archived_check_contract import evaluate_snapshot
    report=evaluate_snapshot(snapshot,checks=[check])
    assert SECRET not in json.dumps(snapshot) and TOKEN not in json.dumps(snapshot)
    assert SECRET not in json.dumps(report) and TOKEN not in json.dumps(report)
    return [f['status'] for f in report['findings']]


def test_actual_sealed_collect_evaluate_plaintext_fails():
    assert status(captured_snapshot(secret=False)) == ['FAIL']


def test_actual_sealed_clean_and_security_history_remain_unknown():
    snapshot=captured_snapshot()
    assert status(snapshot)==['UNKNOWN']
    assert status(snapshot,native.TEST_CHECK)==['UNKNOWN']


def test_actual_preview_plaintext_fails_without_retaining_value():
    assert status(captured_snapshot(yaml='variables:\n  AZURE_CLIENT_SECRET: '+SECRET))==['FAIL']


def test_unassociated_group_does_not_invent_pipeline_plaintext():
    assert status(captured_snapshot(unrelated=True))==['UNKNOWN']


@pytest.mark.parametrize('mutation',['scope','capture','clock','payload','resource','project','coverage'])
def test_native_binding_rejects_resealed_wrong_or_mutated_evidence(mutation):
    from peaso.snapshot import seal
    snapshot=captured_snapshot(secret=False)
    item=snapshot['collections'][0]['items'][0];evidence=item['expandedVariables'];proof=evidence['_provenance']
    if mutation=='scope':proof['scope']='/devops/foreign'
    if mutation=='capture':proof['capture_id']='55555555-5555-5555-5555-555555555555'
    if mutation=='clock':proof['captured_at']='2026-10-14T20:00:00Z'
    if mutation=='payload':evidence['variables'][0]['name']='PASSWORD'
    if mutation=='resource':proof['resource_id']=PROJECT+'/pipelines/2'
    if mutation=='project':item['projectId']=REPO
    if mutation=='coverage':
        evidence['coverage']['projects']='complete'
        proof['payload_sha256']=native.digest({k:v for k,v in evidence.items() if k!='_provenance'})
    assert status(seal(snapshot))==['UNKNOWN']


def test_yaml_task_inputs_cannot_be_mistaken_for_pipeline_variables():
    assert native.expanded_yaml('steps:\n- task: Example@1\n  inputs:\n    variables:\n      AZURE_CLIENT_SECRET: '+SECRET,'1')['variables']==[]

@pytest.mark.parametrize('mutation',['revision','invalid-project','capture-shape','pins-shape'])
def test_native_identity_rejects_unbound_revision_and_malformed_capture(mutation):
    from peaso.snapshot import seal
    snapshot=captured_snapshot(secret=False);item=snapshot['collections'][0]['items'][0]
    capture=snapshot['metadata']['native_devops_pipeline_capture'];evidence=item['expandedVariables']
    if mutation=='revision':
        item['revision']=evidence['revision']='definition:8/git:'+'b'*40
        evidence['_provenance']['payload_sha256']=native.digest({k:v for k,v in evidence.items()if k!='_provenance'})
    if mutation=='invalid-project':item['projectId']='not-a-uuid'
    if mutation=='capture-shape':snapshot['metadata']['native_devops_pipeline_capture']=[]
    if mutation=='pins-shape':capture['revision_pins']=[]
    assert status(seal(snapshot))==['UNKNOWN']


@pytest.mark.parametrize('count',[True,None,'0',2,-1])
def test_group_page_count_cannot_hide_or_invent_rows(count):
    client,opener=api({'count':count,'value':[]})
    with pytest.raises(ValueError):client.pages(PROJECT,'groups')


def test_duplicate_native_group_ids_rejected_across_pages():
    raw={'id':7,'name':'used','type':'Vsts','variables':{}}
    client,opener=api({'count':2,'value':[raw,raw]})
    with pytest.raises(ValueError):client.pages(PROJECT,'groups')


def test_public_azure_dispatch_collects_seals_and_evaluates_native_plaintext():
    snapshot=captured_snapshot(secret=False,public=True)
    assert '/devops/owned' in snapshot['scopes']
    assert status(snapshot)==['FAIL']


def test_native_list_pages_honor_shared_call_budget_hook():
    from peaso.collectors.azure import _Reader, AzureReadError
    client,opener=api({'count':0,'value':[]})
    reader=_Reader({'max_calls':1,'retries':0})
    invoke=lambda *a,**kw:reader.call(client.call,*a,**kw)
    assert client.pages(PROJECT,'groups',invoke=invoke)==[]
    with pytest.raises(AzureReadError):client.pages(PROJECT,'groups',invoke=invoke)
    assert len(opener.requests)==1

@pytest.mark.parametrize('mutation',[
    'foreign-group','duplicate-group','traversal-group','zero-group','bool-source-group',
    'foreign-variable-scope','wrong-variable-source','foreign-native-project',
    'native-revision','native-group-scope','native-source-digest','extra-native-value'])
def test_v2_native_source_joins_reject_resealed_foreign_or_ambiguous_facts(mutation):
    from peaso.snapshot import seal
    snapshot=captured_snapshot(secret=False);item=snapshot['collections'][0]['items'][0]
    evidence=item['expandedVariables'];proof=evidence['_provenance'];sources=proof['native_metadata']
    group=PROJECT+'/variableGroups/7'
    if mutation=='foreign-group':
        foreign=REPO+'/variableGroups/7';evidence['variableGroupIds']=[foreign]
        evidence['variables'][0].update(source='variableGroup',scopeId=foreign)
    if mutation=='duplicate-group':evidence['variableGroupIds']=[group,group]
    if mutation=='traversal-group':evidence['variableGroupIds']=[PROJECT+'/variableGroups/../7']
    if mutation=='zero-group':evidence['variableGroupIds']=[PROJECT+'/variableGroups/0']
    if mutation=='bool-source-group':sources['group_metadata'][0]['id']=True
    if mutation=='foreign-variable-scope':evidence['variables'][0]['scopeId']=REPO+'/pipelines/1'
    if mutation=='wrong-variable-source':evidence['variables'][0]['source']='yamlInline'
    if mutation=='foreign-native-project':sources['definition']['projectId']=REPO
    if mutation=='native-revision':sources['definition']['revision']=4
    if mutation=='native-group-scope':
        sources['group_metadata'][0]['variables']=[{'name':'AZURE_CLIENT_SECRET','source':'variableGroup','scopeId':'8','isSecret':False}]
    if mutation=='extra-native-value':sources['definition']['variables'][0]['value']='inert-value-not-native-metadata'
    # Recompute the caller-controlled hashes: source joins must still reject.
    proof['redacted_source_metadata_sha256']={k:native.digest(v)for k,v in sources.items()}
    if mutation=='native-source-digest':proof['redacted_source_metadata_sha256']['definition']='0'*64
    proof['payload_sha256']=native.digest({k:v for k,v in evidence.items()if k!='_provenance'})
    assert status(seal(snapshot))==['UNKNOWN']


@pytest.mark.parametrize('plain,yaml',[(True,'variables: {}'),(False,'variables: {}'),
    (False,'variables:\n  AZURE_CLIENT_SECRET: inert-literal')])
def test_v2_new_metadata_joins_allow_real_collector_facts_but_never_clean_pass(plain,yaml):
    snapshot=captured_snapshot(secret=not plain,yaml=yaml,public=True)
    assert status(snapshot)==(['FAIL']if plain or 'inert-literal'in yaml else['UNKNOWN'])
    assert status(snapshot,native.TEST_CHECK)==['UNKNOWN']


def v28_group(name, secret=False, gid=7):
    return {'id':gid,'name':name,'type':'Vsts','variables':{
        'AZURE_CLIENT_SECRET':{'value':SECRET,'isSecret':secret}}}


def v28_group_snapshot(name, *, reference=None, secret=False, extra=()):
    # No definition ID shortcut: the group must join through literal YAML name.
    return captured_snapshot(public=True, definition_group_ids=[],
        yaml='variables:\n- group: '+json.dumps(name if reference is None else reference,ensure_ascii=False),
        group_rows=[v28_group(name,secret),*extra])


@pytest.mark.parametrize('name',['Release secrets', '1 Production / Europe', 'Équipe 東京 🔒',
                                 ' leading and trailing ', 'used'])
def test_v28_group_display_name_actual_public_collect_seal_evaluate(name):
    snapshot=v28_group_snapshot(name)
    item=snapshot['collections'][0]['items'][0]; evidence=item['expandedVariables']
    sources=evidence['_provenance']['native_metadata']
    assert sources['group_metadata'][0]['name']==name
    assert sources['expanded_variable_metadata']['group_names']==[name]
    assert sources['definition']['group_ids']==[]
    assert evidence['variableGroupIds']==[PROJECT+'/variableGroups/7']
    assert evidence['coverage']['variables']=='complete'
    assert status(snapshot)==['FAIL']
    assert status(snapshot,native.TEST_CHECK)==['UNKNOWN']


def test_v28_group_clean_display_name_stays_unknown_not_pass():
    snapshot=v28_group_snapshot('Release secrets',secret=True)
    assert snapshot['collections'][0]['items'][0]['expandedVariables']['coverage']['variables']=='complete'
    assert status(snapshot)==['UNKNOWN']


@pytest.mark.parametrize('name',[None,True,7,[],{},'', 'x\nline','x\x00nul','x\x85next',
                                 'x\u202edirection','x\ud800surrogate','x'*1025,'é'*513])
def test_v28_group_display_name_rejects_malformed_at_transport_yaml_and_proof(name):
    with pytest.raises(ValueError):native.project(v28_group(name),'group',PROJECT)
    projected=native.expanded_yaml('variables:\n- group: '+json.dumps(name),'1')
    assert projected['group_names']==[] and projected['templates_resolved'] is False
    snapshot=captured_snapshot(); item=snapshot['collections'][0]['items'][0]
    sources=item['expandedVariables']['_provenance']['native_metadata']
    for target in ('group_metadata','expanded_variable_metadata'):
        modified=copy.deepcopy(sources)
        if target=='group_metadata':modified[target][0]['name']=name
        else:modified[target]['group_names']=[name]
        with pytest.raises(ValueError):
            native.joined_native_variables(modified,PROJECT,item['id'],item['revision'])


@pytest.mark.parametrize('name',['x'*1024,'é'*512])
def test_v28_group_display_name_local_budget_boundary_preserves_identity(name):
    assert native.project(v28_group(name),'group',PROJECT)['name']==name
    assert native.expanded_yaml('variables:\n- group: '+json.dumps(name),'1')['group_names']==[name]


@pytest.mark.parametrize('expression',['$(group)', '$[ variables.group ]', '${{ parameters.group }}'])
def test_v28_group_dynamic_yaml_never_joins_literal_metadata_or_native_proof(expression):
    snapshot=v28_group_snapshot(expression)
    item=snapshot['collections'][0]['items'][0];evidence=item['expandedVariables']
    assert evidence['variableGroupIds']==[]
    assert evidence['coverage']['variables']=='partial'
    assert status(snapshot)==['UNKNOWN']
    sources=copy.deepcopy(evidence['_provenance']['native_metadata'])
    sources['expanded_variable_metadata']['group_names']=[expression]
    with pytest.raises(ValueError):
        native.joined_native_variables(sources,PROJECT,item['id'],item['revision'])


@pytest.mark.parametrize('reference',['release secrets','Release secrets ','Releasé secrets'])
def test_v28_group_display_identity_no_casefold_trim_or_fuzzy_join(reference):
    snapshot=v28_group_snapshot('Release secrets',reference=reference)
    evidence=snapshot['collections'][0]['items'][0]['expandedVariables']
    assert evidence['variableGroupIds']==[] and evidence['coverage']['variables']=='partial'
    assert status(snapshot)==['UNKNOWN']


def test_v28_group_duplicate_display_name_native_proof_still_ambiguous():
    snapshot=v28_group_snapshot('Release secrets')
    item=snapshot['collections'][0]['items'][0]
    sources=copy.deepcopy(item['expandedVariables']['_provenance']['native_metadata'])
    duplicate=copy.deepcopy(sources['group_metadata'][0]);duplicate['id']=8
    duplicate['variables'][0]['scopeId']='8'
    sources['group_metadata'].append(duplicate)
    with pytest.raises(ValueError,match='ambiguous'):
        native.joined_native_variables(sources,PROJECT,item['id'],item['revision'])


@pytest.mark.parametrize('mutation',['foreign-project','foreign-group-scope','foreign-fact-scope'])
def test_v28_group_display_name_resealed_native_identity_joins_stay_strict(mutation):
    from peaso.snapshot import seal
    snapshot=v28_group_snapshot('Équipe 東京')
    item=snapshot['collections'][0]['items'][0];evidence=item['expandedVariables']
    proof=evidence['_provenance'];sources=proof['native_metadata']
    if mutation=='foreign-project':sources['definition']['projectId']=REPO
    if mutation=='foreign-group-scope':sources['group_metadata'][0]['variables'][0]['scopeId']='8'
    if mutation=='foreign-fact-scope':evidence['variables'][-1]['scopeId']=REPO+'/variableGroups/7'
    proof['redacted_source_metadata_sha256']={k:native.digest(v)for k,v in sources.items()}
    proof['payload_sha256']=native.digest({k:v for k,v in evidence.items()if k!='_provenance'})
    assert status(seal(snapshot))==['UNKNOWN']


@pytest.mark.parametrize('name',['Release secrets','1Production','Équipe'])
def test_v28_group_display_fix_does_not_broaden_variable_key_type(name):
    with pytest.raises(ValueError):native.variables({name:{'isSecret':False}},'pipeline','1')
    with pytest.raises(ValueError):native.expanded_yaml('variables:\n  '+name+': inert','1')

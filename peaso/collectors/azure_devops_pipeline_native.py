"""Bounded DevOps configuration metadata. Never queue a run or retain values.

Accessible API pagination does not prove the authorization universe. Native
plaintext counterexamples may be useful; clean coverage and historical security
process claims stay unresolved unless separately authoritative evidence exists.
"""
from __future__ import annotations
import base64
import copy
import json
import re
import threading
import time
import uuid
import unicodedata
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler
from .azure_devops_git_native import _NoRedirect, _object
from peaso.azure_devops_git_policy import normalize as git_applicability, ORG, UUID

KIND = 'devops_pipeline'
NATIVE_TYPES = {KIND}
SECRET_CHECK = 'azure_devops_project_3_5_1_7_dc58423'
TEST_CHECK = 'azure.other.devops_security_test_evidence'
MAX_BODY = 2_000_000
MAX_TOTAL = 16_000_000
MAX_CALLS = 256
MAX_PAGES = 20
MAX_ROWS = 1000
MAX_SECONDS = 120
SHA = r'[0-9a-f]{40}'
NAME = r'[A-Za-z_][A-Za-z0-9_.-]{0,127}'
# Collector-local UTF-8 budget, not an Azure DevOps service naming limit.
MAX_GROUP_NAME_BYTES = 1024


def group_name(value):
    """Display identity, not a variable key; preserve bytes, spaces and case.

    YAML/REST specify a string, not NAME's variable-identifier grammar. Reject
    control/format/surrogate codepoints locally; never normalize an identity.
    """
    return (isinstance(value, str) and 0 < len(value) <= MAX_GROUP_NAME_BYTES
            and not any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in value)
            and len(value.encode('utf-8')) <= MAX_GROUP_NAME_BYTES)


def group_reference(value):
    """Only literal YAML group references can be joined by exact display name."""
    return group_name(value) and not any(x in value for x in ('$(', '$[', '${{'))


def integer(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        raise ValueError('invalid DevOps numeric identity')
    return value


def variables(raw, source, scope):
    """Whitelist names/typed flags; discard every value without even hashing it."""
    if not isinstance(raw, dict) or len(raw) > MAX_ROWS:
        raise ValueError('invalid variable metadata')
    out = []
    for name, value in raw.items():
        if not isinstance(name, str) or not re.fullmatch(NAME, name) or not isinstance(value, dict):
            raise ValueError('invalid variable identity')
        flag = value.get('isSecret')
        row = {'name': name, 'source': source, 'scopeId': scope}
        # Missing/nullable metadata is unresolved, never silently nonsecret.
        if type(flag) is bool:
            row['isSecret'] = flag
        out.append(row)
    return out


def expanded_yaml(text, scope):
    """Project variables only; aliases/tags/duplicates/dynamic kinds fail closed."""
    import yaml
    if not isinstance(text, str) or len(text.encode()) > 500_000:
        raise ValueError('expanded YAML limit')
    tokens = list(yaml.scan(text))
    if len(tokens) > 32768 or any(isinstance(t, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)) for t in tokens):
        raise ValueError('ambiguous YAML graph')
    class Unique(yaml.SafeLoader):
        pass
    def mapping(loader, node):
        out = {}
        for k, v in node.value:
            key = loader.construct_object(k, deep=True)
            if not isinstance(key, str) or key in out:
                raise ValueError('ambiguous YAML mapping')
            out[key] = loader.construct_object(v, deep=True)
        return out
    Unique.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    document = yaml.load(text, Loader=Unique)
    if not isinstance(document, dict):
        raise ValueError('pipeline YAML object unavailable')
    rows, groups, unresolved = [], [], False
    stack = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop(); nodes += 1
        if depth > 24 or nodes > 8192:
            raise ValueError('pipeline YAML nesting limit')
        if isinstance(value, dict):
            if any(k in value for k in ('template', 'extends')) or any('${{' in k for k in value):
                unresolved = True
            for key, child in value.items():
                if key != 'variables':
                    if key in ('stages', 'jobs') and isinstance(child, (dict, list)):
                        stack.append((child, depth + 1))
                    continue
                entries = [{'name': k, 'value': v} for k, v in child.items()] if isinstance(child, dict) else child
                if not isinstance(entries, list) or len(entries) > MAX_ROWS:
                    raise ValueError('invalid expanded variables')
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError('invalid expanded variable')
                    if set(entry) == {'group'}:
                        name = entry['group']
                        if not group_reference(name):
                            unresolved = True
                        else:
                            groups.append(name)
                        continue
                    if not {'name', 'value'} <= set(entry) or set(entry) - {'name', 'value', 'readonly'}:
                        unresolved = True
                        continue
                    name, literal = entry['name'], entry['value']
                    if not isinstance(name, str) or not re.fullmatch(NAME, name):
                        raise ValueError('invalid expanded variable name')
                    if not isinstance(literal, (str, int, float, bool)) or isinstance(literal, str) and any(x in literal for x in ('$(', '$[', '${{')):
                        unresolved = True
                        continue
                    rows.append({'name': name, 'source': 'yamlLiteral', 'scopeId': scope, 'isSecret': False})
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value if isinstance(child, (dict, list)))
    if len(rows) > MAX_ROWS or len(groups) != len(set(groups)):
        raise ValueError('expanded variable/group limit or duplicates')
    repositories = document.get('resources', {}).get('repositories', []) if isinstance(document.get('resources', {}), dict) else [None]
    if repositories:
        # Preview returns no authoritative resolved revision map for external templates.
        unresolved = True
    return {'variables': rows, 'group_names': groups, 'templates_resolved': not unresolved}


def project(raw, operation, project_id=None, pipeline_id=None):
    """Immediate secret-free projection at the transport boundary."""
    if not isinstance(raw, dict):
        raise ValueError('native DevOps object unavailable')
    if operation == 'definition':
        pid = raw.get('project', {}).get('id') if isinstance(raw.get('project'), dict) else None
        if not isinstance(pid, str) or pid.lower() != project_id or type(raw.get('id')) is not int or raw.get('id') != pipeline_id:
            raise ValueError('foreign definition')
        revision = integer(raw.get('revision'))
        process = raw.get('process'); repository = raw.get('repository')
        if not isinstance(process, dict) or not isinstance(repository, dict):
            raise ValueError('definition source unavailable')
        repo_id = repository.get('id')
        if repository.get('type') != 'TfsGit' or not isinstance(repo_id, str) or not re.fullmatch(UUID, repo_id):
            raise ValueError('unsupported definition repository')
        result = {'id': pipeline_id, 'projectId': project_id, 'revision': revision,
                  'repository_id': repo_id.lower(), 'process_type': process.get('type'),
                  'variables': variables(raw.get('variables', {}), 'pipeline', str(pipeline_id)),
                  'group_ids': []}
        for group in raw.get('variableGroups', []):
            gid = group.get('id') if isinstance(group, dict) else group
            result['group_ids'].append(integer(gid))
        if len(result['group_ids']) != len(set(result['group_ids'])):
            raise ValueError('duplicate definition group')
        return result
    if operation == 'group':
        gid = integer(raw.get('id')); name = raw.get('name'); kind = raw.get('type')
        if not group_name(name) or kind not in ('Vsts', 'AzureKeyVault'):
            raise ValueError('variable group metadata unavailable')
        return {'id': gid, 'name': name, 'type': kind,
                'variables': variables(raw.get('variables'), 'keyVault' if kind == 'AzureKeyVault' else 'variableGroup', str(gid))}
    if operation == 'preview':
        return expanded_yaml(raw.get('finalYaml'), str(pipeline_id))
    if operation == 'build':
        definition = raw.get('definition')
        if not isinstance(definition, dict) or definition.get('id') != pipeline_id:
            raise ValueError('foreign build definition')
        return {k: raw[k] for k in ('id', 'status', 'result', 'sourceVersion', 'startTime', 'finishTime') if k in raw}
    if operation == 'test_run':
        return {k: raw[k] for k in ('id', 'state', 'isAutomated', 'totalTests', 'passedTests', 'unanalyzedTests', 'startedDate', 'completedDate') if k in raw}
    raise ValueError('unsupported DevOps projection')


class MetadataAPI:
    """Fixed-origin GET and dedicated Preview POST only; no run endpoint."""
    def __init__(self, organization, credential, opener=None):
        if not isinstance(organization, str) or not re.fullmatch(ORG, organization):
            raise ValueError('invalid organization')
        if credential.get('server') != 'https://dev.azure.com/' + organization:
            raise ValueError('credential origin mismatch')
        self.organization, self.credential = organization, credential
        self.opener = opener or build_opener(ProxyHandler({}), _NoRedirect())
        self.bytes = self.calls = 0
        self.deadline = time.monotonic() + MAX_SECONDS
        self.lock = threading.Lock()

    def call(self, project_id, operation, *, pipeline_id=None, revision=None, group_id=None, commit=None, continuation=None):
        if not isinstance(project_id, str) or not re.fullmatch(UUID, project_id):
            raise ValueError('invalid project UUID')
        suffix = None; query = {'api-version': '7.1'}; body = None; projection = operation
        if operation in ('definition', 'preview', 'builds'):
            integer(pipeline_id)
        if operation == 'definition':
            suffix = 'build/definitions/' + str(pipeline_id)
            if revision is not None:query['revision'] = str(integer(revision))
        elif operation == 'groups':
            suffix = 'distributedtask/variablegroups'; query['$top'] = '100'; projection = 'group'
        elif operation == 'preview':
            query['pipelineVersion'] = str(integer(revision))
            if not isinstance(commit, str) or not re.fullmatch(SHA, commit):
                raise ValueError('preview requires immutable commit')
            suffix = 'pipelines/' + str(pipeline_id) + '/preview'
            body = json.dumps({'previewRun': True, 'resources': {'repositories': {'self': {'version': commit}}}}).encode()
        elif operation == 'builds':
            suffix = 'build/builds'; query.update(definitions=str(pipeline_id), **{'$top': '100'}); projection = 'build'
        else:
            raise ValueError('unsupported DevOps operation')
        if continuation is not None:
            if operation not in ('groups', 'builds') or not isinstance(continuation, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,256}', continuation):
                raise ValueError('invalid DevOps continuation')
            query['continuationToken'] = continuation
        url = 'https://dev.azure.com/' + self.organization + '/' + project_id + '/_apis/' + suffix + '?' + urlencode(query)
        token = self.credential['token']; method = self.credential['method']
        if method not in ('pat', 'bearer') or not isinstance(token, str) or not token or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
            raise ValueError('invalid DevOps credential')
        auth = 'Bearer ' + token if method == 'bearer' else 'Basic ' + base64.b64encode((':' + token).encode()).decode()
        with self.lock:
            if self.calls >= MAX_CALLS or self.bytes >= MAX_TOTAL or time.monotonic() >= self.deadline:
                raise ValueError('DevOps read budget exhausted')
            self.calls += 1
        request = Request(url, data=body, headers={'Authorization': auth, 'Accept': 'application/json', 'Content-Type': 'application/json'}, method='POST' if body else 'GET')
        try:
            with self.opener.open(request, timeout=max(.01, min(20, self.deadline - time.monotonic()))) as response:
                raw_bytes = response.read(min(MAX_BODY, MAX_TOTAL - self.bytes) + 1)
                self.bytes += len(raw_bytes)
                if len(raw_bytes) > MAX_BODY or self.bytes > MAX_TOTAL:
                    raise ValueError('DevOps byte limit')
                raw = json.loads(raw_bytes, object_pairs_hook=_object)
                token = response.headers.get('x-ms-continuationtoken')
            if operation in ('groups', 'builds'):
                if not isinstance(raw, dict) or type(raw.get('count')) is not int or not isinstance(raw.get('value'), list) or raw['count'] != len(raw['value']) or len(raw['value']) > MAX_ROWS:
                    raise ValueError('DevOps list response malformed')
                if token is not None and (not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,256}', token)):
                    raise ValueError('DevOps continuation malformed')
                return {'items': [project(row, projection, project_id, pipeline_id) for row in raw['value']], 'continuation': token}
            if token is not None:
                raise ValueError('unexpected DevOps continuation')
            return project(raw, projection, project_id, pipeline_id)
        except HTTPError as error:
            status = error.code; error.close()
            from .azure import AzureReadError
            raise AzureReadError('devops_http_error', status) from None

    def pages(self, project_id, operation, *, invoke=None, **kwargs):
        rows, seen, identifiers = [], set(), set(); token = None
        for _ in range(MAX_PAGES):
            page = (invoke or self.call)(project_id, operation, continuation=token, **kwargs)
            for row in page['items']:
                identifier = integer(row.get('id'))
                if identifier in identifiers:raise ValueError('duplicate DevOps native row')
                identifiers.add(identifier); rows.append(row)
                if len(rows) > MAX_ROWS:raise ValueError('DevOps resource limit')
            token = page['continuation']
            if token is None:return rows
            if token in seen:raise ValueError('DevOps continuation loop')
            seen.add(token)
        raise ValueError('DevOps page limit')


def digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def normalize(options, auth=None):
    """Only applicability, version pins and normative names; never observations."""
    bindings = git_applicability(options, auth)
    parent = options.get('compliance_parameters', {})
    if 'azure_devops_pipelines' not in parent:return None
    raw = parent['azure_devops_pipelines']
    if (not isinstance(raw, dict) or set(raw) != {'credentialVariableNames','requiredVariableNames','pipelines'}
            or len(json.dumps(raw, allow_nan=False)) > 50000 or len(bindings) != 1):
        raise ValueError('DevOps pipeline parameters require one explicit subscription binding')
    owner = next(iter(bindings.values()))
    for field in ('credentialVariableNames','requiredVariableNames'):
        values = raw[field]
        if (not isinstance(values,list) or len(values)>256 or any(not isinstance(n,str) or not re.fullmatch(NAME,n) for n in values)
                or len(values)!=len(set(values))):raise ValueError('invalid credential name policy')
    if 'AZURE_CLIENT_SECRET' not in raw['credentialVariableNames'] or not set(raw['requiredVariableNames'])<=set(raw['credentialVariableNames']):
        raise ValueError('incomplete credential name policy')
    pins = raw['pipelines'];seen=set()
    if not isinstance(pins,list) or not 1<=len(pins)<=64:raise ValueError('invalid pipeline pins')
    for pin in pins:
        if not isinstance(pin,dict) or set(pin)!={'project_id','pipeline_id','definition_revision','commit'}:
            raise ValueError('invalid native pipeline pin fields')
        if pin['project_id'] not in owner['project_ids']:raise ValueError('pipeline project outside declared applicability')
        integer(pin['pipeline_id']);integer(pin['definition_revision'])
        if not isinstance(pin['commit'],str)or not re.fullmatch(SHA,pin['commit']):raise ValueError('immutable pipeline commit required')
        key=pin['project_id'],pin['pipeline_id']
        if key in seen:raise ValueError('duplicate pipeline pin')
        seen.add(key)
    return {**copy.deepcopy(owner),**copy.deepcopy(raw)}


def pipeline_key(project_id, pipeline_id):
    return project_id+'/pipelines/'+str(pipeline_id)


def collect(reader, request, transport, scopes, wanted, options, auth, api_factory=None):
    if KIND not in wanted:return
    from .azure import ARM, AzureReadError
    api_factory = api_factory or MetadataAPI
    owner=normalize(options,auth)
    if owner is None:
        for scope in scopes:reader.unavailable(KIND,scope,'AzureDevOps',AzureReadError('devops_owner_pins_missing'))
        return
    scope=owner['scope'];org=owner['organization'];devops_scope='/devops/'+org
    if scope not in {s.lower()for s in scopes}:raise ValueError('DevOps subscription not selected')
    credentials=[c for c in auth.get('devops_credentials',[])if c['server']=='https://dev.azure.com/'+org]
    capture=str(uuid.uuid4());reader.native_devops_pipeline_capture={'capture_id':capture,'scope':devops_scope,
        'owner_subscription':scope,'organization':org,'project_ids':owner['project_ids'],
        'pipeline_ids':[pipeline_key(p['project_id'],p['pipeline_id'])for p in owner['pipelines']],
        'revision_pins':{pipeline_key(p['project_id'],p['pipeline_id']):'definition:'+str(p['definition_revision'])+'/git:'+p['commit']for p in owner['pipelines']}}
    reader.native_devops_pipeline_scopes=[devops_scope]
    reader.native_devops_pipeline_policy={'status':'collected','scope':devops_scope,
        'devopsCredentialPolicy':{k:owner[k]for k in ('credentialVariableNames','requiredVariableNames')}}
    def fetch():
        try:
            if len(credentials)!=1:raise ValueError('explicit DevOps credential unavailable')
            subscription=reader.call(request,ARM+scope+'?api-version=2022-12-01')
            tenant=getattr(transport,'verified_tenant',None)
            if (not isinstance(subscription,dict)or str(subscription.get('id','')).lower()!=scope
                    or not isinstance(tenant,str)or str(subscription.get('tenantId','')).lower()!=tenant.lower()):
                raise ValueError('DevOps owner subscription identity unverified')
            client=api_factory(org,credentials[0]);group_cache={}
            for pin in owner['pipelines']:
                reader.check_cancelled();project_id=pin['project_id'];pid=pin['pipeline_id'];rid=pipeline_key(project_id,pid)
                definition=reader.call(client.call,project_id,'definition',pipeline_id=pid,revision=pin['definition_revision'])
                if definition['revision']!=pin['definition_revision']:raise ValueError('native definition revision differs')
                if project_id not in group_cache:
                    group_cache[project_id]=client.pages(project_id,'groups',invoke=lambda *a,**kw:reader.call(client.call,*a,**kw))
                groups=group_cache[project_id];by_name={g['name']:g for g in groups}
                if len(by_name)!=len(groups):raise ValueError('ambiguous variable group names')
                preview={'variables':[],'group_names':[],'templates_resolved':False}
                if definition['process_type']==2:
                    preview=reader.call(client.call,project_id,'preview',pipeline_id=pid,revision=pin['definition_revision'],commit=pin['commit'])
                current=reader.call(client.call,project_id,'definition',pipeline_id=pid,revision=None)
                if current!=definition:raise ValueError('definition changed during capture')
                rows=copy.deepcopy(definition['variables'])+copy.deepcopy(preview['variables'])
                for row in rows:row['scopeId']=rid
                # Only associated groups belong to this pipeline; unrelated project groups
                # must never create a plaintext finding for this resource.
                associated = set(definition['group_ids']) | {by_name[n]['id'] for n in preview['group_names'] if n in by_name}
                group_ids=[]
                for group in groups:
                    if group['id'] not in associated:continue
                    gid=project_id+'/variableGroups/'+str(group['id']);group_ids.append(gid)
                    for value in group['variables']:
                        value=copy.deepcopy(value);value['scopeId']=gid;rows.append(value)
                unresolved=(not set(definition['group_ids'])<={g['id']for g in groups}
                            or not set(preview['group_names'])<=set(by_name)
                            or not preview['templates_resolved'])
                revision='definition:'+str(definition['revision'])+'/git:'+pin['commit']
                evidence={'status':'collected','revision':revision,'variableGroupIds':group_ids,'variables':rows,
                    'coverage':{'projects':'partial','pipelines':'partial','variableGroups':'partial',
                                'templates':'partial'if unresolved else'complete','variables':'partial'if unresolved else'complete'}}
                # This is a metadata digest, NEVER a hash of raw YAML or variable values.
                sources={'definition':digest(definition),'group_metadata':digest(groups),'expanded_variable_metadata':digest(preview)}
                evidence['_provenance']={'native_devops_schema':1,'authority':'AzureDevOps-native-metadata',
                    'read_only':True,'capture_id':capture,'resource_id':rid,'scope':devops_scope,
                    'redacted_source_metadata_sha256':sources,'payload_sha256':digest(evidence),
                    'native_metadata':{'definition':definition,'group_metadata':groups,'expanded_variable_metadata':preview}}
                item={'id':rid,'organization':org,'projectId':project_id,'revision':revision,
                    'expandedVariables':evidence,'securityTestingEvidence':{'status':'unknown',
                    'reason':'security_process_classification_change_deployment_and_review_history_not_authoritatively_joined'},
                    '_provenance':{'source_operation':'BuildDefinitions_Get+VariableGroups_List+Pipelines_Preview',
                    'read_only':True,'api_version':'7.1','owner_subscription':scope}}
                yield [item]
        except Exception:
            # Do not leak a provider parser error or a response body into snapshots.
            raise AzureReadError('native_devops_pipeline_metadata_unresolved')from None
    reader.run([(KIND,devops_scope,'AzureDevOps',fetch)])


def bind_snapshot(snapshot):
    """Bind a capture clock before resealing; no self-referential content hash."""
    from peaso.snapshot import seal,validate
    for collection in snapshot['collections']:
        if collection['type']!=KIND:continue
        for item in collection['items']:
            proof=item.get('expandedVariables',{}).get('_provenance',{})
            if proof.get('native_devops_schema')==1:proof['captured_at']=snapshot['created_at']
    return validate(seal(snapshot))



def joined_native_variables(metadata, project_id, resource_id, revision):
    """Validate typed redacted source identities and rebuild only associated facts."""
    if not isinstance(metadata,dict)or set(metadata)!={'definition','group_metadata','expanded_variable_metadata'}:
        raise ValueError('native source metadata unavailable')
    definition=metadata['definition'];groups=metadata['group_metadata'];preview=metadata['expanded_variable_metadata']
    if (not isinstance(definition,dict)or set(definition)!={'id','projectId','revision','repository_id','process_type','variables','group_ids'}
            or definition['projectId']!=project_id or pipeline_key(project_id,integer(definition['id']))!=resource_id
            or not revision.startswith('definition:'+str(integer(definition['revision']))+'/git:')
            or not re.fullmatch('definition:[1-9][0-9]*/git:'+SHA,revision)
            or not isinstance(definition['repository_id'],str)or not re.fullmatch(UUID,definition['repository_id'])
            or type(definition['process_type'])is not int or definition['process_type']not in (1,2)):
        raise ValueError('native definition binding unavailable')
    if (not isinstance(groups,list)or len(groups)>MAX_ROWS or not isinstance(preview,dict)
            or set(preview)!={'variables','group_names','templates_resolved'}or type(preview['templates_resolved'])is not bool
            or not isinstance(preview['group_names'],list)or len(preview['group_names'])>MAX_ROWS
            or any(not group_reference(n)for n in preview['group_names'])
            or len(set(preview['group_names']))!=len(preview['group_names'])):
        raise ValueError('native expansion metadata unavailable')
    refs=definition['group_ids']
    if not isinstance(refs,list)or len(refs)>MAX_ROWS:raise ValueError('native group references unavailable')
    if any(type(g)is not int or not 1<=g<=2147483647 for g in refs)or len(set(refs))!=len(refs):
        raise ValueError('native group references ambiguous')
    def rows(values,source,old_scope,new_scope):
        if not isinstance(values,list)or len(values)>MAX_ROWS:raise ValueError('native variables unavailable')
        out=[]
        for row in values:
            if (not isinstance(row,dict)or not {'name','source','scopeId'}<=set(row)
                    or set(row)-{'name','source','scopeId','isSecret'}or not isinstance(row['name'],str)
                    or not re.fullmatch(NAME,row['name'])or row['source']!=source or row['scopeId']!=old_scope
                    or 'isSecret'in row and type(row['isSecret'])is not bool
                    or source=='yamlLiteral'and row.get('isSecret')is not False):
                raise ValueError('native variable source binding unavailable')
            out.append({**row,'scopeId':new_scope})
        return out
    pipeline_id=str(definition['id'])
    expected=rows(definition['variables'],'pipeline',pipeline_id,resource_id)
    expected+=rows(preview['variables'],'yamlLiteral',pipeline_id,resource_id)
    seen=set();names=set();ids=[]
    for group in groups:
        if (not isinstance(group,dict)or set(group)!={'id','name','type','variables'}
                or not group_name(group['name'])
                or group['type']not in ('Vsts','AzureKeyVault')):raise ValueError('native group unavailable')
        gid=integer(group['id'])
        if gid in seen or group['name']in names:raise ValueError('native group identity ambiguous')
        seen.add(gid);names.add(group['name']);qualified=project_id+'/variableGroups/'+str(gid)
        facts=rows(group['variables'],'keyVault'if group['type']=='AzureKeyVault'else'variableGroup',str(gid),qualified)
        if gid in refs or group['name']in preview['group_names']:
            ids.append(qualified);expected+=facts
    if len(expected)>MAX_ROWS:raise ValueError('expanded metadata resource limit')
    return expected,ids


def native_evidence(item, field, index):
    """Typed native alternative only; the signed legacy evidence branch is intact."""
    from peaso.checks.facts import Unavailable
    def invalid():raise Unavailable('native DevOps evidence binding unresolved')
    context=index.get('context',{});metadata=context.get('metadata',{});capture=metadata.get('native_devops_pipeline_capture',{})
    if not isinstance(capture,dict):invalid()
    evidence=item.get(field);proof=evidence.get('_provenance')if isinstance(evidence,dict)else None
    if field!='expandedVariables'or not isinstance(proof,dict):invalid()
    if (not isinstance(capture.get('project_ids'),list)or not isinstance(capture.get('pipeline_ids'),list)
            or not isinstance(capture.get('revision_pins'),dict)or not isinstance(item.get('id'),str)
            or not isinstance(item.get('projectId'),str)or not re.fullmatch(UUID,item['projectId'])
            or not re.fullmatch(re.escape(item['projectId'])+r'/pipelines/[1-9][0-9]*',item['id'])
            or item.get('revision')!=capture['revision_pins'].get(item['id'])
            or not isinstance(capture.get('organization'),str)or not re.fullmatch(ORG,capture['organization'])
            or capture.get('scope')!='/devops/'+capture['organization']):invalid()
    if (type(proof.get('native_devops_schema'))is not int or proof.get('native_devops_schema')!=1 or proof.get('authority')!='AzureDevOps-native-metadata'
            or proof.get('read_only')is not True or evidence.get('status')!='collected'
            or not isinstance(proof.get('capture_id'),str)or not re.fullmatch(UUID,proof['capture_id'])
            or proof['capture_id']!=capture.get('capture_id')or proof.get('scope')!=context.get('scope')
            or proof['scope']!=capture.get('scope')or proof.get('resource_id')!=item.get('id')
            or item.get('id')not in capture.get('pipeline_ids',[])or item.get('projectId')not in capture.get('project_ids',[])
            or item.get('organization')!=capture.get('organization')or item.get('revision')!=evidence.get('revision')
            or proof.get('captured_at')!=context.get('created_at')
            or not re.fullmatch('/subscriptions/'+UUID,str(capture.get('owner_subscription','')))):
        invalid()
    payload={k:v for k,v in evidence.items()if k!='_provenance'}
    if proof.get('payload_sha256')!=digest(payload):invalid()
    sources=proof.get('redacted_source_metadata_sha256')
    if not isinstance(sources,dict)or set(sources)!={'definition','group_metadata','expanded_variable_metadata'}or any(not isinstance(v,str)or not re.fullmatch('[0-9a-f]{64}',v)for v in sources.values()):invalid()
    native=proof.get('native_metadata')
    try:
        if not isinstance(native,dict)or set(native)!=set(sources)or any(digest(native[k])!=sources[k]for k in sources):invalid()
        expected,groups=joined_native_variables(native,item['projectId'],item['id'],item['revision'])
        if evidence.get('variables')!=expected or evidence.get('variableGroupIds')!=groups:invalid()
    except (ValueError,TypeError,KeyError,AttributeError):invalid()
    # A GET page cannot establish the authorization universe. Never permit a
    # caller to turn this bounded producer into a synthetic clean PASS.
    if any(evidence.get('coverage',{}).get(k)!='partial'for k in ('projects','pipelines','variableGroups')):invalid()
    return evidence

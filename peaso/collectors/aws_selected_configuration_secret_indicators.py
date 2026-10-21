"""Bounded exact-selected AWS configuration reads; opaque, offline projections.

SDK responses are allocated before this projection. Bounds limit inspected and
retained bytes, not transport allocation. No secret store, execution or writes.
"""

from peaso.secret_evidence import scan_with_source, source_context, target_source
from copy import deepcopy
from datetime import date, datetime
import base64
import json
import math
import re
import time
from uuid import uuid4
from urllib.parse import urlsplit
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .aws_configuration_payload_secret_indicators import decode, _json

KIND = 'configuration_selected_content'
CHECK = 'aws.review.configuration.selected_content_secret_indicators'
OPTION = 'selected_aws_configuration_content'
PROFILE = 'aws-selected-configuration-content-v1'
MARKER = 'SelectedConfigurationSecretIndicators'
SCHEMA = 'aws-selected-configuration-content-v1'
MAX_TARGETS = 16
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONTENT = 1024 * 1024
MAX_PAIRS = 256
MAX_LEAKS = 128
MAX_LOCATIONS = 512
MAX_SECONDS = 120
MAX_CALLS = 32
MAX_REDACTION_WINDOWS = 1000000
MAX_REDACTION_DESCRIPTORS = 512
MAX_REDACTION_VALUE = 65536
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
# A real operation descriptor is required by the existing planner; every read is
# dispatched by collect_selected, never by the generic DescribeStacks handler.
SPECS = {KIND: ('cloudformation', 'describe_stacks', None)}
NATIVE_IDS = {KIND: 'id'}
SURFACES = {
 'cloudformation_outputs': ('cloudformation','describe_stacks','cloudformation','stack/([A-Za-z][A-Za-z0-9-]{0,127})/([A-Za-z0-9-]{1,128})'),
 'codebuild_environment': ('codebuild','batch_get_projects','codebuild','project/([A-Za-z0-9][A-Za-z0-9_-]{1,254})'),
 'rest_stage_variables': ('apigateway','get_stage','apigateway','/restapis/([a-z0-9]{1,32})/stages/([A-Za-z0-9_-]{1,128})'),
 'ecs_environment': ('ecs','describe_task_definition','ecs','task-definition/([A-Za-z0-9_-]{1,255}):([1-9][0-9]{0,9})'),
 'amplify_environment': ('amplify','get_app','amplify','apps/([a-z0-9]{1,20})'),
 'batch_environment': ('batch','describe_job_definitions','batch','job-definition/([A-Za-z0-9_-]{1,128}):([1-9][0-9]{0,9})'),
 'beanstalk_options': ('elasticbeanstalk','describe_configuration_settings','elasticbeanstalk','environment/([A-Za-z0-9_-]{1,100})/([A-Za-z0-9-]{4,40})'),
 'glue_job_arguments': ('glue','get_job','glue','job/([A-Za-z0-9_. -]{1,255})'),
 'glue_connection_properties': ('glue','get_connection','glue','connection/([A-Za-z0-9_. -]{1,255})'),
 'launch_template_userdata': ('ec2','describe_launch_template_versions','ec2','launch-template/(lt-[a-f0-9]{8,17})'),
 'launch_configuration_userdata': ('autoscaling','describe_launch_configurations','autoscaling','launchConfiguration:([A-Za-z0-9-]{1,128}):launchConfigurationName/([A-Za-z0-9_.-]{1,255})'),
 'ssm_document': ('ssm','get_document','ssm','document/([A-Za-z0-9_.-]{3,128})'),
 'state_machine_definition': ('stepfunctions','describe_state_machine','states','stateMachine:([A-Za-z0-9_-]{1,80})'),
 'notebook_lifecycle': ('sagemaker','describe_notebook_instance_lifecycle_config','sagemaker','notebook-instance-lifecycle-config/([A-Za-z0-9-]{1,63})'),
 'pipeline_definition': ('datapipeline','get_pipeline_definition','datapipeline','pipeline/(df-[A-Za-z0-9]{1,128})'),
}
PROJECTION_OPERATIONS = {(s,o) for s,o,_,_ in SURFACES.values()} | {('ssm','describe_document')}
READ_ACTIONS = PROJECTION_OPERATIONS


def enabled(options):
    return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list)
            and KIND in options['_content_secret_scan_kinds'])


def parse(target):
    if not isinstance(target,dict) or set(target)-{'surface','scope','resource_id','version'} or not {'surface','scope','resource_id'}<=set(target):
        raise ValueError('invalid_configuration_selection')
    surface=target['surface'];scope=target['scope'];arn=target['resource_id']
    if not isinstance(surface,str) or surface not in SURFACES or not isinstance(scope,str) or not SCOPE.fullmatch(scope) or not isinstance(arn,str) or len(arn)>2048:
        raise ValueError('invalid_configuration_selection')
    account,region=SCOPE.fullmatch(scope).groups()
    partition='aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if '-iso' in region:raise ValueError('invalid_configuration_selection')
    service,operation,arn_service,resource=SURFACES[surface]
    arn_account='' if surface=='rest_stage_variables' else account
    match=re.fullmatch('arn:'+partition+':'+arn_service+':'+region+':'+arn_account+':'+resource,arn)
    if not match:raise ValueError('invalid_configuration_selection')
    versioned=surface in ('launch_template_userdata','ssm_document')
    if versioned:
        if type(target.get('version')) is not int or not 1<=target['version']<=2147483647:raise ValueError('invalid_configuration_selection')
    elif 'version' in target:raise ValueError('invalid_configuration_selection')
    return surface,account,region,partition,match.groups()


def selected_targets(options,scopes):
    """Credential-free public selector validator; numeric versions, no URLs."""
    if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):raise ValueError('invalid_configuration_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list) or not 1<=len(scopes)<=8
            or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes) or len(set(scopes))!=len(scopes)
            or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_configuration_selection')
    seen=set()
    for target in targets:
        parse(target);key=identity(target)
        if target['scope'] not in scopes or key in seen:raise ValueError('invalid_configuration_selection')
        seen.add(key)
    return deepcopy(targets)


def identity(target):return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))
def opaque_arguments(arguments):return {'request_locator':'configuration-request:'+_fingerprint(json.dumps(arguments,sort_keys=True,separators=(',',':')))}


def route(target,*,ownership=False):
    surface,account,region,partition,names=parse(target)
    service,operation,_,_=SURFACES[surface];arn=target['resource_id']
    arguments={
      'cloudformation_outputs':lambda:{'StackName':arn},
      'codebuild_environment':lambda:{'names':[arn]},
      'rest_stage_variables':lambda:{'restApiId':names[0],'stageName':names[1]},
      'ecs_environment':lambda:{'taskDefinition':arn},
      'amplify_environment':lambda:{'appId':names[0]},
      'batch_environment':lambda:{'jobDefinitions':[arn]},
      'beanstalk_options':lambda:{'ApplicationName':names[0],'EnvironmentName':names[1]},
      'glue_job_arguments':lambda:{'JobName':names[0]},
      'glue_connection_properties':lambda:{'CatalogId':account,'Name':names[0],'HidePassword':True},
      'launch_template_userdata':lambda:{'LaunchTemplateId':names[0],'Versions':[str(target['version'])]},
      'launch_configuration_userdata':lambda:{'LaunchConfigurationNames':[names[1]]},
      'ssm_document':lambda:{'Name':arn,'DocumentVersion':str(target['version'])},
      'state_machine_definition':lambda:{'stateMachineArn':arn,'includedData':'ALL_DATA'},
      'notebook_lifecycle':lambda:{'NotebookInstanceLifecycleConfigName':names[0]},
      'pipeline_definition':lambda:{'pipelineId':names[0],'version':'latest'},
    }[surface]()
    return service,('describe_document' if ownership else operation),arguments


def initialize(requests,options,scopes):
    targets=selected_targets(options,scopes)
    requests.configuration_content_metadata={KIND+'_authorized':enabled(options),KIND+'_selection':{
        scope:[identity(t) for t in targets if t['scope']==scope] for scope in scopes},KIND+'_capture':'configuration-capture:'+uuid4().hex,
        KIND+'_principals':{}}
    requests.configuration_content_metadata[KIND+'_redaction_complete']=True
    requests.configuration_content_sessions={};requests.configuration_content_approved={};requests.configuration_content_owned={}
    requests.configuration_content_state={'deadline':None,'responses':0,'bytes':0,'attempts':0}
    requests.configuration_content_redactions={}
    requests.configuration_content_redaction_overflow=False
    for target in targets:
        surface,account,region,partition,names=parse(target)
        for ownership in ((True,False) if surface=='ssm_document' else (False,)):
            service,operation,args=route(target,ownership=ownership)
            key=(service,operation,region,opaque_arguments(args)['request_locator'])
            if key in requests.configuration_content_approved:raise ValueError('ambiguous_configuration_selection')
            # No raw selection, request argument, name, ARN or content is retained.
            requests.configuration_content_approved[key]={'id':identity(target),'scope':target['scope'],'surface':surface,
                'account':account,'region':region,'partition':partition,'version':target.get('version'),'ownership':ownership}


def remaining(requests):
    requests.check_deadline()
    with requests._lock:
        state=requests.configuration_content_state
        if state['deadline'] is None:state['deadline']=time.monotonic()+MAX_SECONDS
        left=state['deadline']-time.monotonic()
    if left<=0:raise ValueError('configuration_deadline')
    return left


def before_request(requests):
    from .aws import ReadFailure
    remaining(requests)
    with requests._lock:
        state=requests.configuration_content_state
        if state['attempts']>=MAX_CALLS:raise ReadFailure('not_collected','selected_configuration_call_bound')
        state['attempts']+=1


def validate_request(service,operation,arguments,*,request_context=None,region=None):
    from .aws import ReadFailure
    try:
        requests,session=request_context
        info=requests.configuration_content_approved[(service,operation,region,opaque_arguments(arguments)['request_locator'])]
        if (requests.content_secret_scans is not True or KIND not in requests.content_secret_scan_kinds
                or requests.configuration_content_metadata[KIND+'_authorized'] is not True
                or requests.configuration_content_sessions[id(session)]['account']!=info['account']
                or requests.configuration_content_sessions[id(session)]['partition']!=info['partition']):raise ValueError()
        if info['surface']=='ssm_document' and not info['ownership'] and info['id'] not in requests.configuration_content_owned:raise ValueError()
        remaining(requests)
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ReadFailure('not_collected','selected_configuration_request_unbound') from None


def validate_native_client(client,service,region):
    from .aws import ReadFailure
    try:
        endpoint=urlsplit(client.meta.endpoint_url)
        prefix={'sagemaker':'api.sagemaker','stepfunctions':'states'}.get(service,service)
        suffix='amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
        if (endpoint.scheme!='https' or endpoint.netloc!=prefix+'.'+region+'.'+suffix
                or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment):raise ValueError()
    except (ValueError,TypeError,AttributeError):
        raise ReadFailure('not_collected','selected_configuration_endpoint_unbound') from None


def response_size(value):
    stack=[(value,0)];nodes=0
    while stack:
        v,depth=stack.pop();nodes+=1
        if nodes>65536 or depth>32:raise ValueError('response_bound')
        if isinstance(v,str):
            if len(v)>MAX_RESPONSE:raise ValueError('response_bound')
        elif isinstance(v,dict):
            if len(v)>65536 or any(not isinstance(k,str) for k in v):raise ValueError('response_shape')
            stack.extend((x,depth+1) for pair in v.items() for x in pair)
        elif isinstance(v,list):
            if len(v)>65536:raise ValueError('response_bound')
            stack.extend((x,depth+1) for x in v)
        elif isinstance(v,(date,datetime)):pass
        elif v is not None and type(v) not in (bool,int,float):raise ValueError('response_shape')
        elif isinstance(v,float) and not math.isfinite(v):raise ValueError('response_shape')
    total=0
    for chunk in json.JSONEncoder(ensure_ascii=False,allow_nan=False,default=lambda v:v.isoformat(),separators=(',',':')).iterencode(value):
        total+=len(chunk.encode('utf-8'))
        if total>MAX_RESPONSE:raise ValueError('response_bound')
    return total


def mapping(value):
    if not isinstance(value,dict) or len(value)>MAX_PAIRS:raise ValueError('map_shape')
    return pairs(list(value.items()))


def pairs(value):
    if not isinstance(value,list) or len(value)>MAX_PAIRS:raise ValueError('pairs_bound')
    out={}
    for key,text in value:
        if (not isinstance(key,str) or not key or len(key)>4096 or key in out or not isinstance(text,str)
                or len(text)>MAX_CONTENT):raise ValueError('pair_shape')
        out[key]=text
    return out


def environment(rows,*,typed=False):
    if not isinstance(rows,list) or len(rows)>MAX_PAIRS:raise ValueError('environment_shape')
    values=[]
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str) or not isinstance(row.get('value'),str) or 'valueFrom' in row:raise ValueError('environment_shape')
        if typed:
            if row.get('type') not in ('PLAINTEXT','PARAMETER_STORE','SECRETS_MANAGER'):raise ValueError('environment_type')
            if row['type']!='PLAINTEXT':continue
        values.append((row['name'],row['value']))
    return pairs(values)


def one(response,field):
    rows=response.get(field)
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):raise ValueError('response_cardinality')
    return rows[0]


def json_literals(text):
    """Inspect source bytes and decoded JSON string literals, never execute."""
    parsed=_json(text);stack=[(parsed,0)];strings=[];nodes=0;total=len(text.encode('utf-8'))
    while stack:
        child,depth=stack.pop();nodes+=1
        if nodes>65536 or depth>32:raise ValueError('definition_structure_bound')
        if isinstance(child,str):
            total+=len(child.encode('utf-8'))
            if total>MAX_CONTENT:raise ValueError('decoded_definition_bound')
            strings.append(child)
        elif isinstance(child,dict):stack.extend((v,depth+1) for pair in child.items() for v in pair)
        elif isinstance(child,list):stack.extend((v,depth+1) for v in child)
    return text+'\n\n'+'\n\n'.join(strings)


def extract(response,service,operation,args,info):
    """Return inspected literal bytes only; no provider text escapes this frame."""
    surface=info['surface'];account=info['account'];region=info['region'];arn_prefix='arn:'+info['partition']+':'
    value=None
    if surface=='cloudformation_outputs':
        row=one(response,'Stacks')
        if (row.get('StackId')!=args['StackName'] or row.get('StackName')!=args['StackName'].split(':stack/',1)[1].split('/',1)[0]
                or row.get('StackStatus') not in ('CREATE_COMPLETE','UPDATE_COMPLETE','IMPORT_COMPLETE','ROLLBACK_COMPLETE','UPDATE_ROLLBACK_COMPLETE','IMPORT_ROLLBACK_COMPLETE')):raise ValueError('stack_identity_state')
        rows=row.get('Outputs')
        if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)-{'OutputKey','OutputValue','Description','ExportName'} for r in rows):raise ValueError('outputs_shape')
        value=pairs([(r.get('OutputKey'),r.get('OutputValue')) for r in rows])
    elif surface=='codebuild_environment':
        if response.get('projectsNotFound'):raise ValueError('project_missing')
        row=one(response,'projects')
        if row.get('arn')!=args['names'][0] or row.get('name')!=args['names'][0].split(':project/',1)[1]:raise ValueError('project_identity')
        env=row.get('environment')
        if not isinstance(env,dict):raise ValueError('environment_shape')
        value=environment(env.get('environmentVariables'),typed=True)
    elif surface=='rest_stage_variables':
        if response.get('stageName')!=args['stageName']:raise ValueError('stage_identity')
        value=mapping(response.get('variables'))
    elif surface=='ecs_environment':
        row=response.get('taskDefinition')
        if not isinstance(row,dict) or row.get('taskDefinitionArn')!=args['taskDefinition'] or row.get('status')!='ACTIVE':raise ValueError('task_identity')
        if row.get('family')!=args['taskDefinition'].split(':task-definition/',1)[1].rsplit(':',1)[0] or str(row.get('revision'))!=args['taskDefinition'].rsplit(':',1)[1]:raise ValueError('task_revision')
        rows=row.get('containerDefinitions')
        if not isinstance(rows,list) or not rows or len(rows)>32:raise ValueError('containers_shape')
        value={};seen=set()
        for index,row in enumerate(rows):
            name=row.get('name') if isinstance(row,dict) else None
            if not isinstance(name,str) or not name or name in seen:raise ValueError('containers_identity')
            seen.add(name)
            for key,text in environment(row.get('environment',[])).items():value[str(index)+':'+key]=text
    elif surface=='amplify_environment':
        row=response.get('app')
        if not isinstance(row,dict) or row.get('appId')!=args['appId'] or row.get('appArn')!=arn_prefix+'amplify:'+region+':'+account+':apps/'+args['appId']:raise ValueError('app_identity')
        value=mapping(row.get('environmentVariables'))
    elif surface=='batch_environment':
        row=one(response,'jobDefinitions')
        if row.get('jobDefinitionArn')!=args['jobDefinitions'][0] or row.get('status')!='ACTIVE' or row.get('type')!='container' or any(k in row for k in ('ecsProperties','eksProperties','nodeProperties')):raise ValueError('batch_variant')
        if str(row.get('revision'))!=args['jobDefinitions'][0].rsplit(':',1)[1] or row.get('jobDefinitionName')!=args['jobDefinitions'][0].split(':job-definition/',1)[1].rsplit(':',1)[0]:raise ValueError('batch_identity')
        container=row.get('containerProperties')
        if not isinstance(container,dict):raise ValueError('batch_shape')
        value=environment(container.get('environment'))
    elif surface=='beanstalk_options':
        row=one(response,'ConfigurationSettings')
        if row.get('ApplicationName')!=args['ApplicationName'] or row.get('EnvironmentName')!=args['EnvironmentName'] or row.get('DeploymentStatus')!='deployed':raise ValueError('environment_identity_state')
        rows=row.get('OptionSettings')
        if not isinstance(rows,list) or len(rows)>MAX_PAIRS:raise ValueError('options_shape')
        entries=[]
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('Namespace'),str) or not isinstance(row.get('OptionName'),str):raise ValueError('options_shape')
            entries.append((row.get('ResourceName','')+'|'+row['Namespace']+'|'+row['OptionName'],row.get('Value')))
        value=pairs(entries)
    elif surface=='glue_job_arguments':
        row=response.get('Job')
        if not isinstance(row,dict) or row.get('Name')!=args['JobName']:raise ValueError('job_identity')
        value={}
        for field in ('DefaultArguments','NonOverridableArguments'):
            for key,text in mapping(row.get(field,{})).items():value[field+':'+key]=text
    elif surface=='glue_connection_properties':
        row=response.get('Connection')
        if not isinstance(row,dict) or row.get('Name')!=args['Name'] or args.get('CatalogId')!=account or args.get('HidePassword') is not True:raise ValueError('connection_identity')
        props=mapping(row.get('ConnectionProperties'))
        value={key:text for key,text in props.items() if key not in ('PASSWORD','ENCRYPTED_PASSWORD')}
    elif surface=='launch_template_userdata':
        row=one(response,'LaunchTemplateVersions')
        if row.get('LaunchTemplateId')!=args['LaunchTemplateId'] or type(row.get('VersionNumber')) is not int or str(row['VersionNumber'])!=args['Versions'][0]:raise ValueError('template_version')
        data=row.get('LaunchTemplateData')
        if not isinstance(data,dict) or 'UserData' not in data:raise ValueError('userdata_missing')
        value=decode(data['UserData'],gzip_ok=True)
    elif surface=='launch_configuration_userdata':
        row=one(response,'LaunchConfigurations')
        if row.get('LaunchConfigurationName')!=args['LaunchConfigurationNames'][0] or not isinstance(row.get('LaunchConfigurationARN'),str) or row['LaunchConfigurationARN']!=info['expected_arn']:raise ValueError('launch_configuration_identity')
        value=decode(row['UserData'],gzip_ok=True)
    elif surface=='ssm_document':
        name=args['Name'].split(':document/',1)[1]
        if response.get('Name')!=name or response.get('DocumentVersion')!=args['DocumentVersion'] or response.get('Status')!='Active':raise ValueError('document_version')
        text=response.get('Content');form=response.get('DocumentFormat')
        if not isinstance(text,str) or not text or len(text.encode())>65536:raise ValueError('document_bound')
        if form=='JSON':
            if not isinstance(_json(text),dict):raise ValueError('document_json')
            text=json_literals(text)
        elif form=='YAML':
            import yaml
            if not isinstance(yaml.compose(text),yaml.MappingNode):raise ValueError('document_yaml')
        elif form!='TEXT':raise ValueError('document_format')
        value=text
    elif surface=='state_machine_definition':
        if response.get('stateMachineArn')!=args['stateMachineArn'] or response.get('name')!=args['stateMachineArn'].split(':stateMachine:',1)[1] or response.get('status')!='ACTIVE':raise ValueError('state_machine_identity_state')
        text=response.get('definition')
        if not isinstance(text,str) or len(text.encode())>MAX_CONTENT:raise ValueError('definition_bound')
        parsed=_json(text)
        if not isinstance(parsed,dict) or not isinstance(parsed.get('States'),dict) or parsed.get('StartAt') not in parsed['States']:raise ValueError('asl_shape')
        value=json_literals(text)
    elif surface=='notebook_lifecycle':
        name=args['NotebookInstanceLifecycleConfigName']
        if response.get('NotebookInstanceLifecycleConfigName')!=name or response.get('NotebookInstanceLifecycleConfigArn')!=arn_prefix+'sagemaker:'+region+':'+account+':notebook-instance-lifecycle-config/'+name:raise ValueError('lifecycle_identity')
        texts=[]
        for field in ('OnCreate','OnStart'):
            rows=response.get(field,[])
            if not isinstance(rows,list) or len(rows)>1:raise ValueError('lifecycle_shape')
            for row in rows:
                if not isinstance(row,dict) or set(row)!={'Content'}:raise ValueError('lifecycle_shape')
                texts.append(field+'\n'+decode(row['Content']))
        value='\n\n'.join(texts)
    else:
        # Latest definition is request-bound: API does not echo the pipeline ID.
        values=[]
        objects=response.get('pipelineObjects')
        if not isinstance(objects,list) or not objects or len(objects)>MAX_PAIRS:raise ValueError('pipeline_shape')
        for obj in objects:
            if not isinstance(obj,dict) or not isinstance(obj.get('id'),str) or not isinstance(obj.get('name'),str) or not isinstance(obj.get('fields'),list):raise ValueError('pipeline_object')
            for field in obj['fields']:
                if not isinstance(field,dict) or not isinstance(field.get('key'),str) or ('stringValue' in field)==('refValue' in field):raise ValueError('pipeline_field')
                if 'stringValue' in field:values.append((str(len(values))+':'+field['key'],field['stringValue']))
                elif not isinstance(field['refValue'],str):raise ValueError('pipeline_reference')
        for obj in response.get('parameterObjects',[]):
            if not isinstance(obj,dict) or not isinstance(obj.get('attributes'),list):raise ValueError('pipeline_parameters')
            for field in obj['attributes']:
                if not isinstance(field,dict):raise ValueError('pipeline_parameters')
                values.append((str(len(values))+':'+str(field.get('key')),field.get('stringValue')))
        for obj in response.get('parameterValues',[]):
            if not isinstance(obj,dict):raise ValueError('pipeline_parameters')
            values.append((str(len(values))+':'+str(obj.get('id')),obj.get('stringValue')))
        value=pairs(values)
    if isinstance(value,dict):
        if not value or not any(value.values()) or len(value)>MAX_PAIRS:raise ValueError('empty_literal_content')
        # Preserve multiline literal values (not JSON-escaped private keys).
        payload=b'\n\n'.join(key.encode('utf-8')+b'='+text.encode('utf-8') for key,text in value.items());count=len(value)
    else:
        if not isinstance(value,str) or not value.strip():raise ValueError('empty_literal_content')
        payload=value.encode('utf-8');count=1
    if not 1<=len(payload)<=MAX_CONTENT:raise ValueError('content_bound')
    return payload,count


def base(info,requests,locator):
    return {'schema':SCHEMA,'kind':KIND,'surface':info['surface'],'identity':info['id'],'scope':info['scope'],
        'account':info['account'],'region':info['region'],'partition':info['partition'],'version':info['version'],
        'capture':requests.configuration_content_metadata[KIND+'_capture'],'principal':None,
        'native_complete':False,'complete':False,'verification':'not_attempted','literal_count':0,'bytes':0,'response_bytes':0,
        'engines':[],'leaks':[],'requests':[],'status':'unavailable','selection_locator':info['id']}


def remember_matches(requests,values):
    # Raw matches exist only during the callback; retained union descriptors are
    # keyed HMACs plus lengths, including one common encoded layer.
    if len(values)>MAX_REDACTION_DESCRIPTORS or any(len(value)>MAX_REDACTION_VALUE for value in values):
        requests.configuration_content_redaction_overflow=True
        return
    patterns=set(values)
    for value in values:
        patterns.add(json.dumps(value,ensure_ascii=True)[1:-1])
        for encoder in (base64.b64encode,base64.urlsafe_b64encode):
            encoded=encoder(value.encode()).decode();patterns.update((encoded,encoded.rstrip('=')))
    with requests._lock:
        descriptors=requests.configuration_content_redactions
        for text in patterns:
            if text:descriptors.setdefault(len(text),set()).add(_fingerprint(text))
        if sum(len(v) for v in descriptors.values())>MAX_REDACTION_DESCRIPTORS:
            requests.configuration_content_redaction_overflow=True


def project_response(response,service,operation,arguments,*,request_context=None,region=None):
    validate_request(service,operation,arguments,request_context=request_context,region=region)
    requests,session=request_context;locator=opaque_arguments(arguments)['request_locator']
    info=deepcopy(requests.configuration_content_approved[(service,operation,region,locator)])
    marker=base(info,requests,locator);marker['principal']=requests.configuration_content_sessions[id(session)]['principal']
    try:
        remaining(requests);size=response_size(response)
        with requests._lock:
            state=requests.configuration_content_state;state['responses']+=1;state['bytes']+=size
            if state['responses']>MAX_CALLS or state['bytes']>MAX_TOTAL:raise ValueError('total_response_bound')
        if (not isinstance(response,dict) or set(response)&{'Error','_coverage','partial','Partial'}
                or any(response.get(field) not in (None,'') for field in ('NextToken','nextToken','nextMarker','NextMarker'))):raise ValueError('partial_native_response')
        meta=response.get('ResponseMetadata')
        if (not isinstance(meta,dict) or type(meta.get('HTTPStatusCode')) is not int or meta['HTTPStatusCode']!=200
                or not isinstance(meta.get('RequestId'),str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',meta['RequestId'])):raise ValueError('native_read_provenance')
        receipt={'locator':locator,'service':service,'operation':operation,'method':'GET' if service in ('apigateway','amplify') else 'POST',
                 'http_status':200,'request_id':'configuration-response:'+_fingerprint(meta['RequestId'])}
        marker['requests']=[receipt];marker['response_bytes']=size
        if info['ownership']:
            row=response.get('Document');name=arguments['Name'].split(':document/',1)[1]
            if (not isinstance(row,dict) or row.get('Name')!=name or row.get('Owner')!=info['account'] or row.get('DocumentVersion')!=arguments['DocumentVersion'] or row.get('Status')!='Active'):raise ValueError('owned_document_authority')
            with requests._lock:requests.configuration_content_owned[info['id']]=deepcopy(receipt)
            marker.update(status='owned_document_metadata',native_complete=True)
        else:
            if info['surface']=='launch_configuration_userdata':
                # Reconstruct actual ARN from the native response and exact
                # approved selector hash; never invent a different read route.
                row=one(response,'LaunchConfigurations');candidate=row.get('LaunchConfigurationARN')
                selection={'surface':info['surface'],'scope':info['scope'],'resource_id':candidate}
                if identity(selection)!=info['id']:raise ValueError('launch_configuration_binding')
                info['expected_arn']=candidate
            payload,count=extract(response,service,operation,arguments,info)
            if info['surface']=='ssm_document':marker['requests'].insert(0,deepcopy(requests.configuration_content_owned[info['id']]))
            marker.update(native_complete=True,status='collected',literal_count=count,bytes=len(payload))
            outcome=scan_with_source(scan_content, payload,info['id']+'.content',timeout=min(60,remaining(requests)),
                _redact_values=lambda values:remember_matches(requests,values), source={'scope': info['scope'], 'path': info['surface'], 'location_kind': 'configuration'}, native=response)
            del payload
            leaks=merge_leaks(outcome['leaks'])
            # Literal rendering/JSON decoding can represent the same source
            # value twice. Retain one opaque native-target occurrence rather
            # than invent provider file line numbers from transformed text.
            for leak in leaks:leak['locations']=[{'path':info['id']+'.content'}]
            if len(leaks)>MAX_LEAKS or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS:raise ValueError('findings_bound')
            marker.update(engines=deepcopy(outcome['engines']),leaks=leaks)
            remaining(requests)
            marker['complete']=outcome['complete'] is True
    except Exception:
        marker['complete']=False
    return {'id':info['id'],MARKER:marker,'_provenance':{'scope':info['scope'],'capture':marker['capture'],'selection_locator':info['id']}}


def collect_selected(requests,session,region,caller,options,scopes):
    from .aws import ReadResult
    targets=selected_targets(options,scopes)
    if not enabled(options):return ReadResult([],'not_collected',{'code':'selected_configuration_disabled'})
    account=caller.get('Account') if isinstance(caller,dict) else None;arn=caller.get('Arn') if isinstance(caller,dict) else None
    if not isinstance(account,str) or not re.fullmatch('[0-9]{12}',account) or not isinstance(arn,str):return ReadResult([],'unknown',{'code':'selected_configuration_caller_unbound'})
    m=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):(?:iam|sts)::'+account+r':.+',arn)
    if not m:return ReadResult([],'unknown',{'code':'selected_configuration_caller_unbound'})
    principal='configuration-principal:'+_fingerprint(arn+'\n'+str(caller.get('UserId')))
    with requests._lock:
        requests.configuration_content_sessions[id(session)]={'account':account,'partition':m[1],'principal':principal}
        requests.configuration_content_metadata[KIND+'_principals'][account]=principal
    items=[]
    for target in targets:
        surface,selected_account,selected_region,partition,_=parse(target)
        if selected_account!=account or selected_region!=region:continue
        service,operation,args=route(target);locator=opaque_arguments(args)['request_locator']
        info=requests.configuration_content_approved[(service,operation,region,locator)]
        try:
            with source_context(**target_source(target, path=surface, location_kind='configuration')):
                if surface=='ssm_document':
                    own_service,own_operation,own_args=route(target,ownership=True)
                    owned=requests.call(session,own_service,region,own_operation,_metadata_profile=PROFILE,**own_args)
                    if owned[MARKER]['status']!='owned_document_metadata':raise ValueError('document_owner_unresolved')
                item=requests.call(session,service,region,operation,_metadata_profile=PROFILE,**args)
        except Exception:
            marker=base(info,requests,locator);marker['principal']=principal
            item={'id':info['id'],MARKER:marker,'_provenance':{'scope':info['scope'],'capture':marker['capture'],'selection_locator':info['id']}}
        items.append(item)
    if not items:return ReadResult([],'not_collected',{'code':'selected_configuration_scope_omitted'})
    return ReadResult(items)


def finalize(requests,collections,metadata):
    """Redact the detected union without retaining raw values between reads.

    This is opt-in value redaction, not a change to generic security-key policy.
    On bounded-work exhaustion, opaque surrogates replace uninspected free text.
    """
    if requests.configuration_content_redaction_overflow:
        # There is no retained raw match set with which to finish redaction.
        # Withhold all affected projections and cached aliases, never a clean
        # result from metadata whose redaction could not be established.
        with requests._lock:
            # Consumers may hold a completed Future's mutable projection;
            # clearing cache entries alone cannot erase that earlier alias.
            for future in requests._cache.values():
                if not future.done():continue
                if future.exception() is None:
                    value=future.result()
                    if isinstance(value,dict):
                        value.clear();value['_coverage']={'content':{'status':'unknown','reason':'selected_configuration_redaction_bound'}}
                    elif isinstance(value,list):value.clear()
                else:
                    failure=future.exception()
                    if hasattr(failure,'code'):
                        failure.code='selected_configuration_redaction_bound';failure.args=(failure.code,)
            requests._cache.clear()
        withheld=[]
        for collection in collections:
            safe={k:deepcopy(collection[k]) for k in ('type','scope','service','account_id','region','global') if k in collection}
            safe.update(status='unknown',items=[],error={'code':'selected_configuration_redaction_bound'})
            withheld.append(safe)
        return withheld,{KIND+'_redaction_complete':False,'intentional_partial':True}
    descriptors=requests.configuration_content_redactions
    if not descriptors:return collections,metadata
    windows=0
    exhausted=False
    def text(value):
        nonlocal windows,exhausted
        if not isinstance(value,str):return value
        matches=[]
        for length,fingerprints in descriptors.items():
            if length>len(value):continue
            for start in range(len(value)-length+1):
                windows+=1
                if windows>MAX_REDACTION_WINDOWS:
                    exhausted=True
                    return 'configuration-redacted:'+_fingerprint(value)
                if _fingerprint(value[start:start+length]) in fingerprints:matches.append((start,start+length))
        if not matches:return value
        result=[];offset=0
        for start,end in sorted(matches):
            if start<offset:offset=max(offset,end);continue
            result.extend((value[offset:start],'[redacted]'));offset=end
        result.append(value[offset:]);return ''.join(result)
    def scrub(value):
        if isinstance(value,str):return text(value)
        if isinstance(value,(list,tuple)):
            rows=[scrub(v) for v in value];return tuple(rows) if isinstance(value,tuple) else rows
        if not isinstance(value,dict):return value
        result={};changed=[]
        for key,child in value.items():
            safe_key=text(key);safe_child=scrub(child);result[safe_key]=safe_child
            if key!='_coverage' and (safe_key!=key or safe_child!=child):changed.append(safe_key)
        if changed:
            coverage=result.get('_coverage');coverage=dict(coverage) if isinstance(coverage,dict) else {}
            coverage.update({key:{'status':'unknown','reason':'detected_secret_redacted'} for key in changed});result['_coverage']=coverage
        return result
    with requests._lock:
        for key,future in list(requests._cache.items()):
            safe_key=scrub(key)
            if future.done() and future.exception() is None:
                current=future.result();safe=scrub(current)
                if isinstance(current,dict):current.clear();current.update(safe)
                elif isinstance(current,list):current[:]=safe
            elif future.done():
                failure=future.exception()
                if hasattr(failure,'code') and text(failure.code)!=failure.code:
                    failure.code='detected_secret_metadata_withheld'
                    failure.args=(failure.code,)
            if safe_key!=key:
                # Do not forge a cache alias that could serve a different native
                # request; evict its already-scrubbed completed projection.
                requests._cache.pop(key,None)
    safe_collections,safe_metadata=scrub(collections),scrub(metadata)
    if exhausted:
        safe_metadata[KIND+'_redaction_complete']=False
        for collection in safe_collections:
            if collection.get('type')==KIND:
                collection.update(status='partial',error={'code':'selected_configuration_redaction_bound'})
    return safe_collections,safe_metadata

"""Explicit Lambda $LATEST environment reads, projected before shared caching.

SDK JSON is already in memory on receipt: bounds here limit inspected/retained
content, not transport streaming. No invoke/update/decrypt or secret-store read.
"""
from copy import deepcopy
import json
import math
import re
import time
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint

KIND='lambda_selected_environment'
CHECK='aws.review.lambda.selected_environment_secret_indicators'
OPTION='selected_aws_lambda_functions'
PROFILE='aws-lambda-environment-content-v1'
MARKER='SelectedLambdaEnvironmentSecretIndicators'
SCHEMA='aws-selected-lambda-environment-secrets-v1'
MAX_TARGETS=8
MAX_RESPONSE=131072
MAX_RESPONSE_TOTAL=1048576
MAX_VARIABLES=128
MAX_ENV_BYTES=4096
MAX_SCAN_BYTES=8192
MAX_LEAKS=128
MAX_LOCATIONS=256
MAX_SECONDS=60
ARN=re.compile(r'arn:(aws|aws-cn|aws-us-gov):lambda:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+):([0-9]{12}):function:([A-Za-z0-9_-]{1,64})\Z')
SCOPE=re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
_UUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z',re.I)
SPECS={KIND:('lambda','get_function_configuration',None)}
NATIVE_IDS={KIND:'id'}
PROJECTION_OPERATIONS={('lambda','get_function_configuration')}
READ_ACTIONS=PROJECTION_OPERATIONS


class Incomplete(ValueError):
    """Stable errors only; never include provider text or selected names."""


def enabled(options):
    return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list)
        and KIND in options['_content_secret_scan_kinds'])


def parse(arn):
    match=ARN.fullmatch(arn) if isinstance(arn,str) else None
    if not match:raise Incomplete('invalid_lambda_selection')
    partition='aws-cn' if match[2].startswith('cn-') else 'aws-us-gov' if match[2].startswith('us-gov-') else 'aws'
    if match[1]!=partition or '-iso' in match[2]:raise Incomplete('invalid_lambda_selection')
    return match


def selected_targets(options,scopes):
    """Exported credential-free public validator; exact unqualified ARN only."""
    if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_lambda_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list) or not 1<=len(scopes)<=8
            or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes))!=len(scopes) or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):
        raise Incomplete('invalid_lambda_selection')
    seen=set()
    for arn in targets:
        match=parse(arn)
        if match[3]+'/'+match[2] not in scopes or arn in seen:raise Incomplete('invalid_lambda_selection')
        seen.add(arn)
    return list(targets)


def identity(arn):return KIND+':'+_fingerprint(arn)


def opaque_arguments(arguments):
    return {'request_locator':'lambda-environment-request:'+_fingerprint(json.dumps(arguments,sort_keys=True,separators=(',',':')))}


def initialize(requests,options,scopes):
    targets=selected_targets(options,scopes)
    requests.lambda_environment_metadata={KIND+'_authorized':enabled(options),KIND+'_selection':{
        s:[identity(t) for t in targets if parse(t)[3]+'/'+parse(t)[2]==s] for s in scopes},KIND+'_capture':'lambda-environment-capture:'+uuid4().hex}
    requests.lambda_environment_sessions={}
    requests.lambda_environment_state={'deadline':None,'response_bytes':0,'responses':0}


def _remaining(requests):
    requests.check_deadline()
    with requests._lock:
        state=requests.lambda_environment_state
        if state['deadline'] is None:state['deadline']=time.monotonic()+MAX_SECONDS
        left=state['deadline']-time.monotonic()
    if left<=0:raise Incomplete('lambda_environment_deadline')
    return left


def validate_request(service,operation,arguments,*,region=None,request_context=None):
    from .aws import ReadFailure
    try:
        if ((service,operation) not in PROJECTION_OPERATIONS or set(arguments)!={'FunctionName'}
                or not isinstance(request_context,tuple) or len(request_context)!=2):raise ValueError()
        requests,session=request_context;match=parse(arguments['FunctionName']);scope=match[3]+'/'+match[2]
        binding=requests.lambda_environment_sessions[id(session)]
        if (requests.content_secret_scans is not True or KIND not in requests.content_secret_scan_kinds
                or requests.lambda_environment_metadata[KIND+'_authorized'] is not True or match[2]!=region
                or binding!={'account':match[3],'partition':match[1]}
                or identity(arguments['FunctionName']) not in requests.lambda_environment_metadata[KIND+'_selection'][scope]):raise ValueError()
        _remaining(requests)
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ReadFailure('not_collected','lambda_environment_request_unbound') from None


def _size(value):
    # Preflight each scalar before serialization, avoiding a second unbounded
    # full response encoding. Actual SDK response allocation happened earlier.
    stack=[(value,0)];nodes=0
    while stack:
        child,depth=stack.pop();nodes+=1
        if nodes>4096 or depth>24:raise Incomplete('response_bound')
        if isinstance(child,str):
            if len(child)>MAX_RESPONSE:raise Incomplete('response_bound')
        elif isinstance(child,dict):
            if len(child)>4096:raise Incomplete('response_bound')
            if any(not isinstance(k,str) for k in child):raise Incomplete('response_shape')
            stack.extend((x,depth+1) for pair in child.items() for x in pair)
        elif isinstance(child,list):
            if len(child)>4096:raise Incomplete('response_bound')
            stack.extend((x,depth+1) for x in child)
        elif child is not None and type(child) not in (bool,int,float):raise Incomplete('response_shape')
        elif isinstance(child,float) and not math.isfinite(child):raise Incomplete('response_shape')
    total=0
    for chunk in json.JSONEncoder(ensure_ascii=False,allow_nan=False,separators=(',',':')).iterencode(value):
        total+=len(chunk.encode('utf-8',errors='strict'))
        if total>MAX_RESPONSE:raise Incomplete('response_bound')
    return total


def _base(arn,requests):
    match=parse(arn);scope=match[3]+'/'+match[2];ident=identity(arn)
    return {'schema':SCHEMA,'kind':KIND,'identity':ident,'scope':scope,'account':match[3],'region':match[2],
        'partition':match[1],'complete':False,'verification':'not_attempted','version':None,'revision':None,
        'variable_count':0,'bytes':0,'response_bytes':0,'engines':[],'leaks':[],
        'capture':requests.lambda_environment_metadata[KIND+'_capture'],'request':{
            'locator':opaque_arguments({'FunctionName':arn})['request_locator'],'operation':'lambda:GetFunctionConfiguration',
            'method':'GET','scope':scope,'identity':ident,'status':'unavailable','http_status':None,'native_request':None}}


def project_response(response,service,operation,arguments,*,request_context=None,region=None):
    """Exactly this read profile enters cache; raw response never does."""
    validate_request(service,operation,arguments,request_context=request_context,region=region)
    requests,session=request_context;arn=arguments['FunctionName'];match=parse(arn);marker=_base(arn,requests)
    try:
        _remaining(requests)
        response_bytes=_size(response)
        with requests._lock:
            state=requests.lambda_environment_state
            state['responses']+=1;state['response_bytes']+=response_bytes
            if state['responses']>MAX_TARGETS or state['response_bytes']>MAX_RESPONSE_TOTAL:raise Incomplete('response_total_bound')
        if (not isinstance(response,dict) or set(response)&{'Error','NextMarker','NextToken','_coverage','partial','Partial'}
                or response.get('FunctionArn')!=arn or response.get('FunctionName')!=match[4]
                or response.get('Version')!='$LATEST' or not isinstance(response.get('RevisionId'),str)
                or not _UUID.fullmatch(response['RevisionId']) or response.get('State')!='Active'
                or response.get('LastUpdateStatus')!='Successful'):raise Incomplete('native_identity_or_partial')
        metadata=response.get('ResponseMetadata')
        if (not isinstance(metadata,dict) or type(metadata.get('HTTPStatusCode')) is not int or metadata['HTTPStatusCode']!=200
                or not isinstance(metadata.get('RequestId'),str) or not _UUID.fullmatch(metadata['RequestId'])):
            raise Incomplete('native_read_provenance')
        env=response.get('Environment')
        if not isinstance(env,dict) or set(env)!={'Variables'} or not isinstance(env['Variables'],dict) or not 1<=len(env['Variables'])<=MAX_VARIABLES:
            raise Incomplete('environment_unavailable')
        parts=[];actual=0
        for key,value in env['Variables'].items():
            if (not isinstance(key,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{1,127}',key)
                    or not isinstance(value,str) or len(value)>MAX_ENV_BYTES):raise Incomplete('environment_unsupported')
            raw=value.encode('utf-8',errors='strict');actual+=len(key.encode('ascii'))+len(raw)
            if actual>MAX_ENV_BYTES or any(ord(c)<32 and c not in '\t\r\n' or ord(c)==127 for c in value):
                raise Incomplete('environment_bound')
            parts.append(key.encode()+b'='+raw)
        if not any(env['Variables'].values()):raise Incomplete('environment_empty')
        payload=b'\n\n'.join(parts)
        if len(payload)>MAX_SCAN_BYTES:raise Incomplete('environment_bound')
        outcome=scan_content(payload,identity(arn)+'.variables',timeout=min(60,_remaining(requests)))
        del payload,parts
        leaks=merge_leaks(outcome['leaks'])
        if len(leaks)>MAX_LEAKS or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS:raise Incomplete('leak_bound')
        marker.update(version='$LATEST',revision='lambda-revision:'+_fingerprint(response['RevisionId']),
            variable_count=len(env['Variables']),bytes=actual,response_bytes=response_bytes,engines=deepcopy(outcome['engines']),leaks=leaks)
        marker['request'].update(status='collected',http_status=200,native_request='lambda-response:'+_fingerprint(metadata['RequestId']))
        _remaining(requests)
        if outcome['complete'] is not True:raise Incomplete('engines_incomplete')
        marker['complete']=True
    except Exception:
        marker['complete']=False
    return {'id':identity(arn),MARKER:marker,'_provenance':{'scope':marker['scope'],
        'capture':marker['capture'],'request_locator':marker['request']['locator']}}


def collect_selected(requests,session,region,caller,options,scopes):
    from .aws import ReadResult
    targets=selected_targets(options,scopes)
    if not enabled(options):return ReadResult([],'not_collected',{'code':'lambda_environment_disabled'})
    if (not isinstance(caller,dict) or not isinstance(caller.get('Account'),str) or not isinstance(caller.get('Arn'),str)
            or not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):(iam|sts)::'+re.escape(caller['Account'])+r':.+',caller['Arn'])):
        return ReadResult([],'not_collected',{'code':'lambda_environment_caller_unbound'})
    account=caller['Account'];partition=caller['Arn'].split(':')[1]
    with requests._lock:requests.lambda_environment_sessions[id(session)]={'account':account,'partition':partition}
    items=[]
    for arn in targets:
        match=parse(arn)
        if match[2]!=region or match[3]!=account:continue
        try:
            _remaining(requests)
            item=requests.call(session,'lambda',region,'get_function_configuration',_metadata_profile=PROFILE,FunctionName=arn)
        except Exception:
            marker=_base(arn,requests)
            item={'id':identity(arn),MARKER:marker,'_provenance':{'scope':marker['scope'],'capture':marker['capture'],'request_locator':marker['request']['locator']}}
        items.append(item)
    return ReadResult(items,'collected' if items else 'not_collected',None if items else {'code':'lambda_environment_scope_unselected'})

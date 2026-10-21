"""Exact selected AWS workload S3 source references, with bounded S3 delegation."""
from copy import deepcopy
from datetime import datetime
import json
import re
from urllib.parse import urlsplit
from uuid import uuid4
from botocore.client import BaseClient
from peaso.secret_scanning import _fingerprint
from peaso.secret_evidence import reuse_image_layer, source_context
from . import aws_s3_selected_source_secret_indicators as s3
from .aws_content_sdk_logging import private_sdk_logs

KIND='workload_referenced_source_content'
CHECK='aws.review.workload.referenced_source_secret_indicators'
OPTION='selected_aws_workload_sources'
PROFILE='aws-workload-referenced-source-v1'
MARKER='WorkloadReferencedSourceSecretIndicators'
SCHEMA='aws-workload-referenced-source-v1'
MAX_TARGETS=4
PROFILES={
 'glue_script':('glue','get_job','text'),
 'emr_serverless_spark':('emr-serverless','get_job_run','text'),
 'emr_serverless_spark_jar':('emr-serverless','get_job_run','zip'),
 'emr_serverless_hive':('emr-serverless','get_job_run','text'),
 'emr_serverless_hive_init':('emr-serverless','get_job_run','text'),
 'emr_step_jar':('emr','describe_step','zip'),
 'sagemaker_hyperpod_lifecycle':('sagemaker','describe_cluster','text'),
 'sagemaker_training_script':('sagemaker','describe_training_job','tar.gz'),
}
SPECS={KIND:('glue','get_job',None)}
NATIVE_IDS={KIND:'id'}


def enabled(options):
    return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds',())


def source_target(target):
    uri=target['source_s3_uri']
    if not isinstance(uri,str) or len(uri)>2048 or not uri.startswith('s3://') or any(ord(c)<32 for c in uri):
        raise ValueError('invalid_workload_s3_uri')
    parsed=urlsplit(uri)
    if parsed.scheme!='s3' or not parsed.netloc or not parsed.path.startswith('/') or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port is not None:
        raise ValueError('invalid_workload_s3_uri')
    selected={'scope':target['scope'],'bucket':parsed.netloc,'key':parsed.path[1:],'format':PROFILES[target['profile']][2]}
    s3.parse(selected)
    return selected


def route(target):
    profile=target['profile']
    service,operation,_=PROFILES[profile]
    if profile=='glue_script':
        return service,operation,{'JobName':target['job_name']}
    if profile.startswith('emr_serverless_'):
        match=re.fullmatch(r'arn:aws:emr-serverless:([a-z0-9-]+):([0-9]{12}):/applications/([0-9a-z]{1,64})/jobruns/([0-9a-z]{1,64})',target['job_run_arn'])
        if not match:raise ValueError('invalid_emr_serverless_arn')
        return service,operation,{'applicationId':match[3],'jobRunId':match[4],'attempt':target['attempt']}
    if profile=='emr_step_jar':
        return service,operation,{'ClusterId':target['cluster_id'],'StepId':target['step_id']}
    if profile=='sagemaker_training_script':
        return service,operation,{'TrainingJobName':target['training_job_arn'].split(':training-job/',1)[1]}
    return service,operation,{'ClusterName':target['cluster_arn']}


def selected_targets(options,scopes):
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS or not isinstance(scopes,list)
            or len(set(scopes))!=len(scopes) or any(not isinstance(scope,str) or not s3.SCOPE.fullmatch(scope) for scope in scopes)):
        raise ValueError('invalid_workload_selection')
    selected_s3=s3.selected_targets(options,scopes)
    seen=set();sources=set()
    for target in targets:
        if not isinstance(target,dict) or target.get('profile') not in PROFILES:
            raise ValueError('invalid_workload_profile')
        profile=target['profile']
        keys={'profile','scope','source_s3_uri'}
        keys|=({'job_name'} if profile=='glue_script' else {'job_run_arn','attempt'} if profile.startswith('emr_serverless_')
            else {'cluster_id','step_id'} if profile=='emr_step_jar'
            else {'training_job_arn','program'} if profile=='sagemaker_training_script'
            else {'cluster_arn','instance_group','entry_script'})
        if set(target)!=keys or target['scope'] not in scopes:raise ValueError('invalid_workload_selection')
        account,region=s3.SCOPE.fullmatch(target['scope']).groups()
        if region.startswith(('cn-','us-gov-')) or '-iso' in region:raise ValueError('unsupported_workload_partition')
        if profile=='glue_script' and (not isinstance(target['job_name'],str) or not re.fullmatch(r'[A-Za-z0-9_\-]{1,255}',target['job_name'])):
            raise ValueError('invalid_glue_job_name')
        if profile.startswith('emr_serverless_'):
            if type(target['attempt']) is not int or not 1<=target['attempt']<=1000:
                raise ValueError('invalid_emr_serverless_attempt')
            match=re.fullmatch(r'arn:aws:emr-serverless:'+region+':'+account+r':/applications/[0-9a-z]{1,64}/jobruns/[0-9a-z]{1,64}',target['job_run_arn']) if isinstance(target['job_run_arn'],str) else None
            if not match:raise ValueError('invalid_emr_serverless_arn')
            if profile=='emr_serverless_spark_jar' and not target['source_s3_uri'].lower().endswith('.jar'):
                raise ValueError('invalid_emr_serverless_jar')
        if profile=='emr_step_jar':
            if (not isinstance(target['cluster_id'],str) or not re.fullmatch(r'j-[A-Z0-9]{1,32}',target['cluster_id'])
                    or not isinstance(target['step_id'],str) or not re.fullmatch(r's-[A-Z0-9]{1,32}',target['step_id'])
                    or not target['source_s3_uri'].lower().endswith('.jar')):
                raise ValueError('invalid_emr_step_selection')
        if profile=='sagemaker_hyperpod_lifecycle':
            if (not isinstance(target['cluster_arn'],str) or not re.fullmatch(r'arn:aws:sagemaker:'+region+':'+account+r':cluster/[a-z0-9]{12}',target['cluster_arn'])
                    or not isinstance(target['instance_group'],str) or not re.fullmatch(r'[A-Za-z0-9-]{1,64}',target['instance_group'])
                    or target['entry_script'] not in ('OnCreate','OnInitComplete')):
                raise ValueError('invalid_sagemaker_lifecycle_selection')
        if profile=='sagemaker_training_script':
            arn=target['training_job_arn'];program=target['program']
            if (not isinstance(arn,str) or not re.fullmatch(r'arn:aws:sagemaker:'+region+':'+account+
                    r':training-job/[A-Za-z0-9](?:-*[A-Za-z0-9]){0,62}',arn)
                    or not isinstance(program,str) or not program.endswith('.py')
                    or not 1<=len(program.encode())<=256
                    or any(not re.fullmatch(r'[A-Za-z0-9_.-]+',part) or part in ('.','..') for part in program.split('/'))
                    or not target['source_s3_uri'].lower().endswith('.tar.gz')):
                raise ValueError('invalid_sagemaker_training_script_selection')
        _,_,args=route(target)
        selected=source_target(target)
        if profile=='sagemaker_hyperpod_lifecycle' and not selected['bucket'].startswith('sagemaker-'):
            raise ValueError('invalid_sagemaker_lifecycle_bucket')
        key=json.dumps(selected,sort_keys=True)
        if selected not in selected_s3 or key in sources or identity(target) in seen:
            raise ValueError('workload_requires_exact_selected_s3_source')
        seen.add(identity(target));sources.add(key)
    if enabled(options) and s3.KIND not in options.get('_content_secret_scan_kinds',()):
        delegated={json.dumps(source_target(t),sort_keys=True) for t in targets}
        if 'ecs_selected_environment_file_content' in options.get('_content_secret_scan_kinds',()):
            from .aws_ecs_environment_file_secret_indicators import source_target as ecs_source_target, OPTION as ecs_option
            delegated|={json.dumps(ecs_source_target(t),sort_keys=True) for t in options.get(ecs_option,())}
        if 'build_deployment_referenced_source_content' in options.get('_content_secret_scan_kinds',()):
            from .aws_build_deployment_referenced_source_indicators import source_target as build_source_target, OPTION as build_option
            delegated|={json.dumps(build_source_target(t),sort_keys=True) for t in options.get(build_option,())}
        if delegated!={json.dumps(t,sort_keys=True) for t in selected_s3}:
            raise ValueError('workload_extra_s3_selection')
    return deepcopy(targets)


def identity(target):
    return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))


def initialize(requests,options,scopes):
    targets=selected_targets(options,scopes)
    requests.workload_source_metadata={KIND+'_authorized':enabled(options),KIND+'_capture':'workload-source:'+uuid4().hex,
        KIND+'_selection':{scope:[identity(t) for t in targets if t['scope']==scope] for scope in scopes}}
    requests.workload_source_targets={identity(t):t for t in targets}
    requests.workload_source_calls={};requests.workload_source_grants={}


def _native_client(client,service,region):
    host={'emr':'elasticmapreduce','sagemaker':'api.sagemaker'}.get(service,service)+'.'+region+'.amazonaws.com'
    if (not isinstance(client,BaseClient) or client.meta.service_model.service_name!=service or client.meta.region_name!=region
            or client.meta.endpoint_url not in ('https://'+host,'https://'+host+'/')
            or client._endpoint.host not in ('https://'+host,'https://'+host+'/')):
        raise ValueError('workload_endpoint_unbound')


def profile_call(requests,session,service,region,operation,*,_projection_context,**args):
    from .aws import ReadFailure
    try:
        target=_projection_context['target'];ident=identity(target);account,own_region=s3.SCOPE.fullmatch(target['scope']).groups()
        if (requests.content_secret_scans is not True or KIND not in requests.content_secret_scan_kinds
                or requests.workload_source_metadata[KIND+'_authorized'] is not True
                or ident not in requests.workload_source_metadata[KIND+'_selection'][target['scope']]
                or requests.workload_source_targets[ident]!=target or region!=own_region
                or (service,operation,args)!=route(target)):
            raise ValueError('workload_request_unbound')
        requests.check_deadline()
        with requests._lock:
            if requests.workload_source_calls.get(ident,0)>=2 or requests.max_calls is not None and requests.calls>=requests.max_calls:
                raise ReadFailure('not_collected','workload_source_call_bound')
            requests.workload_source_calls[ident]=requests.workload_source_calls.get(ident,0)+1;requests.calls+=1
        with private_sdk_logs():
            client=requests.client(session,service,region,_metadata_profile='aws-selected-configuration-content-v1')
            _native_client(client,service,region)
            response=getattr(client,operation)(**args)
        return association(response,target)
    except (KeyError,AttributeError,TypeError,ValueError):
        raise ReadFailure('not_collected','workload_source_request_unbound') from None


def association(response,target):
    from .aws_selected_configuration_secret_indicators import response_size
    if not isinstance(response,dict) or any(k in response for k in ('Error','_coverage','NextToken','nextToken')):
        raise ValueError('workload_response_shape')
    response_size(response)
    meta=response.get('ResponseMetadata')
    if (not isinstance(meta,dict) or type(meta.get('HTTPStatusCode')) is not int or meta['HTTPStatusCode']!=200
            or not isinstance(meta.get('RequestId'),str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',meta['RequestId'])):
        raise ValueError('workload_response_provenance')
    profile=target['profile'];uri=target['source_s3_uri']
    if profile=='glue_script':
        row=response.get('Job')
        if not isinstance(row,dict) or row.get('Name')!=target['job_name'] or not isinstance(row.get('Command'),dict) or row['Command'].get('ScriptLocation')!=uri:
            raise ValueError('glue_script_unbound')
        last=row.get('LastModifiedOn')
        if not isinstance(last,datetime):raise ValueError('glue_job_version_unbound')
        binding=(target['job_name'],last.isoformat(),row['Command'].get('Name'),uri)
    elif profile.startswith('emr_serverless_'):
        row=response.get('jobRun');_,_,args=route(target)
        if (not isinstance(row,dict) or row.get('arn')!=target['job_run_arn'] or row.get('applicationId')!=args['applicationId']
                or row.get('jobRunId')!=args['jobRunId'] or type(row.get('attempt')) is not int or row['attempt']!=target['attempt']
                or not isinstance(row.get('jobDriver'),dict)):
            raise ValueError('emr_serverless_identity')
        field='sparkSubmit' if profile in ('emr_serverless_spark','emr_serverless_spark_jar') else 'hive'
        key='entryPoint' if field=='sparkSubmit' else 'initQueryFile' if profile=='emr_serverless_hive_init' else 'query'
        driver=row['jobDriver']
        if set(driver)!={field} or not isinstance(driver[field],dict) or driver[field].get(key)!=uri:
            raise ValueError('emr_serverless_reference')
        binding=(row['arn'],row['attempt'],field,key,uri)
    elif profile=='emr_step_jar':
        row=response.get('Step');_,_,args=route(target)
        if (not isinstance(row,dict) or row.get('Id')!=args['StepId'] or not isinstance(row.get('Config'),dict)
                or row['Config'].get('Jar')!=uri):
            raise ValueError('emr_step_reference')
        binding=(args['ClusterId'],row['Id'],uri)
    elif profile=='sagemaker_training_script':
        _,_,args=route(target)
        params=response.get('HyperParameters')
        if (response.get('TrainingJobArn')!=target['training_job_arn']
                or response.get('TrainingJobName')!=args['TrainingJobName']
                or not isinstance(response.get('CreationTime'),datetime)
                or response['CreationTime'].tzinfo is None
                or response.get('TrainingJobStatus') not in ('InProgress','Completed','Failed','Stopping','Stopped')
                or not isinstance(params,dict)):
            raise ValueError('sagemaker_training_identity')
        def exact_parameter(value,expected):
            if value==expected:return True
            if not isinstance(value,str) or len(value)>2500:return False
            try:return json.loads(value)==expected
            except (ValueError,TypeError):return False
        if (not exact_parameter(params.get('sagemaker_submit_directory'),uri)
                or not exact_parameter(params.get('sagemaker_program'),target['program'])):
            raise ValueError('sagemaker_training_script_reference')
        binding=(target['training_job_arn'],response['CreationTime'].isoformat(),response['TrainingJobStatus'],
            params['sagemaker_submit_directory'],params['sagemaker_program'],uri,target['program'])
    else:
        row=response
        if row.get('ClusterArn')!=target['cluster_arn'] or row.get('ClusterStatus')!='InService':
            raise ValueError('sagemaker_cluster_identity')
        groups=row.get('InstanceGroups')
        if not isinstance(groups,list) or len(groups)>32:raise ValueError('sagemaker_groups_shape')
        found=[g for g in groups if isinstance(g,dict) and g.get('InstanceGroupName')==target['instance_group']]
        if len(found)!=1 or not isinstance(found[0].get('LifeCycleConfig'),dict):raise ValueError('sagemaker_group_identity')
        lifecycle=found[0]['LifeCycleConfig'];base=lifecycle.get('SourceS3Uri');script=lifecycle.get(target['entry_script'])
        if (not isinstance(base,str) or not isinstance(script,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',script)
                or base.rstrip('/')+'/'+script!=uri):raise ValueError('sagemaker_lifecycle_reference')
        binding=(target['cluster_arn'],target['instance_group'],base,script,uri)
    return {'associated':True,'request':_fingerprint(meta['RequestId']),
        'association':_fingerprint(json.dumps(binding,sort_keys=True,separators=(',',':')))}


def collect_selected(requests,session,region,caller,options,scopes):
    from .aws import ReadResult
    if not enabled(options):return ReadResult([],'not_collected',{'code':'workload_source_disabled'})
    targets=selected_targets(options,scopes);rows=[]
    for target in targets:
        account,own_region=s3.SCOPE.fullmatch(target['scope']).groups()
        if own_region!=region or not isinstance(caller,dict) or caller.get('Account')!=account:continue
        ident=identity(target);source=source_target(target)
        marker={'schema':SCHEMA,'identity':ident,'scope':target['scope'],'profile':target['profile'],
            'capture':requests.workload_source_metadata[KIND+'_capture'],'associated':False,
            'native_request':None,'native_after_request':None,'association':None,'association_coherent':False,
            's3_identity':s3.identity(source),'s3_item':None}
        if target['profile']=='sagemaker_training_script':
            marker['entry_member']=_fingerprint(target['program'])
        service,operation,args=route(target)
        # A source-scoped private witness lets the existing alias helper join
        # this exact S3 read to the reference without exposing its object key.
        source_layer='selected-s3-source:'+marker['s3_identity']
        try:
            bound=requests.call(session,service,region,operation,_metadata_profile=PROFILE,_projection_context={'target':target},**args)
            marker.update(associated=True,native_request=bound['request'],association=bound['association'])
            requests.workload_source_grants[marker['s3_identity']]=(id(session),target['scope'],ident)
            try:
                with source_context(layer=source_layer):
                    read=s3.collect_selected(requests,session,region,caller,{s3.OPTION:[source],
                        'content_secret_scans':True,'_content_secret_scan_kinds':[s3.KIND]},scopes)
                if len(read.items)==1 and read.items[0].get('id')==marker['s3_identity']:
                    marker['s3_item']=read.items[0]
            finally:
                requests.workload_source_grants.pop(marker['s3_identity'],None)
            after=requests.call(session,service,region,operation,_metadata_profile=PROFILE,_projection_context={'target':target},**args)
            marker['native_after_request']=after['request'];marker['association_coherent']=after['association']==bound['association']
            if marker['association_coherent'] and marker['s3_item']:
                leaks=marker['s3_item'].get(s3.MARKER,{}).get('leaks',())
                reuse_image_layer(leaks,resource_id=ident,scope=target['scope'],layer=source_layer)
        except Exception:
            pass
        finally:
            requests.workload_source_grants.pop(marker['s3_identity'],None)
        rows.append({'id':ident,MARKER:marker,'_provenance':{'scope':target['scope'],'capture':marker['capture']}})
    return ReadResult(rows) if rows else ReadResult([],'not_collected',{'code':'workload_source_scope_omitted'})

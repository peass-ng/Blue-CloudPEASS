"""Exact CodeBuild, Elastic Beanstalk, and Amplify S3 source declarations."""
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

KIND='build_deployment_referenced_source_content'
CHECK='aws.review.build_deployment.referenced_source_secret_indicators'
OPTION='selected_aws_build_deployment_sources'
PROFILE='aws-build-deployment-referenced-source-v1'
MARKER='BuildDeploymentReferencedSourceSecretIndicators'
SCHEMA='aws-build-deployment-referenced-source-v1'
MAX_TARGETS=4
UUID=r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
PROFILES={
 'codebuild_s3_source':('codebuild','batch_get_projects','zip'),
 'codebuild_s3_buildspec':('codebuild','batch_get_projects','text'),
 'codebuild_build_output':('codebuild','batch_get_builds','zip'),
 'codebuild_codecommit_source':('codebuild','batch_get_builds','text'),
 'codepipeline_action_output':('codepipeline','list_action_executions','zip'),
 'elasticbeanstalk_source_bundle':('elasticbeanstalk','describe_application_versions','zip'),
 'amplify_s3_zip_deployment':('amplify','get_job','zip'),
}


def enabled(options):
    return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds',())


def source_target(target):
    uri=target['source_s3_uri']
    if not isinstance(uri,str) or len(uri)>2048 or not uri.startswith('s3://') or any(ord(c)<32 for c in uri):
        raise ValueError('invalid_source_uri')
    parsed=urlsplit(uri)
    if parsed.scheme!='s3' or not parsed.netloc or not parsed.path.startswith('/') or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port is not None:
        raise ValueError('invalid_source_uri')
    source={'scope':target['scope'],'bucket':parsed.netloc,'key':parsed.path[1:],'format':PROFILES[target['profile']][2]}
    if 'version_id' in target:source['version_id']=target['version_id']
    s3.parse(source)
    return source


def route(target):
    profile=target['profile'];service,operation,_=PROFILES[profile]
    if profile in ('codebuild_build_output','codebuild_codecommit_source'):
        return service,operation,{'ids':[target['build_arn'].split(':build/',1)[1]]}
    if profile=='codepipeline_action_output':
        return service,operation,{'pipelineName':target['pipeline_name'],
            'filter':{'pipelineExecutionId':target['pipeline_execution_id']},'maxResults':100}
    if profile.startswith('codebuild_'):
        return service,operation,{'names':[target['project_arn']]}
    if profile=='elasticbeanstalk_source_bundle':
        return service,operation,{'ApplicationName':target['application_name'],'VersionLabels':[target['version_label']],'MaxRecords':1}
    return service,operation,{'appId':target['app_id'],'branchName':target['branch_name'],'jobId':target['job_id']}


def identity(target):
    return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))


def selected_targets(options,scopes):
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS or not isinstance(scopes,list)
            or len(set(scopes))!=len(scopes) or any(not isinstance(scope,str) or not s3.SCOPE.fullmatch(scope) for scope in scopes)):
        raise ValueError('invalid_build_deployment_selection')
    codecommit_only=all(isinstance(t,dict) and t.get('profile')=='codebuild_codecommit_source' for t in targets)
    s3_peers={'s3_selected_source_content','ecs_selected_environment_file_content','workload_referenced_source_content'}
    selected_s3=([] if codecommit_only and s3.OPTION not in options
                 and not s3_peers.intersection(options.get('_content_secret_scan_kinds',()))
                 else s3.selected_targets(options,scopes))
    seen=set();sources=set()
    for target in targets:
        if not isinstance(target,dict) or target.get('profile') not in PROFILES:raise ValueError('invalid_build_deployment_profile')
        profile=target['profile']
        keys={'profile','scope'} if profile=='codebuild_codecommit_source' else {'profile','scope','source_s3_uri'}
        if profile=='codebuild_codecommit_source':keys|={'build_arn','repository_arn','commit_id','file_path'}
        if profile=='codebuild_build_output':keys|={'build_arn'}
        elif profile=='codepipeline_action_output':keys|={'pipeline_arn','pipeline_name','pipeline_execution_id','action_execution_id','artifact_name'}
        elif profile.startswith('codebuild_') and profile!='codebuild_codecommit_source':keys|={'project_arn'}
        elif profile=='elasticbeanstalk_source_bundle':keys|={'application_name','version_label','version_arn'}
        elif profile=='amplify_s3_zip_deployment':keys|={'app_id','branch_name','job_id','job_arn'}
        if profile=='codebuild_s3_source' and 'version_id' in target:keys.add('version_id')
        if set(target)!=keys or target['scope'] not in scopes:raise ValueError('invalid_build_deployment_selection')
        account,region=s3.SCOPE.fullmatch(target['scope']).groups()
        if region.startswith(('cn-','us-gov-')) or '-iso' in region:raise ValueError('unsupported_partition')
        uri=target.get('source_s3_uri')
        if profile!='codebuild_codecommit_source' and (not isinstance(uri,str) or not 1<=len(uri)<=2048):raise ValueError('invalid_source_uri')
        if profile in ('codebuild_build_output','codebuild_codecommit_source'):
            arn=target['build_arn']
            if (not isinstance(arn,str) or not re.fullmatch(r'arn:aws:codebuild:'+region+':'+account+
                    r':build/[A-Za-z0-9_-]{1,255}:'+UUID,arn)):
                raise ValueError('invalid_codebuild_build')
            if profile=='codebuild_codecommit_source':
                repo=target['repository_arn'];path=target['file_path'];commit=target['commit_id']
                if (not isinstance(repo,str) or not re.fullmatch(r'arn:aws:codecommit:'+region+':'+account+r':[A-Za-z0-9_.-]{1,100}',repo)
                        or not isinstance(commit,str) or re.fullmatch(r'[0-9a-f]{40}',commit) is None
                        or not isinstance(path,str) or not 1<len(path)<=2048 or not path.startswith('/')
                        or path.endswith('/') or any(part in ('','.','..') for part in path[1:].split('/'))
                        or any(ord(c)<32 for c in path)):
                    raise ValueError('invalid_codecommit_selection')
        elif profile=='codepipeline_action_output':
            name=target['pipeline_name']
            if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9.@_-]{1,100}',name)
                    or target['pipeline_arn']!='arn:aws:codepipeline:'+region+':'+account+':'+name
                    or not isinstance(target['pipeline_execution_id'],str) or not re.fullmatch(UUID,target['pipeline_execution_id'])
                    or not isinstance(target['action_execution_id'],str) or not re.fullmatch(UUID,target['action_execution_id'])
                    or not isinstance(target['artifact_name'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',target['artifact_name'])):
                raise ValueError('invalid_codepipeline_action')
        elif profile.startswith('codebuild_'):
            if not isinstance(target['project_arn'],str) or not re.fullmatch(r'arn:aws:codebuild:'+region+':'+account+r':project/[A-Za-z0-9][A-Za-z0-9_./-]{0,254}',target['project_arn']):
                raise ValueError('invalid_codebuild_project')
            if profile=='codebuild_s3_source' and not uri.lower().endswith('.zip') or profile=='codebuild_s3_buildspec' and not uri.lower().endswith(('.yml','.yaml')):
                raise ValueError('unsupported_codebuild_format')
        elif profile=='elasticbeanstalk_source_bundle':
            if (not isinstance(target['application_name'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',target['application_name'])
                    or not isinstance(target['version_label'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',target['version_label'])
                    or target['version_arn']!='arn:aws:elasticbeanstalk:'+region+':'+account+':applicationversion/'+target['application_name']+'/'+target['version_label']
                    or not uri.lower().endswith(('.zip','.war'))):raise ValueError('invalid_application_version')
        else:
            if (not isinstance(target['app_id'],str) or not re.fullmatch(r'd[a-z0-9]{1,19}',target['app_id'])
                    or not isinstance(target['branch_name'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',target['branch_name'])
                    or not isinstance(target['job_id'],str) or not re.fullmatch(r'[0-9]{1,255}',target['job_id'])
                    or target['job_arn']!='arn:aws:amplify:'+region+':'+account+':apps/'+target['app_id']+'/branches/'+target['branch_name']+'/jobs/'+target['job_id']
                    or not uri.lower().endswith('.zip')):raise ValueError('invalid_amplify_job')
        if profile=='codebuild_codecommit_source':
            if identity(target) in seen:raise ValueError('duplicate_build_deployment_selection')
            seen.add(identity(target));continue
        source=source_target(target);key=json.dumps(source,sort_keys=True)
        if source not in selected_s3 or key in sources or identity(target) in seen:raise ValueError('build_deployment_requires_exact_selected_s3_source')
        seen.add(identity(target));sources.add(key)
    if enabled(options) and s3.KIND not in options.get('_content_secret_scan_kinds',()):
        delegated={json.dumps(source_target(t),sort_keys=True) for t in targets if t['profile']!='codebuild_codecommit_source'}
        if 'ecs_selected_environment_file_content' in options.get('_content_secret_scan_kinds',()):
            from .aws_ecs_environment_file_secret_indicators import source_target as source, OPTION as option
            delegated|={json.dumps(source(t),sort_keys=True) for t in options.get(option,())}
        if 'workload_referenced_source_content' in options.get('_content_secret_scan_kinds',()):
            from .aws_workload_referenced_source_indicators import source_target as source, OPTION as option
            delegated|={json.dumps(source(t),sort_keys=True) for t in options.get(option,())}
        if delegated!={json.dumps(t,sort_keys=True) for t in selected_s3}:raise ValueError('build_deployment_extra_s3_selection')
    return deepcopy(targets)


def initialize(requests,options,scopes):
    targets=selected_targets(options,scopes)
    requests.build_deployment_metadata={KIND+'_authorized':enabled(options),KIND+'_capture':'build-deployment:'+uuid4().hex,
        KIND+'_selection':{scope:[identity(t) for t in targets if t['scope']==scope] for scope in scopes}}
    requests.build_deployment_targets={identity(t):t for t in targets}
    requests.build_deployment_calls={};requests.build_deployment_grants={}


def _native_client(client,service,region):
    host=service+'.'+region+'.amazonaws.com'
    if (not isinstance(client,BaseClient) or client.meta.service_model.service_name!=service or client.meta.region_name!=region
            or client.meta.endpoint_url not in ('https://'+host,'https://'+host+'/') or client._endpoint.host not in ('https://'+host,'https://'+host+'/')):
        raise ValueError('build_deployment_endpoint_unbound')


def profile_call(requests,session,service,region,operation,*,_projection_context,**args):
    from .aws import ReadFailure
    try:
        target=_projection_context['target'];ident=identity(target);account,own_region=s3.SCOPE.fullmatch(target['scope']).groups()
        if (requests.content_secret_scans is not True or KIND not in requests.content_secret_scan_kinds
                or requests.build_deployment_metadata[KIND+'_authorized'] is not True
                or ident not in requests.build_deployment_metadata[KIND+'_selection'][target['scope']]
                or requests.build_deployment_targets[ident]!=target or region!=own_region
                or (service,operation,args)!=route(target)):
            raise ValueError('build_deployment_request_unbound')
        requests.check_deadline()
        with requests._lock:
            if requests.build_deployment_calls.get(ident,0)>=2 or requests.max_calls is not None and requests.calls>=requests.max_calls:
                raise ReadFailure('not_collected','build_deployment_call_bound')
            requests.build_deployment_calls[ident]=requests.build_deployment_calls.get(ident,0)+1;requests.calls+=1
        with private_sdk_logs():
            client=requests.client(session,service,region,_metadata_profile='aws-selected-configuration-content-v1')
            _native_client(client,service,region)
            response=getattr(client,operation)(**args)
        return association(response,target)
    except (KeyError,AttributeError,TypeError,ValueError):
        raise ReadFailure('not_collected','build_deployment_request_unbound') from None


def association(response,target):
    from .aws_selected_configuration_secret_indicators import response_size
    if not isinstance(response,dict) or any(k in response for k in ('Error','_coverage','NextToken','nextToken')):raise ValueError('build_deployment_response_shape')
    response_size(response)
    meta=response.get('ResponseMetadata')
    if (not isinstance(meta,dict) or type(meta.get('HTTPStatusCode')) is not int or meta['HTTPStatusCode']!=200
            or not isinstance(meta.get('RequestId'),str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',meta['RequestId'])):
        raise ValueError('build_deployment_response_provenance')
    profile=target['profile'];uri=target.get('source_s3_uri')
    source=source_target(target) if profile!='codebuild_codecommit_source' else None
    if profile=='codepipeline_action_output':
        rows=response.get('actionExecutionDetails')
        if (not isinstance(rows,list) or not 1<=len(rows)<=100
                or any(not isinstance(row,dict) or row.get('pipelineExecutionId')!=target['pipeline_execution_id'] for row in rows)):
            raise ValueError('codepipeline_execution_shape')
        matches=[row for row in rows if row.get('actionExecutionId')==target['action_execution_id']]
        if len(matches)!=1:raise ValueError('codepipeline_action_identity')
        row=matches[0];output=row.get('output')
        artifacts=output.get('outputArtifacts') if isinstance(output,dict) else None
        if (row.get('status')!='Succeeded' or type(row.get('pipelineVersion')) is not int
                or row['pipelineVersion']<1 or not isinstance(row.get('stageName'),str)
                or not isinstance(row.get('actionName'),str) or not isinstance(artifacts,list)
                or not 1<=len(artifacts)<=32 or any(not isinstance(a,dict) for a in artifacts)):
            raise ValueError('codepipeline_action_output_shape')
        matched=[a for a in artifacts if a.get('name')==target['artifact_name']]
        if len(matched)!=1 or len({a.get('name') for a in artifacts})!=len(artifacts):
            raise ValueError('codepipeline_artifact_ambiguous')
        location=matched[0].get('s3location')
        if (not isinstance(location,dict) or location.get('bucket')!=source['bucket']
                or location.get('key')!=source['key']):raise ValueError('codepipeline_artifact_location')
        binding=(target['pipeline_arn'],row['pipelineExecutionId'],row['actionExecutionId'],
            row['pipelineVersion'],row['stageName'],row['actionName'],row['status'],
            target['artifact_name'],location['bucket'],location['key'])
    elif profile in ('codebuild_build_output','codebuild_codecommit_source'):
        rows=response.get('builds')
        if (not isinstance(rows,list) or len(rows)!=1 or response.get('buildsNotFound') not in (None,[])):
            raise ValueError('codebuild_build_shape')
        row=rows[0];arn=target['build_arn'];build_id=arn.split(':build/',1)[1]
        artifact=row.get('artifacts') if isinstance(row,dict) else None
        if profile=='codebuild_codecommit_source':
            repo=target['repository_arn'].rsplit(':',1)[1]
            location='https://git-codecommit.'+target['scope'].split('/',1)[1]+'.amazonaws.com/v1/repos/'+repo
            spec=row.get('source') if isinstance(row,dict) else None
            if (not isinstance(row,dict) or row.get('arn')!=arn or row.get('id')!=build_id
                    or row.get('projectName')!=build_id.split(':',1)[0]
                    or row.get('buildComplete') is not True or row.get('buildStatus') not in ('SUCCEEDED','FAILED','FAULT','TIMED_OUT','STOPPED')
                    or not isinstance(row.get('endTime'),datetime) or row['endTime'].tzinfo is None
                    or not isinstance(spec,dict) or spec.get('type')!='CODECOMMIT'
                    or spec.get('location')!=location or row.get('resolvedSourceVersion')!=target['commit_id']):
                raise ValueError('codebuild_codecommit_source_unbound')
            binding=(arn,build_id,row['projectName'],row['buildStatus'],row['endTime'].isoformat(),
                     spec['type'],spec['location'],row['resolvedSourceVersion'])
            return {'associated':True,'request':_fingerprint(meta['RequestId']),
                'association':_fingerprint(json.dumps(binding,sort_keys=True,separators=(',',':')))}
        if (row.get('arn')!=arn or row.get('id')!=build_id
                or row.get('projectName')!=build_id.split(':',1)[0]
                or row.get('buildStatus')!='SUCCEEDED' or row.get('buildComplete') is not True
                or not isinstance(row.get('endTime'),datetime) or row['endTime'].tzinfo is None
                or not isinstance(artifact,dict)
                or artifact.get('location')!='arn:aws:s3:::'+source['bucket']+'/'+source['key']):
            raise ValueError('codebuild_artifact_location')
        binding=(arn,build_id,row['projectName'],row['buildStatus'],row['endTime'].isoformat(),
            artifact['location'],artifact.get('sha256sum'))
    elif profile.startswith('codebuild_'):
        rows=response.get('projects')
        if not isinstance(rows,list) or len(rows)!=1 or response.get('projectsNotFound') not in (None,[]):raise ValueError('codebuild_project_shape')
        row=rows[0];project=target['project_arn']
        if (not isinstance(row,dict) or row.get('arn')!=project or row.get('name')!=project.split(':project/',1)[1]
                or not isinstance(row.get('lastModified'),datetime) or not isinstance(row.get('source'),dict)):
            raise ValueError('codebuild_project_identity')
        spec=row['source']
        if profile=='codebuild_s3_source':
            if spec.get('type')!='S3' or spec.get('location')!=source['bucket']+'/'+source['key']:
                raise ValueError('codebuild_source_reference')
            if row.get('sourceVersion')!=target.get('version_id'):
                raise ValueError('codebuild_source_version')
        else:
            if spec.get('buildspec')!='arn:aws:s3:::'+source['bucket']+'/'+source['key']:
                raise ValueError('codebuild_buildspec_reference')
        binding=(project,row['lastModified'].isoformat(),spec.get('type'),spec.get('location'),spec.get('buildspec'),row.get('sourceVersion'),uri)
    elif profile=='elasticbeanstalk_source_bundle':
        rows=response.get('ApplicationVersions')
        if not isinstance(rows,list) or len(rows)!=1:raise ValueError('beanstalk_version_shape')
        row=rows[0];bundle=row.get('SourceBundle') if isinstance(row,dict) else None
        if (row.get('ApplicationVersionArn')!=target['version_arn'] or row.get('ApplicationName')!=target['application_name']
                or row.get('VersionLabel')!=target['version_label'] or not isinstance(row.get('DateUpdated'),datetime)
                or not isinstance(bundle,dict) or bundle.get('S3Bucket')!=source['bucket'] or bundle.get('S3Key')!=source['key']):
            raise ValueError('beanstalk_source_reference')
        binding=(row['ApplicationVersionArn'],row['DateUpdated'].isoformat(),bundle['S3Bucket'],bundle['S3Key'])
    else:
        job=response.get('job');summary=job.get('summary') if isinstance(job,dict) else None
        if (not isinstance(summary,dict) or summary.get('jobArn')!=target['job_arn'] or summary.get('jobId')!=target['job_id']
                or summary.get('sourceUrl')!=uri or summary.get('sourceUrlType') not in (None,'ZIP')
                or summary.get('jobType')!='MANUAL' or not isinstance(summary.get('commitTime'),datetime)
                or not isinstance(summary.get('commitId'),str)):
            raise ValueError('amplify_job_reference')
        binding=(summary['jobArn'],summary['jobId'],summary['commitId'],summary['commitTime'].isoformat(),summary['sourceUrl'],summary.get('sourceUrlType'))
    return {'associated':True,'request':_fingerprint(meta['RequestId']),
        'association':_fingerprint(json.dumps(binding,sort_keys=True,separators=(',',':')))}


def _codecommit_call(requests,session,region,operation,**arguments):
    """One selected SDK read; no Git transport, cache, URL, or response logging."""
    from .aws import ReadFailure
    requests.check_deadline()
    with requests._lock:
        if requests.max_calls is not None and requests.calls>=requests.max_calls:
            raise ReadFailure('not_collected','codecommit_call_bound')
        requests.calls+=1
    with private_sdk_logs():
        client=requests.client(session,'codecommit',region,_metadata_profile='aws-selected-configuration-content-v1')
        _native_client(client,'codecommit',region)
        return getattr(client,operation)(**arguments)


def _successful_response(response):
    meta=response.get('ResponseMetadata') if isinstance(response,dict) else None
    if (not isinstance(meta,dict) or type(meta.get('HTTPStatusCode')) is not int
            or meta['HTTPStatusCode']!=200 or not isinstance(meta.get('RequestId'),str)
            or re.fullmatch(r'[A-Za-z0-9-]{1,128}',meta['RequestId']) is None):
        raise ValueError('codecommit_response_provenance')


def _codecommit_metadata(response,target):
    _successful_response(response)
    repo=target['repository_arn'].rsplit(':',1)[1]
    row=response.get('repositoryMetadata') if isinstance(response,dict) else None
    if (not isinstance(row,dict) or row.get('repositoryName')!=repo
            or row.get('Arn')!=target['repository_arn']
            or row.get('accountId')!=target['scope'].split('/',1)[0]
            or not isinstance(row.get('repositoryId'),str)
            or not re.fullmatch(r'[A-Za-z0-9-]{8,128}',row['repositoryId'])):
        raise ValueError('codecommit_repository_unbound')
    return row['repositoryId']


def _codecommit_file_shape(response,target):
    _successful_response(response)
    if (not isinstance(response,dict) or response.get('commitId')!=target['commit_id']
            or response.get('filePath')!=target['file_path']
            or response.get('fileMode') not in ('NORMAL','EXECUTABLE')
            or not isinstance(response.get('blobId'),str)
            or re.fullmatch(r'[0-9a-f]{40}',response['blobId']) is None
            or not isinstance(response.get('fileContent'),bytes)
            or type(response.get('fileSize')) is not int
            or not 0<response['fileSize']<=6291456
            or len(response['fileContent'])!=response['fileSize']):
        raise ValueError('codecommit_file_unbound')
    return (response['commitId'],response['blobId'],response['filePath'],
            response['fileMode'],response['fileSize'])


def _is_termination(exc):
    from .aws import ReadFailure
    return isinstance(exc,ReadFailure) and exc.code in (
        'collection_cancelled','intentional_scan_deadline','deadline_exceeded')


def _collect_codecommit(requests,session,region,target,marker):
    from . import aws_code_log_content_indicators as code
    repo=target['repository_arn'].rsplit(':',1)[1]
    arguments={'repositoryName':repo,'commitSpecifier':target['commit_id'],'filePath':target['file_path']}
    before=_codecommit_metadata(_codecommit_call(requests,session,region,'get_repository',repositoryName=repo),target)
    response=_codecommit_call(requests,session,region,'get_file',**arguments)
    first=_codecommit_file_shape(response,target)
    with source_context(layer='selected-codecommit-source:'+marker['identity']):
        projected=code.project_response(response,'codecommit','get_file',arguments,
            request_context={'remaining_bytes':code.MAX_BYTES},region=region)['value']
    del response
    marker['codecommit_item']={'leaks':projected.get('leaks',[]),
        'complete':projected.get('scanner_complete') is True and projected.get('readable') is True,
        'inspected_bytes':projected['inspected_bytes']}
    after=_codecommit_metadata(_codecommit_call(requests,session,region,'get_repository',repositoryName=repo),target)
    response=_codecommit_call(requests,session,region,'get_file',**arguments)
    second=_codecommit_file_shape(response,target)
    del response
    marker['association_coherent']=(before==after and first==second)
    marker['native_after_request']=_fingerprint(json.dumps([after,second],sort_keys=True))


def collect_selected(requests,session,region,caller,options,scopes):
    from .aws import ReadResult
    if not enabled(options):return ReadResult([],'not_collected',{'code':'build_deployment_disabled'})
    targets=selected_targets(options,scopes);rows=[]
    for target in targets:
        account,own_region=s3.SCOPE.fullmatch(target['scope']).groups()
        if own_region!=region or not isinstance(caller,dict) or caller.get('Account')!=account:continue
        if target['profile']=='codebuild_codecommit_source':
            ident=identity(target)
            marker={'schema':SCHEMA,'identity':ident,'scope':target['scope'],'profile':target['profile'],
                'capture':requests.build_deployment_metadata[KIND+'_capture'],'associated':False,
                'native_request':None,'native_after_request':None,'association':None,
                'association_coherent':False,'codecommit_item':None}
            service,operation,args=route(target)
            try:
                bound=requests.call(session,service,region,operation,_metadata_profile=PROFILE,
                    _projection_context={'target':target},**args)
                marker.update(associated=True,native_request=bound['request'],association=bound['association'])
                try:_collect_codecommit(requests,session,region,target,marker)
                except Exception as exc:
                    if _is_termination(exc):raise
                after=requests.call(session,service,region,operation,_metadata_profile=PROFILE,
                    _projection_context={'target':target},**args)
                marker['native_after_request']=after['request']
                marker['association_coherent']=marker['association_coherent'] and after['association']==bound['association']
                if marker['association_coherent'] and marker['codecommit_item']:
                    reuse_image_layer(marker['codecommit_item']['leaks'],
                        resource_id=ident,scope=target['scope'],layer='selected-codecommit-source:'+ident)
            except Exception as exc:
                marker['association_coherent']=False
                marker['native_after_request']=None
                if _is_termination(exc):raise
            rows.append({'id':ident,MARKER:marker,'_provenance':{'scope':target['scope'],'capture':marker['capture']}})
            continue
        ident=identity(target);source=source_target(target)
        marker={'schema':SCHEMA,'identity':ident,'scope':target['scope'],'profile':target['profile'],
            'capture':requests.build_deployment_metadata[KIND+'_capture'],'associated':False,
            'native_request':None,'native_after_request':None,'association':None,'association_coherent':False,
            's3_identity':s3.identity(source),'s3_item':None}
        service,operation,args=route(target)
        # A source-scoped private witness lets the existing alias helper join
        # this exact S3 read to the reference without exposing its object key.
        source_layer='selected-s3-source:'+marker['s3_identity']
        try:
            bound=requests.call(session,service,region,operation,_metadata_profile=PROFILE,_projection_context={'target':target},**args)
            marker.update(associated=True,native_request=bound['request'],association=bound['association'])
            requests.build_deployment_grants[marker['s3_identity']]=(id(session),target['scope'],ident)
            try:
                with source_context(layer=source_layer):
                    read=s3.collect_selected(requests,session,region,caller,{s3.OPTION:[source],
                        'content_secret_scans':True,'_content_secret_scan_kinds':[s3.KIND]},scopes)
                if len(read.items)==1 and read.items[0].get('id')==marker['s3_identity']:
                    marker['s3_item']=read.items[0]
            finally:requests.build_deployment_grants.pop(marker['s3_identity'],None)
            after=requests.call(session,service,region,operation,_metadata_profile=PROFILE,_projection_context={'target':target},**args)
            marker['native_after_request']=after['request'];marker['association_coherent']=after['association']==bound['association']
            if marker['association_coherent'] and marker['s3_item']:
                leaks=marker['s3_item'].get(s3.MARKER,{}).get('leaks',())
                reuse_image_layer(leaks,resource_id=ident,scope=target['scope'],layer=source_layer)
        except Exception as exc:
            if _is_termination(exc):raise
        finally:requests.build_deployment_grants.pop(marker['s3_identity'],None)
        rows.append({'id':ident,MARKER:marker,'_provenance':{'scope':target['scope'],'capture':marker['capture']}})
    return ReadResult(rows) if rows else ReadResult([],'not_collected',{'code':'build_deployment_scope_omitted'})

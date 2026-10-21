"""Selected Flex Function configured deployment-container archives; never active code."""
from copy import deepcopy
from datetime import datetime,timezone
from email.utils import format_datetime
import http.client
import json
import re
import time
from urllib.parse import urlsplit
from uuid import uuid4
from xml.etree import ElementTree
from peaso.secret_evidence import reuse_image_layer, source_context
from peaso.secret_scanning import _fingerprint
from . import azure_selected_storage_secret_indicators as storage
from . import azure_app_settings_secret_indicators as settings
from .azure_function_settings_declarations_20261020 import private_native_logs

KIND='azure_flex_configured_deployment_archives'
CHECK='azure.review.function.configured_deployment_container_archives_secret_indicators'
OPTION='selected_azure_flex_deployment_containers'
MARKER='ConfiguredFlexDeploymentArchives'
SCHEMA='azure-flex-configured-deployment-archives-v1'
SITE_VERSION='2025-03-01'
MAX_TARGETS=2
MAX_ARCHIVES=4
MAX_LIST=65536
MAX_CALLS=32
MAX_SECONDS=120

class Incomplete(ValueError):pass

def identity(target):
    return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')).casefold())

def selected_targets(options,scopes):
    if not isinstance(options,dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise Incomplete('invalid_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list) or not 1<=len(scopes)<=8 or any(not isinstance(s,str) or not storage.SCOPE.fullmatch(s) for s in scopes)
            or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise Incomplete('invalid_selection')
    seen=set()
    for target in targets:
        if not isinstance(target,dict) or set(target)!={'site_resource_id','storage_account_resource_id','container'}:
            raise Incomplete('invalid_selection')
        site=target['site_resource_id'];account=target['storage_account_resource_id'];container=target['container']
        sm=settings._RESOURCE.fullmatch(site) if isinstance(site,str) and len(site)<=512 else None
        am=storage.ACCOUNT.fullmatch(account) if isinstance(account,str) and len(account)<=512 else None
        if (not sm or sm[4] is not None or not am or '/.' in site or '/.' in account
                or sm[1].casefold()!=am[1].casefold() or sm[1].casefold() not in {s.casefold() for s in scopes}
                or not isinstance(container,str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])',container)
                or '--' in container or identity(target) in seen):raise Incomplete('invalid_selection')
        seen.add(identity(target))
    return deepcopy(targets)

def enabled(options):
    return (options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds',())
            and CHECK in options.get('_azure_flex_named_checks',()))

def _provisional(target):
    return {'service':'blob','resource_id':target['storage_account_resource_id'],'container':target['container'],
            'object':'provisional.zip','format':'zip'}

def _origin(target):
    m=storage.ACCOUNT.fullmatch(target['storage_account_resource_id'])
    return 'https://'+m[3].lower()+'.blob.core.windows.net/'+target['container']

def _site(data,target):
    site=target['site_resource_id'];match=settings._RESOURCE.fullmatch(site)
    if (not isinstance(data,dict) or set(data)&{'error','nextLink','partial','_coverage'}
            or str(data.get('id','')).casefold()!=site.casefold()
            or str(data.get('type','')).casefold()!='microsoft.web/sites'
            or str(data.get('name','')).casefold()!=match[3].casefold()
            or not isinstance(data.get('kind'),str) or 'functionapp' not in {x.strip().lower() for x in data['kind'].split(',')}
            or 'linux' not in {x.strip().lower() for x in data['kind'].split(',')}):raise Incomplete('site_identity')
    props=data.get('properties');config=props.get('functionAppConfig') if isinstance(props,dict) else None
    deployment=config.get('deployment') if isinstance(config,dict) else None
    location=deployment.get('storage') if isinstance(deployment,dict) else None
    if (not isinstance(location,dict) or location.get('type')!='blobContainer' or location.get('value')!=_origin(target)):
        raise Incomplete('configured_container_mismatch')
    # Hash the whole selected site representation to detect native changes without exporting settings.
    return _fingerprint(json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False))

def _http(reader,transport,state,operation,host,path,*,blob=False):
    storage.remaining(reader,state)
    if state['total_calls']>=MAX_CALLS:raise Incomplete('flex_call_bound')
    state['total_calls']+=1
    token=storage._token(transport,storage.STORAGE if blob else storage.ARM,state)
    headers={'Authorization':'Bearer '+token,'Accept-Encoding':'identity','Accept':'application/xml' if blob else 'application/json'}
    if blob:headers.update({'x-ms-version':storage.DATA_VERSION,'x-ms-date':format_datetime(datetime.now(timezone.utc),usegmt=True)})
    response=connection=None
    try:
        connection=http.client.HTTPSConnection(host,timeout=storage.remaining(reader,state));connection.set_debuglevel(0)
        connection.request('GET',path,body=None,headers=headers);del token
        response=connection.getresponse()
        if (type(response.status) is not int or response.status!=200 or response.getheader('Transfer-Encoding') is not None
                or response.getheader('Content-Encoding') not in (None,'','identity') or response.getheader('Content-Range') is not None
                or (response.getheader('Content-Type') or '').split(';')[0].strip().lower()!=('application/xml' if blob else 'application/json')
                or blob and response.getheader('x-ms-version')!=storage.DATA_VERSION):raise Incomplete('flex_read_unavailable')
        length=response.getheader('Content-Length');request_id=response.getheader('x-ms-request-id')
        cap=MAX_LIST if blob else storage.MAX_ARM
        if (not isinstance(length,str) or not re.fullmatch('[0-9]{1,10}',length) or not 1<=int(length)<=cap
                or not isinstance(request_id,str) or not re.fullmatch('[A-Za-z0-9-]{1,128}',request_id)):
            raise Incomplete('flex_response_bound')
        raw=bytearray()
        while True:
            storage.remaining(reader,state);chunk=response.read(min(16384,cap+1-len(raw)))
            if not isinstance(chunk,bytes):raise Incomplete('flex_stream_shape')
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>cap:raise Incomplete('flex_response_bound')
        if len(raw)!=int(length):raise Incomplete('flex_truncated')
        return bytes(raw)
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()

def _list(raw,target):
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():raise Incomplete('unsupported_listing')
    try:root=ElementTree.fromstring(raw)
    except ElementTree.ParseError:raise Incomplete('malformed_listing') from None
    if (root.tag!='EnumerationResults' or root.attrib.get('ServiceEndpoint')!=_origin(target).rsplit('/',1)[0]+'/'
            or root.attrib.get('ContainerName')!=target['container'] or root.findtext('NextMarker') not in (None,'')):
        raise Incomplete('listing_identity_or_truncation')
    blobs=root.find('Blobs')
    if blobs is None or len(blobs)>MAX_ARCHIVES or any(row.tag!='Blob' for row in blobs):raise Incomplete('listing_bound')
    result=[];seen=set()
    for row in blobs:
        name=row.findtext('Name');props=row.find('Properties')
        if (not isinstance(name,str) or not name.lower().endswith('.zip') or props is None
                or props.findtext('BlobType')!='BlockBlob' or name in seen):raise Incomplete('unsupported_listing_object')
        candidate={'service':'blob','resource_id':target['storage_account_resource_id'],'container':target['container'],'object':name,'format':'zip'}
        storage.parse(candidate)
        etag=props.findtext('Etag');length=props.findtext('Content-Length')
        if (not isinstance(etag,str) or not re.fullmatch(r'"[A-Za-z0-9-]{1,128}"',etag)
                or not isinstance(length,str) or not length.isdecimal() or not 1<=int(length)<=storage.MAX_OBJECT):
            raise Incomplete('listing_object_metadata')
        seen.add(name);result.append((name,etag,int(length)))
    if not result:raise Incomplete('empty_deployment_container')
    return tuple(sorted(result))

def _one(reader,transport,target):
    blob=_provisional(target);scope=storage.parse(blob)[1];capture='flex-archives:'+uuid4().hex
    marker={'schema':SCHEMA,'identity':identity(target),'scope':scope,'capture':capture,'configured_container':False,
            'native_stable':False,'listing_stable':False,'complete':False,'reason':'incomplete','tenant':None,'principal':None,
            'archive_count':0,'archives':[],'listing_locator':None,'receipts':[]}
    receipts=[];child_layers=[];state={'capture':capture,'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0,'total_calls':0,
                       'expanded':0,'members':0,'authority':None}
    try:
        def read(operation,host,path,method,cap):
            state['total_calls']+=1
            if state['total_calls']>MAX_CALLS:raise Incomplete('flex_call_bound')
            return reader.call(storage._read,reader,transport,state,receipts,blob,operation,host,path,method,cap)
        sub=read('subscription','management.azure.com',scope+'?api-version='+storage.SUB_VERSION,'GET',storage.MAX_ARM)
        storage._bound_subscription(sub,scope,state)
        account=read('account','management.azure.com',target['storage_account_resource_id']+'?api-version='+storage.ARM_VERSION,'GET',storage.MAX_ARM)
        storage._bound_account(account,blob)
        site_path=target['site_resource_id']+'?api-version='+SITE_VERSION
        site_before=_site(reader.call(_arm_json,reader,transport,state,'site_before',site_path),target)
        host=storage.parse(blob)[3]+'.blob.core.windows.net'
        list_path='/'+target['container']+'?restype=container&comp=list&maxresults=5'
        before=_list(reader.call(_http,reader,transport,state,'list_before',host,list_path,blob=True),target)
        marker.update(configured_container=True,tenant=state['authority']['tenant'],principal=state['authority']['principal'],
                      archive_count=len(before),listing_locator='flex-list:'+_fingerprint(json.dumps(before)))
        for name,etag,length in before:
            exact={**blob,'object':name}
            child_id=storage.identity(exact)
            child_layer='flex-selected-archive:'+identity(target)+':'+child_id
            child_state={'capture':capture,'deadline':state['deadline'],'bytes':0,'calls':0,'expanded':0,'members':0,
                         'authority':state['authority']}
            with source_context(layer=child_layer,scope=scope):
                child=storage._one(reader,transport,child_state,exact,receipts)
            state['total_calls']+=child_state['calls']
            if state['total_calls']>MAX_CALLS:raise Incomplete('flex_call_bound')
            found=child[storage.MARKER]
            if child['id']!=child_id or found['identity']!=child_id:raise Incomplete('archive_identity')
            marker['archives'].append(child)
            if found['etag_locator'] is not None and found['etag_locator']!='storage-source-etag:'+_fingerprint(etag):
                raise Incomplete('listing_etag_drift')
            if found['native_complete'] and found['object_bytes']!=length:raise Incomplete('listing_length_drift')
            child_layers.append((child,child_layer))
        after=_list(reader.call(_http,reader,transport,state,'list_after',host,list_path,blob=True),target)
        site_after=_site(reader.call(_arm_json,reader,transport,state,'site_after',site_path),target)
        account_after=read('account','management.azure.com',target['storage_account_resource_id']+'?api-version='+storage.ARM_VERSION,'GET',storage.MAX_ARM)
        storage._bound_account(account_after,blob)
        marker['listing_stable']=before==after
        marker['native_stable']=site_before==site_after and account==account_after
        if marker['native_stable'] and marker['listing_stable']:
            for child,child_layer in child_layers:
                found=child[storage.MARKER]
                if found['native_complete']:
                    reuse_image_layer(found['leaks'],resource_id=identity(target),scope=scope,layer=child_layer)
        marker['complete']=bool(marker['native_stable'] and marker['listing_stable'] and
                                all(c[storage.MARKER]['complete'] for c in marker['archives']))
        marker['reason']='complete' if marker['complete'] else 'incomplete'
    except Exception:
        pass
    marker['receipts']=deepcopy(receipts)
    return {'id':identity(target),MARKER:marker,'_provenance':{'scope':scope,'capture':capture}}

def _arm_json(reader,transport,state,operation,path):
    raw=_http(reader,transport,state,operation,'management.azure.com',path)
    value=storage._json(raw)
    if not isinstance(value,dict) or set(value)&{'error','nextLink','partial','_coverage'}:raise Incomplete('arm_shape')
    return value

def collect(reader,transport,scopes,wanted,options):
    if KIND not in wanted:return
    targets=selected_targets(options,scopes)
    reader.flex_archive_metadata={KIND+'_authorized':enabled(options),KIND+'_selection':{s:[identity(t) for t in targets if settings._RESOURCE.fullmatch(t['site_resource_id'])[1].casefold()==s.casefold()] for s in scopes}}
    if not enabled(options):return
    if not hasattr(reader,'storage_source_secret_redactions'):
        reader.storage_source_secret_redactions=set();reader.storage_source_secret_overflow=False
    with private_native_logs():
        for scope in scopes:
            named=[t for t in targets if settings._RESOURCE.fullmatch(t['site_resource_id'])[1].casefold()==scope.casefold()]
            if named:
                def fetch(named=named):yield [_one(reader,transport,t) for t in named]
                reader.run([(KIND,scope,'Microsoft.Web',fetch)])

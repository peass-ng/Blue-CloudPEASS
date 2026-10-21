"""Selected immutable ACR images; bounded TLS reads and memory-only inspection.

No challenge-derived hosts, catalog/tag enumeration, registry credentials export,
container execution, filesystem extraction, credential validation or raw cache.
"""
from peaso.secret_evidence import scan_with_source, source_context
from copy import deepcopy
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import re
import tarfile
import time
from urllib.parse import urlencode, urlsplit
from .gcp_image_secret_indicators import _tar, _descriptor, DIGEST
from .aws_package_content_indicators import _json, OCI, DOCKER, TAR_TYPES, CONFIG_TYPES
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from peaso import oci_index_20261021 as oci_index

KIND = 'acr_selected_image'
CHECK = 'azure.review.acr.selected_image_secret_indicators'
OPTION = 'selected_azure_acr_images'
MARKER = 'SelectedAcrImageSecretIndicators'
SCHEMA = 'azure-selected-acr-image-secrets-v1'
ARM = 'management.azure.com'
ACR_AUDIENCE = 'https://containerregistry.azure.net'
API_VERSION = '2025-11-01'
MAX_IMAGES = 4
MAX_MANIFEST = 262144
MAX_CONFIG = 1048576
MAX_LAYER = 512 * 1024 * 1024
MAX_IMAGE = 1024 * 1024 * 1024
MAX_TOTAL = MAX_IMAGES * MAX_IMAGE + MAX_IMAGES * (MAX_MANIFEST + MAX_CONFIG + 65536)
MAX_EXPANDED = 4 * 1024 * 1024 * 1024
MAX_MEMBERS = 200000
MAX_LAYERS = 64
MAX_CALLS = 320
MAX_SECONDS = 600
MAX_LEAKS = 256
MAX_LOCATIONS = 2000
MAX_PARTS = 8192
_GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_SCOPE = re.compile(r'/subscriptions/' + _GUID + r'\Z', re.I)
_REGISTRY = re.compile(r'(/subscriptions/' + _GUID + r')/resourceGroups/'
    r'([A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-])'
    r'/providers/Microsoft\.ContainerRegistry/registries/([A-Za-z0-9]{5,50})\Z', re.I)
_REPOSITORY = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z')
MODES = {'LegacyRegistryPermissions', 'AbacRepositoryPermissions'}


class Incomplete(ValueError):
    """Stable safe failures; no provider details, token, URL or content text."""


def enabled(options):
    return (options.get('content_secret_scans') is True
            and isinstance(options.get('_content_secret_scan_kinds'), list)
            and KIND in options['_content_secret_scan_kinds'])


def selected_targets(options, scopes):
    """Exported credential-free public validator; preserve exact routing IDs."""
    if not isinstance(options, dict) or ('content_secret_scans' in options
            and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_acr_selection')
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not _SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_IMAGES):
        raise Incomplete('invalid_acr_selection')
    seen = set()
    for t in targets:
        if not isinstance(t, dict) or set(t) != {'registry_id', 'repository', 'digest'}:
            raise Incomplete('invalid_acr_selection')
        registry, repo, digest = t['registry_id'], t['repository'], t['digest']
        match = _REGISTRY.fullmatch(registry) if isinstance(registry, str) else None
        if (not match or len(registry) > 512 or match[1].casefold() not in {s.casefold() for s in scopes}
                or not isinstance(repo, str) or not 1 <= len(repo) <= 256 or not _REPOSITORY.fullmatch(repo)
                or not isinstance(digest, str) or not DIGEST.fullmatch(digest)):
            raise Incomplete('invalid_acr_selection')
        key = (registry.casefold(), repo, digest)
        if key in seen:
            raise Incomplete('invalid_acr_selection')
        seen.add(key)
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps([target['registry_id'].casefold(),target['repository'],target['digest']],separators=(',',':')))


def selection_metadata(options, scopes):
    targets = selected_targets(options, scopes)
    return {KIND+'_authorized':enabled(options), KIND+'_selection':{
        s:[identity(t) for t in targets if _REGISTRY.fullmatch(t['registry_id'])[1].casefold()==s.casefold()]
        for s in scopes}, KIND+'_receipts':[], KIND+'_digests':{identity(t):t['digest'] for t in targets}}


def _sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _token(value, host, *, tenant=None, repository=None):
    """Conservative JWT shape/expiry/audience/scope checks after bound TLS read.

    This is not a signature validator. The fixed Azure TLS service is the native
    authority; claims reject accidental expired/foreign/overbroad credentials.
    """
    if not isinstance(value,str) or not 16 <= len(value) <= 16384 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',value):
        raise Incomplete('token_unavailable')
    part=value.split('.')[1]
    claims=_json(base64.urlsafe_b64decode(part+'='*((-len(part))%4)).decode('utf-8'))
    now=time.time()
    if (not isinstance(claims,dict) or type(claims.get('exp')) not in (int,float) or claims['exp']<=now+5
            or 'nbf' in claims and (type(claims['nbf']) not in (int,float) or claims['nbf']>now)
            or claims.get('aud') not in ({ACR_AUDIENCE,ACR_AUDIENCE+'/'} if host=='containerregistry.azure.net' else ({host,'https://'+host,'https://'+host+'/'} if host!=ARM else
                {'https://management.azure.com','https://management.azure.com/','https://management.core.windows.net/'}))):
        raise Incomplete('token_binding')
    if tenant is not None and claims.get('tid',claims.get('tenant'))!=tenant:
        raise Incomplete('token_tenant')
    if repository is not None and claims.get('access') != [{'type':'repository','name':repository,'actions':['pull']}]:
        raise Incomplete('token_scope')
    return claims


def _native(data, target):
    registry=target['registry_id'];match=_REGISTRY.fullmatch(registry)
    if (not isinstance(data,dict) or set(data)&{'error','nextLink','partial','_partial','_coverage','resultTruncated'} or not isinstance(data.get('id'),str) or data['id'].casefold()!=registry.casefold()
            or not isinstance(data.get('name'),str) or data['name'].casefold()!=match[3].casefold()
            or not isinstance(data.get('type'),str) or data['type'].casefold()!='microsoft.containerregistry/registries'
            or not isinstance(data.get('properties'),dict)):
        raise Incomplete('registry_identity')
    p=data['properties'];host=p.get('loginServer')
    prefix=re.escape(match[3].lower())
    if (not isinstance(host,str) or not re.fullmatch(prefix+r'(?:-[a-z0-9]{5,32})?\.azurecr\.io',host.lower())
            or p.get('provisioningState')!='Succeeded'
            or p.get('roleAssignmentMode') not in MODES
            or p.get('policies',{}).get('azureADAuthenticationAsArmPolicy',{}).get('status') not in {'enabled','disabled'}):
        raise Incomplete('registry_host_or_auth_policy')
    host=host.lower()
    data_hosts=p.get('dataEndpointHostNames',[])
    if isinstance(data_hosts,list) and all(isinstance(h,str) for h in data_hosts):data_hosts=[h.lower() for h in data_hosts]
    if (not isinstance(data_hosts,list) or len(data_hosts)>16 or len(set(data_hosts))!=len(data_hosts)
            or any(not isinstance(h,str) or not re.fullmatch(re.escape(host[:-len('.azurecr.io')])+r'\.[a-z][a-z0-9-]{0,62}\.data\.azurecr\.io',h) for h in data_hosts)
            or data_hosts and p.get('dataEndpointEnabled') is not True):
        raise Incomplete('registry_data_host')
    return host, data_hosts, p['roleAssignmentMode'],p['policies']['azureADAuthenticationAsArmPolicy']['status']


def _location(location, hosts):
    # Only a native single-hop Location from the bound login server is accepted.
    # The service owns its opaque signed path/query; never export them or auth.
    if not isinstance(location,str) or not 1<=len(location)<=8192 or any(ord(c)<=32 or ord(c)>126 for c in location):
        raise Incomplete('unsupported_data_location')
    parsed=urlsplit(location)
    if (parsed.scheme!='https' or parsed.hostname not in hosts or parsed.netloc!=parsed.hostname
            or parsed.port is not None or parsed.username is not None or parsed.password is not None or parsed.fragment
            or not re.fullmatch(r'/[A-Za-z0-9_./%~+@=-]{1,2048}',parsed.path)
            or any(part in ('.','..','') for part in parsed.path[1:].split('/'))
            or re.search(r'%(?![0-9A-Fa-f]{2})',parsed.path)
            or re.search(r'%2[fF]|%5[cC]|%2[eE]|%00',parsed.path)):
        raise Incomplete('unsupported_data_location')
    return parsed.hostname,parsed.path+('?' + parsed.query if parsed.query else '')


class Reader:
    def __init__(self, reader, transport, receipts, scope, target, state):
        self.reader,self.transport,self.receipts,self.scope,self.target,self.state=reader,transport,receipts,scope,target,state
        self.ident=identity(target);self.host=None;self.data_hosts=[];self.mode=None;self.auth_audience=None
    def check(self):
        self.reader.check_cancelled()
        if time.monotonic()>=self.state['deadline']:raise Incomplete('image_deadline')
    def timeout(self):
        self.check();return min(10,self.state['deadline']-time.monotonic())
    def request(self,host,route,operation,cap,*,body=None,authorization=None,digest=None,size=None,redirect=False,destination=None):
        if self.state['calls']>=MAX_CALLS:raise Incomplete('image_call_limit')
        self.check();self.state['calls']+=1
        receipt={'id':'acr-read-'+str(len(self.receipts)+1),'identity':self.ident,'scope':self.scope,
            'method':'POST' if body is not None else 'GET','operation':operation,'endpoint':
            'arm' if host==ARM else ('registry' if host==self.host else 'native_dedicated_data'),
            'status':'unavailable','http_status':0,'bytes':0,'digest':digest,'verified':False,'bound':False}
        self.receipts.append(receipt)
        connection=response=None
        try:
            connection=http.client.HTTPSConnection(host,timeout=self.timeout());connection.set_debuglevel(0)
            headers={'Accept-Encoding':'identity','Accept':', '.join((OCI,DOCKER,oci_index.OCI_INDEX,
                oci_index.DOCKER_LIST)) if operation=='manifest' else 'application/octet-stream'}
            if body is not None:headers.update({'Content-Type':'application/x-www-form-urlencoded','Content-Length':str(len(body))})
            if authorization is not None:headers['Authorization']='Bearer '+authorization
            connection.request(receipt['method'],route,body=body,headers=headers)
            response=connection.getresponse();receipt['http_status']=response.status
            if response.status==307 and redirect:
                location=response.getheader('Location')
                rh,rr=_location(location,self.data_hosts)
                if response.getheader('WWW-Authenticate') is not None:raise Incomplete('auth_challenge')
                receipt.update(status='redirect',verified=True,bound=True)
                # No registry token, cookies or identity headers reach data origin.
                return self.get(rh,rr,'blob_data',cap,digest=digest,size=size,destination=destination)
            if type(response.status) is not int or response.status!=200 or response.getheader('WWW-Authenticate') is not None or response.getheader('Location') is not None:
                raise Incomplete('native_unavailable')
            if response.getheader('Content-Encoding') not in (None,'','identity'):raise Incomplete('encoded_response')
            length=response.getheader('Content-Length');expected=None
            if length is not None:
                if not isinstance(length,str) or not re.fullmatch(r'[0-9]{1,10}',length):raise Incomplete('stream_length')
                expected=int(length)
                if expected>cap or size is not None and expected!=size:raise Incomplete('stream_length')
            header_digest=response.getheader('Docker-Content-Digest')
            if header_digest is not None and (digest is None or header_digest!=digest):raise Incomplete('digest_header')
            output=None;created=False;raw=bytearray();count=0;checksum=hashlib.sha256()
            try:
                if destination is not None:
                    if (not isinstance(destination,Path) or not destination.is_absolute() or
                            size is None or shutil.disk_usage(destination.parent).free < size + 256*1024*1024):
                        raise Incomplete('scratch_disk_bound')
                    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                    created=True;output=os.fdopen(fd,'wb')
                while True:
                    timeout=self.timeout()
                    if getattr(connection,'sock',None) is not None:connection.sock.settimeout(timeout)
                    block=response.read(min(16384,cap+1-count))
                    if not isinstance(block,bytes):raise Incomplete('stream_type')
                    count+=len(block);self.state['bytes']+=len(block);receipt['bytes']+=len(block)
                    if self.state['bytes']>MAX_TOTAL or count>cap or size is not None and count>size:
                        raise Incomplete('stream_bound')
                    if not block:break
                    checksum.update(block)
                    if output is None:raw.extend(block)
                    else:
                        if shutil.disk_usage(destination.parent).free < len(block)+256*1024*1024:
                            raise Incomplete('scratch_disk_bound')
                        output.write(block)
                self.check()
                if (not count or expected is not None and count!=expected or size is not None and count!=size
                        or digest is not None and 'sha256:'+checksum.hexdigest()!=digest):
                    raise Incomplete('digest_or_truncation')
                if output is not None:output.close();output=None
            except BaseException:
                if output is not None:output.close()
                if created:destination.unlink(missing_ok=True)
                raise
            receipt.update(status='collected',verified=True,bound=digest is not None)
            return destination if destination is not None else bytes(raw)
        except Exception as exc:
            if (type(exc).__name__=='AzureReadError'
                    and getattr(exc,'code',None) in ('collection_cancelled','deadline_exceeded')):
                raise
            raise Incomplete('native_image_read_unavailable') from None
        finally:
            if response is not None:response.close()
            if connection is not None:connection.close()
    def get(self,*args,**kwargs):
        return self.reader.call(self.request,*args,**kwargs)
    def authenticate(self):
        arm=self.transport.token('https://'+ARM)
        claims=_token(arm,ARM)
        tenant=claims.get('tid')
        if not isinstance(tenant,str) or not re.fullmatch(_GUID,tenant,re.I):raise Incomplete('tenant_unbound')
        if getattr(self.transport,'verified_tenant',None)!=tenant:raise Incomplete('tenant_unbound')
        raw=self.get(ARM,self.target['registry_id']+'?api-version='+API_VERSION,'registry_identity',MAX_CONFIG,authorization=arm)
        self.host,self.data_hosts,self.mode,arm_policy=_native(_json(raw),self.target)
        self.receipts[-1]['bound']=True
        del raw
        try:
            exchange_token=self.transport.token(ACR_AUDIENCE)
        except Exception as exc:
            # An unavailable fixed audience permits the existing ARM token only
            # under explicit native acceptance. Never fall back on bad claims.
            if (arm_policy!='enabled' or not (getattr(exc,'code',None)=='audience_token_unavailable'
                    or type(exc).__name__=='CredentialUnavailableError')):
                raise Incomplete('acr_audience_unavailable') from None
            exchange_token=arm;self.auth_audience='arm'
        else:
            _token(exchange_token,'containerregistry.azure.net',tenant=tenant)
            if getattr(self.transport,'verified_tenant',None)!=tenant:raise Incomplete('tenant_unbound')
            self.auth_audience='acr'
        refresh=_json(self.get(self.host,'/oauth2/exchange','oauth_exchange',32768,body=urlencode({
            'grant_type':'access_token','service':self.host,'tenant':tenant,'access_token':exchange_token}).encode()))['refresh_token']
        del arm,exchange_token
        _token(refresh,self.host,tenant=tenant)
        self.receipts[-1]['bound']=True
        access=_json(self.get(self.host,'/oauth2/token','oauth_pull',32768,body=urlencode({
            'grant_type':'refresh_token','service':self.host,'scope':'repository:'+self.target['repository']+':pull','refresh_token':refresh}).encode()))['access_token']
        del refresh
        _token(access,self.host,repository=self.target['repository'])
        self.receipts[-1]['bound']=True
        return access
    def blob(self,category,digest,cap,token,size=None,destination=None):
        return self.get(self.host,'/v2/'+self.target['repository']+'/'+category+'/'+digest,
            'manifest' if category=='manifests' else 'blob',cap,authorization=token,digest=digest,size=size,redirect=category=='blobs',destination=destination)


def _scan_bytes(raw,path,reader):
    reader.check()
    remaining=reader.state['deadline']-time.monotonic()
    if remaining<1:raise Incomplete('scanner_deadline')
    from .azure_selected_secret_integration_20261020 import remember
    result=scan_with_source(scan_content,raw,path,source={},timeout=min(30,remaining),
        _redact_values=lambda values:remember(reader.reader,'acr_image_secret_redactions',values))
    reader.check()
    if result['complete'] is not True:raise Incomplete('scanners_incomplete')
    return result



def _scan_json(raw, document, path, reader):
    # Inspect original bytes and decoded JSON strings, so an escaped multiline
    # credential in Env/history/annotations is not lost at the JSON boundary.
    with source_context(native=document, path=path, location_kind='configuration'):
        original=_scan_bytes(raw,path,reader)
        stack=[document];strings=[];size=0;nodes=0
        while stack:
            value=stack.pop();nodes+=1
            if nodes>MAX_MEMBERS*4:raise Incomplete('json_content_bound')
            if isinstance(value,str):
                payload=value.encode('utf-8',errors='strict');size+=len(payload)+2
                if size>MAX_CONFIG*2:raise Incomplete('json_content_bound')
                strings.append(payload)
            elif isinstance(value,dict):
                stack.extend(reversed(list(value.values())));stack.extend(reversed(list(value)))
            elif isinstance(value,list):stack.extend(reversed(value))
        if not strings:raise Incomplete('json_content_unavailable')
        decoded=_scan_bytes(b'\n\n'.join(strings),path,reader)
    return {'complete':True,'engines':original['engines'],
            'leaks':merge_leaks(original['leaks']+decoded['leaks'])}


def inspect_image(reader):
    from .azure_acr_image_stream_inspection_20261021 import inspect_image as streamed
    return streamed(reader)


def collect(reader,transport,scopes,wanted,options):
    if KIND not in wanted:return
    targets=selected_targets(options,scopes)
    reader.acr_image_secret_redactions=set()
    reader.acr_image_secret_metadata=selection_metadata(options,scopes)
    if not enabled(options):return
    state={'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0}
    receipts=reader.acr_image_secret_metadata[KIND+'_receipts']
    for scope in scopes:
        selected=[t for t in targets if _REGISTRY.fullmatch(t['registry_id'])[1].casefold()==scope.casefold()]
        if not selected:continue
        def fetch(selected=selected,scope=scope):
            yield [inspect_image(Reader(reader,transport,receipts,scope,t,state)) for t in selected]
        reader.run([(KIND,scope,'Microsoft.ContainerRegistry',fetch)])

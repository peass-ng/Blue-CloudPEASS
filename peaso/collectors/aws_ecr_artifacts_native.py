"""Opt-in ECR artifact content for an explicit, bounded OCI/Cosign storage profile."""
import base64,copy,hashlib,json,re,time,threading
from urllib.parse import urlsplit
from urllib.request import build_opener,HTTPRedirectHandler,ProxyHandler

PROFILE='oci11-and-cosign-v2-same-repository'
SIGN='application/vnd.dev.cosign.simplesigning.v1+json'
SBOM={'application/spdx+json','application/vnd.cyclonedx+json'}
OCI='application/vnd.oci.image.manifest.v1+json'
DOCKER='application/vnd.docker.distribution.manifest.v2+json'
MAX_BODY=4*1024*1024
MAX_CONTENT_BYTES=16*1024*1024
MAX_ARTIFACTS=128
SPECS={'ecr_image':('ecr','batch_get_image','images'),'ecr_oci_artifact':('ecr','list_image_referrers','referrers')}
NATIVE_IDS={'ecr_image':'imageDigest','ecr_oci_artifact':'artifactDigest'}
READ_ACTIONS={('ecr','batch_get_image'),('ecr','list_image_referrers'),('ecr','get_download_url_for_layer')}
_SENTINEL='__unverified_native_signature__'

def _digest(v):return isinstance(v,str)and re.fullmatch(r'sha256:[0-9a-f]{64}',v)is not None

def normalize(options):
 parameters=options.get('compliance_parameters',{})
 if not isinstance(parameters,dict):raise ValueError('invalid compliance parameter namespace')
 value=parameters.get('aws_ecr_artifacts')
 if value is None:return None
 if not isinstance(value,dict)or set(value)!={'profile','content_read_approved','images','approved_signing_public_keys'}or value['profile']!=PROFILE or value['content_read_approved']is not True:raise ValueError('explicit supported ECR content profile required')
 images=value['images'];keys=value['approved_signing_public_keys']
 if not isinstance(images,list)or not 1<=len(images)<=128 or not isinstance(keys,list)or len(keys)>32:raise ValueError('invalid ECR image/key bounds')
 seen=set()
 for row in images:
  if not isinstance(row,dict)or set(row)!={'scope','repository_name','image_digest'}:raise ValueError('ECR owner input cannot supply observations')
  scope,repo,digest=row['scope'],row['repository_name'],row['image_digest']
  if not isinstance(scope,str)or not re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]',scope)or not isinstance(repo,str)or not 2<=len(repo)<=256 or not re.fullmatch(r'[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*',repo)or not _digest(digest)or(scope,digest)in seen:raise ValueError('invalid or ambiguous ECR owner identity')
  seen.add((scope,digest))
 from cryptography.hazmat.primitives import serialization
 from cryptography.hazmat.primitives.asymmetric import ed25519,rsa,ec
 ids=set();materials=set()
 for key in keys:
  if not isinstance(key,dict)or set(key)!={'KeyId','PublicKeyPem'}or not isinstance(key['KeyId'],str)or not 1<=len(key['KeyId'])<=128 or key['KeyId']==_SENTINEL or key['KeyId']in ids or not isinstance(key['PublicKeyPem'],str)or len(key['PublicKeyPem'])>8192:raise ValueError('invalid approved public key')
  public=serialization.load_pem_public_key(key['PublicKeyPem'].encode())
  if not isinstance(public,(ed25519.Ed25519PublicKey,rsa.RSAPublicKey,ec.EllipticCurvePublicKey)):raise ValueError('unsupported approved key algorithm')
  der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
  if der in materials:raise ValueError('ambiguous approved key aliases')
  ids.add(key['KeyId']);materials.add(der)
 return copy.deepcopy(value)

def owner_metadata(policy):
 if policy is None:return {}
 return {'deployed_image_digests':list(dict.fromkeys(x['image_digest']for x in policy['images'])),
         'approved_signing_public_keys':copy.deepcopy(policy['approved_signing_public_keys']),
         'ecr_artifact_profile':{'source':'operator-declared normative acceptance profile','profile':PROFILE,'content_read_approved':True,'deployed_images_observed':False}}


def companion_policy(options):
 """Proposal only: no role creation, attachment or modification occurs."""
 from botocore.session import Session
 policy=normalize(options)
 if policy is None:raise ValueError('explicit ECR artifact owner policy required')
 endpoints=Session();resources=set()
 for image in policy['images']:
  account,region=image['scope'].split('/')
  partition=endpoints.get_partition_for_region(region)
  resources.add(f"arn:{partition}:ecr:{region}:{account}:repository/{image['repository_name']}")
 return {'Version':'2012-10-17','Statement':[{'Sid':'ExplicitEcrArtifactContentRead','Effect':'Allow',
  'Action':['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'],'Resource':sorted(resources)}]}

class _NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):return None

def validate_url(url,region,partition):
 if not isinstance(url,str)or len(url)>32768 or any(ord(c)<=32 or ord(c)==127 for c in url):raise ValueError('invalid layer URL')
 p=urlsplit(url);host=p.hostname or '';suffix='amazonaws.com.cn'if partition=='aws-cn'else'amazonaws.com'
 endpoint=r'(?:s3[.-]'+re.escape(region)+r'|s3)\.'+re.escape(suffix)
 if p.scheme!='https'or p.username is not None or p.password is not None or p.port not in(None,443)or p.fragment or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*\.'+endpoint,host)or not p.path.startswith('/'):raise ValueError('layer download is not bounded AWS S3 HTTPS')
 return url

def fetch_layer(requests,url,size):
 from .aws import ReadFailure
 # Consume the same global attempt budget as SDK requests, under its lock.
 with requests._lock:
  requests.check_deadline()
  if requests.max_calls is not None and requests.calls>=requests.max_calls:raise ReadFailure('not_collected','call_limit')
  requests.calls+=1
 remaining=requests.deadline-time.monotonic()if requests.deadline is not None else requests.timeout
 timeout=min(requests.timeout,remaining)
 if timeout<=0:raise ReadFailure('timeout','intentional_scan_deadline')
 opener=build_opener(ProxyHandler({}),_NoRedirect())
 try:
  with opener.open(url,timeout=timeout)as response:
   if response.geturl()!=url or response.status!=200 or response.headers.get('Content-Encoding','identity')!='identity':raise ValueError('unexpected layer HTTP response')
   length=response.headers.get('Content-Length')
   if length is not None and(not length.isdecimal()or int(length)!=size):raise ValueError('layer length mismatch')
   data=response.read(size+1)
   if len(data)!=size:raise ValueError('layer length mismatch')
   return data
 except Exception:raise ReadFailure('not_collected','ecr_layer_download_unavailable')from None

def _json(raw):
 def pairs(items):
  out={}
  for k,v in items:
   if k in out:raise ValueError('duplicate JSON key')
   out[k]=v
  return out
 def constant(value):raise ValueError('non-JSON numeric constant')
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)

def _key_id(raw,signature,keys):
 from cryptography.exceptions import InvalidSignature
 from cryptography.hazmat.primitives import serialization,hashes
 from cryptography.hazmat.primitives.asymmetric import ed25519,rsa,ec,padding
 sig=base64.b64decode(signature,validate=True)
 for key in keys:
  public=serialization.load_pem_public_key(key['PublicKeyPem'].encode())
  try:
   if isinstance(public,ed25519.Ed25519PublicKey):public.verify(sig,raw)
   elif isinstance(public,rsa.RSAPublicKey):public.verify(sig,raw,padding.PKCS1v15(),hashes.SHA256())
   else:public.verify(sig,raw,ec.ECDSA(hashes.SHA256()))
   return key['KeyId']
  except InvalidSignature:continue
 return _SENTINEL

def _collect(requests,session,region,account):
 from .aws import ReadResult,ReadFailure
 policy=getattr(requests,'ecr_artifacts_policy',None)
 if policy is None:raise ReadFailure('not_collected','ecr_artifact_content_opt_in_missing')
 selected=[x for x in policy['images']if x['scope']==account+'/'+region]
 if not selected:return [],[]
 partition=session.get_partition_for_region(region)
 identity=requests.detail(session,'sts',region,'get_caller_identity')
 if identity.get('collection_status')!='collected'or identity.get('Account')!=account or not re.fullmatch(re.escape('arn:'+partition+':')+r'(?:sts|iam)::'+re.escape(account)+r':.+',identity.get('Arn','')):raise ValueError('ECR caller binding mismatch')
 content_bytes=0
 artifact_fetches=0
 def batch(repo,selector,missing=False):
  nonlocal content_bytes
  raw=requests.detail(session,'ecr',region,'batch_get_image',registryId=account,repositoryName=repo,imageIds=[selector])
  if raw.get('collection_status')!='collected':raise ReadFailure(raw.get('collection_status','malformed'),(raw.get('error')or{}).get('code','ecr_manifest_unavailable'))
  failures=raw.get('failures');images=raw.get('images')
  if (missing and images==[]and isinstance(failures,list)and len(failures)==1 and failures[0].get('failureCode')=='ImageNotFound'and failures[0].get('imageId')==selector):return None
  if 'imageDigest' in selector:
   from .aws_ecr_manifest_aliases import select_digest_image
   item=select_digest_image(images,failures,account,repo,selector['imageDigest'])
  else:
   if failures!=[]or not isinstance(images,list)or len(images)!=1:raise ValueError('ECR manifest response ambiguous')
   item=images[0]
  iid=item.get('imageId');manifest=item.get('imageManifest')
  if item.get('registryId')!=account or item.get('repositoryName')!=repo or not isinstance(iid,dict)or any(iid.get(k)!=v for k,v in selector.items())or not _digest(iid.get('imageDigest'))or not isinstance(manifest,str)or len(manifest.encode())>MAX_BODY or 'sha256:'+hashlib.sha256(manifest.encode()).hexdigest()!=iid['imageDigest']:raise ValueError('ECR manifest identity/hash mismatch')
  manifest_bytes=len(manifest.encode())
  if content_bytes+manifest_bytes>MAX_CONTENT_BYTES:raise ReadFailure('not_collected','ecr_content_budget_exceeded')
  content_bytes+=manifest_bytes
  document=_json(manifest)
  if not isinstance(document,dict)or document.get('schemaVersion')!=2 or type(document.get('schemaVersion'))is not int:raise ValueError('unsupported ECR manifest schema')
  return item,document
 def artifact_batch(repo,selector,missing=False):
  nonlocal artifact_fetches
  if artifact_fetches>=MAX_ARTIFACTS:raise ReadFailure('not_collected','ecr_artifact_fetch_budget_exceeded')
  artifact_fetches+=1
  result=batch(repo,selector,missing)
  if result is None:artifact_fetches-=1
  return result
 images=[];artifacts=[];seen={}
 for owner in selected:
  repo,digest=owner['repository_name'],owner['image_digest'];parent=batch(repo,{'imageDigest':digest})
  images.append({'imageDigest':digest,'registryId':account,'repositoryName':repo,'_provenance':{'source_operation':'BatchGetImage','deployed_status':'operator-declared; not observed','read_only':True}})
  refs=requests.pages(session,'ecr',region,'list_image_referrers','referrers',_tokens=('nextToken','nextToken'),_page_limit=max(1,(MAX_ARTIFACTS+49)//50),registryId=account,repositoryName=repo,subjectId={'imageDigest':digest},maxResults=50)
  if refs.status not in('collected','empty'):raise ReadFailure(refs.status,(refs.error or{}).get('code','ecr_referrers_incomplete'))
  if len(refs.items)>MAX_ARTIFACTS-artifact_fetches:raise ReadFailure('not_collected','ecr_artifact_fetch_budget_exceeded')
  pending=[];refseen=set()
  for ref in refs.items:
   if not isinstance(ref,dict)or not _digest(ref.get('digest'))or ref['digest']in refseen or ref.get('artifactStatus')!='ACTIVE'or ref.get('mediaType')!=OCI or ref.get('artifactType')not in SBOM|{SIGN}:raise ReadFailure('not_collected','ecr_referrer_format_or_identity_unresolved')
   refseen.add(ref['digest']);pending.append((artifact_batch(repo,{'imageDigest':ref['digest']}),ref,None))
  for suffix in ('sig','sbom','att'):
   tag=digest.replace(':','-')+'.'+suffix;legacy=artifact_batch(repo,{'imageTag':tag},missing=True)
   if legacy is not None:
    if suffix=='att':raise ReadFailure('not_collected','ecr_legacy_attestation_unsupported')
    pending.append((legacy,None,suffix))
  for result,ref,legacy_kind in pending:
   item,manifest=result;aid=item['imageId']['imageDigest']
   if aid in seen:
    if seen[aid]!=digest:raise ValueError('one artifact reported for conflicting subjects')
    continue
   seen[aid]=digest
   config=manifest.get('config')
   if not isinstance(config,dict)or not _digest(config.get('digest'))or type(config.get('size'))is not int or config['size']<0 or not isinstance(config.get('mediaType'),str):raise ValueError('artifact config descriptor malformed')
   if manifest.get('mediaType')not in(OCI,DOCKER)or item.get('imageManifestMediaType')!=manifest['mediaType']:raise ValueError('ECR artifact media mismatch')
   if 'subject'in manifest and(not isinstance(manifest['subject'],dict)or manifest['subject'].get('digest')!=digest):raise ValueError('artifact declared subject contradicts requested image')
   if ref is not None:
    subject=manifest.get('subject')
    if type(ref.get('size'))is not int or ref['size']!=len(item['imageManifest'].encode()):raise ValueError('referrer manifest byte length mismatch')
    if not isinstance(subject,dict)or subject.get('digest')!=digest or manifest.get('artifactType')!=ref['artifactType']:raise ValueError('ECR referrer manifest subject/type mismatch')
   layers=manifest.get('layers')
   if not isinstance(layers,list)or len(layers)!=1 or not isinstance(layers[0],dict):raise ReadFailure('not_collected','ecr_multilayer_artifact_unsupported')
   layer=layers[0];typ=layer.get('mediaType');size=layer.get('size');ld=layer.get('digest')
   if 'artifactType'in manifest and manifest['artifactType']!=typ:raise ValueError('artifact declared type contradicts actual content')
   if 'urls'in layer:raise ReadFailure('not_collected','ecr_external_layer_descriptor_unsupported')
   if typ not in SBOM|{SIGN}or not _digest(ld)or type(size)is not int or not 0<size<=MAX_BODY:raise ReadFailure('not_collected','ecr_layer_schema_or_size_unsupported')
   if ref is not None and typ!=ref['artifactType']or legacy_kind=='sig'and typ!=SIGN or legacy_kind=='sbom'and typ not in SBOM:raise ValueError('artifact content format mismatch')
   if len(artifacts)>=MAX_ARTIFACTS or content_bytes+size>MAX_CONTENT_BYTES:raise ReadFailure('not_collected','ecr_content_budget_exceeded')
   content_bytes+=size
   download=requests.detail(session,'ecr',region,'get_download_url_for_layer',registryId=account,repositoryName=repo,layerDigest=ld)
   if download.get('collection_status')!='collected':raise ReadFailure(download.get('collection_status','malformed'),(download.get('error')or{}).get('code','ecr_layer_location_unavailable'))
   if download.get('layerDigest')!=ld:raise ValueError('download layer identity mismatch')
   url=validate_url(download.get('downloadUrl'),region,partition);content=fetch_layer(requests,url,size)
   if not isinstance(content,bytes)or len(content)!=size or 'sha256:'+hashlib.sha256(content).hexdigest()!=ld:raise ValueError('downloaded layer hash mismatch')
   payload=content.decode('utf-8');_json(payload)
   artifact={'artifactDigest':aid,'artifactType':typ,'subject':{'digest':digest},'payload':payload,'_provenance':{'source_operations':['ListImageReferrers','BatchGetImage','GetDownloadUrlForLayer'],'payload_sha256':ld,'exact_manifest_digest_verified':True,'storage_profile':PROFILE,'read_only':True}}
   if typ==SIGN:
    annotations=layer.get('annotations')
    if not isinstance(annotations,dict)or not isinstance(annotations.get('dev.cosignproject.cosign/signature'),str):raise ReadFailure('not_collected','ecr_cosign_signature_annotation_missing')
    signature=annotations['dev.cosignproject.cosign/signature'];artifact.update(signature=signature,keyId=_key_id(content,signature,policy['approved_signing_public_keys']))
   artifacts.append(artifact)
 return images,artifacts

def _read(requests,session,region,account,index):
 from .aws import ReadResult,ReadFailure
 # One account/Region batch supplies both collections; the collector invokes
 # fetchers concurrently, so serialize this small opt-in projection cache.
 with requests._lock:
  state=getattr(requests,'_ecr_artifact_state',None)
  if state is None:state=requests._ecr_artifact_state=(threading.RLock(),{})
 lock,cache=state
 with lock:
  key=(id(session),region,account)
  if key not in cache:
   try:
    pair=_collect(requests,session,region,account);cache[key]=[ReadResult(rows,'collected'if rows else'empty')for rows in pair]
   except ReadFailure as e:cache[key]=[ReadResult([],e.status,{'code':e.code})for _ in range(2)]
   except Exception:cache[key]=[ReadResult([],'malformed',{'code':'ecr_artifact_native_join_unresolved'})for _ in range(2)]
  return cache[key][index]
FETCHERS={'ecr_image':lambda *a:_read(*a,0),'ecr_oci_artifact':lambda *a:_read(*a,1)}

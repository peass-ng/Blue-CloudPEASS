import gzip, hashlib, importlib.util, io, json, sys, tarfile, unittest
from copy import deepcopy
from pathlib import Path

from peaso.collectors import azure_selected_aks_image_20261021 as bridge
from peaso.collectors import k8s_selected_registry_image_20261021 as image
from peaso import container_image_archive_20261020 as archive
from peaso.checks import azure_selected_aks_image_review_20261021 as review

RID = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks'
SCOPE = RID.split('/resourceGroups/')[0]

def digest(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()

def fixture():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        raw = b'mode=ready\n'
        member = tarfile.TarInfo('app/config.txt'); member.size = len(raw)
        tar.addfile(member, io.BytesIO(raw))
    tar_raw = stream.getvalue(); layer = gzip.compress(tar_raw, mtime=0)
    config = json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[digest(tar_raw)]}},separators=(',',':')).encode()
    manifest = json.dumps({'schemaVersion':2,'mediaType':archive.OCI,'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':digest(config),'size':len(config)},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':digest(layer),'size':len(layer)}]},separators=(',',':')).encode()
    ref = 'ghcr.io/owned/demo@' + digest(manifest)
    target = {'cluster_id':RID,'namespace':'default','pod':'pod-a','uid':'poduid','resource_version':'42','container_type':'regular','container_name':'app','image':ref}
    pod = {'apiVersion':'v1','kind':'Pod','metadata':{'namespace':'default','name':'pod-a','uid':'poduid','resourceVersion':'42'},'spec':{'containers':[{'name':'app','image':ref}]},'status':{'containerStatuses':[{'name':'app','image':ref,'imageID':'docker-pullable://'+ref,'state':{'running':{'startedAt':'2026-10-21T10:00:00Z','containerID':'containerd://abc123'}},'containerID':'containerd://abc123','restartCount':0,'ready':True}]}}
    return target,pod,{('manifests',digest(manifest)):manifest,('blobs',digest(config)):config,('blobs',digest(layer)):layer}

class Response:
    def __init__(self, payload, status=200, truncated=False):
        self.status=status;self.stream=io.BytesIO(payload);self.headers={'Content-Length':str(len(payload)+(1 if truncated else 0)),'Content-Encoding':'identity','Content-Type':archive.OCI};self.closed=False
    def read(self,n):return self.stream.read(n)
    def close(self):self.closed=True
class Connection:
    def __init__(self):self.closed=False
    def close(self):self.closed=True
class Wire:
    def __init__(self,blobs,fault=None):self.blobs=blobs;self.fault=fault;self.calls=[];self.responses=[]
    def __call__(self,host,path,headers,timeout):
        assert host=='ghcr.io' and path.startswith('/v2/owned/demo/') and 'Authorization' not in headers
        _,category,key=path.rsplit('/',2)
        response=Response(self.blobs[(category,key)],403 if self.fault=='denied' else 200,self.fault=='truncated' and category=='blobs')
        self.calls.append((host,path));self.responses.append(response)
        return Connection(),response

def scanner(raw,path,source,check,leaks,parts):
    check();parts.append({'part':path,'bytes':len(raw),'complete':True,'engines':[{'engine':'kingfisher','version':'1.4.0','status':'complete'},{'engine':'trufflehog','version':'3.92.5','status':'complete'}]})
    if b'mode=ready' in raw and scanner.hit:
        leaks.append({'fingerprint':'a'*64,'locations':[{'path':path}],'detectors':[{'engine':'kingfisher','rule':'fixture-rule'}]})
        if scanner.partial:raise ValueError('fixture partial')
scanner.hit=False
scanner.partial=False

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.target,self.pod,self.blobs=fixture();self.calls=[];scanner.hit=False;scanner.partial=False
        self.arm={'id':RID,'name':'aks','type':'Microsoft.ContainerService/managedClusters','properties':{'provisioningState':'Succeeded','fqdn':'aks.example.com','resourceUID':'arm-uid'}}
        self.context={'cluster_id':RID,'server':'https://aks.example.com','ca_cert_data':'test-only','token':'test-only'}
        self.ns={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'kube-system','uid':'cluster-uid'}}
    def run_case(self,fault=None,pod=None,arm=None,ns=None,context=None,cancel=None,trivy_runner=None):
        wire=Wire(self.blobs,fault)
        def arm_get(_):self.calls.append('arm');return deepcopy(self.arm if arm is None else arm)
        def ns_get():self.calls.append('namespace');return deepcopy(self.ns if ns is None else ns)
        def pod_get(_):self.calls.append('pod');return deepcopy(self.pod if pod is None else pod)
        result=bridge.inspect_selected(self.target,arm_get=arm_get,namespace_get=ns_get,pod_get=pod_get,
            context=self.context if context is None else context,tenant='tenant-id',allowed_hosts=['ghcr.io'],
            registry_factory=lambda h,r,c,**kw:image.RegistryReader(h,r,c,open_https=wire,**kw),scanner=scanner,
            cancel=cancel or (lambda:None),trivy_enabled=trivy_runner is not None,trivy_runner=trivy_runner)
        return result,wire
    def test_clean_hit_and_native_oci(self):
        for hit,expected in ((False,'PASS'),(True,'FAIL')):
            scanner.hit=hit;self.calls=[]
            result,wire=self.run_case()
            self.assertIsNotNone(result['image'],result)
            self.assertEqual(result['image']['status'],expected,result)
            self.assertEqual(result['arm_before'],result['arm_after'])
            self.assertEqual(self.calls,['arm','namespace','pod','pod','namespace','arm'])
            self.assertEqual(len(wire.calls),3)
            self.assertTrue(all(r.closed for r in wire.responses))
            self.assertNotIn('mode=ready',json.dumps(result))
            item={'id':bridge.identity(self.target),'SelectedAksImage':result}
            index={'context':{'provider':'azure','scope':SCOPE,'metadata':{bridge.KIND+'_authorized':True,bridge.OPTION:[self.target]}},
                   'collections':{bridge.KIND:[{'scope':SCOPE,'status':'collected' if result['complete'] else 'partial','items':[item]}]}}
            self.assertEqual(review.evaluate(item,index)[0],expected)
    def test_partial_positive_survives_and_clean_incomplete_unknown(self):
        scanner.hit=True;scanner.partial=True
        result,_=self.run_case()
        self.assertFalse(result['complete']);self.assertEqual(result['image']['status'],'FAIL')
        item={'id':bridge.identity(self.target),'SelectedAksImage':result}
        index={'context':{'provider':'azure','scope':SCOPE,'metadata':{bridge.KIND+'_authorized':True,bridge.OPTION:[self.target]}},
               'collections':{bridge.KIND:[{'scope':SCOPE,'status':'partial','items':[item]}]}}
        self.assertEqual(review.evaluate(item,index)[0],'FAIL')
        item['SelectedAksImage']['image']['leaks']=[]
        self.assertEqual(review.evaluate(item,index)[0],'UNKNOWN')
    def test_optional_trivy_positive(self):
        finding={'severity':'HIGH','image_digest':self.target['image'].rsplit('@',1)[1],
                 'vulnerability_id':'CVE-2026-1001','package':'pkg','version':'1'}
        def runner(identity,manifest,config,layers,**kwargs):
            self.assertEqual(kwargs['native_verifier'](),identity)
            return {'status':'FAIL','complete':False,'findings':[finding]}
        result,_=self.run_case(trivy_runner=runner)
        item={'id':bridge.identity(self.target),'SelectedAksImage':result}
        index={'context':{'provider':'azure','scope':SCOPE,'metadata':{bridge.VULN_KIND+'_authorized':True,bridge.OPTION:[self.target]}},
               'collections':{bridge.VULN_KIND:[{'scope':SCOPE,'status':'partial','items':[item]}]}}
        self.assertEqual(review.evaluate_vulnerability(item,index)[0],'FAIL')
    def test_foreign_cluster_pod_and_drift(self):
        for case in ('arm','endpoint','uid','pod'):
            self.calls=[];target=self.target
            arm={**self.arm,'id':RID+'/foreign'} if case=='arm' else None
            ctx={**self.context,'server':'https://foreign.example.com'} if case=='endpoint' else None
            ns={**self.ns,'metadata':{'name':'kube-system','uid':''}} if case=='uid' else None
            pod={**self.pod,'metadata':{**self.pod['metadata'],'uid':'foreign'}} if case=='pod' else None
            result,wire=self.run_case(arm=arm,context=ctx,ns=ns,pod=pod)
            self.assertFalse(result['complete']);self.assertIsNone(result['image']) if case!='pod' else self.assertEqual(result['reason'],'pod_image_binding')
            self.assertEqual(len(wire.calls),0)
    def test_denied_truncated_cancel_and_arc(self):
        for fault in ('denied','truncated'):
            result,wire=self.run_case(fault=fault)
            self.assertFalse(result['complete']);self.assertEqual(result['image']['status'],'UNKNOWN')
        result,wire=self.run_case(cancel=lambda:(_ for _ in ()).throw(RuntimeError('cancelled')))
        self.assertEqual(result['reason'],'native_read_unavailable');self.assertFalse(wire.calls)
        arc={**self.target,'cluster_id':RID.replace('Microsoft.ContainerService/managedClusters','Microsoft.Kubernetes/connectedClusters')}
        result=bridge.inspect_selected(arc,arm_get=lambda _:self.fail('ARM called'),namespace_get=lambda:self.fail('K8s called'),pod_get=lambda _:self.fail('Pod called'),context=None,tenant='tenant-id')
        self.assertEqual(result['reason'],'arc_kubernetes_api_endpoint_unavailable')
    def test_missing_capability_and_after_read_drift(self):
        result=bridge.inspect_selected(self.target,arm_get=lambda _:deepcopy(self.arm),
            namespace_get=lambda:self.fail('K8s called'),pod_get=lambda _:self.fail('Pod called'),
            context=None,tenant='tenant-id')
        self.assertEqual(result['reason'],'explicit_kubernetes_context_required')
        for drift in ('arm','namespace'):
            calls=[0];ns_calls=[0]
            def arm_get(_):
                calls[0]+=1
                value=deepcopy(self.arm)
                if drift=='arm' and calls[0]==2:value['properties']['resourceUID']='new-cluster'
                return value
            def ns_get():
                ns_calls[0]+=1
                value=deepcopy(self.ns)
                if drift=='namespace' and ns_calls[0]==2:value['metadata']['uid']='new-cluster'
                return value
            wire=Wire(self.blobs)
            result=bridge.inspect_selected(self.target,arm_get=arm_get,namespace_get=ns_get,
                pod_get=lambda _:deepcopy(self.pod),context=self.context,tenant='tenant-id',
                allowed_hosts=['ghcr.io'],registry_factory=lambda h,r,c,**kw:image.RegistryReader(h,r,c,open_https=wire,**kw),
                scanner=scanner)
            self.assertFalse(result['complete']);self.assertIsNone(result['image'])
            self.assertEqual(len(wire.calls),3)
    def test_default_off_and_preflight(self):
        self.assertEqual(bridge.selected_targets({},[SCOPE],[]),[])
        self.assertIsNone(bridge.collect(object(),lambda *_:self.fail('ARM called'),object(),[SCOPE],
                                         {bridge.KIND}, {}, {}))
        opts={bridge.OPTION:[self.target],image.ALLOWLIST:['ghcr.io'],'content_secret_scans':True}
        self.assertEqual(len(bridge.selected_targets(opts,[SCOPE],[bridge.CHECK])),1)
        for target in ({**self.target,'cluster_id':RID.replace('/subscriptions/11111111','/subscriptions/22222222')},
                       {**self.target,'image':'ghcr.io/owned/demo:latest'},
                       {**self.target,'namespace':'../secret'}):
            with self.assertRaises(ValueError):bridge.selected_targets({**opts,bridge.OPTION:[target]},[SCOPE],[bridge.CHECK])

if __name__=='__main__':unittest.main()

"""Compare32/128-source complete package batches with real pinned detectors.

Linux with verified volatile /dev/shm is required. Run in an isolated process;
this benchmark changes only its own in-memory batch constants and result cache.
Use Docker --cpus1 to reproduce the recorded one-CPU comparison.
"""
import io,json,time,resource,tarfile,zipfile,hashlib
from types import SimpleNamespace
from peaso import secret_scanning as scanning,secret_scanning_batch as batch
from peaso.collectors import aws_package_content_indicators as archives
assert batch._volatile_shm_available(65536)
assert scanning.scan_content(b'warmup','warmup.txt')['complete']
token='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
files=[(f'file-{i}.txt',(f'token={token}\nsource={i}\n' if i%2 else f'plain source={i}\n').encode()) for i in range(128)]
zipraw,tarraw=io.BytesIO(),io.BytesIO()
with zipfile.ZipFile(zipraw,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for name,raw in files:z.writestr(name,raw)
with tarfile.open(fileobj=tarraw,mode='w',format=tarfile.USTAR_FORMAT) as t:
 for name,raw in files:
  item=tarfile.TarInfo(name);item.size=len(raw);t.addfile(item,io.BytesIO(raw))
execute=scanning._run;calls=[]
def tracked(argv,*args):
 if len(argv)>1 and argv[1] in ('filesystem','stdin'):calls.append(argv[1])
 return execute(argv,*args)
scanning._run=tracked
outputs={};request=SimpleNamespace(check_deadline=lambda:None)
for size in (32,128):
 batch.MAX_BATCH_ITEMS=archives.BATCH_ITEMS=size
 for kind,raw in (('zip',zipraw.getvalue()),('tar',tarraw.getvalue())):
  scanning._RESULTS.clear();calls.clear();s=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.perf_counter()
  result=archives.scan_zip(raw,request) if kind=='zip' else archives.scan_tar(raw,'application/vnd.oci.image.layer.v1.tar',request)
  wall=time.perf_counter()-start;s2=resource.getrusage(resource.RUSAGE_SELF);c2=resource.getrusage(resource.RUSAGE_CHILDREN)
  cpu=s2.ru_utime+s2.ru_stime+c2.ru_utime+c2.ru_stime-s.ru_utime-s.ru_stime-c.ru_utime-c.ru_stime
  digest=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest();outputs[size,kind]=digest
  assert len(result[0])==64
  print(json.dumps({'batch_items':size,'format':kind,'files':len(files),'wall_seconds':round(wall,6),'cpu_seconds':round(cpu,6),'process_modes':calls,'references':len(result[0]),'output_digest':digest}),flush=True)
for kind in ('zip','tar'):assert outputs[32,kind]==outputs[128,kind]
print('Both ZIP and TAR outputs match on one CPU; paths/redactions/engine evidence unchanged.',flush=True)

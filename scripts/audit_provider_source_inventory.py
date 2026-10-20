"""Bounded current Azure/Kubernetes reference inventory, never evaluator parity.

Downloads only provider Prowler metadata and Turbot control/query files. Records
pinned Git object identities and explicit new/retired source IDs against the
reviewed manifest. Missing IDs require individual semantic disposition; presence
never establishes implementation or compliance. No cloud credentials are used.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib,json,re,sys,threading,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.peaso_review_catalog import blocks,quoted
LIMIT=32*1024*1024
REPOSITORIES={
 'azure':['prowler-cloud/prowler','turbot/steampipe-mod-azure-compliance','turbot/steampipe-mod-azure-perimeter'],
 'k8s':['prowler-cloud/prowler','turbot/steampipe-mod-kubernetes-compliance'],
}
def sha(data):return hashlib.sha256(data).hexdigest()
def blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def selected(repo,path,provider):
 if repo=='prowler-cloud/prowler':
  native='kubernetes'if provider=='k8s'else provider
  return (path.startswith('prowler/providers/'+native+'/services/')and path.endswith('.metadata.json')
          or path.startswith('prowler/compliance/'+native+'/')and path.endswith('.json'))
 return path.endswith(('.pp','.sp','.sql'))
class Inventory:
 def __init__(self,provider,cache):
  self.provider,self.cache=provider,cache;self.lock=threading.Lock();self.used=sum(p.stat().st_size for p in cache.rglob('*')if p.is_file())
  if self.used>LIMIT:raise ValueError('Source cache exceeds32MiB')
 def get(self,url):
  req=urllib.request.Request(url,headers={'User-Agent':'peasso-readonly-source-review','Accept':'application/vnd.github+json'})
  with urllib.request.urlopen(req,timeout=30)as response:data=response.read(LIMIT+1)
  if len(data)>LIMIT:raise ValueError('Oversized source response')
  return data
 def api(self,repo,tail):return json.loads(self.get('https://api.github.com/repos/'+repo+'/'+tail))
 def fetch(self):
  sources=[]
  for repo in REPOSITORIES[self.provider]:
   commit=self.api(repo,'commits/HEAD');revision=commit['sha'];tree_sha=commit['commit']['tree']['sha']
   if repo=='prowler-cloud/prowler':
    native='kubernetes'if self.provider=='k8s'else self.provider
    entries=[]
    for prefix in ['prowler/providers/'+native+'/services','prowler/compliance/'+native]:
     current=tree_sha
     for component in prefix.split('/'):
      subtree=self.api(repo,'git/trees/'+current)['tree'];current=next(r['sha']for r in subtree if r['path']==component)
     tree=self.api(repo,'git/trees/'+current+'?recursive=1')
     if tree.get('truncated'):raise ValueError('Truncated provider subtree')
     entries.extend({**r,'path':prefix+'/'+r['path']}for r in tree['tree'])
   else:
    tree=self.api(repo,'git/trees/'+tree_sha+'?recursive=1');entries=tree['tree']
   if tree.get('truncated'):raise ValueError('Truncated source tree')
   entries=[r for r in entries if r['type']=='blob'and selected(repo,r['path'],self.provider)]
   if not entries:raise ValueError('No supported source files: '+repo)
   def download(row):
    path=self.cache/repo.split('/')[-1]/row['path'];data=path.read_bytes()if path.exists()else b''
    if blob(data)!=row['sha']:
     data=self.get('https://raw.githubusercontent.com/'+repo+'/'+revision+'/'+row['path'])
     if blob(data)!=row['sha']:raise ValueError('Git object mismatch')
     with self.lock:
      previous=path.stat().st_size if path.exists()else 0
      if self.used-previous+len(data)>LIMIT:raise ValueError('32MiB source cache budget')
      path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);self.used+=len(data)-previous
    return {'path':row['path'],'git_blob_sha1':row['sha'],'sha256':sha(data)}
   with ThreadPoolExecutor(max_workers=8)as pool:files=list(pool.map(download,entries))
   sources.append({'repository':repo,'revision':revision,'tree_sha':tree_sha,'files':sorted(files,key=lambda r:r['path'])})
   print(repo,revision,len(files),'verified blobs',flush=True)
  self.cache.mkdir(parents=True,exist_ok=True);(self.cache/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');return sources
 def verify(self):
  sources=json.loads((self.cache/'sources.json').read_text())
  if {r['repository']for r in sources}!=set(REPOSITORIES[self.provider]):raise ValueError('Repository roster mismatch')
  for source in sources:
   if not re.fullmatch('[0-9a-f]{40}',source['revision']):raise ValueError('Unpinned revision')
   for row in source['files']:
    p=Path(row['path'])
    if p.is_absolute()or'..'in p.parts or not selected(source['repository'],str(p),self.provider):raise ValueError('Unexpected source path')
    data=(self.cache/source['repository'].split('/')[-1]/p).read_bytes()
    if sha(data)!=row['sha256']or blob(data)!=row['git_blob_sha1']:raise ValueError('Source integrity failure')
  return sources
 def rows(self,sources):
  rows=[]
  for source in sources:
   repo=source['repository']
   compliance={}
   if repo=='prowler-cloud/prowler':
    for file in source['files']:
     if not file['path'].startswith('prowler/compliance/'):continue
     document=json.loads((self.cache/'prowler'/file['path']).read_text())
     for requirement in document.get('Requirements',[]):
      for cid in requirement.get('Checks',[]):
       compliance.setdefault(cid,[]).append({'framework_id':Path(file['path']).stem,'control_id':str(requirement['Id']),'source_path':file['path'],'source_sha256':file['sha256']})
   defined=set()
   for file in source['files']:
    path=file['path'];data=(self.cache/repo.split('/')[-1]/path).read_text()
    if repo=='prowler-cloud/prowler':
     if path.startswith('prowler/compliance/'):continue
     entry=json.loads(data);cid='prowler.'+('kubernetes'if self.provider=='k8s'else self.provider)+'.'+entry['CheckID'];declarations=[(cid,entry.get('CheckTitle',''))]
     defined.add(entry['CheckID'])
    else:declarations=[(repo.split('/')[-1].removeprefix('steampipe-mod-')+'.control.'+name,quoted(body,'title'))for kind,name,body,line in blocks(data)if kind=='control']
    for cid,title in declarations:rows.append({'check_id':cid,'title':title,'repository':repo,'revision':source['revision'],'path':path,'source_sha256':file['sha256'],'source_url':'https://github.com/'+repo+'/blob/'+source['revision']+'/'+path,**({'framework_references':compliance.get(entry['CheckID'],[])}if repo=='prowler-cloud/prowler'else{})})
   if repo=='prowler-cloud/prowler':
    for cid in sorted(compliance.keys()-defined):
     rows.append({'check_id':'prowler.'+('kubernetes'if self.provider=='k8s'else self.provider)+'.'+cid,'title':'Unresolved upstream compliance reference','repository':repo,'revision':source['revision'],'catalog_entry_type':'missing_definition','framework_references':compliance[cid]})
  ids=[r['check_id']for r in rows]
  if len(ids)!=len(set(ids)):raise ValueError('Duplicate reference IDs')
  return rows
 def report(self,sources):
  rows=self.rows(sources);baseline=[r for r in json.loads((ROOT/'peaso/rulepacks/upstream_manifest.json').read_text())['checks']if r['provider']==self.provider];old={r['check_id']:r for r in baseline};current={r['check_id']for r in rows}
  for row in rows:
   previous=old.get(row['check_id']);row['inventory_status']='new_requires_semantic_review'if previous is None else'present_in_reviewed_manifest'
   if previous:row['prior_disposition']={k:previous[k]for k in ['disposition','native_checks','reason']if k in previous}
  return {'schema_version':1,'captured_at_utc':datetime.now(timezone.utc).isoformat(),'provider':self.provider,'status':'source_inventory_only_semantic_review_required','limits':['Source-ID conservation does not demonstrate evaluator equivalence, current permissions, native field coverage or live behavior.','Kubernetes has no perimeter plugin in this reviewed source roster; do not invent one.']if self.provider=='k8s'else['Source-ID conservation does not demonstrate evaluator equivalence, current permissions, native field coverage or live behavior.'],'sources':sources,'counts':{'current':len(rows),'baseline':len(old),'new':len(current-set(old)),'retired':len(set(old)-current)},'new_ids':sorted(current-set(old)),'retired_ids':sorted(set(old)-current),'checks':rows}
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--provider',choices=sorted(REPOSITORIES),required=True);parser.add_argument('--cache',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--fetch',action='store_true');args=parser.parse_args();audit=Inventory(args.provider,args.cache);sources=audit.fetch()if args.fetch else audit.verify();report=audit.report(sources);args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['counts'],sort_keys=True))
if __name__=='__main__':main()

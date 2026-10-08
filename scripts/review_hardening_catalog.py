import argparse,csv,hashlib,json,pathlib,re,collections,shutil,tempfile
from fnmatch import fnmatchcase
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent))
from bluepeass.finding_filters import blacklist_rules
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'docker'))
from query_context import prepare_query_context
parser=argparse.ArgumentParser(description='Review the complete pinned benchmark catalog and SQL hashes')
parser.add_argument('--mods-root',required=True,type=pathlib.Path)
parser.add_argument('--out-json',type=pathlib.Path)
parser.add_argument('--out-csv',type=pathlib.Path)
parser.add_argument('--check-context',action='store_true',help='Verify and record query corrections against the pinned source.')
args=parser.parse_args()
root=args.mods_root
catalog=json.loads((pathlib.Path(__file__).resolve().parent.parent/'bluepeass/hardening_catalog.json').read_text())
token=re.compile(r'(?P<heredoc><<-?(?P<label>[A-Za-z_]\w*)[^\n]*\n.*?^\s*(?P=label)\s*$)|"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*|\#[^\n]*|[{}]',re.M|re.S)
def blocks(text):
 for match in re.finditer(r'^(control|benchmark|query)\s+"([^"]+)"\s*\{',text,re.M):
  depth=1
  for t in token.finditer(text,match.end()):
   if t.group()=='{':depth+=1
   elif t.group()=='}':depth-=1
   if not depth:
    yield match.group(1),match.group(2),text[match.end():t.start()],text[:match.start()].count('\n')+1
    break
def quoted(body,key):
 m=re.search(r'^\s*'+key+r'\s*=\s*("(?:\\.|[^"\\])*")',body,re.M)
 if m:
  try:return json.loads(m[1])
  except:return m[1]
 return ''
output=[]
for provider,entries in catalog.items():
 for entry in entries:
  mod=entry['mod'];definitions=collections.defaultdict(dict)
  applied=set()
  if args.check_context:
   with tempfile.TemporaryDirectory(prefix='bluepeass-review-') as work:
    copy=pathlib.Path(work)/mod;shutil.copytree(root/mod,copy)
    applied=set(prepare_query_context(copy,provider))
  for p in (root/mod).rglob('*.pp'):
   text=p.read_text()
   for kind,name,body,line in blocks(text):
    definitions[kind][name]={'body':body,'path':str(p.relative_to(root/mod)),'line':line}
  controls=set()
  def visit(name):
   b=definitions['benchmark'][name]['body']
   m=re.search(r'children\s*=\s*\[(.*?)\]',b,re.S)
   if not m:return
   for kind,child in re.findall(r'\b(benchmark|control)\.([\w]+)',m[1]):
    if kind=='control':controls.add(child)
    else:visit(child)
  for benchmark in entry['benchmarks']:visit(benchmark)
  for name in sorted(controls):
   control=definitions['control'][name];b=control['body'];sql=b;refs=re.findall(r'\bquery\.([\w]+)',b)
   parts=[]
   for ref in refs:
    query=definitions['query'].get(ref)
    if query:parts.append(query['body'])
   if parts:sql='\n'.join(parts)
   sql_m=re.search(r'\bsql\s*=\s*<<-?(\w+)[^\n]*\n(.*?)^\s*\1\s*$',sql,re.M|re.S)
   if sql_m:sql=sql_m[2]
   record={'provider':provider,'suite':mod,'version':entry['version'],'control_id':mod.replace('-','_')+'.control.'+name,'name':name,'title':quoted(b,'title'),'description':quoted(b,'description'),'source':control['path'],'line':control['line'],'queries':refs,'query_sources':[definitions['query'][r]['path']+':'+str(definitions['query'][r]['line']) for r in refs if r in definitions['query']],'sql':sql,'sql_sha256':hashlib.sha256(sql.encode()).hexdigest()}
   record['context_queries']=sorted(set(refs or [name])&applied)
   record['sql_normalized_sha256']=hashlib.sha256(re.sub(r'\s+',' ',sql).strip().encode()).hexdigest()
   record['query_parameters_sha256']=hashlib.sha256(('\n'.join(parts) if parts else b).encode()).hexdigest()
   output.append(record)
  print(provider,mod,len(controls),'controls',len(definitions['query']),'queries',sum(bool(r['queries']) for r in output if r['suite']==mod),'referenced query controls')
if args.out_json:args.out_json.write_text(json.dumps(output,indent=2))
if args.out_csv:
 fields=['provider','suite','version','control_id','title','query_sources','sql_sha256','sql_normalized_sha256','query_parameters_sha256','source_url','disposition','context_queries','rules','rationale']
 with args.out_csv.open('w',newline='') as f:
  writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
  for record in output:
   matched=[r for r in blacklist_rules() if r['provider']==record['provider'] and 'hardening' in r['sections'] and any(fnmatchcase(record['control_id'],p) for p in r.get('control_patterns',[]))]
   disposition='retain-configuration-or-exposure'
   rationale='Security/configuration/exposure evidence remains relevant; customer intent and organization policy require scoped review rather than a generic suppression.'
   if matched:
    disposition='conditional-resource-exclusion' if any(r.get('attribute_patterns') or r.get('identifier_patterns') for r in matched) else 'conditional-duplicate' if any(r.get('duplicate_of') for r in matched) else 'invalid-assessment-exclusion'
    rationale=' | '.join(r['reason'] for r in matched)
   if record['provider']=='kubernetes' and (record['name'].startswith('pod_security_policy_') or record['name'].endswith('_container_argument_pod_security_policy_enabled') or record['name'].endswith('_container_argument_security_context_deny_enabled') or record['name'].endswith('_container_argument_insecure_port_0')):
    disposition='version-dependent-coverage-exclusion';rationale='Removed API/admission/insecure-serving feature; exclude only after a successful server-version read proves the feature removed.'
   elif record['name']=='secret_default_namespace_used':
    disposition='secret-read-contract-exclusion';rationale='Secret-object reads are outside the scanner contract; exclusion stays explicit in coverage.'
   if record['context_queries']:rationale+=' Runtime applicability/query corrections: '+', '.join(record['context_queries'])+'.'
   writer.writerow({**{k:record[k] for k in ['provider','suite','version','control_id','title','sql_sha256','sql_normalized_sha256','query_parameters_sha256']},'query_sources':';'.join(record['query_sources']),'source_url':'https://github.com/turbot/steampipe-mod-'+record['suite']+'/blob/'+record['version']+'/'+record['source']+'#L'+str(record['line']),'disposition':disposition,'context_queries':';'.join(record['context_queries']),'rules':';'.join(r['id'] for r in matched),'rationale':rationale})
print('Total',len(output))

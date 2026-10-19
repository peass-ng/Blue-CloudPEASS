"""Exact evidence-only successors preserve the pinned native evaluator contract."""
import ast
from copy import deepcopy
import hashlib
import importlib
from pathlib import Path
import pytest
from peaso.checks.fixtures import CASES

SUCCESSORS = [('peaso/checks/gcp_ports_compute.py', '62910aa2696e4b1982b86061f756fc2dadda003597c9ceca4c1dfa44c9be3d4a', '1de1b1e016b5c8c3eeb450552fe4fa866e04ba21c1af5de71dacd18db83aff96', [('    forwarding = get(item, "canIpForward", bool)\n    return result(forwarding, can_ip_forward=forwarding, semantics="IP forwarding configuration only")\n', '    return result(get(item, "canIpForward", bool), semantics="IP forwarding configuration only")\n'), ('    blocked = metadata_flag(item, "metadata.items", "block-project-ssh-keys")\n    return result(not blocked, block_project_ssh_keys=blocked)\n', '    return result(not metadata_flag(item, "metadata.items", "block-project-ssh-keys"))\n')]), ('peaso/checks/gcp_ports_metadata.py', '4391e626a44dc4b7b5984b2ecc0fd839649b1e7cf49834265fc171c4c7a6b89c', 'a2188d2fc080d2c4b4a80829a5fa0db38443a587e43255758967e14228979327', [('    public = sorted({value for row in access for value in\n                     (row.get("specialGroup"), row.get("iamMember"))\n                     if value in ("allAuthenticatedUsers", "allUsers") and\n                     (row.get("specialGroup") == "allAuthenticatedUsers" or row.get("iamMember") == "allUsers")})\n', ''), ('        public_acl_principals=public,\n', ''), ('                semantics="Incoming public/private and outgoing source address declarations; network reachability is separate")\n', '                semantics="No observed public incoming SQL IP in the collected address declarations; OUTGOING is an outbound source and does not prove a private incoming endpoint or effective reachability")\n')])]

# Independently reviewed semantic changes must be reversed before checking the
# immutable evidence-only successor and original hashes above.
LATER_SOURCE_CHANGES = {
 'peaso/checks/gcp_ports_compute.py': [(
  '''def sql_ssl(item, index):
    from .gcp_sql_transport_native import sql_transport
    return sql_transport(item, index)


rule("sql_instance_require_ssl_enabled", "sql_instance", "SQL metadata requires encrypted client connections", sql_ssl,
    {"databaseVersion": "POSTGRES_16", "settings": {"ipConfiguration": {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}}},
    {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}})
''',
  '''def sql_ssl(item, index):
    mode = get(item, "settings.ipConfiguration.sslMode", str)
    if mode not in ("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
        return unknown("unrecognized SQL TLS mode")
    return result(mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED", sslMode=mode,
        semantics="Encrypted-only and trusted-client-certificate modes both require encrypted client connections")


rule("sql_instance_require_ssl_enabled", "sql_instance", "SQL metadata requires encrypted client connections", sql_ssl,
    {"settings": {"ipConfiguration": {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}}},
    {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}})
''')],
}

def original_bytes(path):
 row=next(r for r in SUCCESSORS if r[0]==path)
 data=Path(path).read_bytes()
 text=data.decode()
 for current,original in LATER_SOURCE_CHANGES.get(path,[]):
  assert text.count(current)==1
  text=text.replace(current,original,1)
 assert hashlib.sha256(text.encode()).hexdigest()==row[2]
 for current,original in row[3]:
  assert text.count(current)==1
  text=text.replace(current,original,1)
 assert hashlib.sha256(text.encode()).hexdigest()==row[1]
 return text

@pytest.mark.parametrize('path',[r[0]for r in SUCCESSORS])
def test_evidence_successor_reverses_to_exact_original_source(path):
 original_bytes(path)


def function(source,name,namespace):
 tree=ast.parse(source)
 node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
 exec(compile(ast.Module(body=[node],type_ignores=[]),'<pinned original>','exec'),namespace)
 return namespace[name]


def outcome(callback,item,index):
 try:
  status,evidence=callback(deepcopy(item),deepcopy(index))
  # New fields and neutral wording are observations only.
  return ('result',status)
 except Exception as exc:return ('error',type(exc).__name__,str(exc))

CASES_TO_COMPARE={
 'gcp.ports.compute_instance_ip_forwarding_disabled':('gcp_ports_compute','no_forward',None),
 'gcp.ports.compute_instance_block_project_wide_ssh_enabled':('gcp_ports_compute','block_project_keys',None),
 'gcp.ports.bigquery_dataset_not_publicly_accessible':('gcp_ports_metadata','dataset_public',None),
 'gcp.ports.sql_instance_with_no_public_ips':('gcp_ports_metadata','sql_address','source_second_gen'),
 'gcp.ports.sql_instance_not_publicly_accessible':('gcp_ports_metadata','sql_address','private_network'),
 'gcp.ports.sql_private_ip_assignments':('gcp_ports_metadata','sql_address','private_only'),
 'gcp.ports.sql_no_primary_address':('gcp_ports_metadata','sql_address','primary'),
}

def callbacks_for(cid):
 modname,name,criterion=CASES_TO_COMPARE[cid]
 module=importlib.import_module('peaso.checks.'+modname)
 namespace=dict(vars(module))
 old=function(original_bytes('peaso/checks/'+modname+'.py'),name,namespace)
 new=getattr(module,name)
 if criterion:
  old_callbacks=[];new_callbacks=[]
  namespace['rule']=lambda *args,**kw:old_callbacks.append(args[2])
  old('parity',criterion)
  new_namespace=dict(vars(module));new_namespace['rule']=lambda *args,**kw:new_callbacks.append(args[2])
  current=function(Path(module.__file__).read_text(),name,new_namespace)
  current('parity',criterion)
  old,new=old_callbacks[0],new_callbacks[0]
 return old,new

@pytest.mark.parametrize(('cid','branch'),[(cid,branch) for cid in CASES_TO_COMPARE for branch in ('pass','fail','unknown','malformed') if branch in CASES[cid]])
def test_actual_native_fixtures_keep_original_status_and_errors(cid,branch):
 spec=CASES[cid]
 old,new=callbacks_for(cid)
 item=spec[branch];index=spec.get(branch+'_index',spec.get('index',{}))
 assert outcome(old,item,index)==outcome(new,item,index)


@pytest.mark.parametrize('cid',CASES_TO_COMPARE)
@pytest.mark.parametrize('item',[{}, {'_coverage':None}, {'canIpForward':'not-a-boolean','metadata':{'items':['bad']},'access':['bad']}])
def test_malformed_inputs_keep_original_status_and_errors(cid,item):
 old,new=callbacks_for(cid)
 assert outcome(old,item,{})==outcome(new,item,{})

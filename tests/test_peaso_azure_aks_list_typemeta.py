"""Kubernetes typed LIST items omit TypeMeta; their typed envelope supplies it.

Primary server maintainer explanation:
https://github.com/kubernetes/kubernetes/pull/127361#issuecomment-2353199198
"""
import copy
import pytest
from tests import test_peaso_azure_aks_readonly_root_native as previous
from tests.test_peaso_azure_aks_workloads_native import ca
from peaso.collectors import azure_aks_workloads_native as native

PATHS=('/api/v1/namespaces',*(row[0] for row in native.WORKLOADS.values()))
KINDS=tuple(native.WORKLOADS)

def wire(monkeypatch,omitted,*,changed_path=None,changed_field=None,changed_value=None,parent=False):
 original=previous.case
 def case(*args,**kwargs):
  routes,options,auth,Base=original(*args,**kwargs)
  class Api(Base):
   def get_json(self,path,params):
    result=copy.deepcopy(super().get_json(path,params))
    if path in omitted:
     for item in result['items']:
      item.pop('kind',None);item.pop('apiVersion',None)
    if path==changed_path:
     if parent:result[changed_field]=changed_value
     else:
      for item in result['items']:item[changed_field]=changed_value
    return result
  return routes,options,auth,Api
 monkeypatch.setattr(previous,'case',case)

@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
@pytest.mark.parametrize('path',PATHS)
def test_one_native_typed_list_omits_item_typemeta(monkeypatch,ca,path,via):
 wire(monkeypatch,{path})
 status,snapshot,_=previous.capture(monkeypatch,ca,via=via)
 assert status=='PASS'
 for row in snapshot['collections']:
  if row['type'] in native.WORKLOADS:
   _,kind,version,_=native.WORKLOADS[row['type']]
   assert all(item['kind']==kind and item['apiVersion']==version for item in row['items'])

@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_all_native_lists_omit_item_typemeta_public_pipeline(monkeypatch,ca,via):
 wire(monkeypatch,set(PATHS))
 assert previous.capture(monkeypatch,ca,via=via)[0]=='PASS'

@pytest.mark.parametrize('kind',KINDS)
def test_native_omitted_typemeta_keeps_actual_writable_counterexample(monkeypatch,ca,kind):
 wire(monkeypatch,set(PATHS))
 assert previous.capture(monkeypatch,ca,mode='false',affected=kind,via='planner')[0]=='FAIL'

@pytest.mark.parametrize('path',PATHS)
@pytest.mark.parametrize('field,value',[('kind',None),('kind','Foreign'),('apiVersion',None),('apiVersion','foreign/v1')])
def test_explicit_invalid_item_typemeta_cannot_be_repaired(monkeypatch,ca,path,field,value):
 wire(monkeypatch,set(PATHS),changed_path=path,changed_field=field,changed_value=value)
 assert previous.capture(monkeypatch,ca,via='planner')[0]=='UNKNOWN'

@pytest.mark.parametrize('path',PATHS)
@pytest.mark.parametrize('field,value',[('kind','ForeignList'),('apiVersion','foreign/v1')])
def test_omitted_item_typemeta_never_bypasses_list_generation(monkeypatch,ca,path,field,value):
 wire(monkeypatch,set(PATHS),changed_path=path,changed_field=field,changed_value=value,parent=True)
 assert previous.capture(monkeypatch,ca,via='planner')[0]=='UNKNOWN'

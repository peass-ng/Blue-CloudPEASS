"""Native Azure report schema, bound guest measurements and failure preservation."""
import copy
from datetime import datetime, timezone
import json
import pytest
from peaso.collectors.azure import _Reader, AzureReadError
from peaso.collectors.azure_guest_reports import collect_reports, project_report
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
VM=SCOPE+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/qa'
AID=VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/baseline'
RID=AID+'/reports/7367cbb8-ae99-47d0-a33b-a283564d2cb1'
PREFIX='azure.gap.compute_vm_'
SUFFIXES=['administrators_group_with_extra_accounts_windows',
 'administrators_group_with_no_specified_members_windows','administrators_group_with_specified_members_windows',
 'meet_firewall_properties_windows','password_file_permissions_0644_linux',
 'with_no_specified_certificates_in_trusted_root_windows']

def case(suffix=SUFFIXES[0]):
 now=datetime.now(timezone.utc).isoformat()
 policy={'assignmentName':'baseline','configurationName':'qa-baseline','configurationVersion':'1.0','maxReportAgeSeconds':3600}
 properties={'group':'Administrators','membershipComplete':True,'observedMembers':['alice']}
 params=[]
 fields={SUFFIXES[0]:('approvedAdministrators',['alice']),SUFFIXES[1]:('requiredAdministrators',['alice']),
         SUFFIXES[2]:('prohibitedAdministrators',['mallory']),SUFFIXES[5]:('requiredThumbprints',['a'*40])}
 if suffix in fields:
  key,value=fields[suffix];policy[key]=value;params.append({'name':key,'value':json.dumps(value)})
 if suffix==SUFFIXES[5]:properties={'store':'LocalMachine\\Root','certificateSetComplete':True,'observedThumbprints':['a'*40]}
 if suffix==SUFFIXES[4]:
  properties={'path':'/etc/passwd','mode':'0644'}
  params.extend([{'name':'filePaths','value':'["/etc/passwd"]'},{'name':'requiredModes','value':'["0644"]'}])
 resources=[{'resourceId':'setting','complianceStatus':'Compliant','properties':properties}]
 if suffix==SUFFIXES[3]:
  settings={key:{'category':key,'expected':True}for key in ('firewallState','inboundConnections','outboundConnections','ruleManagement','notifications')}
  policy['requiredSettings']=settings;params.append({'name':'requiredSettings','value':json.dumps(settings)})
  resources=[{'resourceId':key,'complianceStatus':'Compliant','properties':{'settingName':key,'expected':True,'observed':True}}for key in settings]
 assignment={'id':AID,'name':'baseline','properties':{'latestReportId':RID,'complianceStatus':'Compliant',
  'guestConfiguration':{'name':'qa-baseline','version':'1.0','configurationParameter':params}}}
 vm={'id':VM,'properties':{'storageProfile':{'osDisk':{'osType':'Linux'if suffix==SUFFIXES[4]else'Windows'}}},
     'guestConfigurationAssignments':[assignment],'_coverage':{'guestConfigurationAssignments':{'status':'collected',
      '_provenance':{'source_operation':'GuestConfigurationAssignments_List','read_only':True,'observed_at':now}}}}
 native={'id':RID,'properties':{'assignment':{'name':'baseline','configuration':{'name':'qa-baseline','version':'1.0'}},
  'vm':{'id':VM},'reportId':RID.rsplit('/',1)[-1],'complianceStatus':'Compliant','startTime':now,'endTime':now,
  'details':{'complianceStatus':'Compliant','startTime':now,'endTime':now,'jobId':RID.rsplit('/',1)[-1],
             'operationType':'Consistency','resources':resources}}}
 return vm,assignment,native,policy

def collected(vm,native,**options):
 reader=_Reader({'retries':0,**options});reader.collections=[{'type':'vm','scope':SCOPE,'service':'Microsoft.Compute','status':'collected','items':[vm]}]
 if 'max_calls' in options:reader.budget.calls=options['max_calls']
 calls=[]
 def request(url):
  calls.append(url)
  if isinstance(native,Exception):raise native
  return copy.deepcopy(native)
 collect_reports(reader,request,[SCOPE],{'guest_configuration_report'})
 return reader,calls

def run(reader,suffix,policy):
 snapshot=make_snapshot('azure',[SCOPE],reader.collections,metadata={'compliance_policy':{'status':'collected','scope':SCOPE,'checks':{PREFIX+suffix:policy}}})
 return evaluate_snapshot(snapshot,checks=[PREFIX+suffix],include_not_applicable=True)['findings'][0]['status']

@pytest.mark.parametrize('suffix',SUFFIXES)
def test_native_report_all_six_baselines_and_real_negative_measurement(suffix):
 vm,assignment,native,policy=case(suffix)
 reader,calls=collected(vm,native)
 assert calls==['https://management.azure.com'+RID+'?api-version=2024-04-05']
 assert run(reader,suffix,policy)=='PASS'
 bad=copy.deepcopy(native);bad['properties']['complianceStatus']='NonCompliant';bad['properties']['details']['complianceStatus']='NonCompliant'
 resource=bad['properties']['details']['resources'][0];resource['complianceStatus']='NonCompliant'
 props=resource['properties']
 if suffix==SUFFIXES[0]:props['observedMembers'].append('mallory')
 if suffix==SUFFIXES[1]:props['observedMembers']=[]
 if suffix==SUFFIXES[2]:props['observedMembers'].append('mallory')
 if suffix==SUFFIXES[4]:props['mode']='0666'
 if suffix==SUFFIXES[5]:props['observedThumbprints']=[]
 reader,_=collected(vm,bad)
 assert run(reader,suffix,policy)=='FAIL'

@pytest.mark.parametrize('mutation',['pending','wrong_job','future','missing_details','no_end_time','foreign_vm','foreign_assignment','unbound_version','foreign_id','missing_resources','duplicate_resources'])
def test_invalid_or_unmeasured_report_cannot_pass(mutation):
 vm,assignment,native,policy=case();props=native['properties']
 if mutation=='pending':props['complianceStatus']='Pending'
 if mutation=='wrong_job':props['details']['jobId']='wrong'
 if mutation=='future':props['endTime']=props['details']['endTime']='2099-01-01T00:00:00Z'
 if mutation=='missing_details':del props['details']
 if mutation=='no_end_time':del props['endTime']
 if mutation=='foreign_vm':props['vm']['id']=VM+'other'
 if mutation=='foreign_assignment':props['assignment']['name']='other'
 if mutation=='unbound_version':props['assignment']['configuration']['version']='2.0'
 if mutation=='foreign_id':native['id']=RID+'other'
 if mutation=='missing_resources':del props['details']['resources']
 if mutation=='duplicate_resources':props['details']['resources']*=2
 reader,_=collected(vm,native)
 assert run(reader,SUFFIXES[0],policy) not in ('PASS','FAIL','NOT_APPLICABLE')

def test_sensitive_dsc_properties_and_diagnostic_reason_never_leave_projection():
 vm,assignment,native,policy=case();before=copy.deepcopy(native)
 row=native['properties']['details']['resources'][0]
 row['properties']['PsDscRunAsCredential']='secret-marker'
 row['properties']['InlineScript']='secret-script'
 row['reasons']=[{'phrase':'secret-reason'}]
 projected=project_report(native,RID,VM,assignment)
 assert 'secret-' not in json.dumps(projected)
 assert row['properties']['PsDscRunAsCredential']=='secret-marker'

@pytest.mark.parametrize('state',['denied','partial','not_collected'])
def test_unavailable_vm_inventory_is_never_empty_success(state):
 reader=_Reader({});reader.collections=[{'type':'vm','scope':SCOPE,'service':'Microsoft.Compute','status':state,'items':[]}]
 collect_reports(reader,lambda *args:pytest.fail('must not read absent VMs'),[SCOPE],{'guest_configuration_report'})
 assert reader.collections[-1]['status'] not in ('collected','empty')

def test_complete_empty_vm_inventory_and_assignment_inventory():
 reader=_Reader({});reader.collections=[{'type':'vm','scope':SCOPE,'service':'Microsoft.Compute','status':'empty','items':[]}]
 collect_reports(reader,lambda *args:pytest.fail('no guest report exists'),[SCOPE],{'guest_configuration_report'})
 assert reader.collections[-1]['status']=='empty'
 vm,assignment,native,policy=case();vm['guestConfigurationAssignments']=[];vm['_coverage']['guestConfigurationAssignments']['status']='empty'
 reader,calls=collected(vm,native)
 assert not calls and reader.collections[-1]['status']=='empty'
 assert run(reader,SUFFIXES[0],policy)=='FAIL'

def test_denied_child_and_budget_limit_preserve_unknown():
 vm,assignment,native,policy=case()
 for failure in (AzureReadError('denied',403),native):
  reader,calls=collected(vm,failure,**({'max_calls':1}if failure is native else {}))
  assert reader.collections[-1]['status'] not in ('collected','empty')
  assert run(reader,SUFFIXES[0],policy) not in ('PASS','FAIL','NOT_APPLICABLE')

def test_native_resource_id_in_dsc_properties_is_normalized_without_ambiguity():
 vm,assignment,native,policy=case();row=native['properties']['details']['resources'][0]
 row['properties']['ResourceId']=row.pop('resourceId')
 assert project_report(native,RID,VM,assignment)['properties']['details']['resources'][0]['resourceId']=='setting'
 row['resourceId']='different'
 with pytest.raises(ValueError):project_report(native,RID,VM,assignment)

@pytest.mark.parametrize('suffix',SUFFIXES)
def test_full_native_collector_keeps_owner_policy_and_collects_bound_report(suffix):
 from urllib.parse import urlsplit
 from peaso.collectors import azure
 vm,assignment,native,policy=case(suffix)
 source={key:copy.deepcopy(value)for key,value in vm.items()if key in ('id','properties')}
 source['type']='Microsoft.Compute/virtualMachines'
 class Transport:
  def request(self,url,**kwargs):
   path=urlsplit(url).path
   if path=='/providers/Microsoft.ResourceGraph/resources':return {'data':[]}
   if path==SCOPE+'/providers/Microsoft.Compute/virtualMachines':return {'value':[copy.deepcopy(source)]}
   if path==VM:return copy.deepcopy(source)
   if path==VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments':return {'value':[copy.deepcopy(assignment)]}
   if path==RID:return copy.deepcopy(native)
   if path==VM+'/instanceView':return {'statuses':[{'code':'PowerState/running'}]}
   if path in (VM+'/extensions',VM+'/providers/Microsoft.Insights/diagnosticSettings'):return {'value':[]}
   raise AssertionError('unexpected native request '+path)
 options={'inventories':['guest_configuration_report'],'retries':0,
          'compliance_parameters':{'azure_guest_configuration':{'scope':SCOPE,'checks':{PREFIX+suffix:policy}}}}
 snapshot=azure.collect({'scopes':[SCOPE],'options':options},['guest_configuration_report'],transport=Transport())
 report=evaluate_snapshot(snapshot,checks=[PREFIX+suffix])
 assert len(report['findings'])==1 and report['findings'][0]['status']=='PASS'
 assert snapshot['metadata']['compliance_policy']['source']=='owner_declared_policy'
 inventory=next(c for c in snapshot['collections']if c['type']=='guest_configuration_report'and c['scope']==SCOPE)
 assert inventory['status']=='collected' and len(inventory['items'])==1
 assert 'operationStatus' not in inventory['items'][0]['properties']

@pytest.mark.parametrize('mutation',['foreign_vm','foreign_report_path','query_in_report','duplicate_assignment','incomplete_assignments','empty_conflict'])
def test_untrusted_parent_bindings_do_not_certify_empty_inventory(mutation):
 vm,assignment,native,policy=case()
 if mutation=='foreign_vm':vm['id']=VM.replace('11111111','22222222')
 if mutation=='foreign_report_path':assignment['properties']['latestReportId']='/subscriptions/foreign/report'
 if mutation=='query_in_report':assignment['properties']['latestReportId']=RID+'?token=bad'
 if mutation=='duplicate_assignment':vm['guestConfigurationAssignments'].append(copy.deepcopy(assignment))
 if mutation=='incomplete_assignments':vm['_coverage']['guestConfigurationAssignments']['status']='partial'
 if mutation=='empty_conflict':vm['_coverage']['guestConfigurationAssignments']['status']='empty'
 reader,calls=collected(vm,native)
 assert reader.collections[-1]['status'] not in ('collected','empty')
 if mutation!='duplicate_assignment':assert calls==[]
 assert run(reader,SUFFIXES[0],policy) not in ('PASS','FAIL','NOT_APPLICABLE')

def test_conflicting_native_assignment_pages_are_partial_and_never_a_pass():
 vm,assignment,native,policy=case()
 other=copy.deepcopy(assignment);other['properties']['guestConfiguration']['version']='foreign-version'
 reader=_Reader({})
 def pages():yield [assignment];yield [other]
 result=reader._read(('embedded_guestConfigurationAssignments',VM,'Microsoft.Resources',pages))
 assert result['status']=='partial' and len(result['items'])==1
 vm['_coverage']['guestConfigurationAssignments']={'status':result['status']}
 vm['guestConfigurationAssignments']=result['items']
 reader,calls=collected(vm,native)
 assert not calls and run(reader,SUFFIXES[0],policy) not in ('PASS','FAIL','NOT_APPLICABLE')

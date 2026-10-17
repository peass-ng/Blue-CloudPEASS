"""Read-only guest report extension coverage and identity boundaries."""
from peaso.collectors.batch_remaining_azure_vm_storage import collect_guest_configuration_reports

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
VM=SCOPE+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
ASSIGNMENT=VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/baseline'
REPORT=ASSIGNMENT+'/reports/latest'

class Reader:
    def __init__(self, vm, response=None, state='collected'):
        self.collections=[{'type':'vm','scope':SCOPE,'status':state,'items':[vm] if vm else []}]
        self.response=response
        self.urls=[]
    def call(self, request, url):
        self.urls.append(url)
        if isinstance(self.response, Exception):raise self.response
        return self.response
    def run(self, jobs):
        for kind,scope,service,fetch in jobs:
            try:
                rows=[row for page in fetch() for row in page]
                self.collections.append({'type':kind,'scope':scope,'service':service,'status':'collected' if rows else 'empty','items':rows})
            except Exception as exc:self.unavailable(kind,scope,service,exc)
    def unavailable(self,kind,scope,service,exc):
        self.collections.append({'type':kind,'scope':scope,'service':service,'status':'error','items':[], 'error':{'code':type(exc).__name__}})

def vm(assignments=True):
    rows=[{'id':ASSIGNMENT,'name':'baseline','properties':{'latestReportId':'latest','guestConfiguration':{'name':'approved-baseline','version':'1.0'}}}] if assignments else []
    return {'id':VM,'_coverage':{'guestConfigurationAssignments':{'status':'collected' if rows else 'empty'}},'guestConfigurationAssignments':rows}

def response():
    return {'id':REPORT,'properties':{'endTime':'2026-10-13T23:00:00Z','reportId':'latest','complianceStatus':'Compliant','details':{'operationType':'Consistency','resources':[{'resourceId':'r','complianceStatus':'Compliant','properties':{}}]}}}

def test_report_get_binds_vm_assignment_and_details():
    reader=Reader(vm(),response())
    collect_guest_configuration_reports(reader,None,[SCOPE])
    child=reader.collections[-1]
    assert child['status']=='collected'
    row=child['items'][0]
    assert row['properties']['vm']['id']==VM
    assert row['properties']['assignment']['configuration']=={'name':'approved-baseline','version':'1.0'}
    assert row['_coverage']['resources']['status']=='collected'
    assert row['_provenance']['read_only'] is True
    assert len(reader.urls)==1 and reader.urls[0].endswith('/reports/latest?api-version=2024-04-05')

def test_empty_parent_assignment_inventory_is_complete_empty():
    reader=Reader(vm(False))
    collect_guest_configuration_reports(reader,None,[SCOPE])
    assert reader.collections[-1]['status']=='empty' and reader.urls==[]

def test_denied_or_partial_parent_never_fabricates_empty():
    reader=Reader(vm(False),state='partial')
    collect_guest_configuration_reports(reader,None,[SCOPE])
    assert reader.collections[-1]['status']=='error'

def test_foreign_report_or_missing_details_is_unavailable():
    for bad in ({**response(),'id':REPORT+'-foreign'}, {'id':REPORT,'properties':{'details':{}}}):
        reader=Reader(vm(),bad)
        collect_guest_configuration_reports(reader,None,[SCOPE])
        assert reader.collections[-1]['status']=='error'

def test_report_read_error_is_unavailable():
    reader=Reader(vm(),PermissionError('denied'))
    collect_guest_configuration_reports(reader,None,[SCOPE])
    assert reader.collections[-1]['status']=='error'

def test_guest_policy_projection_is_explicit_scoped_and_whitelisted():
    from peaso.collectors.batch_remaining_azure_vm_storage import project_guest_policy
    check='azure.gap.compute_vm_administrators_group_with_extra_accounts_windows'
    raw={'compliance_policy':{'azure_vm_storage':{'status':'collected','scope':SCOPE,
         'checks':{check:{'assignmentName':'baseline','configurationName':'approved-baseline',
                          'configurationVersion':'1.0','maxReportAgeSeconds':3600,
                          'approvedAdministrators':['alice'],'unrelatedSecret':'drop'}}}}}
    projected=project_guest_policy(raw,[SCOPE])
    assert projected['checks'][check]['approvedAdministrators']==['alice']
    assert 'unrelatedSecret' not in projected['checks'][check]
    assert project_guest_policy(raw,['/subscriptions/other']) is None

def test_guest_policy_merge_preserves_existing_controls_and_rejects_conflict():
    from peaso.collectors.batch_remaining_azure_vm_storage import merge_guest_policy
    guest={'status':'collected','scope':SCOPE,'checks':{'azure.gap.compute_vm_administrators_group_with_extra_accounts_windows':{'assignmentName':'baseline'}}}
    existing={'status':'collected','sw03':{'status':'collected','scope':SCOPE,'storageAccess':{'expectedSettings':{'allowBlobPublicAccess':False}}},'checks':{'other.control':{'approved':True}}}
    merged,reason=merge_guest_policy(existing,guest)
    assert reason is None
    assert merged['sw03']==existing['sw03']
    assert merged['checks']['other.control']==existing['checks']['other.control']
    assert all(merged['checks'][key]==value for key,value in guest['checks'].items())
    foreign={**existing,'scope':'/subscriptions/other'}
    unchanged,reason=merge_guest_policy(foreign,guest)
    assert unchanged==foreign and reason=='owner_policy_scope_conflict'
    conflicting={**existing,'checks':{**existing['checks'],next(iter(guest['checks'])):{'assignmentName':'different'}}}
    unchanged,reason=merge_guest_policy(conflicting,guest)
    assert unchanged==conflicting and reason=='owner_check_policy_conflict'


def test_guest_report_drops_opaque_secret_and_free_text_fields():
    raw=response()
    raw['properties']['output']='SENTINEL_SECRET'
    raw['properties']['details']['resources'][0]['properties'].update(body='SENTINEL_SECRET',text='SENTINEL_SECRET')
    raw['properties']['details']['resources'][0]['message']='SENTINEL_SECRET'
    reader=Reader(vm(),raw)
    collect_guest_configuration_reports(reader,None,[SCOPE])
    assert reader.collections[-1]['status']=='collected'
    assert 'SENTINEL_SECRET' not in str(reader.collections[-1])


def test_official_shape_omits_optional_resource_id_without_fabrication():
    raw=response()
    raw['properties']['details']['resources'][0].pop('resourceId')
    reader=Reader(vm(),raw)
    collect_guest_configuration_reports(reader,None,[SCOPE])
    assert reader.collections[-1]['status']=='collected'
    detail=reader.collections[-1]['items'][0]['properties']['details']['resources'][0]
    assert 'resourceId' not in detail
    assert 'operationStatus' not in reader.collections[-1]['items'][0]['properties']

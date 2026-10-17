"""Read exact latest VM guest configuration reports; never execute guest code.

Native schema: https://learn.microsoft.com/en-us/rest/api/guestconfiguration/guest-configuration-assignment-reports/get?view=rest-guestconfiguration-2024-04-05
"""
from datetime import datetime, timezone
import re

ARM = 'https://management.azure.com'
VERSION = '2024-04-05'
RESOURCE_PROPERTIES = frozenset({'group', 'membershipComplete', 'observedMembers', 'store',
    'certificateSetComplete', 'observedThumbprints', 'path', 'mode', 'settingName',
    'expected', 'observed', 'serviceName', 'state'})


def project_report(value, expected, vm_id, assignment):
    if not isinstance(value, dict) or str(value.get('id', '')).casefold() != expected.casefold():
        raise ValueError('foreign guest configuration report')
    props=value.get('properties')
    if not isinstance(props,dict) or not isinstance(props.get('vm'),dict) or str(props['vm'].get('id','')).casefold()!=vm_id.casefold():
        raise ValueError('guest report VM identity mismatch')
    config=assignment.get('properties',{}).get('guestConfiguration',{})
    binding=props.get('assignment',{})
    if not isinstance(binding,dict) or not isinstance(binding.get('configuration'),dict) or binding.get('name')!=assignment.get('name') or any(binding['configuration'].get(key)!=config.get(key) for key in ('name','version')):
        raise ValueError('guest report baseline identity mismatch')
    details=props.get('details');rows=details.get('resources') if isinstance(details,dict) else None
    safe_rows=[]
    if isinstance(rows,list):
        seen=set()
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('properties'),dict):
                raise ValueError('malformed guest report resource')
            rid=row.get('resourceId',row['properties'].get('ResourceId'))
            if not isinstance(rid,str) or not rid or rid in seen or ('ResourceId' in row['properties'] and row['properties']['ResourceId']!=rid):
                raise ValueError('invalid guest report resource identity')
            seen.add(rid)
            safe_rows.append({'resourceId':rid,'complianceStatus':row.get('complianceStatus'),
                             'properties':{key:data for key,data in row['properties'].items() if key in RESOURCE_PROPERTIES}})
    safe={key:data for key,data in props.items() if key in ('complianceStatus','startTime','endTime','reportId')}
    safe.update(vm={'id':vm_id},assignment={'name':binding['name'],'configuration':{key:binding['configuration'].get(key) for key in ('name','version')}},
                details={key:data for key,data in (details or {}).items() if key in ('complianceStatus','startTime','endTime','jobId','operationType')})
    if isinstance(rows,list):safe['details']['resources']=safe_rows
    return {'id':expected,'properties':safe,
            '_coverage':{'resources':{'status':'collected' if safe_rows else 'empty' if isinstance(rows,list) else 'not_collected'}},
            '_provenance':{'source_operation':'GuestConfigurationAssignmentReports_Get','read_only':True,
                           'api_version':VERSION,'native_report_schema':True,
                           'observed_at':datetime.now(timezone.utc).isoformat()}}


def collect_reports(reader,request,scopes,wanted):
    if 'guest_configuration_report' not in wanted:return
    from .azure import AzureReadError
    jobs=[]
    for scope in scopes:
        sources=[c for c in reader.collections if c['type']=='vm' and c['scope'].casefold()==scope.casefold()]
        def fetch(sources=sources,scope=scope):
            failures=[];seen=set()
            if not sources:raise AzureReadError('guest_report_vm_inventory_unavailable')
            for source in sources:
                if source['status'] not in ('collected','empty'):failures.append(AzureReadError('guest_report_vm_inventory_incomplete'))
                for vm in source['items']:
                    vm_id=vm['id'];coverage=vm.get('_coverage',{}).get('guestConfigurationAssignments',{})
                    if (not isinstance(vm_id,str) or not vm_id.casefold().startswith(scope.casefold()+'/resourcegroups/') or
                            not re.fullmatch(r'/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft.Compute/virtualMachines/[^/?#]+',vm_id,re.I)):
                        failures.append(ValueError('foreign guest report VM'));continue
                    assignments=vm.get('guestConfigurationAssignments')
                    if coverage.get('status') not in ('collected','empty') or not isinstance(assignments,list):
                        failures.append(AzureReadError('guest_assignment_inventory_incomplete'));continue
                    if coverage['status']=='empty' and assignments:
                        failures.append(ValueError('empty guest assignment inventory conflicts with rows'));continue
                    for assignment in assignments:
                        try:
                            aid=assignment.get('id','');name=assignment.get('name','')
                            if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or aid.casefold()!=(vm_id+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/'+name).casefold() or aid.casefold() in seen:
                                raise ValueError('invalid guest assignment identity')
                            seen.add(aid.casefold())
                            latest=assignment.get('properties',{}).get('latestReportId')
                            if not isinstance(latest,str) or not latest:raise ValueError('guest latest report unavailable')
                            expected=latest if latest.startswith('/') else aid+'/reports/'+latest
                            prefix=aid+'/reports/'
                            if not expected.casefold().startswith(prefix.casefold()) or not re.fullmatch(r'[A-Za-z0-9_.-]+',expected[len(prefix):]):
                                raise ValueError('foreign guest latest report identity')
                            value=reader.call(request,ARM+expected+'?api-version='+VERSION)
                            yield [project_report(value,expected,vm_id,assignment)]
                        except Exception as exc:failures.append(exc)
            if failures:raise failures[0]
        jobs.append(('guest_configuration_report',scope,'Microsoft.GuestConfiguration',fetch))
    reader.run(jobs)

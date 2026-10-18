"""Measured current monitor violations must not need a Completed sibling job.

All provider metadata is collected through the actual inert ARM HTTP stub.
The independently supplied process observations are synthetic external evidence.
"""
import copy
from datetime import datetime, timedelta
from tests import test_peaso_backup_c5_native_binding as fixtures
from tests.test_peaso_backup_c5_native_binding import MONITOR, JOB, VAULT, captured, supplied_monitor, reseal, data, status
from tests.test_peaso_azure_bulk_native import Transport


def scenario(monkeypatch, states=('Failed',), ages=None):
    def transport(responses):
        responses=copy.deepcopy(responses)
        template=responses[VAULT+'/backupJobs']['value'][0]
        native=[]
        for i,state in enumerate(states):
            row=copy.deepcopy(template);row['id']=JOB if i==0 else JOB+'-'+str(i+1)
            row['name']=row['id'].rsplit('/',1)[-1]
            row['properties']['status']=state
            if ages is not None:
                end=datetime.fromisoformat(template['properties']['endTime'])+timedelta(days=2-ages[i])
                row['properties'].update(startTime=(end-timedelta(hours=1)).isoformat(),endTime=end.isoformat())
            native.append(row)
        responses[VAULT+'/backupJobs']={'value':native}
        return Transport(responses)
    monkeypatch.setattr(fixtures,'Transport',transport)
    native=captured(monkeypatch,MONITOR)
    snap=supplied_monitor(native)
    jobs=next(env for env in snap['collections'] if env['type']=='backup_job')['items']
    props=data(snap,'backup_monitor_evidence')['properties']
    template=props['monitoringValidation']['jobBindings'][0]
    props['observedJobIds']=[row['id'] for row in jobs]
    props['monitoringValidation']['jobBindings']=[dict(copy.deepcopy(template),jobId=row['id'],
                                                   jobStatus=row['properties']['status']) for row in jobs]
    return reseal(snap)


def test_recent_failed_only_execution_is_not_hidden_by_no_completed_job(monkeypatch):
    snap=scenario(monkeypatch)
    assert status(snap,MONITOR)=='FAIL',status.last_findings


def test_confirmed_process_failure_without_completed_execution_is_fail(monkeypatch):
    for missing,summary in [('MissingAlertRouting','jobAlertsRouted'),('MissingDocumentation','ops06Documented')]:
        snap=scenario(monkeypatch,('Cancelled',))
        props=data(snap,'backup_monitor_evidence')['properties'];props[summary]=False
        props['monitoringValidation']['jobBindings'][0]['monitoringResult']=missing
        assert status(reseal(snap),MONITOR)=='FAIL',status.last_findings


def test_recent_failed_plus_completed_execution_retains_violation(monkeypatch):
    for states in [('Failed','Completed'),('Completed','Failed')]:
        assert status(scenario(monkeypatch,states),MONITOR)=='FAIL',status.last_findings


def test_all_successful_current_executions_can_still_pass(monkeypatch):
    assert status(scenario(monkeypatch,('Completed','Completed')),MONITOR)=='PASS',status.last_findings


def test_missing_observation_or_exact_binding_never_becomes_measured_failure(monkeypatch):
    for missing in ('observedAt','jobStatus','protectedItemId','resultArtifactSha256'):
        snap=scenario(monkeypatch);props=data(snap,'backup_monitor_evidence')['properties']
        props['monitoringValidation']['jobBindings'][0].pop(missing)
        assert status(reseal(snap),MONITOR)=='UNKNOWN',status.last_findings


def test_foreign_stale_or_unavailable_authority_and_history_remain_unknown(monkeypatch):
    for mutation in ('foreign-capture','stale','missing-history','missing-author','wrong-workload'):
        snap=scenario(monkeypatch);validation=data(snap,'backup_monitor_evidence')['properties']['monitoringValidation']
        if mutation=='foreign-capture':validation['customer_context_id']='another-customer'
        elif mutation=='stale':validation['expires_at']=(datetime.fromisoformat(snap['created_at'])-timedelta(days=1)).isoformat()
        elif mutation=='missing-history':validation['historyComplete']=False
        elif mutation=='missing-author':validation.pop('authorized_by')
        else:validation['workloadType']='unproved-workload'
        assert status(reseal(snap),MONITOR)=='UNKNOWN',status.last_findings


def test_unknown_status_after_failed_binding_keeps_scope_unresolved(monkeypatch):
    for states in [('Failed','UnknownFutureState'),('UnknownFutureState','Failed')]:
        assert status(scenario(monkeypatch,states),MONITOR)=='UNKNOWN',status.last_findings


def test_outside_approved_window_failures_are_not_new_universal_sla(monkeypatch):
    assert status(scenario(monkeypatch,('Failed',),[10]),MONITOR)=='UNKNOWN',status.last_findings
    assert status(scenario(monkeypatch,('Failed','Completed'),[10,1]),MONITOR)=='PASS',status.last_findings


def test_confirmed_failure_does_not_override_contradictory_process_summary(monkeypatch):
    snap=scenario(monkeypatch)
    props=data(snap,'backup_monitor_evidence')['properties']
    props['monitoringValidation']['jobBindings'][0]['monitoringResult']='MissingDocumentation'
    # Both summary flags still claim success: this external observation is inconsistent.
    assert status(reseal(snap),MONITOR)=='UNKNOWN',status.last_findings

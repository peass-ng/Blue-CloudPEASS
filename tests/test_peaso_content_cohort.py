"""Bounded cohort source association, failure isolation, retry budgets and cleanup."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import threading
import time
import pytest
from peaso import secret_scanning_batch as batch,secret_scanning as scanner

spec=importlib.util.spec_from_file_location('peaso._cohort_test',Path(__file__).resolve().parents[1]/'peaso/secret_scanning_cohort.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_eight_sources_share_one_preparation_and_keep_exact_output(monkeypatch):
    calls=[];members=[f'source-{i}'for i in range(8)]
    def prepare(items,timeout):
        calls.append(items);return {item:('out-'+item[1]).encode()for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    cohort=module.ContentCohort(members,time.monotonic()+3,max_bytes=1024)
    def run(member):
        try:return cohort.output(member,member.encode(),member)
        finally:cohort.finish(member)
    with ThreadPoolExecutor(8)as pool:assert list(pool.map(run,members))==[('out-'+member).encode()for member in members]
    assert len(calls)==1 and len(calls[0])==8
    cohort.close();assert not cohort.pending and not cohort.results


def test_terminal_denied_peer_does_not_block_other_sources(monkeypatch):
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda items,timeout:{item:b''for item in items})
    cohort=module.ContentCohort(['good','denied'],time.monotonic()+2,max_bytes=1024)
    cohort.finish('denied')
    assert cohort.output('good',b'clean','good')==b''
    cohort.finish('good');cohort.close()


def test_failed_batch_fallback_is_serial_and_does_not_share_exception(monkeypatch):
    def fail(*args):raise RuntimeError('synthetic private detail')
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',fail)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'synthetic')
    active=maximum=0;lock=threading.Lock();timeouts=[]
    def run(argv,payload,timeout):
        nonlocal active,maximum
        assert argv[1]=='stdin' and '--no-verification'in argv and '--fail-on-scan-errors'in argv
        with lock:active+=1;maximum=max(maximum,active);timeouts.append(timeout)
        time.sleep(.01)
        with lock:active-=1
        return payload
    monkeypatch.setattr(scanner,'_run',run)
    members=['one','two','three','four'];cohort=module.ContentCohort(members,time.monotonic()+2,max_bytes=1024)
    def call(member):
        try:return cohort.output(member,member.encode(),member)
        finally:cohort.finish(member)
    with ThreadPoolExecutor(4)as pool:assert list(pool.map(call,members))==[member.encode()for member in members]
    assert maximum==1 and all(0<t<=2 for t in timeouts)
    assert not cohort.results and not cohort.pending


def test_one_active_worker_flushes_without_waiting_for_queued_members(monkeypatch):
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda items,timeout:{item:b''for item in items})
    cohort=module.ContentCohort(['one','two'],time.monotonic()+2,max_bytes=1024,gather_seconds=.01)
    assert cohort.output('one',b'one','one')==b''
    cohort.finish('one')
    assert cohort.output('two',b'two','two')==b''
    cohort.finish('two')


def test_close_wakes_waiter_and_discards_private_working_data(monkeypatch):
    cohort=module.ContentCohort(['one','two'],time.monotonic()+3,max_bytes=1024,gather_seconds=2)
    with ThreadPoolExecutor(1)as pool:
        future=pool.submit(cohort.output,'one',b'synthetic','one')
        while not cohort.pending:time.sleep(.001)
        cohort.close()
        with pytest.raises(RuntimeError,match='unavailable'):future.result(timeout=1)
    assert not cohort.pending and not cohort.results


def test_expired_budget_never_invokes_fallback(monkeypatch):
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda *args:None)
    monkeypatch.setattr(scanner,'_run',lambda *args:pytest.fail('expired fallback executed'))
    cohort=module.ContentCohort(['one'],time.monotonic()-1,max_bytes=1024)
    with pytest.raises(TimeoutError):cohort.output('one',b'one','one')
    cohort.close()


def test_wrong_member_or_path_cannot_receive_another_sources_output():
    cohort=module.ContentCohort(['one'],time.monotonic()+1,max_bytes=1024)
    with pytest.raises(ValueError):cohort.output('other',b'one','one')
    with pytest.raises(ValueError):cohort.output('one',b'one','other')
    cohort.close()


def test_batch_and_fallback_failure_keep_sdk_positive_on_original_caller(monkeypatch):
    from peaso import secret_scanning as core
    spec=importlib.util.spec_from_file_location('peaso._cohort_batch_binding',Path(__file__).resolve().parents[1]/'peaso/secret_scanning_batch.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    started=threading.Event()
    def sdk(*args):started.set();return [('synthetic-value','fixture',1)]
    def fail_prepare(*args):
        assert started.wait(1)
        raise RuntimeError('private failure must not be shared')
    def fail_run(*args):raise TimeoutError('synthetic failure')
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',fail_prepare)
    monkeypatch.setattr(core,'_prepared_trufflehog_output',helper.prepared_output)
    monkeypatch.setattr(core,'_scan_kingfisher',sdk)
    monkeypatch.setattr(core,'_trufflehog',lambda:'synthetic')
    monkeypatch.setattr(core,'_run',fail_run)
    cohort=module.ContentCohort(['own'],time.monotonic()+2,max_bytes=1024)
    with helper.prepared_content_member(cohort,'own'):
        result=core.scan_content(b'synthetic-value','own')
    assert not result['complete'] and result['leaks']
    assert {row['engine']:row['status']for row in result['engines']}=={'kingfisher':'complete','trufflehog':'unavailable'}
    cohort.finish('own');cohort.close()
    assert not cohort.results and not cohort.pending


def test_cancellation_prevents_batch_and_fallback(monkeypatch):
    cancelled=threading.Event();cancelled.set()
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda *args:pytest.fail('cancelled batch executed'))
    cohort=module.ContentCohort(['one'],time.monotonic()+10,max_bytes=1024,cancelled=cancelled)
    with pytest.raises(TimeoutError,match='cancelled'):cohort.output('one',b'one','one')
    cohort.close()


def test_reader_submission_failure_preserves_all_targets_once_in_original_order(monkeypatch):
    # Admit the unchanged native dependency tree before installing detector fakes.
    from peaso.collectors import aws
    import concurrent.futures
    import peaso
    import sys
    from types import SimpleNamespace
    monkeypatch.setitem(sys.modules,'peaso.secret_scanning_cohort',module)
    monkeypatch.setattr(peaso,'secret_scanning_cohort',module,raising=False)
    root=Path(__file__).resolve().parents[1]
    helper_spec=importlib.util.spec_from_file_location('peaso._reader_cohort_binding',root/'peaso/secret_scanning_batch.py')
    helper=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper)
    monkeypatch.setattr(batch,'prepared_content_member',helper.prepared_content_member,raising=False)
    monkeypatch.setattr(batch,'_volatile_shm_available',lambda total:True)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'synthetic')
    reader_spec=importlib.util.spec_from_file_location('peaso.collectors._cohort_reader_test',root/'peaso/collectors/aws_lambda_environment_secret_indicators.py')
    reader=importlib.util.module_from_spec(reader_spec);reader_spec.loader.exec_module(reader)
    original=concurrent.futures.ThreadPoolExecutor
    class Limited(original):
        submissions=0
        def submit(self,*args,**kwargs):
            self.submissions+=1
            if self.submissions>2:raise RuntimeError('synthetic thread capacity')
            return super().submit(*args,**kwargs)
    monkeypatch.setattr(concurrent.futures,'ThreadPoolExecutor',Limited)
    targets=[f'arn:aws:lambda:us-east-1:123456789012:function:Synthetic{i}'for i in range(8)]
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[reader.KIND],reader.OPTION:targets}
    calls=[]
    requests=SimpleNamespace(_lock=threading.RLock(),workers=8,deadline=None,cancel_event=None,check_deadline=lambda:None)
    def call(session,service,region,operation,**arguments):
        arn=arguments['FunctionName'];calls.append(arn)
        return {'id':reader.identity(arn),reader.MARKER:reader._base(arn,requests)}
    requests.call=call
    reader.initialize(requests,options,['123456789012/us-east-1'])
    result=reader.collect_selected(requests,object(),'us-east-1',{'Account':'123456789012','Arn':'arn:aws:iam::123456789012:user/offline'},options,['123456789012/us-east-1'])
    assert [item['id']for item in result.items]==[reader.identity(arn)for arn in targets]
    assert len(calls)==8 and set(calls)==set(targets)

"""A private cohort is caller-local, restored on exceptions and dropped on fork."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import select
import signal
import threading
from types import SimpleNamespace
import pytest

spec=importlib.util.spec_from_file_location('peaso._cohort_context_test',Path(__file__).resolve().parents[1]/'peaso/secret_scanning_batch.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


def test_member_context_restores_on_error_and_nested_bindings():
    outer=SimpleNamespace(output=lambda member,payload,path:member.encode())
    inner=SimpleNamespace(output=lambda member,payload,path:b'inner')
    with helper.prepared_content_member(outer,'outer'):
        assert helper.prepared_output(b'payload','outer')==b'outer'
        with pytest.raises(RuntimeError):
            with helper.prepared_content_member(inner,'inner'):
                assert helper.prepared_output(b'payload','inner')==b'inner'
                raise RuntimeError('synthetic')
        assert helper.prepared_output(b'payload','outer')==b'outer'
    assert helper.prepared_output(b'payload','outer') is None


def test_parallel_members_do_not_replace_each_others_source_thread_state():
    source=threading.local();gate=threading.Barrier(8)
    def output(member,payload,path):
        assert source.identity==member==path
        return payload
    cohort=SimpleNamespace(output=output)
    def call(index):
        member=f'original-{index}';source.identity=member
        with helper.prepared_content_member(cohort,member):
            gate.wait(timeout=3)
            assert helper.prepared_output(member.encode(),member)==member.encode()
        assert helper._PREPARED_COHORT.get() is None
        return source.identity
    with ThreadPoolExecutor(8)as pool:assert list(pool.map(call,range(8)))==[f'original-{i}'for i in range(8)]


def test_existing_prepared_archive_output_takes_precedence():
    cohort=SimpleNamespace(output=lambda *args:pytest.fail('archive crossed into cohort'))
    token=helper._PREPARED_BATCH.set({(b'payload','original'):b'archive'})
    try:
        with helper.prepared_content_member(cohort,'original'):
            assert helper.prepared_output(b'payload','original')==b'archive'
    finally:helper._PREPARED_BATCH.reset(token)


@pytest.mark.skipif(not hasattr(os,'fork'),reason='requires fork')
def test_actual_fork_drops_inherited_cohort_without_acquiring_its_lock():
    lock=threading.Lock()
    def blocked(*args):
        with lock:return b'parent'
    cohort=SimpleNamespace(output=blocked)
    reader,writer=os.pipe();lock.acquire()
    with helper.prepared_content_member(cohort,'original'):
        pid=os.fork()
        if pid==0:
            try:
                os.close(reader)
                value=helper.prepared_output(b'payload','original')
                os.write(writer,b'ok'if value is None else b'bad')
            finally:os._exit(0)
        try:
            os.close(writer)
            assert select.select([reader],[],[],3)[0]
            assert os.read(reader,8)==b'ok'
        finally:
            lock.release();os.close(reader)
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
    assert helper._PREPARED_COHORT.get() is None

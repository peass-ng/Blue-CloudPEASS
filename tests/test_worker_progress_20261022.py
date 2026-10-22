import logging
from peaso.progress import bind_callback, current_callback, emit_progress
from peaso.worker_progress import ProgressStream, stream_progress, record_progress, safe_event


class Pipe:
    def __init__(self):
        self.messages = []
    def send(self, value):
        self.messages.append(value)


def test_count_progress_cannot_transmit_source_or_credential_values():
    event = dict(phase='scanning_images', provider='aws', completed=3, resources=8,
                 scope='private-customer-file', secret='synthetic-secret', payload={'auth': 'private'})
    assert safe_event(event) == {'phase': 'scanning_images', 'provider': 'aws', 'completed': 3, 'resources': 8}
    assert safe_event({'completed': 2**100}) == {}


def test_rate_limited_progress_retains_last_event_and_has_distinct_final_protocol():
    now = [0.0]; pipe = Pipe(); callback = ProgressStream(pipe, clock=lambda: now[0])
    callback({'phase': 'collecting', 'completed': 1})
    callback({'phase': 'collecting', 'completed': 2})
    callback({'phase': 'collecting', 'completed': 3})
    assert len(pipe.messages) == 1
    now[0] = 2.0
    callback({'phase': 'collecting', 'completed': 4})
    callback({'phase': 'scanning_images', 'completed': 0})
    callback({'phase': 'scanning_images', 'completed': 1})
    callback.flush()
    assert [row[1]['completed'] for row in pipe.messages] == [1, 4, 0, 1]
    assert all(row[0] == '__progress__' for row in pipe.messages)


def test_bound_sink_is_restored_after_error_without_fabricating_activity():
    pipe = Pipe(); prior = lambda event: None
    with bind_callback(prior):
        try:
            with stream_progress(pipe):
                assert current_callback() is not prior
                emit_progress(phase='collecting', completed=7, scope='sensitive')
                raise RuntimeError('synthetic')
        except RuntimeError:
            pass
        assert current_callback() is prior
    assert current_callback() is None
    assert pipe.messages == [('__progress__', {'phase': 'collecting', 'completed': 7})]


def test_log_and_persistence_only_receive_whitelisted_fields(caplog):
    class Store:
        def record_progress(self, ident, owner, event):
            assert (ident, owner) == ('job', 'lease-owner')
            assert event == {'phase': 'collecting', 'completed': 2}
            raise OSError('secret-containing provider error must not escape')
    with caplog.at_level(logging.INFO):
        record_progress(Store(), {'id': 'job', 'owner': 'lease-owner'},
                        {'phase': 'collecting', 'completed': 2, 'scope': 'private-source', 'secret': 'private-value'}, logging.getLogger('test.progress'))
    assert 'completed=2' in caplog.text
    assert 'private' not in caplog.text
    assert 'secret-containing' not in caplog.text

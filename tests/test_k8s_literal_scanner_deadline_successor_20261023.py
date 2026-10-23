"""Selected literal scanner deadline stays inside the immutable collector budget."""
import time
import unittest
from unittest.mock import patch

from peaso.collectors import k8s_literal_configmap_association as source


class SelectedLiteralDeadlineTests(unittest.TestCase):
    def test_concurrent_scanner_gets_bounded_cpu_window(self):
        observed = []

        def scanner(payload, path, *, timeout, **kwargs):
            observed.append((payload, path, timeout, kwargs))
            return {'complete': True}

        with patch.object(source, '_SOURCE_SCAN_CONTENT', scanner), patch.object(source.time, 'monotonic', return_value=100):
            token = source._SCAN_DEADLINE.set(160)
            try:
                self.assertEqual(source._scan_selected_content(b'harmless', 'literal', timeout=5), {'complete': True})
                self.assertEqual(observed[-1][2], 15)
                source._SCAN_DEADLINE.set(112)
                source._scan_selected_content(b'harmless', 'literal', timeout=5, _redact_values=None)
                self.assertEqual(observed[-1][2], 6)
            finally:
                source._SCAN_DEADLINE.reset(token)

    def test_expired_deadline_never_launches_scanner(self):
        with patch.object(source, '_SOURCE_SCAN_CONTENT', side_effect=AssertionError('scanner launched')):
            token = source._SCAN_DEADLINE.set(time.monotonic() - 1)
            try:
                with self.assertRaisesRegex(TimeoutError, 'collection deadline'):
                    source._scan_selected_content(b'harmless', 'literal', timeout=5)
            finally:
                source._SCAN_DEADLINE.reset(token)

    def test_unscoped_calls_preserve_original_timeout(self):
        with patch.object(source, '_SOURCE_SCAN_CONTENT', return_value='ok') as scanner:
            self.assertEqual(source._scan_selected_content(b'harmless', 'literal', timeout=5), 'ok')
            self.assertEqual(scanner.call_args.kwargs['timeout'], 5)

    def test_collect_resets_context_after_failure(self):
        class Reader:
            pass

        def fail(*args):
            self.assertIsNotNone(source._SCAN_DEADLINE.get())
            raise RuntimeError('probe')

        self.assertIsNone(source._SCAN_DEADLINE.get())
        with patch.dict(source._GLOBALS, {'collect': fail}):
            with self.assertRaisesRegex(RuntimeError, 'probe'):
                source.collect(Reader(), None, {}, ['qa'], 'cluster')
        self.assertIsNone(source._SCAN_DEADLINE.get())

    def test_enabled_collection_prewarms_before_other_detector(self):
        events = []

        class Reader:
            collections = []

        def warm():
            self.assertIsNotNone(source._SCAN_DEADLINE.get())
            events.append('version')

        def collect(*args):
            events.append('content')
            return {}, set()

        options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND]}
        with patch.object(source, '_trufflehog', warm), patch.dict(source._GLOBALS, {'collect': collect}):
            source.collect(Reader(), None, options, ['qa'], 'cluster')
        self.assertEqual(events, ['version', 'content'])
        self.assertIsNone(source._SCAN_DEADLINE.get())

    def test_preflight_timeout_keeps_normal_scanner_path(self):
        class Reader:
            collections = []

        options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND]}
        with patch.object(source, '_trufflehog', side_effect=TimeoutError('cold probe')) as warm:
            with patch.dict(source._GLOBALS, {'collect': lambda *args: ({}, set())}) as globals_view:
                source.collect(Reader(), None, options, ['qa'], 'cluster')
                warm.assert_called_once_with()
                self.assertIs(globals_view['scan_content'], source._scan_selected_content)
        self.assertIsNone(source._SCAN_DEADLINE.get())


if __name__ == '__main__':
    unittest.main()

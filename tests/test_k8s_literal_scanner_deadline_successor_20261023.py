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


if __name__ == '__main__':
    unittest.main()

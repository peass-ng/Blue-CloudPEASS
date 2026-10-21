from copy import deepcopy
from datetime import datetime, timezone
import json
import socket
import unittest
from unittest.mock import patch

from runtime_native import collect
from test_runtime_reader import SITE, CAT, NEXT, payloads

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


class Reader:
    def __init__(self):
        self.calls = []
    def call(self, request, url, **kwargs):
        self.calls.append((url, kwargs))
        return request(url, **kwargs)


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden'))
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def run_case(self, bodies=None, **options):
        site, config, catalog = deepcopy(bodies or payloads())
        urls = [SITE, SITE + '/config/web', 'catalog']
        def request(url, **kwargs):
            if len(urls) == 0:
                raise AssertionError('unexpected extra native read')
            key = urls.pop(0)
            if key == 'catalog':
                self.assertEqual(url, CAT)
                return catalog
            self.assertEqual(url, 'https://management.azure.com' + key + '?api-version=2024-11-01')
            return site if key == SITE else config
        reader = Reader()
        result = collect(reader, request, site_id=SITE, scope=SCOPE, selected=True, as_of=NOW, **options)
        return result, reader

    def test_native_pass_uses_existing_authenticated_request_contract(self):
        result, reader = self.run_case()
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['complete'])
        self.assertEqual(result['runtime'], 'PYTHON|3.12')
        self.assertEqual(len(reader.calls), 3)
        self.assertTrue(all(kwargs == {'max_response_bytes': 1000000} for _, kwargs in reader.calls))
        self.assertTrue(all(r['method'] == 'GET' and r['read_only'] for r in result['source_requests']))
        self.assertNotIn('raw_body', json.dumps(result))
        self.assertNotIn('wire_sha256', json.dumps(result))

    def test_native_deprecated_fail(self):
        data = payloads()
        settings = data[2]['value'][0]['properties']['majorVersions'][0]['minorVersions'][0]['stackSettings']['linuxRuntimeSettings']
        settings['isDeprecated'] = True
        result, _ = self.run_case(data)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['complete'])

    def test_expired_runtime_fail(self):
        data = payloads()
        settings = data[2]['value'][0]['properties']['majorVersions'][0]['minorVersions'][0]['stackSettings']['linuxRuntimeSettings']
        settings['endOfLifeDate'] = '2025-01-01T00:00:00Z'
        self.assertEqual(self.run_case(data)[0]['status'], 'FAIL')

    def test_preview_is_unknown(self):
        data = payloads()
        settings = data[2]['value'][0]['properties']['majorVersions'][0]['minorVersions'][0]['stackSettings']['linuxRuntimeSettings']
        settings['isPreview'] = True
        result, _ = self.run_case(data)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertNotIn('runtime', result)

    def test_unselected_and_foreign_scope_zero_calls(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('credentials or IO touched')
        reader = Reader()
        self.assertEqual(collect(reader, forbidden, site_id=SITE, scope=SCOPE)['reason'], 'unselected')
        self.assertEqual(collect(reader, forbidden, site_id=SITE, scope='/subscriptions/22222222-2222-2222-2222-222222222222', selected=True)['reason'], 'invalid_or_foreign_selection')
        self.assertEqual(reader.calls, [])

    def test_full_configuration_and_site_secrets_never_exported(self):
        data = payloads()
        canary = 'synthetic-sensitive-canary-not-a-real-secret'
        data[0]['properties'].update(publishingPassword=canary, connectionStrings=[canary])
        data[1]['properties'].update(connectionStrings=[canary], appSettings=[{'value': canary}],
                                     acrUserManagedIdentityID=canary)
        data[2]['value'][0]['properties']['unneeded'] = canary
        result, _ = self.run_case(data)
        self.assertEqual(result['status'], 'PASS')
        self.assertNotIn(canary, json.dumps(result))
        self.assertNotIn('appSettings', json.dumps(result))
        self.assertNotIn('body', result)

    def test_container_reference_never_exported_or_followed(self):
        data = payloads()
        data[1]['properties']['linuxFxVersion'] = 'DOCKER|registry.example/private:credential'
        result, reader = self.run_case(data)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(len(reader.calls), 2)
        self.assertNotIn('registry.example', json.dumps(result))

    def test_foreign_config_never_reads_catalog(self):
        data = payloads()
        data[1]['id'] += '-foreign'
        result, reader = self.run_case(data)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(len(reader.calls), 2)

    def test_native_error_not_exported(self):
        reader = Reader()
        def denied(*args, **kwargs):
            raise RuntimeError('sensitive HTTP exception with credentials')
        result = collect(reader, denied, site_id=SITE, scope=SCOPE, selected=True, as_of=NOW)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertNotIn('credentials', json.dumps(result))

    def test_foreign_next_link_never_followed(self):
        data = payloads()
        data[2]['nextLink'] = 'https://evil.example/credentials'
        result, reader = self.run_case(data)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(len(reader.calls), 3)
        self.assertNotIn('evil.example', json.dumps(result))

    def test_native_byte_limit(self):
        data = payloads()
        data[1]['properties']['ignored'] = 'x' * 1000000
        result, reader = self.run_case(data)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(len(reader.calls), 2)

    def test_supported_paginated_catalog(self):
        site, config, catalog = payloads()
        first = {'value': [], 'nextLink': NEXT}
        queue = [site, config, first, catalog]
        urls = []
        def request(url, **kwargs):
            urls.append(url)
            return queue.pop(0)
        result = collect(Reader(), request, site_id=SITE, scope=SCOPE, selected=True, as_of=NOW)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(urls[-2:], [CAT, NEXT])
        self.assertEqual(len(result['source_requests']), 4)

    def test_page_cycle_stops(self):
        site, config, _ = payloads()
        queue = [site, config, {'value': [], 'nextLink': NEXT}, {'value': [], 'nextLink': NEXT}]
        def request(url, **kwargs): return queue.pop(0)
        result = collect(Reader(), request, site_id=SITE, scope=SCOPE, selected=True, as_of=NOW)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(len(result['source_requests']), 4)

    def test_malformed_lifecycle_flag_cannot_pass(self):
        data = payloads()
        settings = data[2]['value'][0]['properties']['majorVersions'][0]['minorVersions'][0]['stackSettings']['linuxRuntimeSettings']
        settings['isDeprecated'] = 'false'
        self.assertEqual(self.run_case(data)[0]['status'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()

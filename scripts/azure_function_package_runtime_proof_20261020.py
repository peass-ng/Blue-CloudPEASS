"""Explicit local fake-HTTP evidence generation; never runtime registry admission.

Run from the repository with `.venv/bin/python -m scripts.azure_function_package_runtime_proof_20261020`.
Only new binding/CASES files belonging to this adapter are written. Scanner and
native implementations are real; network/auth are denied by the native fixture.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'peaso/collectors/azure_function_package_runtime_20261020.py',
    'peaso/checks/azure_function_package_runtime_consumer_20261020.py',
    'peaso/collectors/azure_function_package_source_20261020.py',
    'peaso/collectors/azure_function_package_portable_20261020.py',
    'peaso/azure_function_package_portable_20261020.py',
    'peaso/collectors/azure_selected_storage_secret_indicators.py',
    'peaso/collectors/azure_app_settings_secret_indicators.py',
    'peaso/collectors/azure_function_settings_declarations_20261020.py',
    'peaso/collectors/aws_package_content_indicators.py',
    'peaso/secret_scanning.py',
    'peaso/collectors/azure.py',
)
BINDING = ROOT / 'peaso/collectors/azure_function_package_runtime_binding_20261020.json'
CASES = ROOT / 'peaso/checks/azure_function_package_runtime_cases_20261020.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-local-binding', action='store_true',
        help='Explicitly replace local consistency pins; this does not grant production admission.')
    args = parser.parse_args()
    if args.refresh_local_binding:
        hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES}
        BINDING.write_text(json.dumps({'status': 'unregistered_local_only', 'sources': hashes}, sort_keys=True, indent=2) + '\n')

    import pytest
    from peaso.collectors import azure_function_package_runtime_20261020 as runtime
    from tests import test_azure_function_package_runtime_20261020 as test
    from tests import test_azure_function_package_source_20261020 as native
    rows = []

    def denied(op, response):
        if op == 'content': response.status = 403
        return response

    def changed(op, response):
        if op == 'properties_after': response.headers['ETag'] = '"changed"'
        return response

    variants = [
        ('clean', 'PASS', {}), ('positive', 'FAIL', {'hit': True}),
        ('app_service_positive', 'FAIL', {'hit': True, 'hosting': 'app_service'}),
        ('current_clean', 'PASS', {'t': native.target(False)}),
        ('partial_clean', 'UNKNOWN', {'raw': native.package(False, ('nested.zip', b'PKbad'))}),
        ('partial_positive', 'FAIL', {'raw': native.package(True, ('nested.zip', b'PKbad'))}),
        ('denied', 'UNKNOWN', {'fault': denied}),
        ('reference', 'UNKNOWN', {'reference': 'https://foreign.example/package.zip'}),
        ('changed_source', 'UNKNOWN', {'fault': changed}),
    ]
    for name, status, kwargs in variants:
        with pytest.MonkeyPatch.context() as monkeypatch:
            offline = native.offline.__wrapped__(monkeypatch)
            next(offline)
            try:
                safe, expected, trace = test.capture_runtime(monkeypatch, **kwargs)
                result = test.evaluate(safe['package_snapshot'], expected)
                assert result[0] == status, (name, result)
                rows.append({'name': name, 'snapshot': safe['package_snapshot'],
                    'expected_index_context': expected, 'expected_status': status,
                    'native_operations': [c[0] for c in trace.calls],
                    'http_fixture': 'original_native_fake_https',
                    'scanner_implementations': 'original_real_offline_kingfisher_and_trufflehog'})
            finally:
                next(offline, None)
    payload = {'status': 'unregistered_local_only', 'created_at': datetime.now(timezone.utc).isoformat(),
        'declaration': runtime.DECLARATION, 'source_hashes': runtime.reviewed_sources(), 'cases': rows,
        'cloud_authenticity': 'not_established', 'live_cloud_auth_network': False}
    encoded = json.dumps(payload, sort_keys=True, indent=2) + '\n'
    for private in (native.SECRET, native.SAS, native.SITE, 'function.zip', 'WEBSITE_RUN_FROM_PACKAGE'):
        assert private not in encoded
    CASES.write_text(encoded)
    print(json.dumps({'cases': [{'name': r['name'], 'status': r['expected_status']} for r in rows],
        'path': str(CASES.relative_to(ROOT)), 'sha256': hashlib.sha256(CASES.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()

"""Pure, unregistered same-process consumer for the package-source proposal.

No install() function and no shared registry mutation. Integration needs the
normal trusted context/admission path; the ephemeral seal is not portable proof.
"""
from copy import deepcopy
import re

from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso.collectors import azure_selected_storage_secret_indicators as storage

DECLARATION = {'id': source.CHECK, 'kind': source.KIND, 'provider': 'azure', 'severity': 'high',
    'finding_type': 'secrets', 'allow_incomplete_failure': True, 'requirements': [],
    'title': 'Selected configured deployment package source has no detected secrets',
    'remediation': 'Remove exposed literals from the selected package, rotate confirmed exposed credentials, and rebuild the package using managed identities or supported secret references.'}


def _unknown():
    return 'UNKNOWN', {'complete': False, 'observed': 'The selected configured package source was unavailable, unbound, unsupported or incompletely inspected.',
        'coverage': 'selected_configured_stored_package_only', 'credential_validation': 'not_attempted'}


def evaluate(envelope, selected_identity, *, scope, expected_selection, expected_capture,
             customer_context_id, credential_context_id, tenant_id):
    """Caller supplies trusted run context, never copies it from untrusted input."""
    try:
        if (not source.authentic(envelope) or envelope['schema'] != source.SCHEMA
                or envelope['authorized'] is not True or not storage.SCOPE.fullmatch(scope)
                or envelope['capture'] != expected_capture
                or not re.fullmatch(r'package-capture:[0-9a-f]{32}', expected_capture)
                or envelope['customer_context_id'] != customer_context_id
                or envelope['credential_context_id'] != credential_context_id
                or envelope['selection'][scope] != expected_selection
                or not isinstance(expected_selection, list) or not 1 <= len(expected_selection) <= source.MAX_TARGETS
                or len(set(expected_selection)) != len(expected_selection) or selected_identity not in expected_selection):
            return _unknown()
        results = [r for r in envelope['results'] if r['scope'].casefold() == scope.casefold()]
        if {r['identity'] for r in results} != set(expected_selection) or len(results) != len(expected_selection):
            return _unknown()
        marker, = [r for r in results if r['identity'] == selected_identity]
        if (marker['association_complete'] is not True or marker['capture'] != expected_capture
                or marker['verification'] != 'not_attempted' or marker['tenant'].casefold() != tenant_id.casefold()
                or not re.fullmatch(r'package-reference:[0-9a-f]{64}', marker['reference_locator'])
                or not re.fullmatch(r'package-etag:[0-9a-f]{64}', marker['etag_locator'])
                or not re.fullmatch(r'package-version:[0-9a-f]{64}', marker['version_locator'])
                or not re.fullmatch(r'storage-source-principal:[0-9a-f]{64}', marker['principal'])
                or marker['selection_mode'] not in ('current', 'versioned')
                or marker['hosting'] not in ('function', 'app_service')
                or marker['coverage'] != 'selected_configured_stored_package_only'):
            return _unknown()
        refs, ledger = marker['source_requests'], envelope['receipts']
        if (len(refs) != len(source.OPERATIONS) or len(set(refs)) != len(refs)
                or len(ledger) > source.MAX_CALLS or len({r['id'] for r in ledger}) != len(ledger)):
            return _unknown()
        for ref, operation in zip(refs, source.OPERATIONS):
            receipt, = [r for r in ledger if r['id'] == ref]
            web = operation.startswith(('site_', 'settings_'))
            if (receipt['operation'] != operation or receipt['status'] != 'collected' or receipt['bound'] is not True
                    or receipt['capture'] != expected_capture or receipt['scope'].casefold() != scope.casefold()
                    or receipt['tenant'] != marker['tenant'] or receipt['principal'] != marker['principal']
                    or receipt['identity'] != (selected_identity if web else marker['object_identity'])
                    or receipt['method'] != ('POST' if operation.startswith('settings_') else 'HEAD' if operation.startswith('properties_') else 'GET')
                    or receipt['origin'] != ('blob' if operation in ('content', 'properties_before', 'properties_after') else 'arm')
                    or receipt['version'] != (source.SITE_VERSION if web else storage.SUB_VERSION if operation == 'subscription' else storage.ARM_VERSION if operation == 'account' else storage.DATA_VERSION)
                    or not isinstance(receipt['native_request'], str)
                    or not re.fullmatch(r'(?:package-web|storage-source)-response:[0-9a-f]{64}', receipt['native_request'])
                    or not web and receipt['http_status'] != 200):
                return _unknown()
        parts, leaks = marker['parts'], marker['leaks']
        if (not isinstance(parts, list) or not 1 <= len(parts) <= storage.MAX_MEMBERS
                or merge_leaks(leaks) != leaks or len(leaks) > storage.MAX_LEAKS
                or merge_leaks([leak for part in parts for leak in part['leaks']]) != leaks):
            return _unknown()
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for number, part in enumerate(parts, 1):
            if (part['path'] != marker['object_identity'] + '.file-' + str(number)
                    or type(part['bytes']) is not int or not 1 <= part['bytes'] <= storage.MAX_MEMBER
                    or len(part['engines']) != 2 or {e['engine'] for e in part['engines']} != set(versions)
                    or any(e['version'] != versions[e['engine']] or e['status'] not in ('complete', 'unavailable') for e in part['engines'])
                    or part['complete'] != all(e['status'] == 'complete' for e in part['engines'])):
                return _unknown()
        complete = (marker['complete'] is True and marker['reason'] == 'complete'
                    and all(p['complete'] for p in parts)
                    and 1 <= marker['object_bytes'] <= storage.MAX_OBJECT
                    and 1 <= marker['expanded_bytes'] <= storage.MAX_EXPANDED
                    and len(parts) <= marker['members'] <= storage.MAX_MEMBERS)
        if not leaks and not complete:
            return _unknown()
        observed = ('A likely secret was detected in the selected configured package source; its value is hidden.' if leaks else
                    'Both offline detectors completed without detecting a supported secret in the selected captured package text files.')
        if not complete:
            observed += ' Coverage is incomplete.'
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'complete': complete,
            'coverage': 'selected_configured_stored_package_only', 'credential_validation': 'not_attempted',
            'secret_leaks': deepcopy(leaks), 'parts': deepcopy(parts), 'selection_mode': marker['selection_mode'],
            'runtime_bytes': 'unknown', 'continuous_immutability': 'unknown'}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return _unknown()

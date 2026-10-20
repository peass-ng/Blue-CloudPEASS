"""Pure consumer; importing this proposal registers nothing."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.aws_codebuild_buildspec_source_20261020 import (
    KIND, CHECK, SCHEMA, FIELD, SCOPE, MAX_TARGETS, MAX_CALLS, MAX_RESPONSE,
    MAX_TOTAL, MAX_CONTENT, MAX_LEAKS, MAX_LOCATIONS)

DECLARATION = {'id': CHECK, 'provider': 'aws', 'category': 'exposure', 'kind': KIND,
    'group': 'Secrets', 'finding_type': 'secrets', 'severity': 'high',
    'title': 'Selected inline CodeBuild buildspec has no detected secrets',
    'permissions': ['codebuild:BatchGetProjects'], 'allow_incomplete_failure': True,
    'observed_contract': 'Both offline detectors inspect only returned inline buildspec bytes for an exact selected CodeBuild project. A supported secret produces FAIL even if the other detector is unavailable; PASS requires complete selected coverage, and references or incomplete evidence produce UNKNOWN. Values are hidden and credentials are never validated.'}


def evaluate(item, collection):
    """Use only supplied data; no auth, IO, registration or source execution."""
    try:
        if (set(collection) != {'schema', 'kind', 'authorized', 'binding', 'capture', 'selection',
                'items', 'calls', 'response_bytes', 'complete'} or collection['schema'] != SCHEMA
                or collection['kind'] != KIND or collection['authorized'] is not True):
            raise ValueError()
        def digest(value):
            return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None
        selection, rows = collection['selection'], collection['items']
        if (not digest(collection['binding']) or not isinstance(collection['capture'], str)
                or not re.fullmatch('buildspec-capture:[0-9a-f]{32}', collection['capture'])
                or not isinstance(selection, dict) or not 1 <= len(selection) <= MAX_TARGETS
                or any(not isinstance(v, str) or not re.fullmatch(KIND + ':[0-9a-f]{64}', v) for v in selection)
                or len(set(selection)) != len(selection) or not isinstance(rows, list)
                or len(rows) != len(selection) or any(not isinstance(r, dict) for r in rows)
                or {r['id'] for r in rows} != set(selection) or sum(r == item for r in rows) != 1
                or type(collection['calls']) is not int or not 2 <= collection['calls'] <= MAX_CALLS
                or type(collection['response_bytes']) is not int or not 1 <= collection['response_bytes'] <= MAX_TOTAL
                or type(collection['complete']) is not bool):
            raise ValueError()
        if any(set(v) != {'scope', 'request'} or not isinstance(v['scope'], str)
               or not SCOPE.fullmatch(v['scope']) or not digest(v['request']) for v in selection.values()):
            raise ValueError()
        if (set(item) != {'id', 'scope', 'capture', 'binding', 'field', 'native_complete', 'complete',
                'principal', 'requests', 'bytes', 'engines', 'leaks', 'verification', 'reason'}
                or not isinstance(item['scope'], str) or not SCOPE.fullmatch(item['scope'])
                or item['binding'] != collection['binding'] or item['capture'] != collection['capture']
                or item['field'] != FIELD or item['native_complete'] is not True
                or type(item['complete']) is not bool or not digest(item['principal'])
                or item['verification'] != 'not_attempted' or item['reason'] not in ('inspected', 'detector_incomplete')
                or type(item['bytes']) is not int or not 1 <= item['bytes'] <= MAX_CONTENT):
            raise ValueError()
        if (item['scope'] != selection[item['id']]['scope']
                or any(r['native_complete'] is True and r['scope'].split('/')[0] == item['scope'].split('/')[0]
                    and r['principal'] != item['principal'] for r in rows)):
            raise ValueError()
        requests = item['requests']
        if not isinstance(requests, list) or len(requests) != 2:
            raise ValueError()
        for receipt, service, operation in zip(requests, ('sts', 'codebuild'), ('GetCallerIdentity', 'BatchGetProjects')):
            if (set(receipt) != {'service', 'operation', 'http_status', 'request', 'response', 'bytes'}
                    or receipt['service'] != service or receipt['operation'] != operation
                    or type(receipt['http_status']) is not int or receipt['http_status'] != 200
                    or not digest(receipt['request']) or not digest(receipt['response'])
                    or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= MAX_RESPONSE):
                raise ValueError()
        if requests[1]['request'] != selection[item['id']]['request']:
            raise ValueError()
        engines, leaks = item['engines'], item['leaks']
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (not isinstance(engines, list) or len(engines) != 2
                or {e['engine'] for e in engines} != set(versions)
                or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                    or e['status'] not in ('complete', 'unavailable') for e in engines)
                or not isinstance(leaks, list) or len(leaks) > MAX_LEAKS or merge_leaks(leaks) != leaks
                or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS):
            raise ValueError()
        for leak in leaks:
            if (any(next(e['status'] for e in engines if e['engine'] == d['engine']) != 'complete' for d in leak['detectors'])
                    or any(set(loc) - {'path', 'line'} or loc['path'] != item['id'] + '.source.buildspec' for loc in leak['locations'])):
                raise ValueError()
        complete = (collection['complete'] is True and item['complete'] is True
                    and all(e['status'] == 'complete' for e in engines)
                    and all(r['complete'] is True and r['native_complete'] is True for r in rows))
        if not leaks and not complete:
            raise ValueError()
        observed = ('A likely secret was detected in the selected inline CodeBuild buildspec. Its value is hidden; offline detection did not validate the credential.' if leaks else
                    'Both offline detectors completed without detecting a supported secret in the selected inline CodeBuild buildspec. Coverage is limited to the returned inline bytes.')
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'secret_leaks': deepcopy(leaks),
            'engines': deepcopy(engines), 'complete': complete, 'credential_validation': 'not_attempted',
            'coverage': 'selected_returned_inline_buildspec_only', 'field': FIELD}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, StopIteration):
        return 'UNKNOWN', {'observed': 'The selected inline CodeBuild buildspec was unavailable, a reference, incomplete or unbound. Secret absence could not be assessed.'}

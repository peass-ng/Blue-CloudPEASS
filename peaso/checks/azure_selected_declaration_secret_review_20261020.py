"""Pure unregistered selected declaration checks; no registry mutation on import."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_selected_declaration_secret_indicators as source

DECLARATIONS = [dict(id=p['check'], provider='azure', category='hardening', kind=p['kind'],
    finding_type='secrets', severity='high', requirements=[], dependencies=[p['kind']],
    allow_incomplete_failure=True, ui_group='Secrets', title=p['title'],
    remediation='Remove exposed literal copies and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
    scope='Explicit selected public literals only. Protected values and references are excluded; no execution, dereference, runtime or credential-validation claim.')
    for p in source.PROFILES.values()]


def _evaluate(profile, item, index):
    try:
        detail = source.PROFILES[profile]; kind = detail['kind']; ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if (ctx['provider'] != 'azure' or not source.SCOPE.fullmatch(scope) or meta[kind + '_authorized'] is not True
                or meta['context_binding'] != 'scan_local' or meta.get('tenant_verified') is not True
                or not re.fullmatch(source.GUID, meta['tenant_id'], re.I)):
            raise ValueError()
        capture = meta[kind + '_capture']
        if not re.fullmatch(r'declaration-capture:[0-9a-f]{32}', capture): raise ValueError()
        selected = meta[kind + '_selection'][scope]
        if (not isinstance(selected, list) or not 1 <= len(selected) <= source.MAX_TARGETS or len(set(selected)) != len(selected)
                or any(not re.fullmatch(kind + r':[0-9a-f]{64}', i) for i in selected)):
            raise ValueError()
        own, = [c for c in index['collections'][kind] if c.get('scope') == scope]
        if own['status'] not in ('collected', 'partial') or own['service'] != detail['service']: raise ValueError()
        ids = [i['id'] for i in own['items']]
        if len(set(ids)) != len(ids) or any(i not in selected for i in ids) or sum(obj == item for obj in own['items']) != 1:
            raise ValueError()
        for obj in (own, item):
            proof = obj['_provenance']
            if any(not isinstance(meta.get(k), str) or not meta[k] or proof.get(k) != meta[k]
                for k in ('credential_context_id', 'customer_context_id')): raise ValueError()
        ident = item['id']; marker = item[source.MARKER]
        if (set(marker) != {'schema','identity','scope','profile','capture','complete','parts','leaks','source_requests','literal_count','reference_count','verification'}
                or marker['schema'] != source.SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or marker['profile'] != profile or marker['capture'] != capture or type(marker['complete']) is not bool
                or marker['verification'] != 'not_attempted' or item['_provenance']['scope'] != scope
                or item['_provenance']['capture'] != capture
                or type(marker['literal_count']) is not int or not 1 <= marker['literal_count'] <= source.MAX_VALUES
                or type(marker['reference_count']) is not int or not 0 <= marker['reference_count'] <= 8192): raise ValueError()
        operations = {'app_configuration': ('subscription', 'store', 'key', 'key_bound'),
            'data_factory': ('subscription', 'declaration'), 'synapse': ('subscription', 'workspace', 'pipeline')}[profile]
        refs = marker['source_requests']; ledger = meta[kind + '_receipts']
        if (not isinstance(refs, list) or len(refs) != len(operations) or len(set(refs)) != len(refs)
                or item['_provenance']['source_requests'] != refs or not isinstance(ledger, list)
                or not 1 <= len(ledger) <= source.MAX_CALLS or len({r['id'] for r in ledger}) != len(ledger)): raise ValueError()
        etags = []
        for ref, operation in zip(refs, operations):
            receipt, = [r for r in ledger if r.get('id') == ref]
            expected_audience = source.APP_CONFIG if operation in ('key', 'key_bound') else source.SYNAPSE if operation == 'pipeline' else source.ARM
            if (set(receipt) != {'id','identity','scope','operation','method','host_class','host_binding','audience','request_digest','capture','status','bytes','tenant_id','identity_bound','etag_binding'}
                    or not re.fullmatch(r'declaration-read-[1-9][0-9]*', ref)
                    or receipt['identity'] != ident or receipt['scope'] != scope or receipt['operation'] != operation
                    or receipt['method'] != 'GET' or receipt['audience'] != expected_audience
                    or not re.fullmatch('[0-9a-f]{64}', receipt['host_binding'])
                    or receipt['host_class'] != ('app_configuration' if operation in ('key','key_bound') else 'synapse' if operation == 'pipeline' else 'arm')
                    or not re.fullmatch('[0-9a-f]{64}', receipt['request_digest']) or receipt['capture'] != capture
                    or receipt['status'] != 'collected' or receipt['identity_bound'] is not True
                    or receipt['tenant_id'].casefold() != meta['tenant_id'].casefold()
                    or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= source.MAX_WIRE): raise ValueError()
            if operation in ('key', 'key_bound', 'declaration', 'pipeline'):
                if not re.fullmatch('[0-9a-f]{64}', receipt['etag_binding']): raise ValueError()
                etags.append(receipt['etag_binding'])
            elif receipt['etag_binding'] is not None: raise ValueError()
        if profile == 'app_configuration' and len(set(etags)) != 1: raise ValueError()
        part, = marker['parts']
        if (set(part) != {'bytes','engines','complete'} or type(part['bytes']) is not int or not 1 <= part['bytes'] <= source.MAX_CONTENT
                or type(part['complete']) is not bool): raise ValueError()
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}; engines = part['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or {e['engine'] for e in engines} != set(versions)
                or any(set(e) != {'engine','version','status'} or e['version'] != versions[e['engine']]
                    or e['status'] not in ('complete','unavailable') for e in engines)
                or part['complete'] != all(e['status'] == 'complete' for e in engines)): raise ValueError()
        leaks = marker['leaks']; trusted = {e['engine'] for e in engines if e['status'] == 'complete'}
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > source.MAX_LEAKS
                or sum(len(l['locations']) for l in leaks) > source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}', l['fingerprint']) or not l['detectors'] or not l['locations']
                    or any(d['engine'] not in trusted for d in l['detectors'])
                    or any(loc['path'] != ident + '.inline_literals' for loc in l['locations']) for l in leaks)): raise ValueError()
        complete = bool(marker['complete'] and part['complete'] and not marker['reference_count'] and own['status'] == 'collected' and set(ids) == set(selected))
        if not leaks and not complete: raise ValueError()
        observed = ('A likely secret was detected in the selected public literals. The value is hidden and was not validated.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected public literals. Coverage is limited to these declarations.')
        if not complete: observed += ' Coverage is incomplete.'
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'secret_leaks': deepcopy(leaks), 'complete': complete,
            'coverage': 'selected_public_literals_only' if complete else 'incomplete_selected_public_literals',
            'credential_validation': 'not_attempted', 'profile': profile, 'parts': deepcopy(marker['parts'])}
    except (KeyError, ValueError, TypeError, IndexError, AttributeError):
        return 'UNKNOWN', {'complete': False, 'coverage': 'incomplete_selected_public_literals',
            'observed': 'Selected public literals were unavailable, unbound, protected or incompletely inspected. A clean result cannot be established.'}


def app_configuration(item, index): return _evaluate('app_configuration', item, index)
def data_factory(item, index): return _evaluate('data_factory', item, index)
def synapse(item, index): return _evaluate('synapse', item, index)
EVALUATORS = {'app_configuration': app_configuration, 'data_factory': data_factory, 'synapse': synapse}

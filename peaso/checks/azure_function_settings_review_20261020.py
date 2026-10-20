"""Two unregistered selected Function configuration declarations, no leak scan."""
import re
from peaso.collectors import azure_function_settings_declarations_20261020 as source


def _bound(item, index, check):
    context = index['context']; metadata = context['metadata']; scope = context['scope']
    if (context['provider'] != 'azure' or not isinstance(scope, str) or not source._SCOPE.fullmatch(scope)
            or metadata[source.KIND + '_authorized'] is not True
            or not isinstance(metadata[source.KIND + '_checks'], list)
            or not metadata[source.KIND + '_checks'] or check not in metadata[source.KIND + '_checks']
            or set(metadata[source.KIND + '_checks']) - set(source.CHECKS)):
        raise ValueError()
    capture = metadata[source.KIND + '_capture']; tenant = metadata[source.KIND + '_tenant']
    if not re.fullmatch('[0-9a-f]{32}', capture) or not source.GUID.fullmatch(tenant): raise ValueError()
    if ('tenant_id' in metadata and str(metadata['tenant_id']).casefold() != tenant.casefold()
            or 'tenant_verified' in metadata and metadata['tenant_verified'] is not True
            or 'credential_context_id' in metadata and metadata['credential_context_id'] != capture
            or 'customer_context_id' in metadata and metadata['customer_context_id'] != 'scan-local:' + capture):
        raise ValueError()
    rows = [r for r in index['collections'][source.KIND] if r.get('scope') == scope]
    own, = rows
    selected = metadata[source.KIND + '_selection'][scope]
    if (own['type'] != source.KIND or own['service'] != 'Microsoft.Web' or own['status'] != 'collected'
            or not isinstance(selected, list) or not 1 <= len(selected) <= source.MAX_TARGETS
            or any(not isinstance(v, str) or not re.fullmatch(source.KIND + ':[0-9a-f]{64}', v) for v in selected)
            or len(set(selected)) != len(selected) or len(own['items']) != len(selected)
            or {r['id'] for r in own['items']} != set(selected) or sum(r == item for r in own['items']) != 1):
        raise ValueError()
    marker = item[source.MARKER]; proof = item['_provenance']; ident = item['id']
    if (set(item) != {'id', source.MARKER, '_provenance'}
            or set(marker) != {'schema','identity','scope','capture','complete','hosting','declarations','source_requests'}
            or marker['schema'] != source.SCHEMA or marker['identity'] != ident or marker['scope'] != scope
            or marker['capture'] != capture or marker['complete'] is not True
            or marker['hosting'] not in ('classic','container','flex','not_function','unresolved','unsupported')
            or set(proof) != {'scope','capture','tenant_id','source_requests'} or proof['capture'] != capture
            or proof['scope'] != scope or proof['tenant_id'] != tenant or proof['source_requests'] != marker['source_requests']):
        raise ValueError()
    refs = marker['source_requests']; ledger = metadata[source.KIND + '_receipts']
    settings = marker['declarations']
    expected = ('subscription','site') if settings is None else ('subscription','site','settings')
    if (not isinstance(refs, list) or len(refs) != len(expected) or len(set(refs)) != len(refs)
            or not isinstance(ledger, list) or not 2 <= len(ledger) <= source.MAX_CALLS
            or len({r['id'] for r in ledger}) != len(ledger)
            or sum(r.get('bytes', 0) for r in ledger) > source.MAX_TOTAL):
        raise ValueError()
    for ref, operation in zip(refs, expected):
        receipt, = [r for r in ledger if r['id'] == ref]
        if (set(receipt) != {'id','identity','scope','capture','operation','method','host','api_version',
                'request_digest','status','bytes','tenant_id','identity_bound'}
                or not re.fullmatch(r'function-declaration-read-[1-9][0-9]*', ref)
                or receipt['identity'] != ident or receipt['scope'] != scope or receipt['capture'] != capture
                or receipt['operation'] != operation or receipt['method'] != ('POST' if operation == 'settings' else 'GET')
                or receipt['host'] != source.HOST or receipt['status'] != 'collected' or receipt['identity_bound'] is not True
                or receipt['api_version'] != (source.SUB_VERSION if operation == 'subscription' else source.SITE_VERSION)
                or receipt['tenant_id'] != tenant or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= source.MAX_WIRE
                or not re.fullmatch('[0-9a-f]{64}', receipt['request_digest'])):
            raise ValueError()
    if settings is not None:
        if (not isinstance(settings, dict) or set(settings) != {'connection_string','instrumentation_key','runtime_setting','channel'}
                or settings['connection_string'] not in source.PRESENCE or settings['instrumentation_key'] not in source.PRESENCE
                or settings['runtime_setting'] not in source.PRESENCE
                or settings['channel'] not in source.CHANNELS):
            raise ValueError()
        expected_states = {'absent': ('absent','empty'), 'reference': ('reference',), 'masked': ('masked',)}
        if settings['runtime_setting'] not in expected_states.get(settings['channel'], ('literal',)):
            raise ValueError()
    return marker


def _evaluate(item, index, check):
    try:
        marker = _bound(item, index, check)
        hosting, settings = marker['hosting'], marker['declarations']
        if hosting == 'not_function':
            return 'NOT_APPLICABLE', {'observed': 'The selected native site is not a Function app.'}
        if check == source.RUNTIME:
            if hosting in ('container','flex'):
                text = ('Flex Consumption manages the host update setting through the platform.' if hosting == 'flex'
                        else 'The custom container image selects its Function host runtime.')
                return 'NOT_APPLICABLE', {'observed': text + ' The classic appsetting update-channel criterion does not apply.'}
            if hosting != 'classic' or settings is None: raise ValueError()
            channel = settings['channel']
            if channel in ('unresolved','masked','reference'): raise ValueError()
            observed = {
                'major4_automatic': 'The Function declares the automatic major4 runtime update channel.',
                'legacy_automatic': 'The Function declares an automatic update channel for a retired runtime major.',
                'major4_pin': 'The Function pins a major4 runtime build instead of declaring its automatic update channel.',
                'legacy_pin': 'The Function pins a build from a retired runtime major.',
                'absent': 'The Function does not declare the automatic major4 runtime update channel.'}[channel]
            return ('PASS' if channel == 'major4_automatic' else 'FAIL'), {
                'observed': observed + ' The resolved host build was not tested.', 'channel': channel,
                'coverage': 'selected_function_configuration_only'}
        if settings is None: raise ValueError()
        values = [settings['connection_string'], settings['instrumentation_key']]
        if any(v in ('masked','reference') for v in values): raise ValueError()
        declared = 'literal' in values
        text = ('The Function declares a nonempty Application Insights setting.' if declared
                else 'The Function has no nonempty Application Insights setting.')
        return ('PASS' if declared else 'FAIL'), {'observed': text + ' Telemetry delivery and destination validity were not tested.',
            'telemetry_setting_declared': declared, 'coverage': 'selected_function_configuration_only'}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        text = ('The selected Function telemetry declaration could not be established.' if check == source.TELEMETRY
                else 'The selected Function runtime update-channel declaration could not be established.')
        return 'UNKNOWN', {'observed': text, 'coverage': 'incomplete_selected_function_configuration'}


def telemetry(item, index):
    return _evaluate(item, index, source.TELEMETRY)


def runtime(item, index):
    return _evaluate(item, index, source.RUNTIME)


PROPOSALS = [
    {'id': source.TELEMETRY, 'provider': 'azure', 'category': 'hardening', 'kind': source.KIND,
     'severity': 'medium', 'finding_type': 'monitoring', 'group': 'Monitoring & alerts', 'requirements': [],
     'title': 'Selected Function declares an Application Insights setting', 'dependencies': [source.KIND],
     'description': 'Checks the declared presence of at least one literal Application Insights connection setting on explicitly selected Functions. Telemetry delivery and destination validity are not tested.',
     'remediation': ['Configure APPLICATIONINSIGHTS_CONNECTION_STRING for the selected Function.',
                     'Review telemetry ingestion and authentication separately.'], 'evaluate': telemetry},
    {'id': source.RUNTIME, 'provider': 'azure', 'category': 'hardening', 'kind': source.KIND,
     'severity': 'medium', 'finding_type': 'patching', 'group': 'Patching & versions', 'requirements': [],
     'title': 'Selected classic Function declares the automatic major4 runtime update channel', 'dependencies': [source.KIND],
     'description': 'Checks the classic Function FUNCTIONS_EXTENSION_VERSION declaration for the automatic major4 update channel. Flex Consumption and custom container host versions use separate mechanisms; the resolved build is not tested.',
     'remediation': ['Review compatibility and select ~4 on supported classic Function hosting.',
                     'Review deliberate support-directed build pins before changing them.'], 'evaluate': runtime},
]

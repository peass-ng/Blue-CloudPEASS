"""Native APIM diagnostic routes and source-filtered aggregate sink receipts.

No credential values, request payloads, URLs or raw request IDs are retained.
The built-in Azure Monitor logger has no customer credentials to test.
"""
from datetime import datetime, timezone
import hashlib
import json
import re

from .azure_detection_telemetry import _instant, _identity, API, LOGS, ARM

KIND = 'azure_sw24_evidence'
CONTRACT = 'native-apim-diagnostics-v1'
HTTP_ID = 'azure_api_management_app_http_logs_enabled_21c108d'
VERBOSE_ID = 'azure_api_management_app_http_logs_enabled_9b3b56e'
METHODS_ID = 'azure_api_management_app_http_logs_enabled_9ef06db'
IDS = (HTTP_ID, VERBOSE_ID, METHODS_ID)
VERSION = '2024-05-01'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def configuration(fact):
    def child(row):
        return {key: row[key] for key in ('id', 'properties') if key in row}
    return {'id': fact['id'], 'apis': [{**child(api), 'diagnostics': [child(d) for d in api.get('diagnostics', [])]} for api in fact.get('apis', [])],
            'online_api_ids': fact.get('online_api_ids'), 'diagnostics': [child(d) for d in fact.get('diagnostics', [])],
            'loggers': [child(logger) for logger in fact.get('loggers', [])]}


def reviews(options, scope, service):
    root = options.get('compliance_policy', {}).get('sw24', {})
    if not isinstance(root, dict) or root.get('status') != 'collected' or str(root.get('scope', '')).casefold() != scope.casefold():
        return []
    checks = root.get('checks', [])
    if not isinstance(checks, list) or len(checks) > 64:
        raise ValueError('invalid APIM check policy')
    selected = options.get('_azure_apim_diagnostics_checks', IDS)
    if not isinstance(selected, (list, tuple)) or any(cid not in IDS for cid in selected):
        raise ValueError('invalid internal APIM selection')
    return [row for row in checks if isinstance(row, dict) and row.get('check_id') in selected
            and str(row.get('resource_id', '')).casefold() == service.casefold() and row.get('status') == 'collected']


def query_for(scope, service, api, start, end):
    scope, service = scope.casefold(), service.casefold()
    aid = api['id'].rsplit('/', 1)[-1].split(';rev=', 1)[0].casefold()
    revision = api.get('properties', {}).get('apiRevision')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,256}', aid) or not isinstance(revision, str) or not re.fullmatch(r'[1-9][0-9]{0,9}', revision):
        raise ValueError('APIM API or explicit revision unavailable')
    filters = ('_SubscriptionId =~ ' + json.dumps(scope.rsplit('/', 1)[-1]) + ' and _ResourceId =~ ' + json.dumps(service)
               + ' and ApiId =~ ' + json.dumps(aid) + ' and ApiRevision == ' + json.dumps(revision))
    query = ('ApiManagementGatewayLogs | where TimeGenerated between (datetime(' + start.isoformat() + ') .. datetime(' + end.isoformat() + '))'
             + ' | where ' + filters + ' | where isnotempty(CorrelationId)'
             + ' | summarize event_count=count(), last_ingested_at=max(ingestion_time()), last_event_at=max(TimeGenerated),'
             + ' receipt_ids=make_set(hash_sha256(tostring(CorrelationId)), 1)')
    return {'query': query, 'timespan': start.isoformat() + '/' + end.isoformat()}


def aggregate(response, start, end):
    if not isinstance(response, dict) or any(key in response for key in ('error', 'partialError')):
        raise ValueError('partial APIM Logs response')
    tables = response.get('tables')
    if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
        raise ValueError('ambiguous APIM Logs response')
    columns, rows = tables[0].get('columns'), tables[0].get('rows')
    expected = [('event_count', 'long'), ('last_ingested_at', 'datetime'), ('last_event_at', 'datetime'), ('receipt_ids', 'dynamic')]
    if not isinstance(columns, list) or any(not isinstance(c, dict) for c in columns) or [(c.get('name'), c.get('type')) for c in columns] != expected or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list) or len(rows[0]) != 4:
        raise ValueError('malformed APIM aggregate')
    count, ingested, latest, hashes = rows[0]
    if type(count) is not int or count < 0:
        raise ValueError('invalid APIM count')
    if isinstance(hashes, str):
        hashes = json.loads(hashes)
    if not isinstance(hashes, list) or len(hashes) > 1 or any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in hashes):
        raise ValueError('invalid hashed APIM receipt identity')
    if count:
        if len(hashes) != 1 or not start <= _instant(ingested) <= end or not start <= _instant(latest) <= end:
            raise ValueError('APIM receipt outside approved window')
    elif ingested not in (None, '') or latest not in (None, '') or hashes:
        raise ValueError('empty APIM receipt conflicts with observations')
    return {'event_count': count, 'last_ingested_at': ingested, 'last_event_at': latest, 'receipt_ids': hashes}


def collect(reader, request, scopes, wanted, options):
    if KIND not in wanted:
        return
    from .azure import AzureReadError
    if options.get('_azure_apim_diagnostics_checks') == []:
        for scope in scopes:
            reader.unavailable(KIND, scope, 'Microsoft.ApiManagement', AzureReadError('selected_SW24_adapter_unavailable'))
        return
    jobs = []
    for scope in scopes:
        parents = [c for c in reader.collections if c['type'] == 'api_management' and c['scope'] == scope]
        facts = [c for c in reader.collections if c['type'] == 'apim_native' and c['scope'] == scope]
        def fetch(scope=scope, parents=parents, facts=facts):
            if len(parents) != 1 or len(facts) != 1 or any(c['status'] not in ('collected', 'empty') for c in parents + facts):
                raise AzureReadError('apim_native_parent_inventory_incomplete')
            for fact in facts[0]['items']:
                service = fact['id']
                row = {'id': service + '#native-apim-diagnostics', 'resource_id': service,
                       'configuration_sha256': digest(configuration(fact)), 'routes': [], 'observations': [], 'operations': [],
                       '_provenance': {'contract': CONTRACT, 'read_only': True, 'source_operation': 'APIM_ARM_and_Logs_aggregate'}}
                def route_reads():
                    url = ARM + service + '/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview'
                    seen = set()
                    for page in reader.pages(request, url):
                        for setting in page:
                            sid = setting.get('id') if isinstance(setting, dict) else None
                            if not isinstance(sid, str) or not re.fullmatch(re.escape(service) + r'/providers/Microsoft.Insights/diagnosticSettings/[^/?#%\s]+', sid, re.I):
                                raise ValueError('foreign APIM diagnostic setting')
                            if sid.casefold() in seen:
                                raise ValueError('duplicate APIM diagnostic setting')
                            seen.add(sid.casefold())
                            props = setting.get('properties')
                            if not isinstance(props, dict) or not isinstance(props.get('logs'), list):
                                raise ValueError('APIM diagnostic route unresolved')
                            logs = props['logs']
                            if any(not isinstance(log, dict) or type(log.get('enabled')) is not bool or not isinstance(log.get('category', log.get('categoryGroup')), str) for log in logs):
                                raise ValueError('malformed APIM log categories')
                            safe_props = {'logs': [{key: log[key] for key in ('category', 'categoryGroup', 'enabled') if key in log} for log in logs], 'logAnalyticsDestinationType': props.get('logAnalyticsDestinationType')}
                            enabled = any(isinstance(log, dict) and log.get('enabled') is True and (log.get('category') == 'GatewayLogs' or log.get('categoryGroup') == 'allLogs') for log in logs)
                            if not enabled:
                                continue
                            workspace = props.get('workspaceId')
                            if not workspace:
                                yield [{'id': sid, 'status': 'unsupported_destination', 'properties': safe_props}]
                                continue  # A different exporter cannot prove this supported Logs path.
                            workspace = _identity(workspace, scope, workspace=True)
                            safe_props['workspaceId'] = workspace
                            if props.get('logAnalyticsDestinationType') != 'Dedicated':
                                yield [{'id': sid, 'workspace_id': workspace, 'status': 'unsupported_table_route', 'properties': safe_props}]
                                continue
                            detail = reader.call(request, ARM + workspace + '?api-version=2023-09-01')
                            guid = detail.get('properties', {}).get('customerId') if isinstance(detail, dict) else None
                            if str(detail.get('id', '')).casefold() != workspace or not isinstance(guid, str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', guid, re.I):
                                raise ValueError('APIM workspace identity unavailable')
                            yield [{'id': sid, 'workspace_id': workspace, 'customer_id': guid, 'status': 'collected', 'properties': safe_props, 'workspace': {'id': workspace, 'customerId': guid}}]
                routes = reader._read(('native_apim_route', service, 'Microsoft.Insights', route_reads))
                row['routes'] = routes['items']
                row['_coverage'] = {'routes': {key: routes[key] for key in ('status', 'error') if key in routes}}
                policies = reviews(options, scope, service)
                def workspace_reads():
                    for page in reader.pages(request, ARM + service + '/workspaces?api-version=' + VERSION):
                        safe = []
                        for workspace in page:
                            rid = workspace.get('id') if isinstance(workspace, dict) else None
                            if not isinstance(rid, str) or not re.fullmatch(re.escape(service) + r'/workspaces/[^/?#%\s]+', rid, re.I):
                                raise ValueError('foreign APIM workspace')
                            safe.append({'id': rid})
                        yield safe
                if any(p['check_id'] != VERBOSE_ID for p in policies):
                    workspaces = reader._read(('native_apim_workspaces', service, 'Microsoft.ApiManagement', workspace_reads))
                    row['workspaces'] = workspaces['items']
                    row['_coverage']['workspaces'] = {key: workspaces[key] for key in ('status', 'error') if key in workspaces}
                online = {value.casefold() for value in fact.get('online_api_ids', []) if isinstance(value, str)}
                apis = [api for api in fact.get('apis', []) if str(api.get('id', '')).casefold() in online]
                if any(p['check_id'] == METHODS_ID for p in policies):
                    for api in apis:
                        aid = api['id']
                        def operation_reads(aid=aid):
                            seen = set()
                            for page in reader.pages(request, ARM + aid + '/operations?api-version=' + VERSION):
                                safe = []
                                for raw in page:
                                    rid = raw.get('id') if isinstance(raw, dict) else None
                                    method = raw.get('properties', {}).get('method') if isinstance(raw, dict) else None
                                    if not isinstance(rid, str) or not re.fullmatch(re.escape(aid) + r'/operations/[^/?#%\s]+', rid, re.I) or method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', '*'):
                                        raise ValueError('foreign or malformed APIM operation')
                                    if rid.casefold() in seen:
                                        raise ValueError('duplicate APIM operation')
                                    seen.add(rid.casefold())
                                    safe.append({'id': rid, 'parent_id': aid, 'method': method})
                                yield safe
                        operations = reader._read(('native_apim_operations', aid, 'Microsoft.ApiManagement', operation_reads))
                        row['operations'].append({'api_id': aid, 'status': operations['status'], 'items': operations['items']})
                for policy in policies:
                    if policy['check_id'] == VERBOSE_ID:
                        continue
                    for api in apis:
                        aid = api['id']
                        seen_workspaces = set()
                        for route in routes['items']:
                            if route.get('status') != 'collected' or route.get('workspace_id') in seen_workspaces:
                                continue
                            seen_workspaces.add(route['workspace_id'])
                            observed = {'check_id': policy['check_id'], 'api_id': aid, 'workspace_id': route['workspace_id'],
                                        'customer_id': route['customer_id'], 'policy_sha256': digest(policy)}
                            try:
                                start, end = _instant(policy['window']['start']), _instant(policy['window']['end'])
                                if not start < end <= datetime.now(timezone.utc) or (end-start).total_seconds() > 31*86400:
                                    raise ValueError('invalid APIM observation window')
                                body = query_for(scope, service, api, start, end)
                                response = reader.call(request, API + route['customer_id'] + '/query', audience=LOGS, body=body)
                                observed.update(aggregate(response, start, end), status='collected', query_sha256=digest(body))
                            except Exception as exc:
                                from .azure import _safe_error
                                status, error = _safe_error(exc)
                                observed.update(status=status, error=error)
                            row['observations'].append(observed)
                yield [row]
        jobs.append((KIND, scope, 'Microsoft.ApiManagement', fetch))
    reader.run(jobs)

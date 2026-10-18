"""Bound read-only Flex Function memory metadata; no app settings or host execution."""
from __future__ import annotations

from datetime import datetime, timezone
import re

ARM = 'https://management.azure.com'
VERSION = '2024-11-01'
KIND = 'function_app_runtime_native'
NATIVE_TYPES = {KIND}
_SEG = r'[A-Za-z0-9._()~-]+'
_SITE = re.compile(r'/subscriptions/' + _SEG + r'/resourceGroups/' + _SEG +
                   r'/providers/Microsoft\.Web/sites/' + _SEG, re.I)
_PLAN = re.compile(r'/subscriptions/' + _SEG + r'/resourceGroups/' + _SEG +
                   r'/providers/Microsoft\.Web/serverfarms/' + _SEG, re.I)
_LANGUAGES = frozenset({'dotnet-isolated', 'node', 'java', 'powershell', 'python'})


def required_types(wanted):
    return {'app_service', 'app_service_plan', 'subscription'} if KIND in wanted else set()


def _exact(value, pattern, scope):
    if (not isinstance(value, str) or not pattern.fullmatch(value)
            or not value.casefold().startswith(scope.casefold() + '/')
            or '%' in value or '\\' in value or any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('foreign native resource identity')
    return value


def _complete(reader, kind, scope):
    rows = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0]['status'] not in ('collected', 'empty') or not isinstance(rows[0].get('items'), list):
        raise ValueError('native parent inventory unavailable')
    return rows[0]['items']


def project(site, plan, app_id, plan_id, scope, observed_at, tenant_id, tenant_verified):
    """Whitelist the two ARM GET responses; never retain their other properties."""
    if (not isinstance(site, dict) or not isinstance(plan, dict)
            or site.get('id', '').casefold() != app_id.casefold()
            or plan.get('id', '').casefold() != plan_id.casefold()
            or str(site.get('type', '')).casefold() != 'microsoft.web/sites'
            or str(plan.get('type', '')).casefold() != 'microsoft.web/serverfarms'):
        raise ValueError('native GET identity or type mismatch')
    kind = site.get('kind')
    kinds = {part.strip().casefold() for part in kind.split(',')} if isinstance(kind, str) else set()
    props, sku = site.get('properties'), plan.get('sku')
    if (not isinstance(props, dict) or not isinstance(sku, dict)
            or 'functionapp' not in kinds or 'container' in kinds
            or props.get('serverFarmId', '').casefold() != plan_id.casefold()
            or sku.get('name') != 'FC1' or sku.get('tier') != 'FlexConsumption'):
        raise ValueError('Flex hosting or Function classification unresolved')
    config = props.get('functionAppConfig')
    runtime = config.get('runtime') if isinstance(config, dict) else None
    scale = config.get('scaleAndConcurrency') if isinstance(config, dict) else None
    language = runtime.get('name') if isinstance(runtime, dict) else None
    memory = scale.get('instanceMemoryMB') if isinstance(scale, dict) else None
    if language not in _LANGUAGES or type(memory) is not int or memory <= 0:
        raise ValueError('language or Flex instance memory unavailable')
    return {
        'id': app_id + '/functionRuntime/native', 'scope': scope, 'appId': app_id,
        'status': 'collected', 'hostingModel': 'FlexConsumption',
        'packageType': 'Code', 'runtimeType': 'Language',
        'configuredLanguage': language, 'memoryMB': memory, 'observedAt': observed_at,
        'source': {'operation': 'Microsoft.Web/sites GET',
                   'nativePath': 'properties.functionAppConfig.scaleAndConcurrency.instanceMemoryMB',
                   'apiVersion': VERSION, 'representation': 'full', 'resourceId': app_id,
                   'planOperation': 'Microsoft.Web/serverfarms GET', 'planResourceId': plan_id,
                   'planSkuName': 'FC1', 'planSkuTier': 'FlexConsumption'},
        '_provenance': {'read_only': True, 'source_operation': 'Microsoft.Web/sites GET + Microsoft.Web/serverfarms GET',
                        'api_version': VERSION, 'representation': 'metadata_projection',
                        'tenant_id': tenant_id, 'tenant_verified': tenant_verified,
                        'observed_at': observed_at},
    }


def safe_site_inventory(item):
    """Keep only nonsecret Function app config fields in the generic site row."""
    props = item.get('properties') if isinstance(item, dict) else None
    if isinstance(props, dict) and 'functionAppConfig' in props:
        config = props['functionAppConfig']
        safe = {}
        if isinstance(config, dict):
            runtime = config.get('runtime')
            scale = config.get('scaleAndConcurrency')
            if isinstance(runtime, dict):
                safe['runtime'] = {key: runtime[key] for key in ('name', 'version') if key in runtime}
            if isinstance(scale, dict) and 'instanceMemoryMB' in scale:
                safe['scaleAndConcurrency'] = {'instanceMemoryMB': scale['instanceMemoryMB']}
        props['functionAppConfig'] = safe
        item.setdefault('_coverage', {})['functionAppConfig'] = {
            'status': 'partial', 'reason': 'Only runtime name/version and instanceMemoryMB retained; deployment and other members omitted'}
    return item


def collect(reader, request, scopes, wanted, *, tenant_id, tenant_verified):
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        try:
            parents = _complete(reader, 'app_service', scope)
            plans = _complete(reader, 'app_service_plan', scope)
            subscriptions = [row for collection in reader.collections
                             if collection['type'] == 'subscription'
                             and collection['status'] in ('collected', 'empty')
                             for row in collection['items']
                             if str(row.get('id', '')).casefold() == scope.casefold()]
            if (len(subscriptions) != 1 or not tenant_verified
                    or subscriptions[0].get('tenantId', '').casefold() != str(tenant_id).casefold()):
                raise ValueError('selected subscription tenant binding unavailable')
            plan_ids = {_exact(row.get('id'), _PLAN, scope).casefold() for row in plans}
            seen = set()
            functions = []
            for parent in parents:
                app_id = _exact(parent.get('id'), _SITE, scope)
                if app_id.casefold() in seen:
                    raise ValueError('duplicate selected site')
                seen.add(app_id.casefold())
                kind = parent.get('kind')
                if isinstance(kind, str) and 'functionapp' in {v.strip().casefold() for v in kind.split(',')}:
                    functions.append(app_id)
        except Exception as exc:
            def failed(exc=exc):
                raise exc
                yield []
            jobs.append(((KIND, scope, 'Microsoft.Web', failed), None))
            continue
        if not functions:
            jobs.append(((KIND, scope, 'Microsoft.Web', lambda: iter(([],))), None))
            continue
        for app_id in functions:
            unavailable = {'id': app_id + '/functionRuntime/native', 'scope': scope,
                           'appId': app_id, 'status': 'unavailable',
                           '_provenance': {'read_only': True, 'tenant_id': tenant_id,
                                           'tenant_verified': tenant_verified}}
            def fetch(app_id=app_id, unavailable=unavailable, scope=scope, plan_ids=plan_ids):
                row = unavailable
                try:
                    site = reader.call(request, ARM + app_id + '?api-version=' + VERSION)
                    props = site.get('properties') if isinstance(site, dict) else None
                    plan_id = _exact(props.get('serverFarmId'), _PLAN, scope) if isinstance(props, dict) else None
                    if plan_id is None or plan_id.casefold() not in plan_ids:
                        raise ValueError('site plan not in selected inventory')
                    plan = reader.call(request, ARM + plan_id + '?api-version=' + VERSION)
                    captured = datetime.now(timezone.utc).isoformat()
                    row = project(site, plan, app_id, plan_id, scope, captured, tenant_id, tenant_verified)
                except Exception:
                    # One site is unresolved; no raw response or error body enters
                    # the snapshot. Shared reader limits still count the attempt.
                    pass
                yield [row]
            jobs.append(((KIND, scope, 'Microsoft.Web', fetch), unavailable))
    chunk_size = max(1, reader.workers)
    for offset in range(0, len(jobs), chunk_size):
        if reader.budget.max_calls is not None and reader.budget.calls >= reader.budget.max_calls:
            # One no-network unresolved tail per scope. Do not retry every site
            # after the shared call budget has already been exhausted.
            pending = {}
            for job, unavailable in jobs[offset:]:
                pending.setdefault(job[1], [])
                if unavailable is not None:
                    pending[job[1]].append(unavailable)
            tail = [(KIND, scope, 'Microsoft.Web', lambda rows=rows: iter((rows,)))
                    for scope, rows in pending.items()]
            if tail:
                reader.run(tail)
            break
        reader.run([job for job, _ in jobs[offset:offset + chunk_size]])

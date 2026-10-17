"""Exact built-in Azure Monitor APIM path; delivery requires real sink receipts."""
import math
import re
from datetime import timedelta

from . import result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .azure_apim_native import _fact, _apis, _children, _effective_diagnostics
from peaso.collectors.azure_apim_diagnostics_native import (
    CONTRACT, KIND, HTTP_ID, VERBOSE_ID, METHODS_ID, digest, configuration, query_for)
from peaso.collectors.azure_detection_telemetry import _instant, _identity



def _gateway_logs_enabled(logs):
    """One independently available enabled GatewayLogs selector suffices."""
    for log in logs:
        try:
            if not get(log, 'enabled', bool):
                continue
        except Unavailable:
            continue
        for field, value in (('category', 'GatewayLogs'), ('categoryGroup', 'allLogs')):
            try:
                if optional(log, field, None, str) == value:
                    return True
            except Unavailable:
                continue
    return False


def _matches_selection(row, selectors):
    """Unknown selectors cannot bind proof; a known unrelated selector skips it."""
    unavailable = []
    for field, expected, folded in selectors:
        try:
            value = get(row, field, str)
        except Unavailable as exc:
            unavailable.append(exc)
            continue
        if (value.casefold() if folded else value) != (expected.casefold() if folded else expected):
            return False
    if unavailable:
        raise unavailable[0]
    return True


def evaluate(cid, item, index):
    try:
        service, fact = _fact(item, index)
        apis = _apis(fact)
        scope = get(index, 'context.scope', str)
        policy_root = get(index, 'context.metadata.compliance_policy.sw24', dict)
        if get(policy_root, 'status', str) != 'collected' or get(policy_root, 'scope', str).casefold() != scope.casefold():
            raise Unavailable('APIM approved scope policy unavailable')
        policies = [p for p in list_of_objects(get(policy_root, 'checks', list))
                    if _matches_selection(p, (('check_id', cid, False), ('resource_id', service, True)))]
        if len(policies) != 1 or get(policies[0], 'status', str) != 'collected':
            raise Unavailable('APIM exact approved check policy unavailable')
        policy = policies[0]
        envs = get(get(index, 'collections', dict), KIND, list)
        rows = complete_items(index, KIND)
        if not isinstance(envs, list) or len(envs) != 1 or get(envs[0], 'scope', str).casefold() != scope.casefold() or get(envs[0], 'items', list) != rows:
            raise Unavailable('native APIM evidence scope unavailable')
        matches = [row for row in rows
                   if _matches_selection(row, (('resource_id', service, True), ('_provenance.contract', CONTRACT, False)))]
        if len(matches) != 1:
            raise Unavailable('native APIM evidence missing or ambiguous')
        measured = matches[0]
        if get(measured, '_provenance.read_only', bool) is not True or get(measured, 'configuration_sha256', str) != digest(configuration(fact)):
            raise Unavailable('native APIM evidence configuration differs')
        if cid != VERBOSE_ID and (get(measured, '_coverage.workspaces.status', str) != 'empty' or get(measured, 'workspaces', list)):
            raise Unavailable('APIM workspace API coverage unavailable')
        loggers = {row['id'].casefold(): row for row in _children(fact, 'loggers', 'loggers')}
        service_diags = _children(fact, 'diagnostics', 'diagnostics')
        selected = list(apis)
        if cid == VERBOSE_ID:
            required = get(policy, 'requiredApiIds', list)
            if not required or any(not isinstance(a, str) for a in required) or len({a.casefold() for a in required}) != len(required):
                raise Unavailable('APIM required API approval unavailable')
            actual = {api['id'].casefold(): api for api in apis}
            if not {a.casefold() for a in required} <= actual.keys():
                raise Unavailable('approved APIM API outside deployed revision inventory')
            selected = [actual[a.casefold()] for a in required]
        if cid == METHODS_ID:
            operations = list_of_objects(get(measured, 'operations', list))
            selected = []
            for api in apis:
                entries = [entry for entry in operations
                           if _matches_selection(entry, (('api_id', api['id'], True),))]
                if len(entries) != 1 or get(entries[0], 'status', str) not in ('collected', 'empty'):
                    raise Unavailable('complete native APIM operation coverage unavailable')
                items = list_of_objects(get(entries[0], 'items', list))
                if (get(entries[0], 'status', str) == 'empty') != (not items):
                    raise Unavailable('APIM operation status disagrees with rows')
                ids = set()
                for operation in items:
                    oid = get(operation, 'id', str)
                    if (not re.fullmatch(re.escape(api['id']) + r'/operations/[^/?#%\s]+', oid, re.I)
                            or oid.casefold() in ids or get(operation, 'parent_id', str).casefold() != api['id'].casefold()):
                        raise Unavailable('APIM operation identity unavailable or duplicate')
                    ids.add(oid.casefold())
                if items:
                    selected.append(api)
            if not selected:
                return 'NOT_APPLICABLE', {'reason': 'Complete native deployed operation inventory empty'}
        if not selected:
            raise Unavailable('APIM approved applicable API coverage unavailable')
        failures, unresolved, passed = [], [], []
        for api in selected:
            aid = api['id']
            effective = _effective_diagnostics(service_diags, _children(api, 'diagnostics', 'diagnostics'))
            if not effective:
                failures.append(aid)
                continue
            if len(effective) != 1:
                unresolved.append(aid)
                continue  # Multiple destinations/multiplexing requires independent semantics.
            diagnostic = effective[0]
            props = get(diagnostic, 'properties', dict)
            logger_id = get(props, 'loggerId', str).casefold()
            if not logger_id.startswith(service + '/loggers/') or '/' in logger_id[len(service + '/loggers/'):]:
                raise Unavailable('foreign APIM logger reference')
            logger = loggers.get(logger_id)
            if logger is None:
                failures.append(aid)
                continue
            if get(logger, 'properties.loggerType', str) != 'azureMonitor':
                unresolved.append(aid)
                continue  # Do not infer the usability of third-party keys or identities.
            verbosity = get(props, 'verbosity', str)
            if verbosity not in ('error', 'information', 'verbose'):
                raise Unavailable('APIM verbosity unresolved')
            allowed = ('error', 'verbose') if cid == VERBOSE_ID else ('error', 'information') if cid == METHODS_ID else ('error', 'information', 'verbose')
            if verbosity not in allowed:
                failures.append(aid)
                continue
            sampling = get(props, 'sampling', dict)
            percentage = get(sampling, 'percentage')
            if get(sampling, 'samplingType', str) != 'fixed' or type(percentage) not in (int, float) or not math.isfinite(percentage) or not 0 <= percentage <= 100:
                raise Unavailable('APIM sampling default or value unresolved')
            minimum = get(policy, 'minimumSamplingPercentage') if cid == HTTP_ID else 0.000001
            if type(minimum) not in (int, float) or not math.isfinite(minimum) or not 0 < minimum <= 100:
                raise Unavailable('APIM approved minimum sampling unresolved')
            if percentage < minimum:
                if cid != VERBOSE_ID or optional(props, 'alwaysLog', None, str) != 'allErrors':
                    failures.append(aid)
                    continue
            if cid in (HTTP_ID, VERBOSE_ID):
                for side in ('frontend', 'backend') if cid == HTTP_ID else ('frontend',):
                    for direction in ('request', 'response'):
                        capture = get(props, side + '.' + direction, dict)
                        if 'body' in capture:
                            count = get(capture, 'body.bytes')
                            if type(count) not in (int, float) or not math.isfinite(count) or not 0 <= count <= 8192:
                                raise Unavailable('APIM capture settings malformed')
            if get(measured, '_coverage.routes.status', str) not in ('collected', 'empty'):
                unresolved.append(aid)
                continue
            routes = list_of_objects(get(measured, 'routes', list))
            supported = []
            for route in routes:
                try:
                    if get(route, 'status', str) == 'collected':
                        supported.append(route)
                except Unavailable:
                    continue  # An unavailable route cannot supply this proof.
            if not supported:
                (unresolved if routes else failures).append(aid)
                continue
            route_ids = set()
            for route in supported:
                route_id = get(route, 'id', str)
                if not re.fullmatch(re.escape(service) + r'/providers/Microsoft.Insights/diagnosticSettings/[^/?#%\s]+', route_id, re.I) or route_id.casefold() in route_ids:
                    raise Unavailable('foreign or duplicate APIM diagnostic route')
                route_ids.add(route_id.casefold())
                if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', get(route, 'customer_id', str), re.I):
                    raise Unavailable('APIM workspace customer identity malformed')
                wid = _identity(get(route, 'workspace_id', str), scope, workspace=True)
                if (get(route, 'properties.workspaceId', str).casefold() != wid
                        or get(route, 'properties.logAnalyticsDestinationType', str) != 'Dedicated'
                        or get(route, 'workspace.id', str).casefold() != wid
                        or get(route, 'workspace.customerId', str).casefold() != get(route, 'customer_id', str).casefold()):
                    raise Unavailable('native APIM workspace route identity differs')
                logs = list_of_objects(get(route, 'properties.logs', list))
                if not _gateway_logs_enabled(logs):
                    raise Unavailable('native APIM GatewayLogs route unavailable')
            if cid == VERBOSE_ID:
                passed.append(aid)
                continue  # This signed predicate is configuration-only.
            start, end = _instant(get(policy, 'window.start', str)), _instant(get(policy, 'window.end', str))
            captured = _instant(get(index, 'context.created_at', str))
            if not start < end <= captured or end - start > timedelta(days=31):
                raise Unavailable('APIM approved receipt window unavailable')
            get(api, 'properties.apiRevision', str)  # The exact native receipt query consumes this revision.
            expected_query = digest(query_for(scope, service, api, start, end))
            observations = list_of_objects(get(measured, 'observations', list))
            seen = set()
            usable = False
            for observed in observations:
                try:
                    if not _matches_selection(observed, (('check_id', cid, False), ('api_id', aid, True))):
                        continue
                    if get(observed, 'status', str) != 'collected':
                        continue
                except Unavailable:
                    continue  # An unavailable candidate cannot prove delivery.
                wid = get(observed, 'workspace_id', str).casefold()
                if wid in seen:
                    raise Unavailable('duplicate native APIM sink observation')
                seen.add(wid)
                matching = [route for route in supported if route['workspace_id'].casefold() == wid]
                if not matching:
                    raise Unavailable('APIM receipt belongs to an unconfigured destination')
                if (get(observed, 'policy_sha256', str) != digest(policy) or get(observed, 'query_sha256', str) != expected_query
                        or get(observed, 'customer_id', str).casefold() != matching[0]['customer_id'].casefold()):
                    raise Unavailable('APIM sink proof policy, query or workspace binding differs')
                count = get(observed, 'event_count', int)
                if type(count) is not int or count < 0:
                    raise Unavailable('APIM receipt count invalid')
                if count:
                    hashes = get(observed, 'receipt_ids', list)
                    if len(hashes) != 1 or not isinstance(hashes[0], str) or not re.fullmatch('[0-9a-f]{64}', hashes[0]):
                        raise Unavailable('APIM request receipt identity invalid')
                    if not start <= _instant(get(observed, 'last_ingested_at', str)) <= end or not start <= _instant(get(observed, 'last_event_at', str)) <= end:
                        raise Unavailable('APIM receipt outside approved interval')
                    usable = True
            (passed if usable else unresolved).append(aid)
        if failures:
            return result(True, api_ids=failures, semantics='Complete native APIM configuration proves a gap')
        if unresolved:
            return unknown('Native APIM routing or actual sink receipt unresolved', api_ids=unresolved)
        return result(False, api_ids=passed, semantics='Native configured GatewayLogs path' if cid == VERBOSE_ID else 'Native configuration plus scoped actual sink receipts')
    except Unavailable as exc:
        return unknown(str(exc))
    except (ValueError, KeyError, TypeError) as exc:
        return unknown('Malformed native APIM evidence', error_kind=type(exc).__name__)

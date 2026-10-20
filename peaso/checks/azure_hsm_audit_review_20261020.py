"""Uninstalled native Managed HSM AuditEvent/storage declaration proposal.

Importing this module never changes the public registry. The coordinator admits
its declaration, descriptions and native fixtures together before calling install.
"""
import re
import json
from copy import deepcopy
from pathlib import Path
from .facts import get, list_of_objects, Unavailable
from . import unknown, result

CHECK = 'azure.review.managed_hsm.audit_storage_destination'
UUID = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
HSM_TYPE = 'Microsoft.KeyVault/managedHSMs'
DIAG_TYPE = 'Microsoft.Insights/diagnosticSettings'
VERSION = '2021-05-01-preview'
DECLARATIONS = [{
    'id': CHECK, 'provider': 'azure', 'kind': 'managed_hsm', 'category': 'hardening',
    'finding_type': 'logging', 'severity': 'medium', 'dependencies': ['managed_hsm'],
    'requirements': [], 'title': 'Managed HSM declares AuditEvent logging to Azure Storage',
    'remediation': 'Review the Managed HSM diagnostic settings and configure an enabled AuditEvent category with the intended Azure Storage destination. Verify log delivery and storage retention separately.',
    'evidence_scope': 'Native diagnostic configuration only; no destination existence, effective permissions, log delivery or retention claim.',
}]


def evaluate(item, index):
    try:
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'azure':
            raise Unavailable('provider mismatch')
        scope = get(context, 'scope', str)
        if not re.fullmatch('/subscriptions/' + UUID, scope, re.I):
            raise Unavailable('selected subscription identity unavailable')
        rid = get(item, 'id', str)
        if (not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#%]+/providers/Microsoft\.KeyVault/managedHSMs/[A-Za-z0-9-]{3,24}', rid, re.I)
                or get(item, 'type', str).casefold() != HSM_TYPE.casefold()
                or any(part in ('.', '..') or any(ord(c) < 33 for c in part) for part in rid.split('/'))):
            raise Unavailable('native HSM identity mismatch')
        if 'name' in item and get(item, 'name', str).casefold() != rid.rsplit('/', 1)[-1].casefold():
            raise Unavailable('native HSM name contradicts identity')
        envelopes = get(get(index, 'collections', dict), 'managed_hsm', list)
        own = [row for row in envelopes if get(row, 'scope', str).casefold() == scope.casefold()]
        if (len(own) != 1 or get(own[0], 'status', str) not in ('collected', 'empty')
                or sum(get(row, 'id', str).casefold() == rid.casefold() for row in list_of_objects(get(own[0], 'items', list))) != 1):
            raise Unavailable('complete unique native HSM inventory unavailable')
        coverage = get(item, '_coverage.diagnosticSettings', dict)
        if get(coverage, 'status', str) not in ('collected', 'empty'):
            raise Unavailable('diagnostic settings coverage incomplete')
        settings = list_of_objects(get(item, 'diagnosticSettings', list))
        seen, destinations, unresolved_group = set(), [], False
        request_path = rid + '/providers/' + DIAG_TYPE
        for setting in settings:
            sid = get(setting, 'id', str)
            if (not re.fullmatch(re.escape(request_path) + r'/[^/?#%]+', sid, re.I)
                    or sid.casefold() in seen or get(setting, 'type', str).casefold() != DIAG_TYPE.casefold()
                    or get(setting, 'parent_id', str).casefold() != rid.casefold()):
                raise Unavailable('native diagnostic setting identity unavailable')
            seen.add(sid.casefold())
            proof = get(setting, '_provenance', dict)
            if (proof.get('source_operation') != 'DiagnosticSettings_List' or proof.get('read_only') is not True
                    or proof.get('api_version') != VERSION or str(proof.get('scope', '')).casefold() != rid.casefold()
                    or str(proof.get('request_path', '')).casefold() != request_path.casefold()):
                raise Unavailable('native diagnostic setting source unavailable')
            metadata = get(context, 'metadata', dict)
            credential = get(metadata, 'credential_context_id', str)
            customer = get(metadata, 'customer_context_id', str)
            if (not re.fullmatch(r'[0-9a-f]{32}', credential) or customer != 'scan-local:' + credential
                    or any(proof.get(key) != value or get(item, '_provenance', dict).get(key) != value
                           or get(own[0], '_provenance', dict).get(key) != value
                           for key, value in (('credential_context_id', credential), ('customer_context_id', customer)))):
                raise Unavailable('native diagnostic setting capture context mismatch')
            props = get(setting, 'properties', dict)
            storage = props.get('storageAccountId')
            if storage is not None and (not isinstance(storage, str) or not re.fullmatch(
                    r'/subscriptions/' + UUID + r'/resourceGroups/[^/?#%]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}', storage, re.I)
                    or any(part in ('.', '..') or any(ord(c) < 33 for c in part) for part in storage.split('/'))):
                raise Unavailable('storage destination reference malformed')
            for log in list_of_objects(get(props, 'logs', list)):
                enabled = get(log, 'enabled', bool)
                category, group = log.get('category'), log.get('categoryGroup')
                if ((category is not None and (not isinstance(category, str) or not category))
                        or (group is not None and group not in ('audit', 'allLogs'))
                        or category is not None and group is not None or category is None and group is None):
                    raise Unavailable('native log selector malformed or unsupported')
                if enabled and storage:
                    if category == 'AuditEvent':
                        destinations.append(storage)
                    elif group is not None:
                        unresolved_group = True
        if destinations:
            return result(False, criterion='declared_audit_storage_destination', audit_storage_configured=True, storage_destination_references=sorted(set(destinations)),
                observed='Managed HSM declares AuditEvent logging to Azure Storage. Delivery, destination existence and retention were not tested.')
        if unresolved_group:
            return unknown('native category-group resolution was not collected',
                observed='A diagnostic category group is enabled for storage. Its AuditEvent coverage could not be resolved.')
        return result(True, criterion='declared_audit_storage_destination', audit_storage_configured=False, observed='No enabled AuditEvent logging declaration to an Azure Storage destination was found.')
    except (Unavailable, TypeError, ValueError, KeyError, AttributeError):
        return unknown('native HSM diagnostic declaration incomplete, malformed or unbound',
            observed='Managed HSM diagnostic settings were incomplete or unsupported. The AuditEvent storage declaration could not be assessed.')


def install(registrar):
    """Explicit coordinator-owned activation; no import-time registration."""
    declaration = DECLARATIONS[0]
    path = Path(__file__).with_name('azure_hsm_audit_review_20261020_fixtures.json')
    cases = json.loads(path.read_text())[CHECK]
    from .fixtures import CASES
    CASES[CHECK] = deepcopy(cases)
    return registrar(CHECK, 'azure', 'hardening', 'managed_hsm', declaration['title'], 'medium',
        'security_configuration', declaration['remediation'], dependencies=['managed_hsm'])(evaluate)

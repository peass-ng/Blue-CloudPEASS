"""Uninstalled native Managed HSM AuditEvent destination declaration proposal.

Importing this module never changes the public registry. The coordinator admits
its declaration, descriptions and native fixtures together before calling install.
"""
import re
import json
from copy import deepcopy
from pathlib import Path
from .facts import get, list_of_objects, Unavailable
from . import unknown, result
from peaso.collectors.azure_aks_legacy_projection_review_20261020 import HSM_KIND

CHECK = 'azure.logging.managed_hsm_audit_destination_declared'
UUID = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
HSM_TYPE = 'Microsoft.KeyVault/managedHSMs'
DIAG_TYPE = 'Microsoft.Insights/diagnosticSettings'
VERSION = '2021-05-01-preview'
DECLARATIONS = [{
    'id': CHECK, 'provider': 'azure', 'kind': 'managed_hsm', 'category': 'hardening',
    'finding_type': 'logging', 'severity': 'medium', 'dependencies': ['managed_hsm',HSM_KIND],
    'requirements': [], 'ui_group': 'Logging', 'title': 'Managed HSM declares AuditEvent logging to Storage or Log Analytics',
    'remediation': 'Review the Managed HSM diagnostic settings and configure an enabled AuditEvent category with the intended Storage or Log Analytics destination. Verify log delivery and storage retention separately.',
    'evidence_scope': 'Native diagnostic configuration only; no destination existence, effective permissions, log delivery or retention claim.',
}]


def group_includes_audit(item,index,group):
    """Only native complete category evidence resolves a group selector."""
    ctx=get(index,'context',dict);scope=get(ctx,'scope',str);rid=get(item,'id',str)
    envelopes=get(index,'collections',dict).get(HSM_KIND)
    if not isinstance(envelopes,list) or len(envelopes)!=1:raise Unavailable('native category source absent')
    envelope=envelopes[0]
    if envelope.get('status')!='collected' or str(envelope.get('scope','')).casefold()!=scope.casefold():raise Unavailable('native category source incomplete')
    rows=list_of_objects(get(envelope,'items',list));matches=[r for r in rows if str(r.get('id','')).casefold()==rid.casefold()]
    if len(matches)!=1 or len({str(r.get('id','')).casefold() for r in rows})!=len(rows):raise Unavailable('native category source ambiguous')
    row=matches[0];meta=get(ctx,'metadata',dict);path=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories';proof=get(row,'_provenance',dict)
    for obj in (envelope,row):
        p=get(obj,'_provenance',dict)
        for key in ('credential_context_id','customer_context_id'):
            if not meta.get(key) or p.get(key)!=meta[key]:raise Unavailable('native category capture context mismatch')
    if (str(row.get('parent_id','')).casefold()!=rid.casefold() or proof.get('source_operation')!='HSM_AuditDestinationMetadata'
            or proof.get('read_only') is not True or proof.get('api_version')!=VERSION or proof.get('scope')!=scope or proof.get('request_path')!=path):
        raise Unavailable('native category parent/read binding unavailable')
    inventory=get(row,'category_inventory',dict);source=get(inventory,'_provenance',dict)
    if (inventory.get('status')!='collected' or source.get('source_operation')!='DiagnosticSettingsCategories_List'
            or source.get('read_only') is not True or source.get('api_version')!=VERSION
            or source.get('request_path')!=path or str(source.get('scope','')).casefold()!=rid.casefold()):
        raise Unavailable('complete native category list unavailable')
    seen=set();audit=None
    for cat in list_of_objects(get(inventory,'items',list)):
        name=get(cat,'name',str);props=get(cat,'properties',dict)
        if (name.casefold() in seen or get(cat,'id',str).casefold()!=(path+'/'+name).casefold()
                or get(cat,'type',str).casefold()!='microsoft.insights/diagnosticsettingscategories'
                or props.get('categoryType') not in ('Logs','Metrics')):raise Unavailable('native category identity/type invalid')
        seen.add(name.casefold())
        if name=='AuditEvent' and props['categoryType']=='Logs':audit=props
    if audit is None:raise Unavailable('AuditEvent supported category absent')
    if 'categoryGroups' in audit:
        values=get(audit,'categoryGroups',list)
        if any(not isinstance(g,str) or not g for g in values):raise Unavailable('native category membership malformed')
    if group=='allLogs':return True
    groups=get(audit,'categoryGroups',list)
    if any(not isinstance(g,str) or not g for g in groups):raise Unavailable('native category membership malformed')
    return group in groups


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
        if coverage['status']=='empty' and settings:raise Unavailable('empty diagnostic coverage contradicts returned rows')
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
            workspace = props.get('workspaceId')
            if workspace not in (None,'') and (not isinstance(workspace,str) or re.fullmatch(
                    r'/subscriptions/' + UUID + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.OperationalInsights/workspaces/[^/?#%\\\s]{4,63}',workspace,re.I) is None
                    or any(part in ('.','..') or any(ord(c)<33 for c in part) for part in workspace.split('/'))):
                raise Unavailable('workspace destination reference malformed')
            if not storage and not workspace and any(props.get(k) for k in ('eventHubAuthorizationRuleId','marketplacePartnerId','serviceBusRuleId')):
                unresolved_group = True
            if storage not in (None,'') and (not isinstance(storage, str) or not re.fullmatch(
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
                if enabled and (storage or workspace):
                    if category == 'AuditEvent':
                        destinations.extend({'kind':kind,'resource_id':value} for kind,value in (('Storage',storage),('LogAnalytics',workspace)) if value)
                    elif group is not None:
                        try:
                            if group_includes_audit(item,index,group):
                                destinations.extend({'kind':kind,'resource_id':value} for kind,value in (('Storage',storage),('LogAnalytics',workspace)) if value)
                        except (Unavailable,ValueError,TypeError,KeyError,AttributeError):
                            unresolved_group = True
        if destinations:
            return result(False, criterion='declared_audit_destination', audit_destination_configured=True, destination_references=sorted({(d['kind'],d['resource_id']) for d in destinations}),
                observed='Managed HSM declares enabled AuditEvent logging to Storage or Log Analytics. Destination access, delivery and retention were not tested.')
        if unresolved_group:
            return unknown('native category group or destination form is unsupported',
                observed='The diagnostic declaration uses an unresolved category group or unsupported destination. AuditEvent destination coverage could not be assessed.')
        return result(True, criterion='declared_audit_destination', audit_destination_configured=False, observed='No enabled AuditEvent logging declaration to Storage or Log Analytics was found.')
    except (Unavailable, TypeError, ValueError, KeyError, AttributeError):
        return unknown('native HSM diagnostic declaration incomplete, malformed or unbound',
            observed='Managed HSM diagnostic settings were incomplete or unsupported. The AuditEvent destination declaration could not be assessed.')



def install(registrar):
    """Explicit coordinator admission only; import never mutates registration."""
    d=DECLARATIONS[0]
    return registrar(CHECK,'azure','hardening','managed_hsm',d['title'],'medium',
        'security_configuration',d['remediation'],dependencies=d['dependencies'])(evaluate)

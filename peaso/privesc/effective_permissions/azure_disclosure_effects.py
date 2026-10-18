"""Reviewed, metadata-only proofs of seven terminal Azure disclosures.

The standard collector does not supply these proofs. Imported projections must
retain exact resource identities and source operations, and omit secret values.
A proof creates an operation on one resource, never a cloud/service principal.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

CONTRACT = json.loads(Path(__file__).resolve().parents[1].joinpath('azure_disclosure_effects.json').read_text())
_METADATA = 'azure_disclosure_source_metadata'
# Keep immutable historical entries, but fail closed where an operation returns
# names, redacted fields or references rather than proven secret values. A
# reviewed SecretConfigured assertion cannot override these API semantics.
UNSUPPORTED_DISCLOSURES = {
    'azure-spring-apps-microsoftappplatformspringapmslistsecretkeysaction':
        'sensitive_property_names_only: Apms_ListSecretKeys lists names of sensitive properties, not their values; value disclosure is unsupported.',
    'azure-spring-apps-config-server-bindings-secret-exposure':
        'spring_secret_value_unproven: App secret.value is write-only; binding generatedProperties omits secrets; configService/read is a separate data-plane action and cannot establish an ARM secret-value disclosure.',
    'azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret':
        'service_linker_configuration_value_unproven: KeyVaultSecret configurations are references and Default configurations can contain non-secret values; configured-secret metadata does not prove disclosed credential values.',
    'azure-sre-agent-microsoftappagentsdataconnectorslistsecretsaction':
        'sre_dataconnectors_action_endpoint_unverified: The exact legacy dataconnectors action and secret-value response are unverified; the current connectors/listSecrets family cannot be substituted, and managed-identity data sources need not contain secrets.',
    'azure-sre-agent-microsoftappagentslistsecretsaction':
        'sre_agent_listsecrets_endpoint_unverified: No exact agent-level listSecrets endpoint and secret-value response are verified; connector-level operations cannot establish the legacy agent action.'
}
# A permission valid on a different child-resource type does not authorize the
# configured-secret endpoint. Match each requirement's exact resource family.
_ACTION_TYPES = {
 'microsoft.web/sourcecontrols/read': 'microsoft.web/sourcecontrols',
 'microsoft.keyvault/vaults/secrets/getsecret/action': 'microsoft.keyvault/vaults/secrets',
 'microsoft.servicelinker/linkers/read': 'microsoft.servicelinker/linkers',
 'microsoft.servicelinker/linkers/listconfigurations/action': 'microsoft.servicelinker/linkers',
 'microsoft.servicelinker/linkers/generateconfigurations/action': 'microsoft.servicelinker/linkers',
 'microsoft.appplatform/spring/apps/read': 'microsoft.appplatform/spring/apps',
 'microsoft.appplatform/spring/apps/bindings/read': 'microsoft.appplatform/spring/apps/bindings',
 'microsoft.appplatform/spring/configservice/read': 'microsoft.appplatform/spring/configservice',
 'microsoft.appplatform/spring/apms/listsecretkeys/action': 'microsoft.appplatform/spring/apms',
 'microsoft.app/agents/dataconnectors/listsecrets/action': 'microsoft.app/agents/dataconnectors',
 'microsoft.app/agents/listsecrets/action': 'microsoft.app/agents',
}
_FORBIDDEN = frozenset({'token','password','secret','value','privatekey','privatekeybytes',
                        'credentials','clientsecret','apikey','accesskey','pfx','secrettext','secretvalue'})

_SOURCE_CONTROL_VALUE_FIELDS = ('token', 'refreshToken', 'tokenSecret')


def source_control_returned_token_fields(response, resource):
    """Reduce one SourceControls_Get response to nonempty token field names.

    Callers must discard the response values. A configured resource, absent/null
    field, or a reference does not establish that a token value was returned.
    """
    if (not isinstance(response, dict) or response.get('id') != resource
            or str(response.get('type', '')).casefold() != 'microsoft.web/sourcecontrols'
            or response.get('name') != resource.rsplit('/', 1)[-1]):
        return []
    properties = response.get('properties')
    if not isinstance(properties, dict):
        return []
    return ['properties.' + field for field in _SOURCE_CONTROL_VALUE_FIELDS
            if _text(properties.get(field))
            and not properties[field].casefold().startswith(('https://', 'http://',
                '@microsoft.keyvault(', '/subscriptions/'))
            and properties[field].casefold() not in ('redacted', 'null', 'none')]




def _text(value):
    return isinstance(value,str) and bool(value) and value==value.strip() and not any(c in value for c in '*?\r\n\x00')


def _safe(value, depth=0):
    if depth>20:return False
    if isinstance(value,dict):
        return all(isinstance(k,str) and re.sub(r'[^a-z]','',k.casefold()) not in _FORBIDDEN
                   and _safe(v,depth+1) for k,v in value.items())
    if isinstance(value,list):return all(_safe(v,depth+1) for v in value)
    return value is None or isinstance(value,(str,int,float,bool))


def _instant(value):
    if not isinstance(value,str):raise ValueError('missing time')
    result=datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.utcoffset() is None:raise ValueError('naive time')
    return result


def _native_type(resource):
    if not _text(resource):return None
    parts=resource.strip('/').split('/')
    if any(not p or p in ('.','..') or '%' in p or '#' in p for p in parts):return None
    providers=[index for index,part in enumerate(parts) if part.casefold()=='providers']
    if not providers:return None
    tail=parts[providers[-1]+1:]
    if len(tail)<3 or len(tail)%2!=1:return None
    return '/'.join([tail[0]]+tail[1::2]).casefold()


def _complete(snapshot,kind,scope):
    collections=snapshot.get('collections',[])
    if not isinstance(collections,list):return None
    envelopes=[c for c in collections if isinstance(c,dict) and c.get('type')==kind
               and isinstance(c.get('scope'),str) and c['scope'].casefold()==scope.casefold()]
    if len(envelopes)!=1 or envelopes[0].get('status') not in ('collected','empty'):return None
    value=envelopes[0].get('items')
    if not isinstance(value,list) or not all(isinstance(row,dict) for row in value):return None
    if (envelopes[0]['status']=='empty') != (not value):return None
    return value


def _native_resource(snapshot,resource,resource_type):
    scope='/'.join(resource.split('/')[:3]) if resource.casefold().startswith('/subscriptions/') else '/'
    if scope!='/':
        subscriptions=[]
        for col in snapshot.get('collections',[]):
            if not isinstance(col,dict) or col.get('type')!='subscription':continue
            if col.get('status') not in ('collected','empty') or not isinstance(col.get('items'),list):return None
            subscriptions.extend(row for row in col['items'] if isinstance(row,dict)
                                 and str(row.get('id','')).casefold()==scope.casefold())
        tenant=(snapshot.get('metadata') or {}).get('tenant_id')
        if len(subscriptions)!=1 or (subscriptions[0].get('tenantId') is not None and subscriptions[0]['tenantId']!=tenant):return None
    rows=_complete(snapshot,'resource_graph',scope)
    if rows is None:return None
    matching=[row for row in rows if isinstance(row.get('id'),str) and row['id'].casefold()==resource.casefold()]
    if len(matching)!=1 or not isinstance(matching[0].get('type'),str):return None
    row=matching[0]
    return row if row['type'].casefold()==resource_type and _native_type(resource)==resource_type else None


def native_binding(snapshot,provenance,source):
    """Bind an optional native projection to the exact authenticated scan subject."""
    context=snapshot.get('metadata') or {}
    subject=context.get('native_disclosure_subject')
    return (isinstance(provenance,dict) and provenance.get('source')=='azure_native_metadata'
            and provenance.get('authenticated_response_bound') is True
            and provenance.get('read_only') is True and provenance.get('values_omitted') is True
            and context.get('tenant_verified') is True and context.get('context_binding')=='scan_local'
            and isinstance(subject,dict) and subject.get('oid')==source
            and subject.get('tid')==context.get('tenant_id')==provenance.get('tenant_id')
            and provenance.get('tenant_verified') is True and provenance.get('source_principal_id')==source
            and all(_text(context.get(key)) and provenance.get(key)==context[key]
                    for key in ('credential_context_id','customer_context_id')))


def _fabric_link(snapshot,metadata):
    link=metadata.get('CertificateLink')
    if not isinstance(link,dict):return False
    cluster,vault=link.get('ClusterId'),link.get('VaultId')
    if not _text(cluster) or not _text(vault):return False
    cluster_row=_native_resource(snapshot,cluster,'microsoft.servicefabric/clusters')
    vault_row=_native_resource(snapshot,vault,'microsoft.keyvault/vaults')
    if cluster_row is None or vault_row is None:return False
    secret=link.get('SecretVersionId');certificate=link.get('CertificateVersionId')
    if not _text(secret) or not _text(certificate):return False
    try:
        sp,cp=urlsplit(secret),urlsplit(certificate)
        if sp.port is not None or cp.port is not None:return False
    except ValueError:return False
    if (sp.scheme!='https' or cp.scheme!='https' or not sp.hostname or sp.hostname!=cp.hostname
            or sp.username or sp.password or sp.query or sp.fragment or cp.username or cp.password or cp.query or cp.fragment):return False
    if (not re.fullmatch(r'/secrets/[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]+',sp.path)
            or not re.fullmatch(r'/certificates/[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]+',cp.path)
            or metadata['ResourceId'].casefold()!=vault.casefold()+'/secrets/'+sp.path.split('/')[2].casefold()):return False
    props=cluster_row.get('properties');vprops=vault_row.get('properties')
    if not isinstance(props,dict) or not isinstance(vprops,dict) or vprops.get('enableRbacAuthorization') is not True:return False
    conf=props.get('certificate')
    native_mode=metadata.get('_provenance',{}).get('source')=='azure_native_metadata'
    if native_mode:
        source=metadata['_provenance'].get('source_principal_id')
        rows=_complete(snapshot,'azure_disclosure_cluster_metadata',cluster)
        matched=[r for r in rows or[] if r.get('id')==cluster]
        if len(matched)!=1:return False
        projection=matched[0];provenance=projection.get('_provenance',{})
        if (not _safe(projection) or not native_binding(snapshot,provenance,source)
                or provenance.get('source_operation')!='Clusters_Get'
                or provenance.get('request_uri')!='https://management.azure.com'+cluster
                or vprops.get('enableRbacAuthorization') is not True):return False
        conf={'thumbprint':projection.get('cluster_certificate_thumbprint')}
        versions=_complete(snapshot,'azure_disclosure_secret_version_metadata',vault)
        secrets=[r for r in versions or[] if r.get('id')==secret and r.get('parent_id')==vault]
        if len(secrets)!=1:return False
        version=secrets[0];vp=version.get('_provenance',{});attributes=version.get('attributes')
        if (not _safe(version) or not native_binding(snapshot,vp,source)
                or vp.get('source_operation')!='Secrets_ListVersions'
                or vp.get('request_uri')!='https://'+sp.netloc+'/secrets/'+sp.path.split('/')[2]+'/versions'
                or not isinstance(attributes,dict) or attributes.get('enabled') is not True):return False
        try:
            captured=_instant(snapshot.get('created_at'))
            for projection in (projection,version):
                if not 0<=(captured-_instant(projection['_provenance'].get('observed_at'))).total_seconds()<=900:return False
            for key in ('nbf','exp'):
                if key in attributes:
                    value=attributes[key]
                    if type(value) is not int or (key=='nbf' and value>captured.timestamp()) or (key=='exp' and value<=captured.timestamp()):return False
        except (TypeError,ValueError,OverflowError):return False
    thumb=link.get('CertificateThumbprint')
    if (not isinstance(thumb,str) or not re.fullmatch(r'[0-9a-fA-F]{40}',thumb)
            or not isinstance(conf,dict) or not isinstance(conf.get('thumbprint'),str)
            or conf['thumbprint'].casefold()!=thumb.casefold()
            or vprops.get('vaultUri')!='https://'+sp.netloc+'/'):return False
    # Exact safe certificate projection imported from Certificates_Get. The
    # normal certificate collector drops sid/policy, so it is insufficient.
    rows=_complete(snapshot,'azure_disclosure_certificate_metadata',vault)
    if rows is None:return False
    matching=[r for r in rows if r.get('id')==certificate]
    if len(matching)!=1:return False
    native=matching[0];provenance=native.get('_provenance');policy=native.get('policy')
    if (not _safe(native) or native.get('sid')!=secret or native.get('parent_id')!=vault
            or not isinstance(policy,dict) or not isinstance(policy.get('key_props'),dict)
            or policy['key_props'].get('exportable') is not True
            or not isinstance(provenance,dict) or provenance.get('source_operation')!='Certificates_Get'
            or provenance.get('request_uri')!=certificate or provenance.get('read_only') is not True
            or provenance.get('values_omitted') is not True
            or provenance.get('observed_at')!=metadata['_provenance']['observed_at']):return False
    if native_mode:
        binding=native.get('policy_binding');attributes=native.get('attributes')
        if (not isinstance(binding,dict)or not isinstance(attributes,dict)or attributes.get('enabled')is not True
                or any(binding.get(key)!=native.get(key)for key in('id','sid','x5t','policy'))
                or provenance.get('policy_version_id')!=certificate):return False
        operation=binding.get('source_operation');uri=binding.get('request_uri')
        if operation not in('Certificates_Get','Certificates_GetCurrent'):return False
        expected=certificate if operation=='Certificates_Get'else certificate.rsplit('/',1)[0]
        if (uri!=expected or provenance.get('policy_source_operation')!=operation
                or provenance.get('policy_request_uri')!=uri):return False
        try:
            captured=_instant(snapshot.get('created_at')).timestamp()
            for key in('nbf','exp'):
                if key in attributes:
                    value=attributes[key]
                    if type(value)is not int or(key=='nbf'and value>captured)or(key=='exp'and value<=captured):return False
        except (TypeError,ValueError,OverflowError):return False
    # x5t is the provider's base64url-encoded SHA-1 certificate thumbprint.
    import base64
    try:
        x5t=native.get('x5t')
        if not isinstance(x5t,str) or not re.fullmatch(r'[A-Za-z0-9_-]{27}=?',x5t):return False
        decoded=base64.b64decode(x5t.rstrip('=')+'=',altchars=b'-_',validate=True)
    except (ValueError,TypeError):return False
    if native_mode and not native_binding(snapshot,provenance,source):return False
    return decoded.hex()==thumb.casefold()


def valid(model,technique,fact,source,resource,scope):
    if technique in UNSUPPORTED_DISCLOSURES:return False
    spec=CONTRACT.get(technique)
    if spec is None:return True
    if (not isinstance(fact,dict) or not _safe(fact) or fact.get('TechniqueId')!=technique
            or fact.get('SourceId')!=source or fact.get('TargetKind')!='azure_verified_authority'
            or fact.get('TargetId')!=resource or fact.get('TargetScope')!=scope or fact.get('Status')!='verified'
            or fact.get('VerifiedPreconditions') is not True or fact.get('EffectType')!='terminal_configuration_disclosure'
            or not _text(fact.get('EvidenceRef'))):return False
    conditions=fact.get('VerifiedConditionIds')
    if not isinstance(conditions,list) or not all(isinstance(c,str) for c in conditions) or sorted(conditions)!=sorted(spec['conditions']):return False
    try:
        captured=_instant(model.snapshot.get('created_at'));observed=_instant(fact.get('EvidenceObservedAt'))
        if not 0<=(captured-observed).total_seconds()<=900:return False
    except (TypeError,ValueError,OverflowError):return False
    if not _text(resource) or not _text(scope):return False
    rtype=_native_type(resource)
    if spec['service']=='app_services':
        if scope!='/' or rtype!='microsoft.web/sourcecontrols' or not resource.casefold().startswith('/providers/microsoft.web/sourcecontrols/'):return False
    elif (scope.casefold()!=resource.casefold()
          or not re.match(r'^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/',resource,re.I)):return False
    metadata_rows=_complete(model.snapshot,_METADATA,scope)
    if metadata_rows is None:return False
    matching=[row for row in metadata_rows if row.get('ResourceId')==resource and row.get('TechniqueId')==technique]
    if len(matching)!=1:return False
    metadata=matching[0];provenance=metadata.get('_provenance')
    if (not _safe(metadata) or not isinstance(metadata.get('ResourceType'),str)
            or metadata['ResourceType'].casefold()!=rtype or metadata.get('SecretConfigured') is not True
            or metadata.get('CredentialReferenceId')!=fact.get('CredentialReferenceId') or not _text(metadata.get('CredentialReferenceId'))
            or metadata.get('CustomerTenantId')!=model.tenant or fact.get('CustomerTenantId')!=model.tenant
            or not isinstance(provenance,dict) or (provenance.get('source')!='reviewed_metadata_only' and not (spec['service'] in ('service_fabric','app_services') and native_binding(model.snapshot,provenance,source)))
            or provenance.get('read_only') is not True or provenance.get('values_omitted') is not True
            or provenance.get('observed_at')!=fact.get('EvidenceObservedAt')
            or metadata.get('EvidenceRef')!=fact.get('EvidenceRef')):return False
    if provenance.get('source')=='azure_native_metadata' and not native_binding(model.snapshot,fact.get('_provenance'),source):return False
    if spec['service']=='service_fabric':
        if not _fabric_link(model.snapshot,metadata):return False
    elif spec['service']=='app_services':
        # SourceControls_Get is a provider-global endpoint, outside subscription
        # Resource Graph. Preserve the exact imported metadata projection.
        # A configured source control can return only identity or null token
        # fields. Require a scan-bound authenticated response projection.
        if (provenance.get('source')!='azure_native_metadata'
                or provenance.get('source_operation')!='SourceControls_Get'
                or provenance.get('request_uri')!='https://management.azure.com'+resource
                or provenance.get('response_status')!=200
                or metadata.get('ProviderGlobal') is not True
                or any(fact.get('_provenance',{}).get(key)!=provenance.get(key)
                       for key in ('source_operation','request_uri','response_status','observed_at'))):return False
        fields=metadata.get('ReturnedCredentialFields')
        if (not isinstance(fields,list) or not fields or len(fields)!=len(set(fields))
                or any(field not in {'properties.'+name for name in _SOURCE_CONTROL_VALUE_FIELDS}
                       for field in fields)):return False
        native=metadata.get('NativeResource')
        if (not isinstance(native,dict) or native.get('id')!=resource or not isinstance(native.get('type'),str) or native['type'].casefold()!=rtype
                or native.get('name')!=resource.rsplit('/',1)[-1]):return False
    elif _native_resource(model.snapshot,resource,rtype) is None:return False
    bindings=fact.get('ActionResources')
    if not isinstance(bindings,dict):return False
    principal=model.principals.get(source)
    if principal is None:return False
    from ..schema import expand_requires
    for path in expand_requires(spec['requires']):
        good=True
        for requirement in path:
            action=requirement['action']
            if bindings.get(action)!=[scope] or _ACTION_TYPES.get(action.casefold())!=rtype:
                good=False;break
            grant=model.check(principal,{'action':action,'data_action':bool(requirement.get('data_action'))},scope)
            if grant is None or grant.confidence=='unknown':good=False;break
        if good:return True
    return False

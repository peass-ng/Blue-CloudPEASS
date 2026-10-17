"""Optional Service Fabric certificate-disclosure metadata, never secret values.

Only the authenticated ARM/Vault subject receives a source fact. Other six V7
techniques keep their reviewed-import adapter requirement.
"""
from __future__ import annotations
import base64
from datetime import datetime,timezone
import hashlib
import re
from uuid import uuid4

ARM='https://management.azure.com';VAULT='https://vault.azure.net'
TECHNIQUE='azure-audit-cluster-client-certificate-theft-data-plane-admin'
VERSION='2025-07-01'
KINDS={'azure_disclosure_source_metadata','azure_disclosure_certificate_metadata',
       'azure_disclosure_cluster_metadata','azure_disclosure_secret_version_metadata','azure_privesc_challenge_evidence'}


def required_types(options):
    enabled=options.get('native_disclosure_metadata',False)
    if type(enabled)is not bool:raise ValueError('native_disclosure_metadata must be boolean')
    return {'subscription','resource_graph'}if enabled else set()


def _complete(reader,kind,scope):
    env=[c for c in reader.collections if c['type']==kind and c['scope'].casefold()==scope.casefold()]
    if len(env)!=1 or env[0]['status']not in('collected','empty'):return None
    rows=env[0]['items']
    return rows if isinstance(rows,list)and(env[0]['status']=='empty')==(not rows)else None


def _subject_claims(token,audience):
    """Parse a routing hint; this function does not authenticate a bearer token.

    Authority comes only from AzureTransport recording these exact claims after
    Azure accepts the same token on its native endpoint.
    """
    from .azure import _claims
    claims=_claims(token)
    oid,tid=claims.get('oid'),claims.get('tid')
    guid=r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
    if not isinstance(oid,str)or not isinstance(tid,str)or not re.fullmatch(guid,oid)or not re.fullmatch(guid,tid):return None
    aliases={ARM:{ARM,ARM+'/', 'https://management.core.windows.net/'},VAULT:{VAULT,VAULT+'/', 'cfa8b339-82a2-471a-a3c9-0fc0be7a4093'}}
    if claims.get('aud')not in aliases.get(audience,set()):return None
    if claims.get('iss')not in('https://sts.windows.net/'+tid+'/', 'https://login.microsoftonline.com/'+tid+'/v2.0'):return None
    return {'oid':oid,'tid':tid}


def accepted_subject(token,audience):
    """Post-success receipt: Azure validated this exact token on its endpoint."""
    return _subject_claims(token,audience)


def _attributes(value,now):
    if not isinstance(value,dict)or value.get('enabled')is not True:return False
    for key in('nbf','exp'):
        if key in value:
            stamp=value[key]
            if type(stamp)is not int or(key=='nbf'and stamp>now)or(key=='exp'and stamp<=now):return False
    return True


def collect(reader,transport,scopes,options,credential_context_id,customer_context_id):
    """Append exact native projections after ordinary inventories are collected."""
    if not required_types(options):return
    from .azure import AzureReadError
    from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT
    # Untrusted routing hint only; both exact tokens must subsequently succeed
    # on their native endpoints before any source fact is emitted.
    identity=_subject_claims(transport.token(ARM),ARM)
    if identity is None:return
    source,tenant=identity['oid'],identity['tid']
    # These are scan-generated opaque IDs, never caller-selected credentials.
    if not credential_context_id or not customer_context_id:return
    binding={'credential_context_id':credential_context_id,'customer_context_id':customer_context_id,
             'source_principal_id':source,'tenant_id':tenant,'tenant_verified':True}
    safe_cache={}
    def project(value,url,audience):
        if not isinstance(value,dict):raise ValueError('disclosure response malformed')
        if audience==ARM:
            return {'id':value.get('id'),'type':value.get('type'),'properties':{'certificate':{
                'thumbprint':value.get('properties',{}).get('certificate',{}).get('thumbprint')}}}
        def attrs(row):
            data=row.get('attributes')
            return {k:v for k,v in data.items()if k in('enabled','nbf','exp')}if isinstance(data,dict)else None
        if 'value'in value:
            if not isinstance(value['value'],list)or any(not isinstance(r,dict)for r in value['value']):raise ValueError('disclosure list malformed')
            return {'value':[{'id':r.get('id'),'attributes':attrs(r)}for r in value['value']],
                    **({'nextLink':value['nextLink']}if value.get('nextLink')else{})}
        result={'id':value.get('id'),'sid':value.get('sid'),'x5t':value.get('x5t'),'attributes':attrs(value)}
        if 'policy'in value:
            policy=value['policy']
            result['policy']={'key_props':{'exportable':policy.get('key_props',{}).get('exportable')}}if isinstance(policy,dict)else None
        return result
    def raw(url,*,body=None,audience=ARM):
        # Bypass the raw response cache. AzureTransport records the subject of
        # the exact token only after its native HTTP response succeeds.
        key=(audience,url)
        if key in safe_cache:return safe_cache[key]
        value=transport.request(url,body=body,audience=audience,capture_subject=True)
        accepted=getattr(transport,'disclosure_accepted_subjects',{}).get(audience)
        if accepted!=identity:raise AzureReadError('disclosure_source_identity_mismatch')
        safe_cache[key]=project(value,url,audience)
        return safe_cache[key]
    def call(url,audience=ARM):return reader.call(raw,url,audience=audience)
    emitted=set()
    def append(kind,target,items):
        matches=[c for c in reader.collections if c['type']==kind and c['scope']==target]
        if not matches:
            reader.collections.append({'type':kind,'scope':target,'service':'AzureDisclosure','status':'collected','items':items})
        elif len(matches)==1 and matches[0].get('service')=='AzureDisclosure':
            for item in items:
                if not any(old.get('id')==item.get('id') for old in matches[0]['items'])or 'id'not in item:matches[0]['items'].append(item)
    for scope in scopes:
        rows=_complete(reader,'resource_graph',scope)
        if rows is None:continue
        selected=[r for r in rows if str(r.get('type','')).casefold()in('microsoft.servicefabric/clusters','microsoft.keyvault/vaults')]
        ids=[r.get('id')for r in selected]
        if any(not isinstance(i,str)or not i.casefold().startswith(scope.casefold()+'/')for i in ids)or len(set(i.casefold()for i in ids))!=len(ids):continue
        clusters=[r for r in selected if r['type'].casefold()=='microsoft.servicefabric/clusters']
        vaults=[r for r in selected if r['type'].casefold()=='microsoft.keyvault/vaults']
        for cluster in clusters:
            try:
                cluster_id=cluster['id'];detail=call(ARM+cluster_id+'?api-version=2021-06-01')
                thumb=detail.get('properties',{}).get('certificate',{}).get('thumbprint')
                if (detail.get('id','').casefold()!=cluster_id.casefold()or str(detail.get('type','')).casefold()!='microsoft.servicefabric/clusters'
                        or not isinstance(thumb,str)or not re.fullmatch(r'[0-9a-fA-F]{40}',thumb)):continue
                for vault in vaults:
                    vault_id=vault['id'];props=vault.get('properties',{});origin=props.get('vaultUri','').rstrip('/')
                    if props.get('enableRbacAuthorization')is not True:continue
                    expected='https://'+vault_id.rsplit('/',1)[-1].casefold()+'.vault.azure.net'
                    if origin.casefold()!=expected or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net',origin):continue
                    if hasattr(transport,'allow_vault'):transport.allow_vault(origin)
                    list_url=origin+'/certificates?api-version='+VERSION
                    # Lists contain public certificate metadata, not key material.
                    for page in reader.pages(raw,list_url,audience=VAULT):
                        for listed in page:
                            cid=listed.get('id')if isinstance(listed,dict)else None
                            if not isinstance(cid,str)or not re.fullmatch(re.escape(origin)+r'/certificates/[A-Za-z0-9-]{1,127}',cid):raise ValueError('certificate identity invalid')
                            current=call(cid+'?api-version='+VERSION,VAULT)
                            cert_id=current.get('id')
                            if not isinstance(cert_id,str)or not re.fullmatch(re.escape(cid)+r'/[A-Za-z0-9-]+',cert_id):continue
                            # The current GET can include policy while the exact
                            # version GET omits it. Preserve only a policy bound to
                            # the same observed version, backing secret and thumbprint.
                            resolved=current
                            current=call(cert_id+'?api-version='+VERSION,VAULT)
                            if any(current.get(key)!=resolved.get(key)for key in('id','sid','x5t')):continue
                            sid,x5t=current.get('sid'),current.get('x5t')
                            policy_source=current if 'policy'in current else resolved
                            policy=policy_source.get('policy')
                            if not isinstance(policy,dict)or not isinstance(policy.get('key_props'),dict)or policy['key_props'].get('exportable')is not True:continue
                            if 'policy'in resolved and resolved['policy']!=policy:continue
                            policy_operation='Certificates_Get'if 'policy'in current else'Certificates_GetCurrent'
                            policy_uri=cert_id if 'policy'in current else cid
                            if not isinstance(sid,str)or not re.fullmatch(re.escape(origin)+r'/secrets/[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]+',sid):continue
                            if not isinstance(x5t,str)or not re.fullmatch(r'[A-Za-z0-9_-]{27}=?',x5t):continue
                            decoded=base64.b64decode(x5t.rstrip('=')+'=',altchars=b'-_',validate=True)
                            if decoded.hex()!=thumb.casefold():continue
                            now=datetime.now(timezone.utc)
                            if not _attributes(current.get('attributes'),now.timestamp()):continue
                            name=sid.split('/')[-2];matched=[];seen_versions=set()
                            for version_page in reader.pages(raw,origin+'/secrets/'+name+'/versions?api-version='+VERSION,audience=VAULT):
                                for version in version_page:
                                    vid=version.get('id')if isinstance(version,dict)else None
                                    if (not isinstance(vid,str)or not re.fullmatch(re.escape(origin+'/secrets/'+name)+r'/[A-Za-z0-9-]+',vid)
                                            or vid in seen_versions):raise ValueError('secret version identity invalid')
                                    seen_versions.add(vid)
                                    if vid==sid:matched.append(version)
                            if len(matched)!=1 or not _attributes(matched[0].get('attributes'),now.timestamp()):continue
                            observed=datetime.now(timezone.utc).isoformat();resource=vault_id+'/secrets/'+name
                            if resource.casefold()in emitted:continue
                            evidence='native-disclosure:'+hashlib.sha256((source+resource+sid+credential_context_id).encode()).hexdigest()
                            reference='opaque-certificate:'+uuid4().hex
                            provenance={'source':'azure_native_metadata','read_only':True,'values_omitted':True,'observed_at':observed,'authenticated_response_bound':True,**binding}
                            metadata={'TechniqueId':TECHNIQUE,'ResourceId':resource,'ResourceType':'Microsoft.KeyVault/vaults/secrets',
                              'SecretConfigured':True,'CredentialReferenceId':reference,'CustomerTenantId':tenant,'EvidenceRef':evidence,
                              'CertificateLink':{'ClusterId':cluster_id,'VaultId':vault_id,'SecretVersionId':sid,'CertificateVersionId':cert_id,'CertificateThumbprint':thumb},
                              '_provenance':dict(provenance)}
                            certificate={'id':cert_id,'sid':sid,'x5t':x5t,'parent_id':vault_id,'policy':policy,
                              'attributes':dict(current['attributes']),
                              'policy_binding':{'id':policy_source['id'],'sid':policy_source['sid'],'x5t':policy_source['x5t'],
                                                'policy':policy,'source_operation':policy_operation,'request_uri':policy_uri},
                              '_provenance':{**provenance,'source_operation':'Certificates_Get','request_uri':cert_id,'api_version':VERSION,
                                             'policy_source_operation':policy_operation,'policy_request_uri':policy_uri,'policy_version_id':cert_id}}
                            native_cluster={'id':cluster_id,'cluster_certificate_thumbprint':thumb,
                              '_provenance':{**provenance,'source_operation':'Clusters_Get','request_uri':ARM+cluster_id,'api_version':'2021-06-01'}}
                            secret={'id':sid,'parent_id':vault_id,'attributes':{k:v for k,v in matched[0]['attributes'].items()if k in('enabled','nbf','exp')},
                              '_provenance':{**provenance,'source_operation':'Secrets_ListVersions','request_uri':origin+'/secrets/'+name+'/versions'}}
                            action='Microsoft.KeyVault/vaults/secrets/getSecret/action'
                            fact={'TechniqueId':TECHNIQUE,'SourceId':source,'TargetKind':'azure_verified_authority','TargetId':resource,'TargetScope':resource,
                              'Status':'verified','VerifiedPreconditions':True,'EffectType':'terminal_configuration_disclosure','EvidenceRef':evidence,
                              'VerifiedConditionIds':CONTRACT[TECHNIQUE]['conditions'],'EvidenceObservedAt':observed,
                              'CredentialReferenceId':reference,'CustomerTenantId':tenant,'ActionResources':{action:[resource]},'_provenance':dict(provenance)}
                            if reader.budget.max_items is not None and len(emitted)>=reader.budget.max_items:return
                            emitted.add(resource.casefold())
                            append('azure_disclosure_source_metadata',resource,[metadata]);append('azure_disclosure_certificate_metadata',vault_id,[certificate])
                            append('azure_disclosure_cluster_metadata',cluster_id,[native_cluster]);append('azure_disclosure_secret_version_metadata',vault_id,[secret])
                            append('azure_privesc_challenge_evidence',resource,[fact])
            except Exception:
                # Ordinary inventory remains intact; failed optional proof reads
                # never become an empty/pass or expose provider error material.
                continue

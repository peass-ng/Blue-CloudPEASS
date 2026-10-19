"""Check-bound observations from recorded GCP facts, including legacy limitations.

No status-to-fact inference. Unsupported or unreadable payloads keep their
existing uncertainty and raw evidence; no cloud operation is performed.
"""
from datetime import datetime
import re

_ROLE_VM = {
 'gcp.claude.instance.sa_no_data_destruction_permission':'data-destruction',
 'gcp.claude.instance.sa_no_database_write_permission':'database-write',
 'gcp.claude.instance.sa_no_deployments_manager_permission':'Deployment Manager',
 'gcp.claude.instance.sa_no_disrupt_logging_permission':'logging-change',
 'gcp.claude.instance.sa_no_iam_write_permission':'IAM-write',
 'gcp.claude.instance.sa_no_service_account_impersonate_permission':'service-account impersonation',
 'gcp.claude.instance.sa_no_deny_policy_write_permission':'deny-policy write',
}
_PUBLIC_BINDINGS = {
 'gcp.storage.no_public_iam':('public_bindings','Bucket policy'),
 'gcp.ports.storage_bucket_not_publicly_accessible':('public_bindings','Bucket policy'),
 'gcp.ports.cloudfunction_function_restrict_public_access':('public_bindings','Function policy'),
 'gcp.ports.function_active_public_binding':('public_bindings','Function policy'),
 'gcp.ports.cloudrun_service_restrict_public_access':('public_bindings','Cloud Run policy'),
 'gcp.ports.cloud_run_service_policy_prohibit_public_access':('public_principal_declarations','Cloud Run policy'),
}
_FUNCTION_ROLES={
 'gcp.ports.function_logging_mutation_declarations':'logging-change',
 'gcp.ports.function_legacy_deployment_role_declarations':'legacy-deployment',
 'gcp.ports.function_basic_role_declarations':'basic-role',
}

def _text(value):
 return isinstance(value,str) and bool(value) and len(value)<=200 and not any(ord(c)<32 for c in value)

def _strings(value):
 return isinstance(value,list) and all(_text(v) for v in value)

def _roles(rows):
 if not isinstance(rows,list) or any(not isinstance(r,dict) or not _text(r.get('role')) for r in rows):return None
 values=list(dict.fromkeys(r['role'] for r in rows))
 return ', '.join(values[:2])+(' and others' if len(values)>2 else '')

def evidence_summary(finding):
 if not isinstance(finding,dict) or finding.get('provider')!='gcp' or finding.get('status') not in {'PASS','FAIL'}:return None
 cid=finding.get('check_id');e=finding.get('evidence')
 if not isinstance(cid,str) or not isinstance(e,dict):return None
 if cid=='gcp.ports.compute_instance_ip_forwarding_disabled':
  state=e.get('can_ip_forward')
  if type(state)is bool:return 'IP forwarding is '+('enabled.' if state else 'disabled.')
  if e=={'semantics':'IP forwarding configuration only'}:return 'The recorded IP-forwarding assessment omits the forwarding setting.'
 if cid=='gcp.ports.compute_instance_block_project_wide_ssh_enabled':
  state=e.get('block_project_ssh_keys')
  if type(state)is bool:return 'Project-wide SSH keys are '+('blocked.' if state else 'not blocked.')
  if e=={}:return 'The recorded SSH-key assessment omits the project-key blocking setting.'
 if cid=='gcp.ports.bigquery_dataset_not_publicly_accessible':
  principals=e.get('public_acl_principals')
  if _strings(principals) and all(p in {'allUsers','allAuthenticatedUsers'} for p in principals):
   return 'The dataset ACL names public principals: '+', '.join(principals)+'.' if principals else 'The dataset ACL has no allUsers or allAuthenticatedUsers grants.'
  if e=={'semantics':'Dataset public ACL declarations; authorized views and effective permissions are separate'}:return 'The recorded dataset ACL assessment omits the principal grants.'
 if cid=='gcp.ports.sql_private_ip_assignments':
  types=e.get('address_types');public=e.get('public_incoming_types')
  if not _strings(types) or not _strings(public) or any(v not in {'PRIMARY','PRIVATE','OUTGOING','MIGRATED_1ST_GEN'} for v in types):return None
  if public!=[v for v in types if v in {'PRIMARY','MIGRATED_1ST_GEN'}]:return None
  if public:return 'The Cloud SQL address list includes a public incoming IP.'
  if 'PRIVATE'in types:return 'A private incoming IP is declared; no public incoming IP is declared.'
  if 'OUTGOING'in types:return 'No public incoming IP is declared; OUTGOING is an outbound source and does not establish a private incoming endpoint.'
  return 'No incoming IP addresses are declared in the recorded address list.'
 if cid in _ROLE_VM:
  rows=e.get('matching_bindings');roles=_roles(rows)
  if roles is None or not _strings(e.get('service_accounts')):return None
  return 'The VM service account is named in project IAM bindings for '+roles+'.' if rows else 'No project IAM binding matched the '+_ROLE_VM[cid]+' rule for the attached service accounts.'
 if cid in _FUNCTION_ROLES:
  rows=e.get('role_assignment_declarations');roles=_roles(rows)
  if roles is None:return None
  return 'The function identity has declared roles: '+roles+'. Their matching permissions were not stored.' if rows else 'No declared function role matched the '+_FUNCTION_ROLES[cid]+' rule.'
 if cid in _PUBLIC_BINDINGS:
  key,noun=_PUBLIC_BINDINGS[cid];rows=e.get(key);roles=_roles(rows)
  if roles is None:return None
  return noun+' declares public-principal bindings for '+roles+'.' if rows else noun+' has no recorded public-principal bindings.'
 if cid=='gcp.ports.compute_ssl_policy_strict_declaration':
  if e.get('reason')=='No explicit SSL policy; default compatibility does not establish the strict cipher/TLS policy':return 'No explicit SSL policy is configured.'
  if e.get('profile') in {'COMPATIBLE','MODERN','RESTRICTED','CUSTOM'} and e.get('min_tls_version') in {'TLS_1_0','TLS_1_1','TLS_1_2','TLS_1_3'}:return 'The SSL policy declares '+e['profile']+' with minimum '+e['min_tls_version'].replace('_',' ')+'.'
 if cid=='gcp.ports.api_key_meaningful_restrictions':
  services=e.get('restricted_services');caller=e.get('caller_declaration')
  if not _strings(services):return None
  if services:return 'The API key restricts API targets to '+', '.join(services[:2])+'.'
  if not isinstance(caller,dict):return None
  mode=caller.get('restriction_mode');allowed=caller.get('allowed')
  if not _strings(allowed):return None
  if not services and mode=='serverKeyRestrictions' and any(v in {'0.0.0.0/0','::/0'} for v in allowed):return 'The API key has no API-target restriction and declares unrestricted source IPs.'
  if services:return 'The API key restricts API targets to '+', '.join(services[:2])+'.'
  if mode in {'serverKeyRestrictions','browserKeyRestrictions','androidKeyRestrictions','iosKeyRestrictions'}:return 'The API key declares '+str(len(allowed))+' caller restrictions; API targets are unrestricted.'
 if cid=='gcp.claude2.logging.sink_all_log_entries':
  if _strings(e.get('sinks')) and e['sinks'] and e.get('source')in {'project','folder','organization'}:return 'An all-entry log sink is declared at '+e['source']+' scope.'
  if _strings(e.get('sinks')) and _strings(e.get('ancestors')):return 'The recorded sink assessment lists '+str(len(e['sinks']))+' sinks; their effective all-entry coverage was not stored.'
 if cid=='gcp.ports.compute_network_dns_logging_scoped':
  if _text(e.get('network_reference')):return 'The DNS policy names network '+e['network_reference']+'; its matched logging setting was not stored.'
 if cid in {'gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1','gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1'}:
  if e.get('key_type') in {'keySigning','zoneSigning'} and e.get('state') in {'on','off','transfer'}:return 'The '+('key-signing' if e['key_type']=='keySigning' else 'zone-signing')+' algorithm was assessed, but its name was not stored.'
 if cid=='gcp_certificate_validity':
  expiry=e.get('expire_time')
  if e.get('certificate_type') in {'selfManaged','managed'} and _text(expiry):
   try:datetime.fromisoformat(expiry.replace('Z','+00:00'))
   except ValueError:return None
   return 'The '+('self-managed' if e['certificate_type']=='selfManaged' else 'managed')+' certificate expires at '+expiry+'.'
 if cid=='gcp_certificate_renewal_30_days':
  if _text(e.get('certificate')) and type(e.get('threshold_crossed'))is bool:return 'The certificate '+('has crossed' if e['threshold_crossed'] else 'has not crossed')+' the renewal threshold; replacement coverage was not stored.'
 if cid=='gcp_pci_bucket_157fb0c69361':
  grants=e.get('grants')
  if isinstance(grants,list) and grants and all(isinstance(g,(list,tuple)) and len(g)==2 and g[0] in {'bucketAccessControls','defaultObjectAccessControls'} and g[1] in {'allUsers','allAuthenticatedUsers'} for g in grants):return 'Bucket ACL metadata grants access to '+', '.join(sorted({g[1] for g in grants}))+'.'
  if e.get('uniform_bucket_access')is True and type(e.get('inspected_iam_bindings'))is int:return 'Uniform bucket-level access is enabled; '+str(e['inspected_iam_bindings'])+' IAM bindings were inspected.'
 if cid=='gcp.identity.super_admin_recovery_group':
  if _text(e.get('principal')) and e.get('recovery_email')=='':return 'The administrator has no recorded recovery email.'
  if _text(e.get('recovery_email')) and type(e.get('active_member_count'))is int and e['active_member_count']>=0:return 'The administrator recovery group has '+str(e['active_member_count'])+' active members.'
  if _text(e.get('recovery_email')) and e.get('reason')=='missing or non-group recovery address':return 'The recovery address was not resolved to a directory group.'
 if cid in {'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3','gcp_cloud_armor_waf_enabled'}:
  if _text(e.get('policy')):return 'Cloud Armor policy '+e['policy']+' was assessed; the deciding rule settings were not stored.'
 if cid in {'gcp_kms_key_destroy_alert','gcp_logging_enumeration_alert'}:
  name='key-destruction' if cid=='gcp_kms_key_destroy_alert' else 'enumeration'
  if e.get('reason')=='no qualifying enabled alert in complete inventories':return 'No qualifying enabled '+name+' alert was found in the complete inventory.'
  if _text(e.get('metric')) and _text(e.get('alert')):return 'The '+name+' log metric is linked to a configured alert.'
 core=_core_observation(cid,e)
 if core:return core
 from .gcp_success_observed_evidence import evidence_summary as success_summary
 return success_summary(finding)


def _core_observation(cid,e):
 if cid=='gcp.storage.uniform_access' and type(e.get('uniform_bucket_level_access'))is bool:
  return 'Uniform bucket-level access is '+('enabled.' if e['uniform_bucket_level_access'] else 'disabled.')
 if cid=='gcp.storage.public_access_prevention':
  if e.get('configured')=='enforced':return 'Bucket public access prevention is enforced.'
  if e.get('configured')=='inherited' and type(e.get('org_policy_enforced'))is bool:return 'Inherited public access prevention is '+('enforced.' if e['org_policy_enforced'] else 'not enforced.')
 if cid=='gcp.iam.restrict_public_members':
  roles=_roles(e.get('public_bindings'))
  if roles is not None:return 'The project policy declares public-principal grants for '+roles+'.' if roles else 'The project policy has no unconditional public-principal grants.'
 if cid=='gcp.iam.avoid_basic_roles':
  roles=_roles(e.get('broad_bindings'))
  if roles is not None:return 'The project policy declares '+roles+' grants.' if roles else 'The project policy has no owner or editor grants.'
 if cid=='gcp.compute.no_external_ip' and _strings(e.get('external_ips')):
  ips=e['external_ips'];return 'The VM has external IPs: '+', '.join(ips[:2])+'.' if ips else 'No external IP address is assigned to the VM interfaces.'
 if cid=='gcp.compute.restrict_internet_ingress':
  ranges=e.get('source_ranges');allowed=e.get('allowed')
  if _strings(ranges) and isinstance(allowed,list) and all(isinstance(row,dict) and _text(row.get('IPProtocol')) for row in allowed):
   entries=[]
   for row in allowed[:2]:
    ports=row.get('ports',[])
    if not _strings(ports):return None
    entries.append(row['IPProtocol']+('/'+','.join(ports)if ports else ' (all ports)'))
   if entries:return 'The ingress rule allows '+', '.join(entries)+' from '+(', '.join(ranges[:2]) if ranges else 'declared source selectors')+'.'
 if cid=='gcp_pci_kms_key_a3927a5f3b84' and _strings(e.get('effective_principals')):
  p=e['effective_principals']
  if any(v in {'allUsers','allAuthenticatedUsers'} for v in p):return 'The resolved key-use principals include a public identity.'
  return 'The resolved key-use list contains '+str(len(set(p)))+' distinct principals.'
 if cid=='gcp_c5_log_event_fields':
  timestamp,method,principal=e.get('timestamp'),e.get('method'),e.get('principal')
  if _text(timestamp) and _text(method) and isinstance(principal,str):
   try:valid=datetime.fromisoformat(timestamp.replace('Z','+00:00')).tzinfo is not None
   except ValueError:valid=False
   if not valid:return 'The audit record has an invalid timestamp.'
   if not principal.strip():return 'The audit record has no actor identity.'
   if _text(principal):return 'The audit record identifies '+principal+' performing '+method+' at '+timestamp+'.'
 if cid=='gcp_logging_detect_t1110':
  if type(e.get('count'))is int and e['count']>=9 and _text(e.get('principal')) and _text(e.get('caller_ip')):return str(e['count'])+' failed authentication events were recorded for '+e['principal']+' from '+e['caller_ip']+'.'
  interval=e.get('interval')
  if type(e.get('inspected_entries'))is int and e['inspected_entries']>=0 and _strings(interval) and len(interval)==2:return str(e['inspected_entries'])+' audit entries were assessed from '+interval[0]+' to '+interval[1]+'.'
 if cid=='gcp_pci_bucket_56c6b1b7f813':
  source=e.get('source')
  if source in {'known public object-write IAM role','effective IAM','active bucket ACL','active ACL'}:return 'A public bucket-write grant was found in '+source+'.'
  if source in {'IAM; uniform access disables ACLs','IAM and active ACLs'}:return 'The bucket-write assessment used '+source+'; individual grant observations were not stored.'
 return None

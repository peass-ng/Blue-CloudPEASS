"""Plain sentences for reviewed GCP values; never a label/value dump."""
import math
import re


def _text(value):
    return isinstance(value,str) and bool(value) and len(value)<=300 and all(ord(c)>=32 for c in value)


def _list(value):
    return isinstance(value,list) and all(_text(v) for v in value)


def _items(values):
    if len(values)==1:return values[0]
    if len(values)==2:return values[0]+' and '+values[1]
    return ', '.join(values[:-1])+', and '+values[-1] if len(values)<=4 else ', '.join(values[:2])+f' and {len(values)-2} others'


def _sql(e,p):
    flag=p['flag'];key=p['field'];label=p['label']
    if e.get('flag',e.get('field'))!=flag or key not in e or not label:return None
    value=e[key]
    if value is None or value=='':return label+(' are' if flag=='user options' else ' is')+' not explicitly configured.'
    if not _text(value):return None
    lower=value.lower()
    if flag in {'log_statement','log_error_verbosity'}:
        modes={'log_statement':{'none':'SQL statements are not logged by the statement-logging setting.','ddl':'Schema-changing SQL statements are logged.','mod':'Data-changing and schema-changing SQL statements are logged.','all':'All SQL statements are logged.'},'log_error_verbosity':{'default':'Database errors use the standard level of diagnostic detail.','terse':'Database errors use reduced diagnostic detail.','verbose':'Database errors include extended diagnostic detail.'}}
        return modes[flag].get(lower,label+' uses a value whose runtime meaning is not established by this record.')
    if flag in {'log_min_error_statement','log_min_messages'}:
        if lower.startswith('debug'):
            return ('Failed SQL statements' if flag=='log_min_error_statement' else 'Database messages')+' are logged from debug severity upward.'
        if lower in {'info','notice','warning','error','log','fatal','panic'}:
            subject='Failed SQL statements' if flag=='log_min_error_statement' else 'Database messages'
            return subject+' are logged from '+lower+' severity upward.'
        return label+' is numeric rather than a named severity; its runtime meaning is not established.'
    if flag in {'log_min_duration_statement','log_temp_files','user connections','user options'}:
        if not re.fullmatch(r'-?[0-9]+',value):return label+' uses an unrecognized value.'
        n=int(value)
        if flag=='log_min_duration_statement':
            return 'Duration-based statement logging is disabled.' if n==-1 else 'Every statement duration is logged.' if n==0 else f'Statements taking at least {n} milliseconds are logged.'
        if flag=='log_temp_files':
            return 'Temporary-file logging is disabled.' if n==-1 else 'Every temporary file is logged.' if n==0 else f'Temporary files of at least {n} kilobytes are logged.'
        if flag=='user connections':return 'The database has no configured user-connection limit.' if n==0 else f'The database user-connection limit is {n}.'
        return 'Default database session options are explicitly set with a bitmask; the selected options require review.'
    if lower in {'on','true','1'}:return label+' is enabled.'
    if lower in {'off','false','0'}:return label+' is disabled.'
    return label+' uses a value whose runtime meaning is not established by this record.'


def natural_observation(cid,e,spec):
    p=spec.get('prose')
    if not p:return None
    kind=p['kind']
    if kind=='sql':return _sql(e,p)
    key=p.get('field') or spec['observation'][1]
    if key not in e:return None
    value=e[key]
    if kind=='enum':
        if p.get('expected_field') and e.get('field')!=p['expected_field']:return None
        if not isinstance(value,str):return None
        return p['values'].get(value,p['label']+' uses an unrecognized value; its meaning needs review.')
    if kind=='bool':
        if type(value)is not bool:return None
        if cid in ('gcp_workbench_root_disabled','gcp_workbench_terminal_disabled') and value is False and e.get('approved_exception')is True:
            return ('Notebook root access' if cid=='gcp_workbench_root_disabled' else 'Notebook terminal access')+' is enabled under an approved exception.'
        return p['true' if value else 'false']
    if kind=='text':
        return p['missing'] if value is None else p['present'].format(value=value) if _text(value) else None
    if kind=='number':
        if type(value)not in (int,float) or not math.isfinite(value) or value<0:return None
        if value==0:return p['zero']
        text=p['present'].format(value=value)
        if value==1:
            text=text.replace('1 key versions','1 key version').replace('1 internet-facing backends','1 internet-facing backend').replace('1 successful backups','1 successful backup').replace('1 validated restore tests','1 validated restore test')
        return text
    if kind=='list' and _list(value):
        names={'allUsers':'anyone, including anonymous users','allAuthenticatedUsers':'any authenticated Google identity','data_classification':'data classification','softDeletePolicy':'soft-deletion retention','audit.read':'audit-read events','EU':'the European Union','US':'the United States'}
        return p['present'].format(values=_items([names.get(v,v) for v in value])) if value else p['empty']
    return None


_AUDIT_TYPES={'DATA_READ':'data reads','DATA_WRITE':'data writes','ADMIN_READ':'administrative reads'}
_IP_CHECKS={
 'gcp.claude.sql_instance.second_gen_no_public_ip':'ip_address_types',
 'gcp.claude.sql_instance.private_ip_only':'ip_address_types',
 'gcp.claude2.sql_instance.only_private_ip_addresses':'ip_address_types',
 'gcp.ports.sql_instance_with_no_public_ips':'address_types',
 'gcp.ports.sql_instance_not_publicly_accessible':'address_types',
 'gcp.ports.sql_no_primary_address':'address_types',
}
_AUDIT_CHECKS={
 'gcp.iam.data_access_audit':'configured_types',
 'gcp.ports.audit_logging_configured_for_all_service':'configured_log_types',
 'gcp.claude.project.storage_data_access_audit_logs':'declared_log_types',
}

def natural_extra(cid,e):
    if cid=='gcp_c5_access_approval' and _list(e.get('unapproved_access_events')) and e['unapproved_access_events']:
        count=len(e['unapproved_access_events'])
        return 'One provider access event lacks matching prior customer approval.' if count==1 else f'{count} provider access events lack matching prior customer approval.'
    if cid in ('gcp.claude.dns_zone.dnssec_enabled','gcp.ports.dns_managed_zone_dnssec_enabled'):
        value=e.get('dnssec_state',e.get('state'))
        if value in ('on','off','transfer'):return 'DNSSEC signing is '+('enabled.' if value=='on' else 'disabled.' if value=='off' else 'configured for key transfer.')
    if cid=='gcp_sql_trace3625_off' and e.get('trace_flag_3625') in ('on','off'):
        return 'SQL trace flag 3625 '+('reduces diagnostic error detail.' if e['trace_flag_3625']=='on' else 'does not reduce diagnostic error detail.')
    if cid=='gcp.htbp.cloudbuild.pr_trigger_gated' and type(e.get('approval_required'))is bool:
        comment=e.get('comment_control')
        if comment not in ('COMMENTS_ENABLED','COMMENTS_DISABLED','COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY'):return None
        if e['approval_required']:return 'Pull-request builds require approval.'
        if comment=='COMMENTS_ENABLED':return 'Pull-request builds require a /gcbrun comment; separate build approval is not required.'
        if comment=='COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY':return 'External contributors need a /gcbrun comment to trigger builds; separate approval is not required.'
        return 'Pull-request builds require neither a /gcbrun comment nor build approval.'
    if cid=='gcp.reviewed.storage.soft_delete' and type(e.get('retention_seconds'))is int and e['retention_seconds']>=0:
        return 'Soft deletion is disabled for the bucket.' if e['retention_seconds']==0 else f'Deleted objects can be retained for {e["retention_seconds"]/86400:g} days before permanent removal.'
    if cid in ('gcp.claude.dns_zone.ksk_not_rsasha1','gcp.claude.dns_zone.zsk_not_rsasha1') and type(e.get('rsasha1_specs'))is int and e['rsasha1_specs']>=0:
        return 'The DNSSEC '+('key-signing' if e.get('key_type')=='keySigning' else 'zone-signing')+(' configuration does not use SHA-1.' if e['rsasha1_specs']==0 else ' configuration uses the outdated SHA-1 algorithm.')
    if cid=='gcp.ports.iam_api_key_restricts_websites_hosts_apps':
        mode=e.get('restriction_mode');allowed=e.get('allowed')
        names={'serverKeyRestrictions':'source IP addresses','browserKeyRestrictions':'website referrers','androidKeyRestrictions':'Android applications','iosKeyRestrictions':'iOS applications'}
        if isinstance(mode,str) and mode in names and _list(allowed):return 'API-key callers are restricted by '+names[mode]+'.'
    if cid=='gcp.ports.compute_ssl_policy_strict_declaration':
        profile=e.get('profile');tls=e.get('min_tls_version');names={'COMPATIBLE':'compatibility','MODERN':'modern','RESTRICTED':'restricted','CUSTOM':'custom'}
        if isinstance(profile,str) and profile in names and tls in ('TLS_1_0','TLS_1_1','TLS_1_2','TLS_1_3'):
            return 'The SSL policy uses the '+names[profile]+' cipher profile and requires TLS '+tls[-3:].replace('_','.')+' or later.'
    if cid=='gcp_c5_log_isolation' and e.get('sink_count')==0 and type(e.get('sink_count'))is int:return 'No log sinks were present to assess for shared customer-data storage.'
    if cid=='gcp_c5_cloudbuild_gate' and type(e.get('approval_required'))is bool and _text(e.get('security_test_step')):
        return 'The policy '+('requires' if e['approval_required'] else 'does not require')+' build approval and names a security-test step; observed trigger gate settings were not stored.'
    if cid=='gcp_c5_malware_telemetry' and _text(e.get('required_package')):
        return 'The VM is expected to contain malware-agent package '+e['required_package']+'; the installed-package match was not stored.'
    if cid in ('gcp_cloud_armor_cidr_deny','gcp_cloud_armor_rate_limit') and type(e.get('internet_backends'))is int:
        count=e['internet_backends'];noun='backend' if count==1 else 'backends'
        return f'Cloud Armor was assessed for {count} internet-facing {noun}; the deciding '+('source restrictions' if cid=='gcp_cloud_armor_cidr_deny' else 'rate-limit settings')+' were not stored.'
    if cid in _AUDIT_CHECKS:
        value=e.get(_AUDIT_CHECKS[cid])
        if _list(value) and all(v in _AUDIT_TYPES for v in value):
            return 'The audit policy enables logging for '+_items([_AUDIT_TYPES[v] for v in value])+'.' if value else 'The audit policy has no configured data-access log categories.'
    if cid in _IP_CHECKS:
        values=e.get(_IP_CHECKS[cid]);names={'PRIVATE':'private incoming addresses','PRIMARY':'public incoming addresses','MIGRATED_1ST_GEN':'legacy public incoming addresses','OUTGOING':'outbound source addresses'}
        if _list(values) and all(v in names for v in values):
            return 'Cloud SQL declares '+_items([names[v] for v in values])+'.' if values else 'Cloud SQL declares no incoming or outgoing IP addresses.'
    if cid=='gcp.ports.kubernetes_cluster_node_config_image_cos_containerd':
        pools=e.get('node_pools')
        if isinstance(pools,dict) and pools and all(_text(k) and v in ('COS_CONTAINERD','UBUNTU_CONTAINERD') for k,v in pools.items()):
            ubuntu=[k for k,v in pools.items() if v=='UBUNTU_CONTAINERD']
            if ubuntu:return 'Node pools '+_items(ubuntu)+' use Ubuntu with containerd instead of Container-Optimized OS.'
            return 'Every assessed node pool uses Container-Optimized OS with containerd.'
    if cid=='gcp.ports.organization_essential_contacts_complete':
        categories=e.get('configured_categories');names={'ALL':'all notification categories','BILLING':'billing notices','LEGAL':'legal notices','SECURITY':'security notices','SUSPENSION':'suspension notices','TECHNICAL':'technical notices','TECHNICAL_INCIDENTS':'technical incident notices','PRODUCT_UPDATES':'product updates'}
        if _list(categories) and all(v in names for v in categories):
            return 'Essential Contacts subscribe to '+_items([names[v] for v in categories])+'.' if categories else 'No Essential Contact notification subscriptions are recorded.'
    if cid=='gcp.ports.access_approval_explicit_enrollment':
        products=e.get('enrolled_products')
        if _list(products) and products:
            return 'Access Approval explicitly enrolls all products.' if 'all' in products else 'Access Approval explicitly enrolls '+_items(products)+'.'
        if e.get('enrolled_products')==[] or e.get('reason')=='No product is explicitly enrolled with BLOCK_ALL.':return 'No product is explicitly enrolled to require access approval.'
    if cid=='gcp.appengine.version_https_only':
        levels=e.get('handler_levels');names={'SECURE_ALWAYS':'require HTTPS','SECURE_DEFAULT':'use the default transport setting','SECURE_OPTIONAL':'allow HTTP as well as HTTPS','SECURE_NEVER':'use HTTP rather than HTTPS'}
        if _list(levels) and levels and all(v in names for v in levels):
            return 'App Engine handlers '+_items(list(dict.fromkeys(names[v] for v in levels)))+'.'
    if cid=='gcp_autoscaler_capacity_target' and type(e.get('cpu_target'))in (int,float) and math.isfinite(e['cpu_target']) and 0<=e['cpu_target']<=1:
        return f'The autoscaler targets {e["cpu_target"]*100:g}% CPU utilization.'
    if cid in {'gcp.reviewed.kms.rotation_enabled','gcp.reviewed.kms.rotation_90_days','gcp.ports.kms_key_rotated_within_90_day','gcp.claude.kms_key.rotation_100_days','gcp.claude.secret.rotation_90_days'}:
        seconds=e.get('rotation_seconds')
        if isinstance(seconds,str) and re.fullmatch(r'[0-9]+',seconds):seconds=int(seconds)
        if type(seconds)in (int,float) and math.isfinite(seconds) and seconds>0:
            days=seconds/86400
            noun='secret' if cid=='gcp.claude.secret.rotation_90_days' else 'key'
            if days.is_integer():return f'The {noun} is scheduled to rotate every {int(days)} days.'
            whole=int(seconds)
            days,remainder=divmod(whole,86400)
            if seconds==whole and days and remainder:return f'The {noun} is scheduled to rotate every {days} days and {remainder} '+('second.' if remainder==1 else 'seconds.')
            return f'The {noun} is scheduled to rotate every {seconds:,.0f} seconds.'
    return None


def polish_observation(text):
    """Fix grammar and reviewed terminology, without rewriting identifiers."""
    replacements={
        '1 network interfaces':'1 network interface','1 valid lifecycle rules':'1 valid lifecycle rule',
        '1 caller restrictions':'1 caller restriction','1 node pools were':'1 node pool was',
        '1 assets were':'1 asset was','1 service assets are':'1 service asset is',
        '1 severe SCC findings were':'1 severe SCC finding was','1 audit entries were':'1 audit entry was',
        '1 Access Transparency entries':'1 Access Transparency entry',
        '1 matching discovery calls':'1 matching discovery call',
        'The project _Default log sink':'The project’s default log sink',
        'has no valueFrom reference':'has no reference to an external secret value',
        'No environment-variable names matching the credential heuristic were recorded.':'No environment variable with a credential-like name was recorded.',
        'The dataset declares a public READER or WRITER ACL entry.':'The dataset grants public read or write access.',
        'The dataset declares an allUsers READER special-group ACL.':'The dataset grants anyone read access.',
        'No allUsers READER dataset ACL entries were recorded.':'No dataset ACL grants anyone read access.',
        'No allUsers dataset role bindings were recorded.':'No dataset role binding grants access to anyone.',
        'The dataset ACL assigns a role to allUsers.':'The dataset ACL grants a role to anyone, including anonymous callers.',
        'Bucket ACL metadata grants access to allUsers.':'The bucket ACL grants access to anyone, including anonymous callers.',
        'The deployed ACTIVE managed certificate resource':'The deployed active managed certificate',
        'TLS_1_2':'TLS 1.2',
        'TLS_1_3':'TLS 1.3',
    }
    for old,new in replacements.items():text=text.replace(old,new)
    text=text.replace('1 node pool was assessed; their read-only-port settings were','1 node pool was assessed; its read-only-port setting was')
    text=re.sub(r'\b1 matching ([^.]+?) events were recorded',r'1 matching \1 event was recorded',text)
    return text

"""Plain observations from explicit Kubernetes declaration witnesses.

These sentences describe recorded API configuration, never runtime enforcement.
Status alone cannot supply a fact; raw evidence and evaluator criteria stay intact.
"""
from .k8s_finding_clarity_reviewed import ROWS as COMPONENT_ROWS
from .k8s_workload_clarity_reviewed import ROWS as WORKLOAD_ROWS
from .k8s_gc_threshold_source_correction import ROWS as GC_ROWS
from .k8s_ports_components import compare
from .facts import Unavailable

# Each entry names an actual filtered counterexample list emitted by the native
# predicate, plus the precise absence observed when that list is empty.
_LIST_WITNESSES = {
    'privilege_escalation': ('containers_needing_review', 'Evaluated containers explicitly disable privilege escalation.'),
    'readonly_root': ('containers_needing_review', 'Evaluated containers declare read-only root filesystems.'),
    'native_non_root_identity': ('containers_needing_review', 'Evaluated containers declare a non-root identity restriction.'),
    'native_drop_all': ('containers_needing_review', 'Evaluated containers declare all Linux capabilities dropped.'),
    'restricted_caps': ('containers_needing_review', 'Evaluated containers add no capabilities outside the permitted set.'),
    'native_seccomp': ('containers_needing_review', 'Evaluated containers declare a permitted seccomp profile.'),
    'no_privileged': ('containers_needing_review', 'No evaluated container declares privileged mode.'),
    'privileged': ('containers_needing_review', 'No evaluated container declares privileged mode.'),
    'non_root': ('containers_needing_review', 'Evaluated containers explicitly restrict root execution.'),
    'declared_nonroot': ('containers_needing_review', 'Evaluated containers declare non-root execution.'),
    'context_present': ('containers_needing_review', 'Evaluated containers declare a security context.'),
    'no_host_ports_nonzero': ('containers_needing_review', 'No evaluated container declares a nonzero host port.'),
    'no_added_capabilities': ('containers_needing_review', 'Evaluated containers declare no added Linux capabilities.'),
    'drop_all': ('containers_needing_review', 'Evaluated containers declare all Linux capabilities dropped.'),
    'drop_net_raw': ('containers_needing_review', 'Evaluated containers explicitly drop the NET_RAW capability.'),
    'no_sys_admin': ('containers_needing_review', 'No evaluated container adds the SYS_ADMIN capability.'),
    'cpu_limit': ('containers_needing_review', 'Evaluated containers declare CPU limits.'),
    'cpu_request': ('containers_needing_review', 'Evaluated containers declare CPU requests.'),
    'memory_limit': ('containers_needing_review', 'Evaluated containers declare memory limits.'),
    'memory_request': ('containers_needing_review', 'Evaluated containers declare memory requests.'),
    'readiness_probe': ('containers_needing_review', 'Evaluated containers declare readiness probes.'),
    'liveness_probe': ('containers_needing_review', 'Evaluated containers declare liveness probes.'),
    'no_host_ports': ('containers_needing_review', 'No evaluated container declares a nonzero host port.'),
    'pinned_image': ('containers_needing_review', 'Evaluated container images declare a tag or digest instead of an unpinned latest image.'),
    'always_pull': ('containers_needing_review', 'Evaluated containers declare the Always image-pull policy.'),
    'container_runtime_default_seccomp': ('containers_needing_review', 'Evaluated containers explicitly declare RuntimeDefault seccomp.'),
    'content_digest_or_always_pull': ('containers_needing_review', 'Evaluated images use a digest or declare the Always image-pull policy.'),
    'regular_cpu_limit': ('violations', 'Evaluated regular containers declare CPU limits.'),
    'cpu_requests_set': ('violations', 'Evaluated regular containers declare CPU requests.'),
    'memory_limits_set': ('violations', 'Evaluated regular containers declare memory limits.'),
    'memory_requests_set': ('violations', 'Evaluated regular containers declare memory requests.'),
    'liveness_probe_configured': ('violations', 'Evaluated regular containers declare liveness probes.'),
    'readiness_probe_configured': ('violations', 'Evaluated regular containers declare readiness probes.'),
    'no_windows_host_process': ('violations', 'No evaluated regular container declares Windows HostProcess mode.'),
    'capabilities_dropped': ('violations', 'Evaluated regular containers explicitly drop all Linux capabilities.'),
    'no_net_raw_capability': ('violations', 'No evaluated regular container adds NET_RAW.'),
    'no_root_user': ('violations', 'Evaluated regular containers declare a non-root restriction.'),
    'no_secret_env': ('violations', 'No evaluated regular container loads environment variables from Secret references.'),
    'hostpath': ('host_path_volumes', 'The PodSpec declares no hostPath volumes.'),
    'proc_mount': ('unmasked_containers', 'No evaluated container declares an unmasked proc filesystem.'),
    'selinux_identity': ('custom_selinux_identity', 'Evaluated containers declare no custom SELinux user or role override.'),
    'default_subject': ('default_serviceaccount_subjects', 'The binding declares no default ServiceAccount subject.'),
    'wildcard': ('declared_wildcards', 'The role declares no wildcard in the reviewed permission fields.'),
    'sensitive_rbac': ('declared_sensitive_rules', 'The role declares no matching sensitive RBAC capability.'),
    'csr_review': ('declared_csr_approval_rules', 'The role declares no matching CSR approval permission.'),
    'k8s_wildcards': ('wildcard_rules', 'The role declares no wildcard resource or verb.'),
    'k8s_subjects': ('broad_subjects', 'The binding declares no listed broad authentication-group subject.'),
    'no_wildcard_resources_or_verbs': ('wildcard_rules', 'The role declares no wildcard resource or verb.'),
    'dashboard_not_deployed': ('dashboard_containers', 'No evaluated container image or label identifies Kubernetes Dashboard.'),
    'secrets_as_files': ('secret_environment', 'The PodSpec declares no environment variables loaded from Secrets.'),
    'no_privileged_port': ('privileged_ports', 'The PodSpec declares no container port below 1024.'),
    'run_as_user_10000': ('containers', 'Evaluated regular containers explicitly declare UIDs of at least 10000.'),
    'no_tiller_selector': ('tiller_keys', 'The Service selector declares no Tiller-identifying label.'),
    'no_nginx_snippets': ('snippet_annotations', 'The Ingress declares no NGINX snippet annotation.'),
    'no_nginx_snippet_alias': ('snippet_annotations', 'The Ingress snippets declare no alias directive.'),
    'no_nginx_snippet_lua': ('snippet_annotations', 'The Ingress snippets declare no Lua directive.'),
    'no_pod_create': ('matching_rules', 'The role declares no matching Pod-creation permission.'),
    'no_secret_read': ('matching_rules', 'The role declares no matching Secret-read permission.'),
    'no_bind': ('matching_rules', 'The role declares no matching RBAC bind permission.'),
    'impersonation': ('matching_rules', 'The role declares no matching impersonation permission.'),
    'no_pod_interactive_access': ('matching_rules', 'The role declares no matching Pod exec, attach or port-forward permission.'),
    'no_workload_controller_write': ('matching_rules', 'The role declares no matching workload-controller mutation permission.'),
    'no_service_status_write': ('matching_rules', 'The role declares no matching Service-status mutation permission.'),
    'no_human_csr_approval': ('matching_rules', 'The referenced ClusterRole declares no matching CSR-approval permission.'),
    'no_human_node_proxy': ('matching_rules', 'The referenced ClusterRole declares no matching node-proxy permission.'),
    'no_human_pv_create': ('matching_rules', 'The referenced ClusterRole declares no matching persistent-volume creation permission.'),
    'no_human_serviceaccount_token_create': ('matching_rules', 'The referenced ClusterRole declares no matching ServiceAccount-token creation permission.'),
    'no_human_webhook_config_write': ('matching_rules', 'The referenced ClusterRole declares no matching admission-webhook mutation permission.'),
    'service_external_ips': ('external_ips', 'The Service declares no external IP destinations.'),
    'anonymous_binding': ('anonymous_subjects', 'The binding declares no system:anonymous User subject.'),
    'network_default_allow': ('peer_unrestricted_rules', 'No assessed policy rule declares an unrestricted source peer.'),
    'ingress_sni': ('hosts_without_tls_secret', 'Every assessed Ingress rule hostname has a TLS Secret reference.'),
    'service_ftp': ('declared_tcp_ftp_ports', 'The Service declares no TCP port 20 or 21.'),
    'node_public_ip': ('globally_routable_external_ips', 'No recorded Node external address is a globally routable IP.'),
    'pod_public_ip': ('globally_routable_pod_ips', 'No recorded Pod address is a globally routable IP.'),
    'psp_binding_enforced': ('service_accounts_without_psp', 'The assessed ServiceAccounts have a declared legacy PSP-use binding.'),
}
_BOOLEAN_FIELDS = {
    'automount': ('automount_service_account_token', 'automatic ServiceAccount-token mounting'),
    'serviceaccount_automount': ('automount_service_account_token', 'automatic ServiceAccount-token mounting by default'),
    'no_host_network': ('host_network', 'the host network namespace'),
    'host_network': ('hostNetwork', 'the host network namespace'),
    'no_host_ipc': ('hostIPC', 'the host IPC namespace'),
    'no_host_pid': ('hostPID', 'the host PID namespace'),
}
_BOOL_LABELS={'anonymous-auth':'anonymous authentication','peer-client-cert-auth':'peer client-certificate authentication',
 'client-cert-auth':'client-certificate authentication','auto-tls':'automatic TLS generation','peer-auto-tls':'automatic peer TLS generation',
 'profiling':'profiling','use-service-account-credentials':'individual ServiceAccount credentials','kubelet-https':'HTTPS to kubelets',
 'make-iptables-util-chains':'iptables utility-chain management','protect-kernel-defaults':'kernel-default protection',
 'service-account-lookup':'ServiceAccount lookup','rotate-certificates':'client-certificate rotation'}
_PATH_LABELS={'audit-log-path':'an audit-log path','encryption-provider-config':'an encryption-provider configuration path',
 'etcd-cafile':'an etcd CA path','cert-file':'a serving-certificate path','key-file':'a serving private-key path',
 'peer-cert-file':'a peer-certificate path','peer-key-file':'a peer private-key path','etcd-certfile':'an etcd client-certificate path',
 'etcd-keyfile':'an etcd client private-key path','tls-cert-file':'a TLS certificate path','tls-private-key-file':'a TLS private-key path',
 'root-ca-file':'a root CA path','service-account-private-key-file':'a ServiceAccount signing-key path',
 'client-ca-file':'a client CA path','kubelet-client-certificate':'a kubelet client-certificate path',
 'kubelet-client-key':'a kubelet client private-key path','service-account-key-file':'a ServiceAccount verification-key path',
 'kubelet-certificate-authority':'a kubelet CA path','basic-auth-file':'a basic-authentication file',
 'token-auth-file':'a static-token authentication file','hostname-override':'a hostname override','insecure-bind-address':'an insecure bind address'}


def _text(value,max_length=160):
    return value if isinstance(value,str) and 0<len(value)<=max_length and all(ord(c)>=32 for c in value) else None


def _witness_record(predicate,value):
    """Reject opaque/non-native entries before using a filtered witness list."""
    if isinstance(value,str):return bool(_text(value))
    if type(value) is int:return value>=0
    if not isinstance(value,dict) or not value:return False
    if predicate in ('k8s_wildcards','no_wildcard_resources_or_verbs'):
        return any(isinstance(value.get(k),list) and '*' in value[k] for k in ('resources','verbs'))
    if predicate=='wildcard':
        return value.get('field') in ('verbs','resources','apiGroups','nonResourceURLs','resourceNames') and isinstance(value.get('values'),list) and '*' in value['values']
    if predicate in ('k8s_subjects','default_subject','anonymous_binding'):
        return _text(value.get('kind')) is not None and _text(value.get('name')) is not None
    if predicate=='hostpath':return _text(value.get('path')) is not None
    if predicate in ('sensitive_rbac','csr_review','no_pod_create','no_secret_read','no_bind','impersonation','no_pod_interactive_access','no_workload_controller_write','no_service_status_write','no_human_csr_approval','no_human_node_proxy','no_human_pv_create','no_human_serviceaccount_token_create','no_human_webhook_config_write'):
        return all(isinstance(value.get(k),list) and value[k] and all(isinstance(x,str) for x in value[k]) for k in ('apiGroups','resources','verbs'))
    # Structured container counterexamples identify their declaration owner;
    # optional metadata/values are retained raw rather than shown verbatim.
    return _text(value.get('container')) is not None


def _component(finding,binding):
    evidence=finding['evidence'];observations=evidence.get('observations')
    if not isinstance(observations,list) or not observations:return None
    components=binding['component'];components=[components] if isinstance(components,str) else components
    fields=binding['fields'];status=finding['status']
    flagged=evidence.get('containers_needing_review')
    for observed in observations:
        if not isinstance(observed,dict) or observed.get('component') not in components or not _text(observed.get('container')):continue
        settings=observed.get('settings')
        if not isinstance(settings,dict) or any(field not in settings for field in fields):continue
        if any(settings[f] is not None and (not isinstance(settings[f],str) or len(settings[f])>160 or any(ord(c)<32 for c in settings[f])) for f in fields):continue
        flags={f:settings[f] for f in fields if settings[f] is not None}
        try:matches=compare(flags,fields,binding['operation'],set(binding['expected']) if binding['operation']=='subset' else binding['expected'])
        except (Unavailable,ValueError,TypeError):continue
        if matches != (status=='PASS'):continue
        if status=='FAIL' and (not isinstance(flagged,list) or observed['container'] not in flagged):continue
        component=observed['component'];name=observed['container'];value=settings[fields[0]];field=fields[0]
        prefix=f'Container “{name}” declares {component} '
        if all(f in _PATH_LABELS for f in fields):
            labels=' and '.join(_PATH_LABELS[f] for f in fields)
            if binding['operation']=='absent':return prefix+('without ' if value is None else 'with ')+labels+'.'
            missing=[_PATH_LABELS[f] for f in fields if settings[f]=='']
            return prefix+('missing '+' and '.join(missing) if missing else 'with '+labels)+'.'
        if field in _BOOL_LABELS and value in ('true','false'):
            return prefix+'with '+_BOOL_LABELS[field]+(' enabled.' if value=='true' else ' disabled.')
        if field in ('insecure-port','read-only-port','secure-port') and isinstance(value,str) and value.isdigit():
            label={'insecure-port':'the insecure HTTP listener','read-only-port':'the unauthenticated read-only listener','secure-port':'the secure HTTPS listener'}[field]
            return prefix+'with '+label+(' disabled.' if int(value)==0 else f' on port {value}.')
        if field=='audit-log-maxage':return prefix+f'with audit-log retention of {value} days.'
        if field=='audit-log-maxbackup':return prefix+f'with at most {value} rotated audit-log files.'
        if field=='audit-log-maxsize':return prefix+f'with an audit-log rotation size of {value} MB.'
        if field=='terminated-pod-gc-threshold':return prefix+f'with a terminated-Pod garbage-collection threshold of {value} Pods.'
        if field=='event-qps':return prefix+f'with an event rate limit of {value} events per second.'
        if field=='streaming-connection-idle-timeout':return prefix+f'with a streaming connection idle timeout of {value}.'
        if field=='bind-address':return prefix+f'listening on the declared address {value}.'
        if field=='enable-admission-plugins':return prefix+f'with the admission-plugin list “{value}”.'
        if field=='authorization-mode':return prefix+f'with the authorization-mode list “{value}”.'
        if field=='feature-gates':return prefix+f'with the feature-gate declaration “{value}”.'
        if field=='tls-cipher-suites':return prefix+f'with the cipher-suite declaration “{value}”.'
    return None


def _failure_text(row,evidence):
    static=row.get('static_observed_sentence')
    if static:return static
    phrase=row.get('observed_failure_phrase')
    if not isinstance(phrase,str):return None
    if phrase.startswith(('The ','A ','An ')):return phrase.rstrip('.')+'.'
    names=evidence.get('containers_needing_review',evidence.get('privileged_containers'))
    if isinstance(names,list) and names and _text(names[0]):return f'Container “{names[0]}” '+phrase.rstrip('.')+'.'
    return 'The resource '+phrase.rstrip('.')+'.'


def _workload(finding,row):
    e=finding['evidence'];status=finding['status'];predicate=row['reviewed_binding']['predicate']
    if predicate in _LIST_WITNESSES:
        field,success=_LIST_WITNESSES[predicate]
        if predicate=='privileged' and 'privileged_containers' in e:field='privileged_containers'
        if predicate in ('no_host_ports','no_added_capabilities') and 'violations' in e:field='violations'
        values=e.get(field)
        if not isinstance(values,list):return None
        if any(not _witness_record(predicate,v) for v in values):return None
        if status=='PASS' and values==[]:
            if predicate=='dashboard_not_deployed' and e.get('dashboard_labels')!=[]:return None
            return success
        if status=='FAIL' and values:return _failure_text(row,e)
        return None
    if predicate in _BOOLEAN_FIELDS:
        field,label=_BOOLEAN_FIELDS[predicate];value=e.get(field)
        if type(value) is not bool or value != (status=='FAIL'):return None
        return 'The declaration '+('enables ' if value else 'disables ')+label+'.'
    if predicate in ('default_sa','explicit_serviceaccount'):
        field='service_account' if predicate=='default_sa' else 'declared_service_account'
        if field not in e:return None
        value=e[field]
        if value is None or value=='':return 'The PodSpec declares no ServiceAccount name.' if status=='FAIL' else None
        if not _text(value):return None
        if (value=='default') != (status=='FAIL') and predicate=='default_sa':return None
        if status=='PASS':return f'The PodSpec declares ServiceAccount “{value}”.'
        return _failure_text(row,e) if predicate=='default_sa' else None
    if predicate in ('host_namespaces','k8s_host'):
        flags=e.get('host_namespace_flags') if predicate=='k8s_host' else {k:e.get(k) for k in ('hostIPC','hostPID')}
        if not isinstance(flags,dict) or not flags or any(type(v) is not bool for v in flags.values()):return None
        names=[k.replace('host','') for k,v in flags.items() if v]
        if bool(names)!=(status=='FAIL'):return None
        return 'The PodSpec declares shared host '+', '.join(names)+' namespaces.' if names else 'The PodSpec declares no shared host namespaces in the assessed fields.'
    if predicate=='namespace_placement':
        value=e.get('namespace')
        if not _text(value):return None
        if (value=='default') != (status=='FAIL'):return None
        return f'The workload is declared in namespace “{value}”.'
    if predicate in ('service_type','k8s_service'):
        value=e.get('service_type')
        if value not in ('ClusterIP','NodePort','LoadBalancer','ExternalName'):return None
        failed=value in ('NodePort','LoadBalancer') or predicate=='k8s_service' and bool(e.get('external_ips'))
        if failed!=(status=='FAIL'):return None
        return f'The Service declares type {value}.'
    if predicate=='admission':
        value=e.get('enforce_level')
        if value not in ('restricted','baseline','privileged') or (value!='restricted')!=(status=='FAIL'):return None
        return f'The namespace declares the {value} Pod Security enforcement level.'
    if predicate=='quota_existence':
        values=e.get('broad_quotas',e.get('declarations'));field=e.get('field');namespace=e.get('namespace')
        if field is None and 'declarations' in e:
            cid=finding['check_id'];resource='CPU' if '_cpu_' in cid else 'memory';request='request' if cid.endswith('_request') else 'limit'
            noun='LimitRange default '+resource+' '+request if 'limit_range' in cid else 'ResourceQuota '+resource+' '+request
            if not isinstance(values,list) or bool(values)!=(status=='PASS') or not _text(namespace):return None
            return f'Namespace “{namespace}” '+('declares a ' if values else 'has no declared ')+noun+'.'
        labels={'limits.cpu':'CPU limits','requests.cpu':'CPU requests','limits.memory':'memory limits','requests.memory':'memory requests'}
        if not isinstance(values,list) or not isinstance(field,str) or field not in labels or not _text(namespace):return None
        if bool(values)!=(status=='PASS'):return None
        return f'Namespace “{namespace}” '+('declares a namespace-wide quota for ' if values else 'has no declared namespace-wide quota for ')+labels[field]+'.'
    if predicate=='network_default_deny':
        values=e.get('matched_policies');namespace=e.get('namespace')
        if not isinstance(values,list) or any(not _text(v) for v in values) or bool(values)!=(status=='PASS') or not _text(namespace):return None
        direction='egress' if finding['check_id'].endswith('_egress') else 'ingress'
        return f'Namespace “{namespace}” '+('has a declared namespace-wide default-deny ' if values else 'has no declared namespace-wide default-deny ')+direction+' policy.'
    if predicate=='legacy_psp':
        good_by_field={'spec.privileged':False,'spec.hostPID':False,'spec.hostIPC':False,'spec.hostNetwork':False,'spec.allowPrivilegeEscalation':False,'spec.readOnlyRootFilesystem':True,'spec.runAsUser.rule':'MustRunAsNonRoot'}
        labels={'spec.privileged':'privileged containers','spec.hostPID':'host PID sharing','spec.hostIPC':'host IPC sharing','spec.hostNetwork':'host networking','spec.allowPrivilegeEscalation':'privilege escalation','spec.readOnlyRootFilesystem':'read-only root filesystems','spec.runAsUser.rule':'non-root user selection'}
        field=e.get('field');value=e.get('configured')
        if not isinstance(field,str) or field not in good_by_field or type(value) is not type(good_by_field[field]) or (value==good_by_field[field])!=(status=='PASS'):return None
        rendered=('enabled' if value else 'disabled') if type(value) is bool else value
        return 'The legacy PodSecurityPolicy declares '+labels[field]+' '+rendered+'.'
    if predicate=='no_tiller_labels':
        labels=e.get('labels')
        if not isinstance(labels,dict) or any(not isinstance(v,str) for v in labels.values()):return None
        hit=labels.get('app')=='helm' or labels.get('name')=='tiller'
        if hit!=(status=='FAIL'):return None
        return 'The Service labels identify Helm v2 Tiller.' if hit else 'The recorded Service labels do not identify Helm v2 Tiller.'
    if predicate=='api_secure_port':
        ports=e.get('ports')
        if not isinstance(ports,list) or any(not isinstance(r,dict) or type(r.get('port')) is not int for r in ports):return None
        failed=not ports or any(r.get('name')!='https' or r['port'] not in (443,6443) for r in ports)
        if failed!=(status=='FAIL'):return None
        return 'The API EndpointSlice declares '+(', '.join(str(r['port']) for r in ports[:3]) if ports else 'no ports')+'; '+('not every entry is named HTTPS on port 443 or 6443.' if failed else 'each entry is named HTTPS on port 443 or 6443.')
    if predicate=='allowed_host_path_restricted':
        volumes,paths=e.get('volumes'),e.get('allowed_host_paths')
        if not isinstance(volumes,list) or any(not isinstance(v,str) for v in volumes) or not isinstance(paths,list):return None
        failed=bool(set(volumes)&{'hostPath','*'}) and not paths
        if failed!=(status=='FAIL'):return None
        return 'The legacy PSP permits hostPath volumes without an allowed-path list.' if failed else 'The legacy PSP declares allowed host paths or does not permit hostPath volumes.'
    if predicate=='security_services_hardening':
        value=e.get('selinux_rule')
        if value=='MustRunAs' and status=='PASS':return 'The legacy PSP declares SELinux MustRunAs.'
        # Other successful paths depend on AppArmor/seccomp annotations not
        # present in legacy payloads; never infer their state from PASS alone.
        if value=='RunAsAny' and status=='FAIL':return 'The legacy PSP declares SELinux RunAsAny.'
        return None
    if predicate=='default_seccomp_profile':
        if 'default_profile' not in e:return None
        value=e['default_profile']
        if value is not None and not _text(value):return None
        if (value in ('runtime/default','docker/default'))!=(status=='PASS'):return None
        return 'The legacy PSP declares no default seccomp profile.' if value is None else f'The legacy PSP declares default seccomp profile “{value}”.'
    if predicate=='pod_runtime_default_seccomp':
        value=e.get('declared_pod_profile')
        if value not in ('RuntimeDefault','Unconfined','Localhost') or (value=='RuntimeDefault')!=(status=='PASS'):return None
        return f'The PodSpec explicitly declares the {value} seccomp profile.'
    if predicate=='effective_runtime_seccomp':
        if status=='PASS' and e.get('effective_profile')=='RuntimeDefault' and type(e.get('assessed_containers')) is int and e['assessed_containers']>0:
            return 'Evaluated Pod and container declarations select RuntimeDefault seccomp.'
        if status=='FAIL' and isinstance(e.get('non_runtime_default'),list) and e['non_runtime_default']:
            return 'An evaluated container declaration selects a seccomp profile other than RuntimeDefault.'
        return None
    if predicate=='runtime_default_seccomp':
        profile=e.get('pod_profile');profiles=e.get('container_profiles')
        if not isinstance(profiles,list) or any(v is not None and not isinstance(v,str) for v in profiles):return None
        failed=any((v if v is not None else profile)!='RuntimeDefault' for v in profiles)
        if failed!=(status=='FAIL'):return None
        return 'A regular container declaration does not select RuntimeDefault seccomp.' if failed else 'Regular container declarations select RuntimeDefault seccomp, including Pod-level inheritance.'
    if predicate=='replicas_minimum_3':
        value=e.get('replicas')
        if type(value) is not int or (value<3)!=(status=='FAIL'):return None
        return f'The Deployment declares {value} desired replicas.'
    if predicate=='controller_manager_gc_threshold':
        values=e.get('thresholds')
        if not isinstance(values,list) or not values or any(type(v) is not int for v in values):return None
        if any(v in (0,12500) for v in values)!=(status=='FAIL'):return None
        return 'The controller-manager declaration sets terminated-Pod garbage-collection thresholds to '+', '.join(str(v) for v in values[:3])+'.'
    if predicate in ('plugin_deny_service_external_ips','plugin_event_rate_limit'):
        expected='DenyServiceExternalIPs' if predicate=='plugin_deny_service_external_ips' else 'EventRateLimit'
        return _component(finding,{'component':'kube-apiserver','fields':['enable-admission-plugins'],'operation':'contains','expected':expected})
    if predicate=='legacy_sa_token':
        value=e.get('secret_type')
        if not _text(value) or (value=='kubernetes.io/service-account-token')!=(status=='FAIL'):return None
        return f'The Secret metadata declares type “{value}”; no token value was read.'
    if predicate=='secret_deletion':
        if 'deletion_timestamp' not in e:return None
        value=e['deletion_timestamp']
        if value is not None and not _text(value):return None
        if (value is not None)!=(status=='FAIL'):return None
        return f'The Secret metadata records a deletion request at {value}.' if value else 'The Secret metadata records no deletion request.'
    if predicate=='deployment_available':
        desired,available,conditions=e.get('desired_replicas'),e.get('available_replicas'),e.get('available_condition')
        if type(desired) is not int or type(available) is not int or not isinstance(conditions,list):return None
        failed=available<desired or 'True' not in conditions
        if failed!=(status=='FAIL'):return None
        return f'The Deployment status records {available} available replicas for {desired} desired replicas.'
    if predicate=='ingress_tls':
        missing,hosts=e.get('missing_tls_secrets'),e.get('rule_hosts_without_resolved_tls')
        if not isinstance(missing,list) or not isinstance(hosts,list) or bool(missing or hosts)!=(status=='FAIL'):return None
        return 'An Ingress hostname has no resolved same-namespace TLS Secret.' if missing or hosts else 'Assessed Ingress hostnames resolve to same-namespace TLS Secret metadata.'
    if predicate=='nonzero_uid':
        observed=e.get('observed')
        if not isinstance(observed,list) or not observed or any(not isinstance(r,dict) or type(r.get('declared_uid')) is not int for r in observed):return None
        if any(r['declared_uid']==0 for r in observed)!=(status=='FAIL'):return None
        first=next((r for r in observed if r['declared_uid']==0),observed[0]) if status=='FAIL' else observed[0]
        if not _text(first.get('container')):return None
        return f'Container “{first["container"]}” declares UID {first["declared_uid"]}.'
    if predicate=='backend_https':
        if 'declared_backend_protocol' not in e or not isinstance(e.get('resolved_backend_services'),list) or not e['resolved_backend_services']:return None
        value=e['declared_backend_protocol']
        if value is not None and not _text(value):return None
        if (value=='HTTPS')!=(status=='PASS'):return None
        return 'The Ingress declares HTTPS for the resolved backend Services.' if value=='HTTPS' else 'The Ingress has no HTTPS backend-protocol declaration.'
    if predicate=='redirect_https':
        annotations=e.get('observed_redirect_annotations')
        if not isinstance(annotations,dict) or not annotations or any(not isinstance(v,str) for v in annotations.values()):return None
        enabled=any(v=='true' for v in annotations.values())
        if enabled!=(status=='PASS'):return None
        return 'The Ingress explicitly declares HTTPS redirection enabled.' if enabled else 'The Ingress declares HTTPS redirection disabled.'
    if predicate=='no_literal_secret_env':
        values=e.get('literal_credential_env')
        if not isinstance(values,list) or bool(values)!=(status=='FAIL'):return None
        return _failure_text(row,e) if values else 'No evaluated credential-like environment variable declares a nonempty literal value.'
    if predicate in ('world_ingress','world_admin'):
        field='all_source_rules' if predicate=='world_ingress' else 'all_source_tcp_remote_admin_rules'
        values=e.get(field)
        if not isinstance(values,list) or any(type(v) is not int for v in values) or bool(values)!=(status=='FAIL'):return None
        if values:return _failure_text(row,e)
        return 'No assessed ingress rule declares all-source TCP 22 or 3389 access.' if predicate=='world_admin' else 'No assessed ingress rule declares an all-source peer.'
    if predicate=='network_empty_rule':
        values=e.get('unrestricted_rule_indexes');direction=e.get('direction')
        if not isinstance(values,list) or any(type(v) is not int for v in values) or direction not in ('Ingress','Egress') or bool(values)!=(status=='FAIL'):return None
        return f'The policy declares {len(values)} unrestricted {direction.lower()} rules.'
    if predicate=='policy_selector':
        labels,expressions=e.get('selector_label_count'),e.get('selector_expression_count')
        if type(labels) is not int or type(expressions) is not int or (labels+expressions==0)!=(status=='FAIL'):return None
        return 'The NetworkPolicy declares an empty selector covering every Pod in its namespace.' if labels+expressions==0 else f'The NetworkPolicy declares {labels} label selectors and {expressions} selector expressions.'
    if predicate in ('ingress_rules','policy_ingress_rules'):
        field='rule_count' if predicate=='ingress_rules' else 'ingress_rule_count';count=e.get(field)
        if type(count) is not int or (count==0)!=(status=='FAIL'):return None
        noun='Ingress routing' if predicate=='ingress_rules' else 'NetworkPolicy ingress'
        return f'The declaration contains {count} {noun} rules.'
    if predicate=='pull_secret':
        values=e.get('image_pull_secret_names')
        if not isinstance(values,list) or any(not _text(v) for v in values) or bool(values)!=(status=='PASS'):return None
        return f'The PodSpec declares {len(values)} image-pull Secret references.'
    if predicate=='consider_external_secret_storage':
        csi=e.get('secrets_store_csi_declared')
        if e.get('native_secret_reference') is not True or type(csi) is not bool or csi!=(status=='PASS'):return None
        return 'The PodSpec declares a native Secret reference and a Secrets Store CSI volume.' if csi else 'The PodSpec declares native Secret references without a Secrets Store CSI volume.'
    if predicate=='k8s_pod_serviceaccount_has_rbac_binding':
        matched=e.get('matching_serviceaccount_binding');account=e.get('service_account')
        if type(matched) is not bool or matched!=(status=='PASS') or not _text(account):return None
        return f'ServiceAccount “{account}” '+('has a matching declared RBAC binding.' if matched else 'has no matching binding in the complete RBAC inventory.')
    if predicate in ('controller_manager_rotate_kubelet_server_certificate_true','the_service_account_extend_token_expiration_parameter_is_set_to_false'):
        rotation=predicate.startswith('controller_manager_');value=e.get('rotate_kubelet_server_certificate' if rotation else 'extend_serviceaccount_token_expiration')
        if value not in ('true','false') or (value==('true' if rotation else 'false'))!=(status=='PASS'):return None
        return 'The component declares '+('kubelet serving-certificate rotation ' if rotation else 'extended ServiceAccount-token expiration ')+('enabled.' if value=='true' else 'disabled.')
    if predicate.startswith('admission_'):
        labels={'allowprivilegeescalation':'privilege escalation','capabilities_add':'added Linux capabilities','capabilities_add_net_raw':'the NET_RAW capability','capabilities_drop':'capability dropping','container_ports_hostport':'host ports','hostipc':'host IPC sharing','hostnetwork':'host network sharing','hostpath':'hostPath volumes','hostpid':'host PID sharing','privileged':'privileged containers','runasnonroot':'non-root execution','windowsoptions_hostprocess':'Windows HostProcess containers'}
        label=labels.get(predicate.removeprefix('admission_'));names=e.get('covered_namespaces' if status=='PASS' else 'namespaces_without_binding')
        if not label or not isinstance(names,list) or not names or any(not _text(v) for v in names):return None
        if status=='PASS' and e.get('cel_subset')!='literal recognized expression':return None
        return ('A recognized CEL restriction for '+label+' covers namespace ' if status=='PASS' else 'No qualifying Deny binding for '+label+' covers namespace ')+f'“{names[0]}”.'
    if predicate=='masters_binding':
        values=e.get('affected_bindings')
        return 'An RBAC binding explicitly names the system:masters group.' if status=='FAIL' and isinstance(values,list) and values else None
    return None


def _unknown(finding,kind):
    reason=finding['evidence'].get('reason')
    if not _text(reason,300):return None
    noun=kind.replace('_',' ')
    if reason=='native resource is not an object':return f'The collected {noun} record is not a usable object.'
    if reason.startswith(('missing fact: ','malformed fact: ')):
        field=reason.split(': ',1)[1]
        labels={'livenessProbe':'liveness probes','readinessProbe':'readiness probes','hostPort':'host ports','hostProcess':'Windows HostProcess mode','runAsUser':'the container user ID','hostIPC':'host IPC sharing','hostPID':'host PID sharing','containerPort':'container ports','spec.replicas':'desired replicas','externalIPs':'external IP destinations','value_length':'the redacted environment-value length','env':'environment variables','add':'added Linux capabilities','podsecuritypolicy':'legacy PodSecurityPolicies'}
        field=labels.get(field,field.replace('_',' '))
        return f'The {noun} record has no usable declaration for {field}.'
    if reason=='RBAC bindings contain no system:masters subject; certificate and provider group memberships unobserved':
        return 'No system:masters subject was declared; certificate and provider-group memberships were not collected.'
    if reason=='missing or foreign scoped namespace inventory':return 'The namespace inventory is missing or belongs to another scope.'
    if reason=='snapshot cluster identity missing':return 'The snapshot does not identify the Kubernetes cluster needed for this join.'
    messages={
        'malformed resource quantity':'A declared CPU or memory quantity could not be interpreted.',
        'literal env value redacted without a length; re-collect with the current collector':'A redacted environment value has no recorded length, so literal-secret use cannot be assessed.',
        'malformed seccomp profile type':'The declared seccomp profile type could not be interpreted.',
        'malformed labels':'The recorded Kubernetes labels are not a usable key-value map.',
        'annotations were filtered by the collector':'Required annotations were filtered from the collected record.',
        'malformed annotations':'The recorded Kubernetes annotations are not a usable key-value map.',
        'malformed threshold':'The declared garbage-collection threshold is not a usable integer.',
        'one or more ingress peer/port declarations malformed or unresolved':'An ingress peer or port declaration could not be resolved.',
        'malformed container runAsUser declaration':'A container user-ID declaration is not a usable integer.',
        'malformed Ingress annotations':'The recorded Ingress annotations are not a usable key-value map.',
        'fact unavailable or malformed coverage: evidence':'The required resource evidence or its collection-coverage record is missing or malformed.',
        'CEL semantics or binding coverage unresolved':'The admission expression or its namespace-binding coverage could not be resolved.',
    }
    return messages.get(reason)


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='k8s' or finding.get('status') not in ('PASS','FAIL','UNKNOWN','DENIED') or not isinstance(finding.get('evidence'),dict):return None
    cid=finding.get('check_id')
    if not isinstance(cid,str):return None
    row=COMPONENT_ROWS.get(cid) or WORKLOAD_ROWS.get(cid) or GC_ROWS.get(cid)
    if row is None:return None
    if finding['status'] in ('UNKNOWN','DENIED'):
        binding=row.get('reviewed_binding',{})
        return _unknown(finding,binding.get('kind','Kubernetes resource'))
    if cid in COMPONENT_ROWS:return _component(finding,COMPONENT_ROWS[cid]['reviewed_binding'])
    if cid in WORKLOAD_ROWS:return _workload(finding,WORKLOAD_ROWS[cid])
    if cid in GC_ROWS:return _component(finding,{'component':'kube-controller-manager','fields':['terminated-pod-gc-threshold'],'operation':'gt','expected':0})
    return None

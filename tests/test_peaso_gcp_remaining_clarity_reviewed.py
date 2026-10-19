"""Source guards and actual evaluator fixtures for reviewed native GCP prose."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_remaining_clarity_reviewed import ROWS, _digest, description, remediation, severity_review
from peaso.checks.gcp_remaining_finding_summary import evidence_summary

PACK=Path(__file__).resolve().parents[1]/'peaso/rulepacks'
CHECK_BY_ID={c.id:c for c in CHECKS}
# These legacy fixture payloads omit a sufficient deciding observation (or
# retain joined results without the underlying role/permission/protocol values).
# Their raw evidence/verdict remain visible; no inferred summary is supplied.
LEGACY_NO_DECISIVE_OBSERVATION = {'gcp.claude.firewall.public_ingress_common_ports',
 'gcp.claude.instance.sa_no_data_destruction_permission',
 'gcp.claude.instance.sa_no_database_write_permission',
 'gcp.claude.instance.sa_no_deny_policy_write_permission',
 'gcp.claude.instance.sa_no_deployments_manager_permission',
 'gcp.claude.instance.sa_no_disrupt_logging_permission',
 'gcp.claude.instance.sa_no_iam_write_permission',
 'gcp.claude.instance.sa_no_service_account_impersonate_permission',
 'gcp.claude2.logging.sink_all_log_entries',
 'gcp.identity.super_admin_recovery_group',
 'gcp.ports.api_key_meaningful_restrictions',
 'gcp.ports.bigquery_dataset_not_publicly_accessible',
 'gcp.ports.cloud_run_service_policy_prohibit_public_access',
 'gcp.ports.cloudfunction_function_restrict_public_access',
 'gcp.ports.cloudrun_service_restrict_public_access',
 'gcp.ports.compute_instance_block_project_wide_ssh_enabled',
 'gcp.ports.compute_instance_ip_forwarding_disabled',
 'gcp.ports.compute_network_dns_logging_scoped',
 'gcp.ports.compute_ssl_policy_strict_declaration',
 'gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1',
 'gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1',
 'gcp.ports.function_active_public_binding',
 'gcp.ports.function_legacy_deployment_role_declarations',
 'gcp.ports.function_logging_mutation_declarations',
 'gcp.ports.storage_bucket_not_publicly_accessible',
 'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3',
 'gcp_certificate_renewal_30_days',
 'gcp_certificate_validity',
 'gcp_cloud_armor_waf_enabled',
 'gcp_kms_key_destroy_alert',
 'gcp_logging_detect_t1110',
 'gcp_logging_enumeration_alert',
 'gcp_pci_bucket_157fb0c69361',
 'gcp_pci_bucket_56c6b1b7f813'}

VALIDATION_CORRECTIONS={'gcp.claude.kms_key.rotation_100_days','gcp.claude.gke.binary_authorization','gcp.claude.gke.release_channel','gcp.ports.cloudfunction_function_no_ingress_settings_allow_all'}


def _index(groups, scope='projects/p', **metadata):
    return {'context':{'provider':'gcp','scope':scope,'created_at':'2026-10-12T00:00:00Z','metadata':metadata},
            'collections':{kind:[{'type':kind,'scope':scope,'status':'collected' if values else 'empty','items':values}] for kind,values in groups.items()},
            **{kind:[{'type':kind,'scope':scope,'provider':'gcp','data':row} for row in values] for kind,values in groups.items()}}


def _bulk_cases(cid):
    cases={}
    for branch in ['pass','fail']:
        if cid=='gcp_c5_log_event_fields':
            row={'timestamp':'2026-10-01T00:00:00Z' if branch=='pass' else 'bad-date','eventClass':'authenticated_audit','protoPayload':{'methodName':'read','authenticationInfo':{'principalEmail':'user@example.com'}}}
            groups={'log_entry':[row]}
        elif cid=='gcp_c5_sbom':
            row={'name':'repo1'};digest='sha256:abc';uri='uri@'+digest
            groups={'artifact_repository':[row],'artifact_image':[{'repository':'repo1','digest':digest,'uri':uri}],
                    'deployed_image':[{'repository':'repo1','digest':digest}],
                    'sbom_occurrence':[{'resourceUri':uri,'kind':'SBOM_REFERENCE','noteName':'projects/p/notes/sbom'}] if branch=='pass' else []}
        elif cid=='gcp_pci_bucket_56c6b1b7f813':
            row={'name':'bucket','_provenance':{'scope':'projects/p'},'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}},'iamPolicy':{'bindings':[] if branch=='pass' else [{'role':'roles/storage.objectCreator','members':['allUsers']}]}}
            groups={'bucket':[row],'bucket_effective_iam':[{'name':'bucket','_provenance':{'scope':'projects/p'},'resolutionComplete':True,'publicAccess':False,'publicWrite':False}]}
        elif cid=='gcp_pci_kms_key_a3927a5f3b84':
            name='projects/p/locations/global/keyRings/r/cryptoKeys/k';row={'name':name,'_provenance':{'scope':'projects/p'}}
            groups={'kms_key':[row],'kms_effective_use':[{'name':name,'_provenance':{'scope':'projects/p'},'resolutionComplete':True,'principals':['user:a@example.com'] if branch=='pass' else ['user:'+x+'@example.com' for x in 'abcd']}]}
        elif cid=='gcp_logging_detect_t1110':
            from datetime import datetime,timedelta,timezone
            base=datetime(2026,10,12,tzinfo=timezone.utc);events=[]
            for n in range(1 if branch=='pass' else 10):
                events.append({'insertId':f'event-{n}','logName':'projects/p/logs/cloudaudit.googleapis.com%2Factivity','resource':{'labels':{'project_id':'p'}},'timestamp':(base+timedelta(seconds=n*20)).isoformat(),'authenticationEvent':True,'protoPayload':{'methodName':'authentication.login','authenticationInfo':{'principalEmail':'user@example.com'},'status':{'code':7},'requestMetadata':{'callerIp':'192.0.2.4'}}})
            row=events[0];groups={'audit_log':events}
        else:return None
        cases[branch]=row;cases[branch+'_index']=_index(groups)
        if cid=='gcp_logging_detect_t1110':
            cases[branch+'_index']['collections']['audit_log'][0]['audit_coverage']={'complete':True,'all_pages':True,'authentication_events':True,'start':'2026-10-12T00:00:00Z','end':'2026-10-12T01:00:00Z'}
    return cases


@pytest.fixture(scope='module')
def originals():
    descriptions=json.loads((PACK/'check_descriptions.json').read_text())['checks']
    from peaso.checks.gcp_inherited_description_overlay import ROWS as inherited_rows, description as inherited_description
    for cid in inherited_rows:
        if cid in ROWS:descriptions[cid]=inherited_description(cid,descriptions[cid])
    rems={cid:None for cid,row in ROWS.items() if row['remediation_base_sha256']==_digest(None)}
    for path in PACK.glob('remediation*.json'):
        value=json.loads(path.read_text())
        if isinstance(value,dict):
            for cid,row in value.items():
                if cid in ROWS and _digest(row)==ROWS[cid]['remediation_base_sha256']:rems[cid]=row
    assert set(rems)==set(ROWS)
    return descriptions,rems

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_description_preserves_criteria_and_provenance(cid,originals):
    source=originals[0][cid];before=deepcopy(source);actual=description(cid,source)
    assert source==before
    assert 4<=len(actual['description'].split())<=45
    changed={'description'}
    if cid in VALIDATION_CORRECTIONS:
        changed|={'pass_when','fail_when','description_correction'}
        assert actual['description_correction']['base_row_sha256']==_digest(source)
        assert actual['description_correction']['reference'].startswith('https://cloud.google.com/')
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in source.items() if k not in changed}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_remediation_is_short_and_does_not_promote_draft_commands(cid,originals):
    source=originals[1][cid];before=deepcopy(source);actual=remediation(cid,source)
    assert source==before
    assert 1<=len(actual['steps'])<=2
    assert len(actual['summary'].split())<=40
    assert len(actual['caveats'])==1
    changed=set(ROWS[cid]['remediation_fields'])
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in (source or {}).items() if k not in changed}
    if not source or source.get('review_status')!='approved':
        assert actual['review_status']=='approved' and actual['cli']==[] and not actual.get('iac')
    if source is None:
        assert actual['field_binding']['fields'] and actual['references']
        assert all(r['url'].startswith(('https://cloud.google.com/','https://developers.google.com/')) and r['url']!='https://cloud.google.com/docs' for r in actual['references'])

@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('kind,apply',[('description',description),('remediation',remediation)])
def test_stale_source_fails_closed(cid,kind,apply,originals):
    source=deepcopy(originals[kind=='remediation'][cid]) or {}
    source['unreviewed']='drift'
    with pytest.raises(ValueError,match='Reviewed GCP clarity base changed'):apply(cid,source)

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_per_id_kind_predicate_severity_and_real_cases(cid):
    check=CHECK_BY_ID[cid];row=ROWS[cid];f=inspect.unwrap(check.evaluate)
    assert row['reviewed_binding']['kind']==check.kind
    assert row['reviewed_binding']['source_qualname']==f.__qualname__
    assert row['reviewed_binding']['module']==f.__module__
    assert severity_review(cid,check.severity)==row['reviewed_severity']
    with pytest.raises(ValueError):severity_review(cid,'different')
    cases=CASES.get(cid) or _bulk_cases(cid)
    if cases is None:
        if cid=='gcp.storage.uniform_access':
            cases={'pass':{'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}}},'fail':{'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':False}}}}
        elif cid=='gcp.storage.public_access_prevention':
            cases={'pass':{'iamConfiguration':{'publicAccessPrevention':'enforced'}},'fail':{'iamConfiguration':{'publicAccessPrevention':'inherited'}},'fail_index':{'context':{'provider':'gcp','scope':'projects/p'},'collections':{'org_policy_effective':[{'scope':'projects/p','status':'collected'}]},'org_policy_effective':[{'data':{'name':'projects/p/policies/storage.publicAccessPrevention','constraint':'storage.publicAccessPrevention','spec':{'rules':[{'enforce':False}]}}}]}}
        elif cid in ('gcp.iam.avoid_basic_roles','gcp.iam.restrict_public_members'):
            cases={'pass':{'bindings':[]},'fail':{'bindings':[{'role':'roles/editor','members':['allUsers' if cid.endswith('members') else 'user:admin@example.com']}]}}
        elif cid=='gcp.compute.no_external_ip':
            cases={'pass':{'networkInterfaces':[]},'fail':{'networkInterfaces':[{'accessConfigs':[{'natIP':'203.0.113.8'}]}]}}
        elif cid=='gcp.compute.restrict_internet_ingress':
            cases={'pass':{'direction':'INGRESS','sourceRanges':['10.0.0.0/8'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]},'fail':{'direction':'INGRESS','sourceRanges':['0.0.0.0/0'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]}}
    assert cases is not None, 'Missing actual source fixture: '+cid
    for branch in ['pass','fail']:
        if branch=='fail' and cid in {'gcp.claude.backend_bucket.bucket_exists','gcp.claude.instance_group_manager.load_balancer_attached','gcp.claude.logging.project_sink_all_entries','gcp.claude.project.audit_logs_configured','gcp.claude.project.storage_data_access_audit_logs'}:
            status,evidence=check.evaluate(deepcopy(cases['manual']),deepcopy(cases.get('manual_index',{})))
            assert status=='MANUAL'
            assert evidence_summary({'provider':'gcp','status':status,'check_id':cid,'evidence':evidence}) is None
            continue
        actual_branch='unknown' if (cid=='gcp.apikeys.active_service_restrictions' and branch=='pass') or (cid=='gcp.logging.access_transparency_entries' and branch=='fail') else branch
        status,evidence=check.evaluate(deepcopy(cases[actual_branch]),deepcopy(cases.get(actual_branch+'_index',cases.get('index',{}))))
        assert status==('UNKNOWN' if actual_branch=='unknown' else branch.upper()),(cid,branch,status,evidence)
        finding={'provider':'gcp','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        assert bool(evidence_summary(finding))==(status=='FAIL' and cid not in LEGACY_NO_DECISIVE_OBSERVATION)
        if status == 'PASS':
            assert evidence_summary({**finding, 'status':'FAIL'}) is None, 'Positive evidence must not become a failing fact'
        assert finding==before
        if isinstance(evidence,dict):
            def wrong(value):
                if isinstance(value,(dict,list)):
                    return 'not-an-inventory-or-configuration-object'
                return {'wrong_shape':True}
            malformed={key:wrong(value) for key,value in evidence.items()}
            assert evidence_summary({**finding,'status':'FAIL','evidence':malformed}) is None


def test_unknown_unowned_or_malformed_findings_are_not_rewritten():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'gcp','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':'unreviewed','evidence':{}}) is None
    value={'description':'preserve','nested':[]};out=description('unreviewed',value);out['nested'].append(1)
    assert value['nested']==[]


@pytest.mark.parametrize('period,expected', [('0s','UNKNOWN'),('-1s','UNKNOWN'),('0.5s','UNKNOWN'),('1s','PASS'),('8640000s','PASS'),('8640001s','FAIL'),('100d','UNKNOWN'),(None,'FAIL')])
def test_automatic_rotation_nonpositive_is_never_pass(period,expected):
    item={'name':'key','purpose':'ENCRYPT_DECRYPT','primary':{'state':'ENABLED'}}
    if period is not None:item['rotationPeriod']=period
    assert CHECK_BY_ID['gcp.claude.kms_key.rotation_100_days'].evaluate(item,{})[0]==expected


@pytest.mark.parametrize('mode,expected', [('DISABLED','FAIL'),('EVALUATION_MODE_UNSPECIFIED','FAIL'),('PROJECT_SINGLETON_POLICY_ENFORCE','PASS'),('POLICY_BINDINGS','PASS'),('POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE','PASS'),('UNKNOWN_NEW_MODE','UNKNOWN'),('','UNKNOWN'),(True,'UNKNOWN'),(17,'UNKNOWN')])
def test_binary_authorization_recognizes_current_stable_and_beta_modes(mode,expected):
    assert CHECK_BY_ID['gcp.claude.gke.binary_authorization'].evaluate({'binaryAuthorization':{'evaluationMode':mode}}, {})[0]==expected


@pytest.mark.parametrize('enabled,expected',[(True,'PASS'),(False,'FAIL')])
def test_binary_authorization_legacy_boolean_fallback(enabled,expected):
    assert CHECK_BY_ID['gcp.claude.gke.binary_authorization'].evaluate({'binaryAuthorization':{'enabled':enabled}}, {})[0]==expected


@pytest.mark.parametrize('channel,expected', [('RAPID','PASS'),('REGULAR','PASS'),('STABLE','PASS'),('EXTENDED','PASS'),('UNSPECIFIED','FAIL'),('BETA','UNKNOWN'),('regular','UNKNOWN'),('', 'UNKNOWN'),(True,'UNKNOWN')])
def test_release_channel_unknown_enums_never_pass(channel,expected):
    assert CHECK_BY_ID['gcp.claude.gke.release_channel'].evaluate({'releaseChannel':{'channel':channel}}, {})[0]==expected


@pytest.mark.parametrize('setting,expected', [('ALLOW_ALL','FAIL'),('INGRESS_SETTINGS_UNSPECIFIED','FAIL'),('ALLOW_INTERNAL_ONLY','PASS'),('ALLOW_INTERNAL_AND_GCLB','PASS'),('ALLOW_UNKNOWN','UNKNOWN'),('','UNKNOWN'),(True,'UNKNOWN'),(None,'UNKNOWN')])
def test_function_ingress_unknown_or_unspecified_never_looks_restricted(setting,expected):
    item={'serviceConfig':{}}
    if setting is not None:item['serviceConfig']['ingressSettings']=setting
    assert CHECK_BY_ID['gcp.ports.cloudfunction_function_no_ingress_settings_allow_all'].evaluate(item,{})[0]==expected


def test_evidence_summary_uses_observed_ports_without_mutating_evidence():
    finding={'provider':'gcp','check_id':'gcp.compute.restrict_internet_ingress','status':'FAIL','evidence':{'allowed':[{'IPProtocol':'tcp','ports':['443']}], 'source_ranges':['0.0.0.0/0']}}
    before=deepcopy(finding)
    assert evidence_summary(finding)=='The firewall rule declares Internet-wide ingress to TCP/443.'
    assert finding==before
    finding['status']='UNKNOWN'
    assert evidence_summary(finding) is None


def test_omission_sentinel_is_never_presented_as_database_runtime_value():
    finding={'provider':'gcp','check_id':'gcp.ports.reference_sql_pg_min_messages','status':'FAIL','evidence':{'field':'log_min_messages','declared':None,'source_omission_value':'missing','database_version':'POSTGRES_16'}}
    assert evidence_summary(finding)=='The database flag log_min_messages is not explicitly configured.'


def test_secret_environment_values_never_enter_observed_summary():
    finding={'provider':'gcp','check_id':'gcp.htbp.function.secret_env_from_secret_manager','status':'FAIL','evidence':{'literal_credential_variables':['API_KEY'],'unexpected_secret':'DO-NOT-PRINT'}}
    assert 'DO-NOT-PRINT' not in evidence_summary(finding)


def _stable_binding(value):
    if callable(value):return {'callable':value.__qualname__}
    if isinstance(value,dict):return {str(k):_stable_binding(v) for k,v in sorted(value.items())}
    if isinstance(value,(list,tuple)):return [_stable_binding(v) for v in value]
    if isinstance(value,(str,int,float,bool)) or value is None:return value
    return {'type':type(value).__name__}


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_predicate_source_and_every_closed_binding_are_pinned(cid):
    import hashlib
    f=inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    nonlocals=inspect.getclosurevars(f).nonlocals
    predicate=nonlocals.get('function',nonlocals.get('evaluator',f))
    for key in ('EVALUATORS','_EVALUATORS'):
        if key in nonlocals:predicate=nonlocals[key][f.__defaults__[0]]
    binding=ROWS[cid]['reviewed_binding']
    assert binding['closure']==_stable_binding(nonlocals)
    assert binding['predicate_qualname']==predicate.__qualname__
    assert binding['predicate_source_sha256']==hashlib.sha256(inspect.getsource(predicate).encode()).hexdigest()
    assert binding['predicate_bindings']==_stable_binding(inspect.getclosurevars(predicate).nonlocals)


def test_all_current_active_gcp_checks_have_exactly_one_review_owner():
    from peaso.checks.native_only import automated_checks
    from peaso.checks.gcp_firewall_clarity_reviewed import ROWS as firewall
    from peaso.checks.gcp_scalar_clarity_reviewed import ROWS as scalar
    from peaso.checks.finding_clarity_reviewed import ROWS as first
    active={c.id for c in automated_checks(CHECKS) if c.provider=='gcp'}
    groups=[set(ROWS)&active,set(firewall)&active,set(scalar)&active,set(first)&active]
    assert set.union(*groups)==active
    assert sum(map(len,groups))==len(active)
    assert not {'gcp_pci_iam_policy_ca1281da7ab2','gcp_pci_iam_policy_9a8ce875703d','gcp_c5_sbom'}&active


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_fail_status_alone_and_wrong_shape_never_supply_a_fact(cid):
    for evidence in ({},None,[],{'semantics':'Previous result was FAIL'}):
        assert evidence_summary({'provider':'gcp','check_id':cid,'status':'FAIL','evidence':evidence}) is None


def test_private_source_values_are_not_rendered_as_credentials():
    cid='gcp.htbp.function.secret_env_from_secret_manager'
    observation=evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{'literal_credential_variables':['DB_PASSWORD'],'value':'never-print-me'}})
    assert observation and 'never-print-me' not in observation


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_approved_guidance_has_precise_primary_references(cid,originals):
    template=remediation(cid,originals[1][cid])
    assert template['references']
    assert all(r.get('url','').startswith(('https://cloud.google.com/','https://developers.google.com/')) for r in template['references'])

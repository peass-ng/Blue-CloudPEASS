"""Exact ten-ID successor, signed mapping and historical conservation gates."""
from tests.release_successor_history import historical_release as read_historical_release
import hashlib,json
from pathlib import Path
from copy import deepcopy
from peaso.checks import CHECKS,HACKTRICKS,evaluate_check,post_dfaf_aws
from peaso.checks.fixtures import CASES
from peaso.checks.catalog import proposal_provenance_for,requirement_tags_for
from scripts.peaso_compliance_compile import spec_digest

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)

CHECKS = registered_before_bulk(CHECKS)

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/fixtures/post_dfaf_integration'
CONTRACT=json.loads((FIXTURE/'contract.json').read_text())
BASELINE=json.loads((FIXTURE/'conservation.json').read_text())
IDS=set(CONTRACT)
NEXT20={'aws_backup_plan_rule_required_frequency','aws_cis_elbv2_only_tls_listeners'}
APIM='azure_api_management_appinsights_ensure_is_configured_42aac6a'
GCP_AUDIT={'gcp_logging_detect_t1136','gcp_logging_detect_t1546'}
PSC={'gcp.network.private_service_connect_google_apis'}
APIM_EDGES = {
    'pci_4.0_azure|10.2.1.1.3',
    'pci_4.0_azure|10.2.1.2.3',
    'pci_4.0_azure|10.2.1.3',
    'pci_4.0_azure|10.2.1.3.3',
    'pci_4.0_azure|10.2.1.4.3',
    'pci_4.0_azure|10.2.1.5.3',
    'pci_4.0_azure|10.2.1.6.3',
    'pci_4.0_azure|10.2.1.7.3',
    'pci_4.0_azure|10.2.2.3',
    'pci_4.0_azure|10.4.1.1',
    'pci_4.0_azure|10.4.1.1.1',
    'pci_4.0_azure|10.4.2.1',
    'pci_4.0_azure|10.6.3.3',
    'pci_4.0_azure|10.7.1.1',
    'pci_4.0_azure|10.7.2.1',
    'pci_4.0_azure|5.3.4.3',
    'pci_4.0_azure|A1.2.1.3',
    'pci_4.0_azure|A3.3.1.1',
    'pci_4.0_azure|A3.5.1.1',
}
GCP_AUDIT_EDGES = {'mitre_attack_gcp|T1136', 'mitre_attack_gcp|T1546'}
PACK=ROOT/'peaso/rulepacks'

def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def masked(value):
    value=deepcopy(value);value.get('proposal_provenance',{}).pop('source_manifest_sha256',None);return value

NEXT_GROUP_IDS = {'azure.cis.defender_external_attack_surface_monitoring_easm', 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28', 'azure.other.entra_app_secret_age_90', 'aws.pci.secretsmanager.kms_encryption_any', 'aws.nist.rds_cluster_member_enhanced_monitoring', 'azure.gap.monitor_log_profile_retention_365_days', 'azure.cis.app_service_entra_registration_enabled', 'aws_ecs_task_definition_credential_environment_names'}
NEXT_GROUP_EDGES = {'azure-compliance.benchmark.cis_v200|azure-compliance.benchmark.cis_v200_2_3', 'azure-compliance.benchmark.cis_v140|azure-compliance.control.cis_v140_9_5', 'azure-compliance.benchmark.nist_csf_v2|azure-compliance.control.monitor_log_profile_retention_365_days', 'pci_4.0_aws|3.5.1.34', 'azure-compliance.benchmark.cis_v300|azure-compliance.control.cis_v300_9_5', 'pci_4.0_azure|8.3.10.1.1', 'azure-compliance.benchmark.cis_v200|azure-compliance.control.cis_v200_9_5', 'azure-compliance.benchmark.cis_v500|azure-compliance.control.cis_v500_8_1_16', 'cis_3.0_azure|9.5', 'azure-compliance.benchmark.cis_v150|azure-compliance.control.cis_v150_9_5', 'azure-compliance.benchmark.cis_v130|azure-compliance.control.cis_v130_9_5', 'cis_3.0_azure|3.1.15', 'pci_4.0_azure|8.3.5.1', 'cis_2.0_azure|9.5', 'azure-compliance.benchmark.rbi_itf_nbfc_v2017|azure-compliance.control.monitor_log_profile_retention_365_days', 'azure-compliance.benchmark.cis_v300|azure-compliance.control.cis_v300_3_1_15', 'aws-compliance.benchmark.nist_800_171_rev_2|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'aws-compliance.benchmark.fedramp_low_rev_4|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'cis_5.0_azure|8.1.16', 'aws-compliance.benchmark.nist_800_172|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'pci_4.0_aws|8.3.2.53', 'azure-compliance.benchmark.cis_v210|azure-compliance.control.cis_v210_2_1_22', 'aws-compliance.benchmark.fedramp_moderate_rev_4|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'aws_foundational_security_best_practices_aws|ECS.8', 'aws-compliance.benchmark.ffiec|aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled', 'cis_4.0_azure|9.1.16', 'cis_2.1_azure|9.4', 'pci_4.0_azure|8.3.9.1', 'cis_2.1_azure|2.1.22', 'pci_4.0_azure|8.3.7.1', 'cis_6.0_azure|8.1.16', 'pci_4.0_azure|8.6.3.1', 'azure-compliance.benchmark.cis_v210|azure-compliance.control.cis_v210_9_4', 'ccc_azure|CCC.IAM.CN06.AR01', 'azure-compliance.benchmark.cis_v400|azure-compliance.control.cis_v400_9_1_16'}

COHORT=json.loads((FIXTURE/'two_hour_native_cohort.json').read_text())
COHORT_IDS=set(COHORT['ids'])
COHORT_SLICES=set(COHORT['changed_slices'])

def test_exact_ten_registered_without_held_or_duplicate_predicates():
    ordered=[c.id for c in CHECKS]
    assert len(ordered)==len(set(ordered))==3434
    assert set(ordered[-14:])==COHORT_IDS
    ordered=ordered[:-14]
    assert set(ordered[-1:])==PSC
    ordered=ordered[:-1]
    assert set(ordered[-8:])==NEXT_GROUP_IDS
    ordered=ordered[:-8]
    assert ordered[:-15]==BASELINE['old_native_ids']
    assert set(ordered[-15:-5])==IDS
    assert set(ordered[-5:-3])==NEXT20 and ordered[-3]==APIM and set(ordered[-2:])==GCP_AUDIT
    assert set(post_dfaf_aws.READY_IDS)=={cid for cid in IDS if cid.startswith('aws')}
    assert not {'aws_nist_efs_access_point_enforce_root_directory','aws_fedramp_rds_cluster_members_enhanced_monitoring'}&set(ordered)


def test_canonical_specs_all_control_edges_and_pending_counts_conserved():
    requirements=ancestor_json(PACK/'compliance_requirements.json')
    native={c.id:c for c in CHECKS}
    assert all(requirements['by_check'][cid]==tags for cid,tags in BASELINE['old_by_check'].items())
    for cid,contract in CONTRACT.items():
        spec=contract['signed_spec'];check=native[cid];provenance=proposal_provenance_for(cid)
        assert provenance['signed_spec_sha256']==contract['canonical_signed_spec_sha256']==spec_digest(spec)
        assert provenance['signed_category']==spec['category']
        assert (check.provider,check.severity,check.title,check.remediation)==(spec['provider'],spec['severity'],spec['title'],spec['remediation_hint'])
        assert {(t['framework_id'],t['requirement_id']) for t in requirement_tags_for(cid)}=={tuple(e) for e in contract['signed_control_edges']}
        assert HACKTRICKS in check.frameworks
    aliases={'aws_g6_redshift_automatic_version_upgrade','aws.pci.cloudtrail.authentication_events','aws_fedramp_rds_cluster_members_enhanced_monitoring'}
    counts={p:sum(c['provider']==p and c['id'] not in native and c['id'] not in aliases for c in requirements['proposed_checks']) for p in ('aws','azure','gcp','k8s')}
    assert counts=={'aws':201,'azure':320,'gcp':24,'k8s':7}
    assert sum(counts.values())==552


def test_old_native_semantics_descriptions_and_signed_slices_unchanged():
    native=ancestor_json(PACK/'native_catalog.json')['checks']
    assert {c['id']:canonical(masked(c)) for c in native if c['id'] not in IDS|NEXT20|{APIM}|GCP_AUDIT|NEXT_GROUP_IDS|PSC|COHORT_IDS}==BASELINE['old_native_masked_sha256']
    descriptions=ancestor_json(ROOT/'docs/compliance-ledgers/descriptions/implemented-new-checks.json')
    assert len(descriptions)==329
    assert {cid:canonical(value) for cid,value in descriptions.items() if cid not in IDS|NEXT20|{APIM}|GCP_AUDIT|NEXT_GROUP_IDS|PSC|COHORT_IDS}==BASELINE['old_supplemental_sha256']
    manifest=ancestor_json(ROOT/'docs/compliance-ledgers/manifest.json')
    assert {k:v for k,v in manifest['slices'].items() if k not in {'azure-cis','gcp-cis-cft'}|COHORT_SLICES}=={k:v for k,v in BASELINE['old_manifest_slices'].items() if k not in {'azure-cis','gcp-cis-cft'}|COHORT_SLICES}
    assert manifest['slices']['azure-cis']['input_sha256']==BASELINE['old_manifest_slices']['azure-cis']['input_sha256']
    assert manifest['slices']['azure-cis']['requirements_total']==BASELINE['old_manifest_slices']['azure-cis']['requirements_total']
    for cid in IDS:
        assert set(descriptions[cid])=={'description','evaluated','pass_when','fail_when','not_applicable_when','proposed_spec_sha256'}
        assert isinstance(descriptions[cid]['evaluated'],list)


def test_only_exact_successor_derived_requirement_rows_changed():
    pack=ancestor_json(PACK/'compliance_requirements.json')
    rows={f['id']+'|'+r['requirement_id']:r for f in pack['frameworks'] for r in f['requirements']}
    assert len(rows)==22212 and set(rows)==set(BASELINE['old_requirement_sha256'])
    expected={f+'|'+rid for c in CONTRACT.values() for f,rid in c['signed_control_edges']}
    changed={k for k,r in rows.items() if canonical(r)!=BASELINE['old_requirement_sha256'][k]}
    next20_edges={
        'nist_800_53_revision_5_aws|cp_9_a',
        'nist_800_53_revision_5_aws|cp_9_b',
        'aws-compliance.benchmark.cisa_cyber_essentials|aws-compliance.control.elb_application_network_lb_use_ssl_certificate',
    }
    assert changed==expected|next20_edges|APIM_EDGES|GCP_AUDIT_EDGES|NEXT_GROUP_EDGES|{'cis_5.0_gcp|3.9'}|set(COHORT['changed_requirements'])
    before=json.loads((FIXTURE/'derived-row-preimages.json').read_text())
    assert len(before)==24
    for name,old in before.items():
        f,rid=name.split('::',1);new=rows[f+'|'+rid]
        assert canonical(old)==BASELINE['old_requirement_sha256'][f+'|'+rid]
        assert {k for k in old if old[k]!=new[k]}<={'native_checks','pending_checks','runtime_status'}
        assert [cid for cid in new['native_checks'] if cid not in IDS]==old['native_checks']
        assert set(old['pending_checks'])-set(new['pending_checks'])==set(new['native_checks'])&IDS
    for key in next20_edges:
        row=rows[key]
        assert row['pending_checks']==[]
        assert set(row['native_checks'])&NEXT20
        assert row['runtime_status']=='partial'


def test_finalized_central_cases_are_exact_and_decisive():
    expected=json.loads((ROOT/'peaso/checks/central_batch_fixtures.json').read_text())
    assert len(expected)==204 and {cid:CASES[cid] for cid in expected}==expected
    for cid in IDS:
        case=CASES[cid]
        for name,status in [('pass','PASS'),('fail','FAIL'),('missing','UNKNOWN'),('malformed','UNKNOWN')]:
            subject=deepcopy(case[name]);index=deepcopy(case.get(name+'_index',case.get('index',{})))
            before=deepcopy((subject,index))
            assert evaluate_check(cid,subject,index)[0]==status,(cid,name)
            assert (subject,index)==before


def test_pending_remediation_does_not_promote_approval():
    for provider in ('aws','azure'):
        rows=json.loads((PACK/f'remediation_compliance_batch_remaining_{provider}.json').read_text())
        for cid in IDS:
            if CONTRACT[cid]['provider']==provider:
                assert rows[cid]['review_status']=='source_bound_pending_review'
                assert rows[cid]['summary']==CONTRACT[cid]['signed_spec']['remediation_hint']
                assert rows[cid]['proposed_spec_sha256']==CONTRACT[cid]['canonical_signed_spec_sha256']


def test_collector_engine_frontend_and_all_privesc_bytes_preserved():
    pins=BASELINE['protected_sha256']
    successor=json.loads((FIXTURE/'live_validation_source_changes.json').read_text())
    history=json.loads((FIXTURE/'gcp_history_source_changes.json').read_text())
    assert history['baseline_source_version']=='7d60a2384e5d1ec0b18213af2dae8f078ef095553e9a938c324ae4af45a4530e'
    published=read_historical_release(ROOT / ('infra/aws/build/peaso-source-'+history['baseline_source_version']+'.zip'))
    psc=json.loads((FIXTURE/'psc_native_source_changes.json').read_text())
    assert psc['baseline_source_version']=='e022caf8ffd81b18571939a12313dfd9afa60c8f2095239cf3ad25e3002a31b7'
    psc_published=read_historical_release(ROOT / ('infra/aws/build/peaso-source-'+psc['baseline_source_version']+'.zip'))
    psc=psc['changes']
    for name,entry in psc.items():
        assert entry['baseline_sha256']==psc_published['files'].get(name)
        assert entry['reason']
        assert ancestor_sha(ROOT/name)==COHORT['source_changes'].get(name,entry)['sha256']
    history=history['changes']
    assert set(history)=={'peaso/collectors/gcp.py','peaso/collectors/gcp_compliance_wave.py',
                          'peaso/collectors/gcp_history.py','peaso/server/validation.py'}
    for name,entry in history.items():
        assert entry['baseline_sha256']==published['files'].get(name)
        assert entry['reason']
        assert psc_published['files'][name]==entry['sha256']
    assert set(successor)=={'frontend/src/ui.tsx','frontend/tests/privesc.spec.ts',
                            'peaso/collectors/azure.py','peaso/collectors/gcp.py','peaso/engine.py'}
    for name,entry in successor.items():
        assert entry['baseline_sha256']==pins[name]
        assert entry['reason']
        assert published['files'][name]==entry['sha256']
    assert sum(n.startswith('peaso/privesc/') for n in pins)==264
    historical=read_historical_release(ROOT / 'infra/aws/build/peaso-source-649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646.zip')
    assert read_historical_release(ROOT / 'infra/aws/build/peaso-source-bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9.zip')['source_version']=='bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9'
    assert historical['source_version']=='649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646'
    assert historical['files']['peaso/collectors/aws.py']=='b51790834366b7758133db1e3af84348d618662b4ede98c395d8d72fd1ca0215'
    evolved={'peaso/collectors/aws.py','peaso/collectors/azure.py','peaso/collectors/gcp.py','peaso/collectors/aws_facts_compute_edge.py'} | set(successor) | set(history) | set(psc) | set(COHORT["source_changes"])
    assert {n:ancestor_sha(ROOT/n) for n in pins if n not in evolved}=={n:v for n,v in pins.items() if n not in evolved}
    assert historical['files']['peaso/collectors/aws_facts_compute_edge.py']==pins['peaso/collectors/aws_facts_compute_edge.py']
    assert ancestor_sha(ROOT/'peaso/collectors/aws_facts_compute_edge.py')=='7457cb0db2aabf2a01a6ac18fed0a0a9cebf587f8bf86bdf863fe1b277379782'
    assert historical['files']['peaso/collectors/azure.py']==pins['peaso/collectors/azure.py']
    assert ancestor_sha(ROOT/'peaso/collectors/azure.py')==COHORT['source_changes']['peaso/collectors/azure.py']['sha256']
    assert historical['files']['peaso/collectors/gcp.py']==pins['peaso/collectors/gcp.py']
    assert ancestor_sha(ROOT/'peaso/collectors/aws.py')==COHORT['source_changes']['peaso/collectors/aws.py']['sha256']


def test_measured_guard_roster_and_byte_budgets_are_exact():
    from scripts import peaso_deploy_artifact_update as guard
    assert (guard.MAX_SOURCE_MEMBERS,guard.MAX_SOURCE_MEMBER_BYTES,guard.MAX_SOURCE_UNCOMPRESSED_BYTES,guard.MAX_SOURCE_ARCHIVE_BYTES)==(1866,40_000_000,250_000_000,32_000_000)
    assert (guard.MAX_API_MEMBERS,guard.MAX_API_MEMBER_BYTES,guard.MAX_API_UNCOMPRESSED_BYTES,guard.MAX_API_ARCHIVE_BYTES)==(4600,40_000_000,240_000_000,55_000_000)
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    old=guard.APPROVED_BATCH_RUNTIME_ADDITIONS
    historical=guard.APPROVED_POST_DFAF_RUNTIME_ADDITIONS
    current=guard.APPROVED_NEXT20_RUNTIME_ADDITIONS
    assert len(old)==35 and len(historical)==38 and len(current)==39
    assert guard.approved_runtime_additions(old) and guard.approved_runtime_additions(historical) and guard.approved_runtime_additions(current)
    for exact in (old,historical,current):
        first=next(iter(exact))
        assert not guard.approved_runtime_additions({k:v for k,v in exact.items() if k!=first})
        assert not guard.approved_runtime_additions({**exact,first:'0'*64})
        assert not guard.approved_runtime_additions({**exact,'peaso/checks/extra_unreviewed.py':'0'*64})

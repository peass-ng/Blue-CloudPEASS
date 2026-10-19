"""Replay every active K8s predicate, keeping declarations distinct from runtime."""
from copy import deepcopy
from collections import Counter
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.native_only import automated_checks
from peaso.finding_observation import evidence_summary

CHECK_BY_ID={c.id:c for c in automated_checks(CHECKS) if c.provider=='k8s'}

# Eleven small supplemental fixtures already accepted by the workload review;
# all other cases use the existing registry fixture authority without copies.
def cases_for(check_id,check):
    cases = CASES.get(check_id)
    if cases is None:
        if check_id in ("k8s.rbac.no_wildcards", "k8s.rbac.role_no_wildcards"):
            cases = {"pass": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
                     "fail": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]}}
        elif check_id in ("k8s.rbac.review_broad_subjects", "k8s.rbac.review_namespaced_subjects"):
            cases = {"pass": {"roleRef": {"name": "view"}, "subjects": [{"kind": "User", "name": "alice"}]},
                     "fail": {"roleRef": {"name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}}
        elif check_id == "k8s.pod.no_privileged_containers":
            cases = {"pass": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}},
                     "fail": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}}
        elif check_id == "k8s.pod.no_host_namespaces":
            cases = {"pass": {"spec": {"hostNetwork": False}}, "fail": {"spec": {"hostNetwork": True}}}
        elif check_id == "k8s.service.review_public_type":
            cases = {"pass": {"spec": {"type": "ClusterIP"}}, "fail": {"spec": {"type": "NodePort"}}}
        elif check_id in {"k8s_ingress_ingress_has_any_associated_ingress_93579100f9",
                          "k8s_networkpolicy_has_ingress_rules",
                          "k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c",
                          "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543"}:
            from peaso.collectors.k8s import _native
            good_spec, bad_spec = ({"rules": [{}]}, {"rules": []}) if check.kind == "ingress" else (
                ({"imagePullSecrets": [{"name": "registry"}], "containers": [{"name": "app"}]},
                 {"imagePullSecrets": [], "containers": [{"name": "app"}]}) if check.kind == "pod" else
                ({"podSelector": {"matchLabels": {"app": "web"}}}, {"podSelector": {}}) if "podselectors" in check_id else
                ({"ingress": [{}]}, {"ingress": []}))
            cases = {}
            for branch, spec in [("pass", good_spec), ("fail", bad_spec)]:
                row = _native({"kind": {"pod": "Pod", "networkpolicy": "NetworkPolicy", "ingress": "Ingress"}[check.kind], "metadata": {"name": "target", "uid": "target-uid", "namespace": "apps"}, "spec": spec}, check.kind, "fixture", "*", True)
                index = {"context": {"provider": "k8s", "scope": "*", "metadata": {"cluster_id": "fixture"}},
                         "collections": {check.kind: [{"type": check.kind, "scope": "*", "status": "collected", "items": [row]}]},
                         check.kind: [{"type": check.kind, "scope": "*", "provider": "k8s", "data": row}]}
                cases[branch], cases[branch + "_index"] = row, index
        else:
            pytest.fail("Missing reviewed actual predicate fixture: " + check_id)
    return cases


@pytest.fixture(scope="module")
def actual_observations():
    rows=[]
    for cid,check in CHECK_BY_ID.items():
        cases=cases_for(cid,check)
        for branch in ('pass','fail','unknown','malformed'):
            if branch not in cases:continue
            status,evidence=check.evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
            rows.append({'provider':'k8s','check_id':cid,'status':status,'evidence':evidence,'fixture_state':branch})
    return rows


def test_all_927_controls_have_actual_supported_observations(actual_observations):
    assert len(CHECK_BY_ID)==927
    counts=Counter()
    for finding in actual_observations:
        before=deepcopy(finding)
        summary=evidence_summary(finding)
        assert isinstance(summary,str) and summary, finding
        assert '\n' not in summary and len(summary)<600
        assert finding==before
        counts[finding['status']]+=1
    assert counts['PASS']==926 and counts['FAIL']==927
    # Other native test modules may install additional valid UNKNOWN fixtures.
    assert counts['UNKNOWN']>=920 and set(counts)=={'PASS','FAIL','UNKNOWN'}


@pytest.mark.parametrize('cid',sorted(CHECK_BY_ID))
def test_empty_and_badly_shaped_payloads_never_supply_facts(cid):
    for status in ('PASS','FAIL','UNKNOWN'):
        assert evidence_summary({'provider':'k8s','check_id':cid,'status':status,'evidence':{}}) is None
    for bad in (None,False,0,'broken',[],[{}]):
        assert evidence_summary({'provider':'k8s','check_id':cid,'status':'FAIL','evidence':bad}) is None


def test_every_present_field_rejects_malformed_containers_without_exceptions(actual_observations):
    for finding in actual_observations:
        if finding['status'] not in ('PASS','FAIL'):continue
        malformed={**finding,'evidence':{key:([None] if isinstance(value,dict) else {}) for key,value in finding['evidence'].items()}}
        assert evidence_summary(malformed) is None, malformed


def test_opposite_status_cannot_invent_opposite_configuration(actual_observations):
    # An observation may remain factual with either status (e.g. a recorded UID),
    # but it must not turn a positive witness into a different negative fact.
    allowed={'k8s.claude.podsecuritypolicy.security_services_hardening'}
    for finding in actual_observations:
        if finding['status'] not in ('PASS','FAIL'):continue
        other={**finding,'status':'FAIL' if finding['status']=='PASS' else 'PASS'}
        summary=evidence_summary(other)
        assert summary is None or summary==evidence_summary(finding) or finding['check_id'] in allowed,(finding,summary)


def test_psp_selinux_does_not_infer_absent_apparmor_or_seccomp():
    cid='k8s.claude.podsecuritypolicy.security_services_hardening'
    assert evidence_summary({'provider':'k8s','check_id':cid,'status':'FAIL','evidence':{'selinux_rule':'RunAsAny'}})=='The legacy PSP declares SELinux RunAsAny.'


def test_secret_content_is_never_formatted(actual_observations):
    marker='UNIQUE-PRIVATE-SECRET-VALUE-DO-NOT-RENDER'
    for f in actual_observations:
        if 'secret' not in f['check_id']:continue
        changed={**f,'evidence':{**f['evidence'],'secret_value':marker,'private_key':marker}}
        assert marker not in (evidence_summary(changed) or '')


# Reconstruct the exact approved pre-enrichment bytes without git/network access.
# Hashing ast.dump across Python versions is unsafe: Python3.13 omits empty
# fields by default. Both trees below are parsed/dumped in the SAME interpreter.
@pytest.mark.parametrize("filename,fields,original_source_sha256,added_fragments", [('batch_remaining_k8s.py', ['extend_serviceaccount_token_expiration', 'matching_serviceaccount_binding', 'native_secret_reference', 'rotate_kubelet_server_certificate', 'secrets_store_csi_declared', 'selector_expression_count', 'selector_label_count'], '0f0c92c50a05e92bfd0357767066e4e481c03320c2f582ff10194d8cc25dd578', [', matching_serviceaccount_binding=matched', ', native_secret_reference=True, secrets_store_csi_declared=csi', ", rotate_kubelet_server_certificate=pairs['RotateKubeletServerCertificate']", ', extend_serviceaccount_token_expiration=value', ', selector_label_count=len(labels), selector_expression_count=len(expressions)']), ('compliance_new_sw10.py', ['extend_serviceaccount_token_expiration', 'matching_serviceaccount_binding', 'native_secret_reference', 'rotate_kubelet_server_certificate', 'secrets_store_csi_declared', 'selector_expression_count', 'selector_label_count'], '6dcd76069c450e4d0291229dd3eeff307fe34b7f5c1061cb9a05b028df2fd986', [', matching_serviceaccount_binding=matched', ', native_secret_reference=True, secrets_store_csi_declared=csi', ", rotate_kubelet_server_certificate=pairs['RotateKubeletServerCertificate']", ', extend_serviceaccount_token_expiration=value', ', selector_label_count=len(labels), selector_expression_count=len(expressions)']), ('k8s_ports_cluster.py', ['unrestricted_rule_indexes'], 'c62ae49c74cc9930c2652991d6a9929628175cc97c4938285426791affd7c5ce', [' unrestricted_rule_indexes=[i for i, rule in enumerate(rules) if rule == {}],']), ('compliance_new_k8s_network.py', ['all_source_rules', 'all_source_tcp_remote_admin_rules'], '5afc05fb25ba7ddc1ddd43098dc912c3158ab83b8fde1ce8c6d79a4d3cfce72c', [' all_source_rules=[],', ' all_source_tcp_remote_admin_rules=[],']), ('claude_gcp_k8s_k8s.py', ['literal_credential_env'], '7f589b98b6d488b8ca99cc673381701e91bdac57adf413e0569af12f981f63d2', [', literal_credential_env=[]'])])
def test_native_enrichment_only_adds_explicit_result_evidence(filename,fields,original_source_sha256,added_fragments):
    import ast,hashlib
    from pathlib import Path
    path=Path(__file__).parents[1]/'peaso'/'checks'/filename
    candidate=path.read_text()
    original=candidate
    for fragment in added_fragments:
        assert original.count(fragment)==1,(filename,fragment)
        original=original.replace(fragment,'',1)
    # Original byte hashes are from accepted source787fcfd, not a new baseline.
    assert hashlib.sha256(original.encode()).hexdigest()==original_source_sha256
    tree=ast.parse(candidate)
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='result' and (filename not in ('compliance_new_k8s_network.py','claude_gcp_k8s_k8s.py') or node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value is False):
            node.keywords=[k for k in node.keywords if k.arg not in fields]
    assert ast.dump(tree)==ast.dump(ast.parse(original))


def test_real_incomplete_ingress_inventory_has_specific_unknown_observation():
    cid='k8s_ingress_ingress_has_any_associated_ingress_93579100f9'
    check=CHECK_BY_ID[cid];case=cases_for(cid,check)
    item=deepcopy(case['pass']);index=deepcopy(case.get('pass_index',case.get('index',{})))
    index['collections']['ingress'][0]['status']='partial'
    status,evidence=check.evaluate(item,index)
    assert status=='UNKNOWN'
    assert evidence=={'reason':'incomplete or foreign-scope ingress inventory'}
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    assert evidence_summary(finding)=='The ingress inventory is incomplete or belongs to another scope.'
    assert finding==before

"""Strict snapshot boundaries for the sw01 Azure predicates."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw01 as sw01
from scripts.peaso_compliance_compile import spec_digest


SUB = "00000000-0000-0000-0000-000000000001"
TENANT = "00000000-0000-0000-0000-000000000002"
GROUP = "00000000-0000-0000-0000-000000000003"
WAF = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/policy"
PUB = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.SignalRService/webPubSub/hub"
HDI = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.HDInsight/clusters/cluster"
AADS = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.AAD/domainServices/directory"


@pytest.fixture(scope="module", autouse=True)
def clean_sw01_registration():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw01.IDS]


def index(kind, rows, *, status="collected", scope=None, extras=None, policy=None):
    scope = scope or f"/subscriptions/{SUB}"
    context = {"provider": "azure", "scope": scope}
    if policy is not None:
        context["metadata"] = {"compliance_policy": policy}
    facts = {"context": context,
             "collections": {kind: [{"type": kind, "scope": scope, "status": status, "items": rows}]},
             kind: [{"type": kind, "scope": scope, "data": row} for row in rows]}
    if extras:
        for extra_kind, value in extras.items():
            facts["collections"][extra_kind] = value
    return facts


def waf(custom=None, managed=None):
    return {"id": WAF, "properties": {"customRules": [] if custom is None else custom,
            "managedRules": {"managedRuleSets": [] if managed is None else managed}},
            "_provenance": {"source_operation": "get", "representation": "full", "read_only": True}}


def pub(connections=None, status="collected"):
    return {"id": PUB, "privateEndpointConnections": [] if connections is None else connections,
            "_coverage": {"privateEndpointConnections": {"status": status}}}


def connection(status="Approved"):
    return {"id": PUB + "/privateEndpointConnections/one", "properties": {
        "privateLinkServiceConnectionState": {"status": status},
        "privateEndpoint": {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"}}}


def group():
    return {"id": GROUP, "groupTypes": []}


def group_facts(members, *, membership_status="collected", required=None):
    scope = f"/tenants/{TENANT}"
    policy = {"status": "collected", "tenant_id": TENANT,
              "required_group_ids": [GROUP] if required is None else required}
    extras = {"directory_membership": [{"type": "directory_membership",
        "scope": scope + "/groups/" + GROUP, "status": membership_status, "items": members}]}
    row = group()
    return row, index("directory_group", [row], scope=scope, extras=extras, policy=policy)


def hdinsight(profile=None):
    return {"id": HDI, "properties": {"securityProfile": {"directoryType": "ActiveDirectory",
        "aaddsResourceId": AADS, "domain": "example.test", "ldapsUrls": ["ldaps://example.test:636"]}
        if profile is None else profile},
        "_provenance": {"source_operation": "get", "representation": "full", "read_only": True}}


def hdinsight_facts(row, *, status="collected"):
    facts = index("hdinsight_cluster", [row], status=status)
    facts["context"]["metadata"] = {"compliance_policy": {"status": "collected",
        "subscription_id": SUB, "approvedAaddsResourceIds": [AADS], "requireLdaps": True}}
    return facts


def test_waf_pass_fail_from_complete_get():
    safe = waf(managed=[{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}])
    assert evaluate_check(sw01.WAF_RULES_ID, safe, index("web_application_firewall_policy", [safe]))[0] == "PASS"
    unsafe = waf()
    assert evaluate_check(sw01.WAF_RULES_ID, unsafe, index("web_application_firewall_policy", [unsafe]))[0] == "FAIL"


def test_waf_unknown_incomplete_malformed_missing_and_foreign():
    row = waf()
    assert evaluate_check(sw01.WAF_RULES_ID, row, index("web_application_firewall_policy", [row], status="partial"))[0] == "UNKNOWN"
    malformed = waf(custom="not an array")
    assert evaluate_check(sw01.WAF_RULES_ID, malformed, index("web_application_firewall_policy", [malformed]))[0] == "UNKNOWN"
    missing = waf()
    del missing["_provenance"]
    assert evaluate_check(sw01.WAF_RULES_ID, missing, index("web_application_firewall_policy", [missing]))[0] == "UNKNOWN"
    assert evaluate_check(sw01.WAF_RULES_ID, row, index("web_application_firewall_policy", [row], scope=f"/subscriptions/{TENANT}"))[0] == "UNKNOWN"


def test_web_pubsub_pass_fail_from_complete_child_list():
    approved = pub([connection()])
    assert evaluate_check(sw01.WEB_PUBSUB_ID, approved, index("web_pubsub", [approved]))[0] == "PASS"
    empty = pub(status="empty")
    assert evaluate_check(sw01.WEB_PUBSUB_ID, empty, index("web_pubsub", [empty]))[0] == "FAIL"
    rejected = pub([connection("Rejected")])
    assert evaluate_check(sw01.WEB_PUBSUB_ID, rejected, index("web_pubsub", [rejected]))[0] == "FAIL"


def test_web_pubsub_unknown_incomplete_malformed_missing_and_foreign():
    row = pub([connection()])
    assert evaluate_check(sw01.WEB_PUBSUB_ID, row, index("web_pubsub", [row], status="partial"))[0] == "UNKNOWN"
    malformed = pub([connection("FutureState")])
    assert evaluate_check(sw01.WEB_PUBSUB_ID, malformed, index("web_pubsub", [malformed]))[0] == "UNKNOWN"
    missing = pub()
    del missing["_coverage"]
    assert evaluate_check(sw01.WEB_PUBSUB_ID, missing, index("web_pubsub", [missing]))[0] == "UNKNOWN"
    assert evaluate_check(sw01.WEB_PUBSUB_ID, row, index("web_pubsub", [row], scope=f"/subscriptions/{TENANT}"))[0] == "UNKNOWN"


def test_group_user_pass_fail_and_not_applicable():
    user = {"id": "00000000-0000-0000-0000-000000000004", "@odata.type": "#microsoft.graph.user"}
    row, facts = group_facts([user])
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "PASS"
    row, facts = group_facts([], membership_status="empty")
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "FAIL"
    row, facts = group_facts([], required=[])
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "NOT_APPLICABLE"


def test_group_user_unknown_incomplete_malformed_missing_and_foreign():
    row, facts = group_facts([], membership_status="partial")
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "UNKNOWN"
    row, facts = group_facts([{"id": "00000000-0000-0000-0000-000000000004"}])
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "UNKNOWN"
    row, facts = group_facts([])
    del facts["context"]["metadata"]
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "UNKNOWN"
    row, facts = group_facts([])
    facts["context"]["scope"] = "/tenants/foreign"
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == "UNKNOWN"


def test_hdinsight_pass_fail_and_unknown():
    safe = hdinsight()
    assert evaluate_check(sw01.HDINSIGHT_ID, safe, hdinsight_facts(safe))[0] == "PASS"
    unsafe = hdinsight({"directoryType": "None"})
    assert evaluate_check(sw01.HDINSIGHT_ID, unsafe, hdinsight_facts(unsafe))[0] == "FAIL"
    assert evaluate_check(sw01.HDINSIGHT_ID, safe, hdinsight_facts(safe, status="partial"))[0] == "UNKNOWN"
    malformed = hdinsight({"directoryType": "Future"})
    assert evaluate_check(sw01.HDINSIGHT_ID, malformed, hdinsight_facts(malformed))[0] == "UNKNOWN"
    missing = hdinsight()
    del missing["_provenance"]
    assert evaluate_check(sw01.HDINSIGHT_ID, missing, hdinsight_facts(missing))[0] == "UNKNOWN"
    foreign = hdinsight()
    facts = hdinsight_facts(foreign)
    facts["context"]["scope"] = f"/subscriptions/{TENANT}"
    assert evaluate_check(sw01.HDINSIGHT_ID, foreign, facts)[0] == "UNKNOWN"


def test_signed_metadata_and_duplicate_ids():
    found = [check for check in CHECKS if check.id in sw01.IDS]
    assert len(found) == len(sw01.IDS) == len({check.id for check in found})
    assert {check.id: check.kind for check in found} == {
        sw01.WAF_RULES_ID: "web_application_firewall_policy",
        sw01.WEB_PUBSUB_ID: "web_pubsub", sw01.GROUP_USER_ID: "directory_group",
        sw01.HDINSIGHT_ID: "hdinsight_cluster"}


def test_signed_spec_digests_match_description_supplement():
    root = Path(__file__).resolve().parents[1] / "docs/compliance-ledgers"
    descriptions = json.loads((root / ".work/swarm/sw01-descriptions.json").read_text())
    signed = {}

    def visit(value):
        if isinstance(value, dict):
            for row in value.get("new_checks", []):
                if row.get("id") in sw01.IDS:
                    signed[row["id"]] = row
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for path in root.glob("azure-*.json"):
        visit(json.loads(path.read_text()))
    assert set(signed) == set(sw01.IDS) == set(descriptions)
    assert all(len(row) == 10 for row in signed.values())
    for check_id, row in signed.items():
        assert spec_digest(row) == descriptions[check_id]["proposed_spec_sha256"] == sw01.PROPOSED_SPEC_SHA256[check_id]
        check = next(check for check in CHECKS if check.id == check_id)
        assert (check.provider, check.kind, check.category, check.severity, check.title) == (
            row["provider"], row["resource_kind"], row["category"], row["severity"], row["title"])


@pytest.mark.parametrize('change', ['native', 'scope', 'type', 'empty'])
def test_inventory_authority_must_match_scoped_index(change):
    from copy import deepcopy
    row = waf(managed=[{'ruleSetType': 'OWASP', 'ruleSetVersion': '3.2'}])
    facts = index('web_application_firewall_policy', [row])
    if change == 'native':
        facts['collections']['web_application_firewall_policy'][0]['items'] = [waf()]
    elif change == 'scope':
        facts['web_application_firewall_policy'][0]['scope'] = f'/subscriptions/{TENANT}'
    elif change == 'type':
        facts['web_application_firewall_policy'][0]['type'] = 'hdinsight_cluster'
    else:
        facts['collections']['web_application_firewall_policy'][0]['status'] = 'empty'
    assert evaluate_check(sw01.WAF_RULES_ID, row, facts)[0] == 'UNKNOWN'


@pytest.mark.parametrize('custom,managed', [([{}], []), ([], [{}])])
def test_empty_rule_objects_do_not_prove_waf_rule_presence(custom, managed):
    row = waf(custom=custom, managed=managed)
    assert evaluate_check(sw01.WAF_RULES_ID, row, index('web_application_firewall_policy', [row]))[0] == 'UNKNOWN'


def test_child_coverage_and_member_type_must_be_resolved():
    row = pub([], status='collected')
    assert evaluate_check(sw01.WEB_PUBSUB_ID, row, index('web_pubsub', [row]))[0] == 'UNKNOWN'
    row, facts = group_facts([{'id': GROUP, '@odata.type': '#microsoft.graph.unknownType'}])
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == 'UNKNOWN'
    row, facts = group_facts([], membership_status='collected')
    assert evaluate_check(sw01.GROUP_USER_ID, row, facts)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['aaddsResourceId', 'domain'])
def test_authoritative_missing_hdinsight_directory_fields_fail(field):
    row = hdinsight()
    del row['properties']['securityProfile'][field]
    assert evaluate_check(sw01.HDINSIGHT_ID, row, hdinsight_facts(row))[0] == 'FAIL'


def test_unavailable_hdinsight_profile_is_not_an_authoritative_absence():
    row = hdinsight()
    del row['properties']['securityProfile']
    row['properties']['_coverage'] = {'securityProfile': {'status': 'denied'}}
    assert evaluate_check(sw01.HDINSIGHT_ID, row, hdinsight_facts(row))[0] == 'UNKNOWN'


def test_hdinsight_approved_id_must_identify_domain_services():
    row = hdinsight()
    row['properties']['securityProfile']['aaddsResourceId'] = WAF
    facts = hdinsight_facts(row)
    facts['context']['metadata']['compliance_policy']['approvedAaddsResourceIds'] = [WAF]
    assert evaluate_check(sw01.HDINSIGHT_ID, row, facts)[0] == 'UNKNOWN'


def test_wrong_native_resource_kind_is_unknown():
    row = waf(managed=[{'ruleSetType': 'OWASP', 'ruleSetVersion': '3.2'}])
    row['id'] = HDI
    assert evaluate_check(sw01.WAF_RULES_ID, row, index('web_application_firewall_policy', [row]))[0] == 'UNKNOWN'


def test_reviewer_remediation_candidates_merge_against_real_signed_registry(tmp_path):
    import json
    from pathlib import Path
    from peaso.remediation import _merge_compliance_reviewed
    candidates = json.loads(Path('docs/compliance-ledgers/.work/swarm/swr-azure-remediation.json').read_text())
    selected = {cid: candidates[cid] for cid in sw01.IDS}
    shard = tmp_path / 'remediation_compliance_new_azure_review.json'
    shard.write_text(json.dumps(selected))
    merged = {}
    _merge_compliance_reviewed(merged, ((shard, 'azure'),))
    assert merged == selected
    for cid, entry in selected.items():
        check = next(check for check in CHECKS if check.id == cid)
        binding = entry['field_binding']
        assert binding['evaluator_family'] == 'peaso.checks.compliance_new_sw01'
        assert binding['kind'] == check.kind and binding['target'] == check.target
        assert binding['path'] and entry['summary'] and entry['steps'] and entry['references']
        assert entry['review_status'] == 'source_bound_pending_review' and entry['cli'] == []
        assert all(ref['url'].startswith('https://') for ref in entry['references'])

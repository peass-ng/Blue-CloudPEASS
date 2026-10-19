"""Evidence enrichment must expose predicate facts without changing its verdict."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS}


@pytest.mark.parametrize("cid", [
    "aws.c2b.apigateway.stage_cache_encrypted",
    "aws.c2b.eventbridge.bus_policy_not_public",
    "aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter",
    "aws.gap.cloudtrail.s3_all_buckets_read_data_events",
    "aws.gap.cloudtrail.s3_all_buckets_write_data_events",
    "aws.gap.s3.object_read_events_logged",
    "aws.gap.s3.object_write_events_logged",
    "aws.gap.s3.object_read_write_events_logged",
    "aws.gap.cloudwatch.cis_alarm.network_acl_changes",
    "aws.gap.cloudwatch.metric_alarm.iam_policy_changes",
    "aws.claude_a.cloudtrail.account_has_logging_multi_region_trail",
    "aws.claude_a.iam.custom_policy_no_blocked_kms_actions",
])
def test_real_fail_fixtures_include_decisive_nonsecret_facts(cid):
    case = CASES[cid]
    item, index = deepcopy(case["fail"]), deepcopy(case.get("fail_index", case.get("index", {})))
    before = deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == "FAIL"
    assert (item, index) == before
    if "cloudwatch" in cid:
        assert evidence["filter_probe_events"]
        assert "No logging trail" in evidence["observed"]
        assert evidence["requires_confirmed_sns_notification"] == ("cis_alarm" in cid)
    elif cid == "aws.claude_a.cloudtrail.account_has_logging_multi_region_trail":
        assert evidence["multi_region_logging_trail_found"] is False
        assert "actively logging" in evidence["observed"]
    elif cid == "aws.claude_a.iam.custom_policy_no_blocked_kms_actions":
        assert evidence["matching_actions"] == ["kms:decrypt"]
    elif ".cloudtrail." in cid or ".gap.s3." in cid:
        assert evidence["trail_evaluations"]
        assert all(row["matches_required_configuration"] is False for row in evidence["trail_evaluations"])
        assert "No evaluated trail" in evidence["observed"]
    elif "stage_cache" in cid:
        assert evidence["encrypted_cache_setting_found"] is False
        assert evidence["observed"] == "None of the cached method settings enables encryption."
    elif "eventbridge" in cid:
        assert evidence["public_policy"] is True
    else:
        assert evidence["public_allow_statements"] > 0


def test_cache_evidence_preserves_the_existential_criterion():
    cid = "aws.c2b.apigateway.stage_cache_encrypted"
    item = deepcopy(CASES[cid]["fail"])
    item["methodSettings"]["protected/GET"] = {"cachingEnabled": True, "cacheDataEncrypted": True}
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "PASS"
    assert evidence["encrypted_cache_setting_found"] is True
    assert evidence["observed"] == "At least one cached method setting enables encryption."


def test_unavailable_filter_evidence_never_becomes_a_negative_observation():
    cid = "aws.gap.cloudwatch.cis_alarm.network_acl_changes"
    status, evidence = REGISTRY[cid].evaluate({}, {})
    assert status == "UNKNOWN"
    assert "observed" not in evidence


def test_security_group_evidence_reports_only_actual_matched_ports():
    cid = "aws.claude_a.vpc.sg_no_world_cassandra"
    fixture = CASES[cid]
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["fail"]), deepcopy(fixture.get("fail_index", fixture.get("index", {}))))
    assert status == "FAIL"
    assert evidence["matching_ingress"]
    for match in evidence["matching_ingress"]:
        assert match["protocol"] == "tcp"
        assert match["source_ranges"] and set(match["source_ranges"]) <= {"0.0.0.0/0", "::/0"}
        assert set(match["ports"]) < set(evidence["ports"])


def test_security_group_enrichment_retains_short_circuit_over_later_missing_facts():
    cid = "aws.claude_a.vpc.sg_no_world_ssh"
    fixture = CASES[cid]
    item = deepcopy(fixture["fail"])
    item["IpPermissions"].append({"IpProtocol": "tcp"})
    status, evidence = REGISTRY[cid].evaluate(item, deepcopy(fixture.get("fail_index", fixture.get("index", {}))))
    assert status == "FAIL"
    assert evidence["matching_ingress"][0]["ports"] == [22]


def test_password_evidence_records_only_the_settings_the_predicate_reads():
    cid = "aws.a.iam.password_policy_strong_min_length_14_reuse_24_age_90"
    fixture = CASES[cid]
    index = deepcopy(fixture["index"])
    policy = index["collections"]["iam_password_policy"][0]["items"][0]["PasswordPolicy"]
    policy["PasswordReusePrevention"] = 10
    del policy["MaxPasswordAge"]
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["pass"]), index)
    assert status == "FAIL"
    assert evidence["password_reuse_prevention"] == 10
    assert "maximum_password_age" not in evidence
    policy["RequireSymbols"] = False
    del policy["PasswordReusePrevention"]
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["pass"]), index)
    assert status == "FAIL"
    assert "password_reuse_prevention" not in evidence


def test_endpoint_and_attachment_evidence_does_not_depend_on_verdict_inference():
    for cid, key in [("aws.claude_a.vpc.interface_endpoint_ssm", "endpoint_present"),
                     ("aws.claude_a.iam.custom_policy_attached_to_role", "role_attachment_found")]:
        case = CASES[cid]
        for name, expected in [("pass", True), ("fail", False)]:
            status, evidence = REGISTRY[cid].evaluate(deepcopy(case[name]), deepcopy(case.get(name + "_index", case.get("index", {}))))
            assert status == ("PASS" if expected else "FAIL")
            assert evidence[key] is expected


def test_frontend_scalar_examples_are_exact_native_evaluator_outputs():
    """The browser samples come from predicates, including absent/malformed boundaries."""
    import json
    from pathlib import Path
    from peaso.checks.aws_finding_clarity_reviewed import SCALAR_EVIDENCE_REVIEW
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-scalar-evidence.json").read_text())
    assert {row["id"] for row in rows} == set(SCALAR_EVIDENCE_REVIEW)
    assert len(rows) == 372
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)
        if name in {"pass", "fail"}:
            assert evidence["field"] == SCALAR_EVIDENCE_REVIEW[row["id"]]["field"]
            assert isinstance(evidence["configured"], (str, bool))


def test_normalized_security_group_rows_keep_actual_protocol_and_range():
    cid = "aws.claude_a.vpc.sg_world_v4_rdp"
    item = deepcopy(CASES[cid]["fail"])
    item["IpPermissions"][0].update(IpProtocol="udp", FromPort=3300, ToPort=3400)
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "FAIL"
    assert evidence["matching_rules"] == 1
    assert evidence["matching_declared_ingress"] == [{
        "ip_protocol": "udp", "from_port": 3300, "to_port": 3400,
        "cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": None}]
    item["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "10.0.0.0/8"}]
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "PASS" and evidence["matching_declared_ingress"] == []


def test_frontend_network_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-network-evidence.json").read_text())
    assert len({row["id"] for row in rows}) == 30
    assert len(rows) == 120
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_frontend_iam_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-iam-evidence.json").read_text())
    assert len({row["id"] for row in rows}) == 30
    assert len(rows) == 120
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_unavailable_guidance_is_replaced_only_by_reviewed_text_without_commands():
    from peaso.checks.aws_finding_clarity_reviewed import ROWS, _digest, remediation
    newly_reviewed = {cid for cid, row in ROWS.items() if row["remediation_base_sha256"] == _digest(None)}
    assert len(newly_reviewed) == 18
    for cid in newly_reviewed:
        details = remediation(cid, None)
        assert details["review_status"] == "approved" and details["cli"] == []
        assert details["references"] and details["caveats"]
        with pytest.raises(ValueError, match="base changed"):
            remediation(cid, {"review_status": "draft", "cli": ["unreviewed command"]})


def test_initial_twenty_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-initial-evidence.json").read_text())
    assert len(rows) == len({row["id"] for row in rows}) == 20
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_frontend_identity_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-identity-evidence.json").read_text())
    assert len({row["id"] for row in rows}) == 37
    assert len(rows) == 148
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_policy_membership_evidence_is_computed_from_collected_assignments():
    for cid in ["aws.claude_a.iam.policy_in_use", "aws.claude_a.iam.custom_policy_in_use"]:
        fixture = CASES[cid]
        for name, expected in [("pass", True), ("fail", False)]:
            item = deepcopy(fixture[name])
            index = deepcopy(fixture.get(name + "_index", fixture.get("index", {})))
            before = deepcopy((item, index))
            status, evidence = REGISTRY[cid].evaluate(item, index)
            assert (item, index) == before
            assert evidence["attached_to_active_identity"] is expected
            assert status == ("PASS" if expected else "FAIL")


def test_non_iam_sts_service_names_are_actual_last_accessed_metadata():
    cid = "aws.claude_a.iam.user_long_lived_keys_only_iam_sts"
    fixture = CASES[cid]
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["fail"]), deepcopy(fixture.get("fail_index", fixture.get("index", {}))))
    assert status == "FAIL"
    assert evidence["non_iam_sts_services"] == ["s3"]
    assert evidence["other_services"] == len(evidence["non_iam_sts_services"])


@pytest.mark.parametrize("filename, count, controls", [
    ("aws-policy-evidence.json", 36, 9),
    ("aws-network-rest-evidence.json", 148, 37),
])
def test_final_policy_and_network_examples_are_exact_native_outputs(filename, count, controls):
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures" / filename).read_text())
    assert len({row["id"] for row in rows}) == controls
    assert len(rows) == count
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


@pytest.mark.parametrize("cid, key", [
    ("aws.claude_a.vpc.sg_no_world_all_traffic", "world_all_traffic_rule_found"),
    ("aws.claude_a.vpc.sg_attached_to_eni", "eni_attachment_found"),
    ("aws.claude_a.vpc.in_use_vpc_has_flow_log", "flow_log_found"),
    ("aws.claude_a.vpc.vpc_has_subnets", "subnet_found"),
    ("aws.claude_a.vpc.in_use_vpc_ec2_endpoint", "matching_service_name_found"),
    ("aws.claude_a.networkfirewall.in_use_vpc_has_firewall", "firewall_found"),
    ("aws.claude_a.networkfirewall.policy_has_rule_groups", "rule_group_reference_found"),
    ("aws.claude_a.vpc.nacl_no_world_tcp_22", "ordered_world_ingress_allowed"),
])
def test_presence_and_acl_facts_are_actual_native_results_without_input_mutation(cid, key):
    fixture = CASES[cid]
    for name in ["pass", "fail"]:
        item = deepcopy(fixture[name])
        index = deepcopy(fixture.get(name + "_index", fixture.get("index", {})))
        before = deepcopy((item, index))
        status, evidence = REGISTRY[cid].evaluate(item, index)
        assert status == ("PASS" if name == "pass" else "FAIL")
        assert isinstance(evidence[key], bool)
        assert (item, index) == before
    status, evidence = REGISTRY[cid].evaluate({}, {})
    assert status == "UNKNOWN" and key not in evidence


def test_security_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-security-evidence.json").read_text())
    assert len(rows) == 120 and len({row["id"] for row in rows}) == 30
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_guardduty_feature_evidence_keeps_short_circuit_and_detector_state():
    cid = "aws.claude_a.guardduty.ec2_runtime_agent_management"
    fixture = CASES[cid]
    item = deepcopy(fixture["pass"])
    item["Configuration"]["Status"] = "DISABLED"
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "FAIL"
    assert evidence["feature_enabled"] is True and evidence["detector_enabled"] is False
    item = deepcopy(fixture["fail"])
    del item["Configuration"]["Status"]
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "FAIL"  # Native predicate never reads detector status after false feature.
    assert evidence["feature_enabled"] is False and evidence["detector_enabled"] is None


def test_securityhub_and_organization_match_flags_are_native_not_status_guesses():
    for cid, key in [
        ("aws.claude_a.organizations.ai_services_opt_out", "opt_out_content_match"),
        ("aws.claude_a.organizations.scp_restricts_regions", "direct_region_deny_match"),
        ("aws.claude_a.securityhub.enabled_with_standard_or_integration", "standard_or_integration_found"),
    ]:
        fixture = CASES[cid]
        for name, expected in [("pass", True), ("fail", False)]:
            status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
            assert status == ("PASS" if expected else "FAIL")
            assert evidence[key] is expected


def test_security_b_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-security-b-evidence.json").read_text())
    assert len(rows) == 120 and len({row["id"] for row in rows}) == 30
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_secret_public_model_fact_is_separate_from_total_statement_count():
    cid = "aws.cb.secretsmanager.policy_not_public"
    fixture = CASES[cid]
    for name, expected in [("pass", False), ("fail", True)]:
        status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert evidence["statements"] == 1
        assert evidence["public_policy"] is expected
        assert status == ("FAIL" if expected else "PASS")


def test_secret_key_manager_observation_preserves_provider_managed_encryption():
    cid = "aws.cb.secretsmanager.cmk_encryption"
    fixture = CASES[cid]
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["fail"]), deepcopy(fixture.get("fail_index", fixture.get("index", {}))))
    assert status == "FAIL" and evidence["key_manager"] == "AWS"
    status, evidence = REGISTRY[cid].evaluate(deepcopy(fixture["pass"]), deepcopy(fixture.get("index", {})))
    assert status == "PASS" and evidence["key_manager"] == "CUSTOMER"


def test_security_b_rest_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-security-b-rest-evidence.json").read_text())
    assert len(rows) == 116 and len({row["id"] for row in rows}) == 29
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_shield_advanced_registration_is_actual_membership_without_mutation():
    ids = [cid for cid in REGISTRY if cid.startswith("aws.cb.shield.")]
    assert len(ids) == 6
    for cid in ids:
        fixture = CASES[cid]
        for name, registered in [("pass", True), ("fail", False)]:
            item = deepcopy(fixture[name])
            index = deepcopy(fixture.get(name + "_index", fixture.get("index", {})))
            before = deepcopy((item, index))
            status, evidence = REGISTRY[cid].evaluate(item, index)
            assert status == ("PASS" if registered else "FAIL")
            assert evidence["shield_advanced_protection_found"] is registered
            assert (item, index) == before


def test_core_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-core-evidence.json").read_text())
    assert len(rows) == 120 and len({row["id"] for row in rows}) == 30
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_tooling_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-tooling-evidence.json").read_text())
    assert len(rows) == 104 and len({row["id"] for row in rows}) == 26
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_devtools_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-devtools-evidence.json").read_text())
    assert len(rows) == 112 and len({row["id"] for row in rows}) == 28
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_identity_b_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-identity-b-evidence.json").read_text())
    assert len(rows) == 108 and len({row["id"] for row in rows}) == 27
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)


def test_batch_frontend_examples_are_exact_native_evaluator_outputs():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "frontend/tests/fixtures/aws-batch-evidence.json").read_text())
    assert len(rows) == 140 and len({row["id"] for row in rows}) == 35
    for row in rows:
        fixture = CASES[row["id"]]
        name = row["case"]
        status, evidence = REGISTRY[row["id"]].evaluate(
            deepcopy(fixture[name]), deepcopy(fixture.get(name + "_index", fixture.get("index", {}))))
        assert (row["status"], row["evidence"]) == (status, evidence)

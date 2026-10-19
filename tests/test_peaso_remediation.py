"""Reviewed remediation templates, safe bindings and legacy rendering."""
import json
import re

from peaso.remediation import bind_command, identity_bindings, report_templates, rules, template
from peaso.reports import _remediation_lines
from peaso.reports import render_markdown
from peaso.engine import attach_reviewed_description_meta, compact_report, expand_report, factor_check_meta, hydrate_finding
from peaso.checks import CHECKS
from peaso.checks.catalog import description_for


def finding(provider, check_id, native, name=None, scope=""):
    return {"provider": provider, "check_id": check_id, "native_resource_id": native,
            "resource_name": name, "scope": scope, "remediation": "Legacy guidance"}


def _public_guidance_prose(check_id):
    value = template(check_id)
    description = description_for(check_id) or {}
    return " ".join([description.get("description", ""), value["summary"],
                     *value["steps"], *value["caveats"]])


def test_reviewed_template_coverage_is_explicit():
    reviewed = {key for key, value in rules().items() if value.get("review_status") == "approved"}
    assert len(reviewed) >= 568
    assert template("aws.iam.no_full_admin")
    assert template("analysis.network_review", "aws")
    assert all(template("analysis.network_review", provider) for provider in ("aws", "gcp", "azure", "k8s"))
    assert all(template("analysis.federated_trust", provider) for provider in ("aws", "gcp", "azure"))
    assert template("analysis.federated_trust", "k8s") is None
    assert all(template("analysis.coverage", provider) for provider in ("aws", "gcp", "azure", "k8s"))
    assert all(template("analysis.grant_review", provider) for provider in ("aws", "gcp", "azure", "k8s"))
    assert template("analysis.grant_review", "gcp")["cli"] == []
    assert all(template("analysis.principal_exposure", provider) for provider in ("aws", "gcp", "azure", "k8s"))
    for analysis_id in ("analysis.inactive_identity", "analysis.internet_exposure"):
        assert all(template(analysis_id, provider) for provider in ("aws", "gcp", "azure", "k8s"))
    assert template("k8s.ports.pod.container_argument_anonymous_auth_disabled")
    assert template("k8s.pod.no_privileged_containers")
    for check_id in ("k8s.pod.non_root", "k8s.pod.drop_capabilities", "k8s.pod.restrict_added_capabilities", "k8s.pod.seccomp",
                     "k8s.pod.no_hostpath", "k8s.pod.no_default_serviceaccount",
                     "k8s.pod.restrict_token_automount", "k8s.pod.default_proc_mount",
                     "k8s.pod.restrict_selinux_identity", "k8s.namespace.restricted_admission"):
        assert template(check_id) and template(check_id)["field_binding"]["target"] == "resource"
    for check_id in ("k8s.rbac.no_wildcards", "k8s.rbac.role_no_wildcards",
                     "k8s.rbac.review_broad_subjects", "k8s.rbac.review_namespaced_subjects",
                     "k8s.pod.no_host_namespaces", "k8s.service.review_public_type",
                     "k8s.network.namespace_policy_inventory"):
        assert template(check_id) and template(check_id)["field_binding"]["target"] == "resource"
    for check_id in ("k8s.htbp.role.no_impersonation", "k8s.htbp.clusterrole.no_service_status_write",
                     "k8s.htbp.service.no_external_ips", "k8s.htbp.secret.no_legacy_service_account_token",
                     "k8s.htbp.rolebinding.no_anonymous_user", "k8s.htbp.clusterrolebinding.no_anonymous_user"):
        assert template(check_id) and template(check_id)["field_binding"]["target"] == "resource"
    assert "-o jsonpath" in template("k8s.htbp.secret.no_legacy_service_account_token")["cli"][0]["code"]
    for check_id in ("aws.claude_a.vpc.sg_world_v4_ssh", "gcp.claude.firewall.public_ingress_tcp_port_6379",
                     "azure.claude.nsg_internet_udp_53", "k8s.ports.cronjob.drop_all",
                     "k8s.ports.namespace.namespace_resource_quota_memory_request",
                     "k8s.ports.networkpolicy.network_policy_default_dont_allow_ingress"):
        assert template(check_id) and template(check_id)["field_binding"]["target"] == "resource"
    assert template("k8s.ports.namespace.namespace_resource_quota_memory_request")["field_binding"]["field"] == "spec.hard.requests.memory"
    assert template("k8s.deployment.no_privileged")["field_binding"]["evaluator_family"] == "k8s_extended._evaluate_pod"
    assert "ownerReferences" in template("k8s.claude.pod.no_literal_secret_env")["cli"][0]["code"]
    assert "-o yaml" not in template("k8s.claude.pod.no_literal_secret_env")["cli"][0]["code"]
    assert "--remote-debugging-enabled false" in template("azure.app.remote_debugging_off")["cli"][1]["code"]
    assert "--auto-minor-version-upgrade" in template("aws.rds.auto_minor_upgrade")["cli"][1]["code"]
    for regional_id in ("aws.gap.vpc.sg_world_any_common_ports", "aws.cloudtrail.logging",
                        "aws.rds.deletion_protection", "aws.claude_a.ebs.snapshot_encrypted",
                        "aws.claude_a.ec2.ami_not_public"):
        regional = template(regional_id)
        assert regional
        for command in regional["cli"]:
            if any(token in command["code"] for token in ("<RESOURCE_ID>", "<RESOURCE_NAME>", "<RESOURCE_ARN>")):
                assert "--region <REGION>" in command["code"], (regional_id, command["code"])
    for sg_id in (check.id for check in CHECKS if check.id.startswith("aws.claude_a.vpc.sg_world")):
        sg = template(sg_id)
        if sg:
            assert all("--region <REGION>" in command["code"] for command in sg["cli"]), sg_id
    assert template("aws.s3.default_encryption")
    assert template("gcp.sql.backups")
    assert "--restart-on-failure" in template("gcp.reviewed.compute.automatic_restart")["cli"][1]["code"]
    assert "defaultToOAuthAuthentication" in template("azure.storage.default_oauth")["field_binding"]["field"]
    assert "cloudasset.googleapis.com" in template("gcp.ports.project_service_cloudasset_api_enabled")["cli"][1]["code"]
    assert "containeranalysis.googleapis.com" in template("gcp.ports.artifacts_container_analysis_enabled")["cli"][1]["code"]
    for check_id, field, update_flag in (
        ("gcp.reviewed.storage.soft_delete", "softDeletePolicy.retentionDurationSeconds", "--soft-delete-duration"),
        ("gcp.reviewed.storage.versioning", "versioning.enabled", "--versioning"),
        ("gcp.reviewed.storage.access_logging", "logging.logBucket", "--log-bucket"),
    ):
        bucket = template(check_id)
        assert bucket["field_binding"]["kind"] == "bucket"
        assert field in bucket["field_binding"]["field"]
        assert update_flag in bucket["cli"][1]["code"]
        assert bucket["cli"][1]["code"].startswith("gcloud storage buckets update gs://<RESOURCE_NAME>")
    for check_id in ("gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on",
                     "gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off",
                     "gcp.ports.sql_instance_sql_remote_access_database_flag_off",
                     "gcp.ports.sql_instance_sql_3625_trace_database_flag_on"):
        reviewed_sql = template(check_id)
        assert reviewed_sql["field_binding"]["kind"] == "sql_instance"
        assert "settings.databaseFlags" in reviewed_sql["field_binding"]["field"]
        assert len(reviewed_sql["cli"]) == 2
        assert reviewed_sql["cli"][0]["code"].startswith("gcloud sql instances describe")
        assert reviewed_sql["cli"][1]["code"].endswith("--flags-file=<REVIEWED_FULL_FLAGS_YAML>")
        assert "--flags-file=<REVIEWED_FULL_FLAGS_YAML>" in reviewed_sql["cli"][1]["code"]
        assert any("replaces every existing flag" in caveat for caveat in reviewed_sql["caveats"])
    for check_id in ("gcp.ports.dns_managed_zone_dnssec_enabled",
                     "gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1",
                     "gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1"):
        dns = template(check_id)
        assert dns["field_binding"]["kind"] == "dns_managed_zone"
        assert "dnssecConfig" in dns["field_binding"]["field"]
        assert dns["cli"][0]["code"].startswith("gcloud dns managed-zones describe")
    for check_id, kind in (("gcp.ports.storage_bucket_not_publicly_accessible", "bucket"),
                           ("gcp.ports.cloudfunction_function_restrict_public_access", "function"),
                           ("gcp.ports.function_active_public_binding", "function"),
                           ("gcp.ports.cloudrun_service_restrict_public_access", "cloudrun_service"),
                           ("gcp.ports.bigquery_dataset_not_publicly_accessible", "bigquery_dataset")):
        public = template(check_id)
        assert public["field_binding"]["kind"] == kind
        assert "allUsers" in public["field_binding"]["field"]
        assert 1 <= len(public["steps"]) <= 2
        if kind != "bigquery_dataset":
            assert "remove-iam-policy-binding" in public["cli"][1]["code"]
            assert "<REVIEWED_PUBLIC_MEMBER>" in public["cli"][1]["code"]
    for check_id in ("gcp.ports.sql_instance_with_no_public_ips",
                     "gcp.ports.sql_instance_not_publicly_accessible",
                     "gcp.ports.sql_no_primary_address"):
        address = template(check_id)
        assert address["field_binding"]["kind"] == "sql_instance"
        assert "ipAddresses" in address["field_binding"]["field"]
        assert "private connectivity" in " ".join(address["steps"]).lower() or "private client connectivity" in " ".join(address["steps"]).lower()
    incoming = template("gcp.ports.sql_private_ip_assignments")
    assert incoming["field_binding"]["kind"] == "sql_instance"
    assert "PRIMARY|MIGRATED_1ST_GEN" in incoming["field_binding"]["field"]
    assert "--no-assign-ip" in incoming["cli"][1]["code"]
    assert "Do not remove OUTGOING" in " ".join(incoming["caveats"])
    for check_id in ("azure.port.storage_account_soft_delete_enabled",
                     "azure.port.storage_account_blob_soft_delete_enabled",
                     "azure.port.storage_account_container_soft_delete_enabled",
                     "azure.port.storage_account_blob_and_container_soft_delete_enabled",
                     "azure.port.storage_account_blob_versioning_enabled"):
        storage = template(check_id)
        assert storage["field_binding"]["kind"] == "storage_account"
        assert "blobServices/default" in storage["field_binding"]["field"]
        assert storage["cli"][0]["code"].startswith("az storage account blob-service-properties show")
    assert "keyExpirationPeriodInDays=90" in template("azure.port.storage_account_key_rotation_reminder_enabled")["field_binding"]["field"]
    assert "does not establish actual key regeneration" in " ".join(template("azure.port.storage_account_key_rotation_reminder_enabled")["caveats"])
    for check_id in reviewed:
        value = rules()[check_id]
        assert value["summary"] and 1 <= len(value["steps"]) <= 5
        assert value["references"] and all(row["url"].startswith("https://") for row in value["references"])
    indexed = {check.id: check for check in CHECKS}
    assert indexed["aws.iam.no_full_admin"].public()["remediation_details"]["summary"] == template("aws.iam.no_full_admin")["summary"]
    legacy = indexed["k8s.ports.pod.container_argument_pod_security_policy_enabled"].public()["remediation_details"]
    assert legacy["cli"] == [] and not legacy.get("iac")
    assert "legacy cluster" in legacy["summary"]
    assert "only through Kubernetes 1.24" in legacy["caveats"][0]
    from copy import deepcopy
    from peaso.checks.fixtures import CASES
    modern = deepcopy(CASES["k8s.ports.pod.container_argument_pod_security_policy_enabled"]["fail"])
    modern["spec"]["containers"][0]["_component_config"]["version"] = "v1.25.0"
    assert indexed["k8s.ports.pod.container_argument_pod_security_policy_enabled"].evaluate(modern, {})[0] == "NOT_APPLICABLE"


def test_second_aws_shard_conflict_rejected(monkeypatch, tmp_path):
    import peaso.remediation as remediation
    candidate = dict(template("aws.iam.no_full_admin"), review_status="approved")
    candidate["summary"] = "Conflicting approved edit"
    shard = tmp_path / "aws-families.json"
    shard.write_text(json.dumps({"aws.iam.no_full_admin": candidate}))
    monkeypatch.setattr(remediation, "AWS_FAMILIES_REVIEWED", shard)
    remediation.rules.cache_clear()
    try:
        try:
            remediation.rules()
        except ValueError as exc:
            assert "conflicts with approved IDs" in str(exc)
        else:
            assert False, "approved shard collision was accepted"
    finally:
        remediation.rules.cache_clear()


def test_approved_regional_aws_service_commands_name_the_region():
    global_services = {"iam", "organizations", "cloudfront", "route53", "account", "sts", "s3api"}
    for check_id, reviewed in rules().items():
        if not check_id.startswith("aws.") or reviewed.get("review_status") != "approved":
            continue
        for command in reviewed.get("cli", []):
            code = command.get("code", "")
            parts = code.split()
            if len(parts) < 3 or parts[0] != "aws" or parts[1] in global_services:
                continue
            # Route 53 Domains uses a fixed regional endpoint; representative
            # direct finding-target tests above separately require <REGION>.
            assert "--region " in code, (check_id, code)


def test_approved_summaries_are_customer_actions_not_source_provenance():
    for check_id, reviewed in rules().items():
        if reviewed.get("review_status") != "approved":
            continue
        assert not re.search(r"(?i)\b(evaluator|Prowler|Steampipe|upstream)\b", reviewed.get("summary", "")), check_id


def test_sampled_c2b_remediation_does_not_invert_source_or_claim_unverified_fix():
    bedrock = rules()["aws.c2b.bedrock.api_key_long_term_expired"]
    assert "unexpired credential" in _public_guidance_prose("aws.c2b.bedrock.api_key_long_term_expired").lower()
    assert "already expired" in " ".join(bedrock["caveats"])
    assert "--status Inactive" in bedrock["cli"][1]["code"]
    assert "--service-specific-credential-id <CREDENTIAL_ID>" in bedrock["cli"][2]["code"]
    efs = rules()["aws.c2b.efs.access_points_posix_user"]
    assert efs["field_binding"]["kind"] == "efs_file_system"
    assert "PosixUser" in description_for("aws.c2b.efs.access_points_posix_user")["description"]
    assert "describe-access-points --file-system-id <RESOURCE_ID>" in efs["cli"][0]["code"]
    assert "--posix-user Uid=<APPROVED_UID>,Gid=<APPROVED_GID>" in efs["cli"][1]["code"]
    assert "without a PosixUser with" not in efs["summary"] + " ".join(efs["steps"])
    for suffix, field in (
        ("cache_at_rest_encryption", "atRestEncryptionEnabled"),
        ("cache_in_transit_encryption", "transitEncryptionEnabled"),
    ):
        appsync = rules()[f"aws.c2b.appsync.{suffix}"]
        assert "GetApiCache NotFound is NOT_APPLICABLE" in " ".join(appsync["caveats"])
        assert field in appsync["field_binding"]["path"]
        assert "delete-api-cache" in appsync["cli"][1]["code"]
        assert "--at-rest-encryption-enabled" in appsync["cli"][2]["code"]
        assert "--transit-encryption-enabled" in appsync["cli"][2]["code"]
        assert "AtRestEncryptionEnabled: true" in appsync["iac"]["code"]
        assert "TransitEncryptionEnabled: true" in appsync["iac"]["code"]


def test_c2b_dms_and_alb_network_repairs_require_exact_owner_inputs():
    dms = rules()["aws.c2b.dms.public_instance_open_sg"]
    assert "PubliclyAccessible=true" in dms["field_binding"]["path"]
    assert "cannot be changed" in " ".join(dms["steps"])
    assert "describe-security-group-rules" in dms["cli"][1]["code"]
    assert "--security-group-rule-ids <REVIEWED_WORLD_OPEN_RULE_ID>" in dms["cli"][2]["code"]
    assert "modify-replication-instance" not in " ".join(x["code"] for x in dms["cli"])
    alb = rules()["aws.c2b.elbv2.alb_sg_outbound_rule"]
    assert "Type=application" in alb["field_binding"]["path"]
    assert "any attached group" in " ".join(alb["steps"])
    assert "no groups" in " ".join(alb["steps"])
    assert "describe-target-groups" in alb["cli"][1]["code"]
    assert "file://<REVIEWED_EGRESS_PERMISSIONS_JSON>" in alb["cli"][3]["code"]
    assert "0.0.0.0/0" not in alb["cli"][3]["code"]


def test_c2b_launch_configuration_replacements_do_not_claim_in_place_update():
    for suffix in (
        "group_lc_imdsv2",
        "group_lc_no_public_ip",
        "lc_hop_limit",
        "lc_imdsv2_required",
        "lc_no_public_ip",
    ):
        rule = rules()[f"aws.c2b.autoscaling.{suffix}"]
        all_text = " ".join(rule["steps"] + rule["caveats"])
        assert "Launch configurations are immutable" in all_text
        assert "pinned reviewed template version" in all_text
        assert "instance refresh" in all_text
        if suffix.startswith("group_"):
            assert "NOT_APPLICABLE" in all_text
        else:
            assert "does not change this resource finding" in all_text


def test_c2b_backup_encryption_guidance_is_resource_type_conditional():
    vault = rules()["aws.c2b.backup.vault_encrypted"]
    assert vault["review_status"] == "approved"
    assert "ListBackupVaults" in vault["field_binding"]["path"]
    assert "DescribeBackupVault" in vault["field_binding"]["path"]
    assert "UNKNOWN" in " ".join(vault["steps"])
    assert "not an unencrypted-vault finding" in " ".join(vault["caveats"])
    point = rules()["aws.c2b.backup.recovery_point_encrypted"]
    assert point["review_status"] == "approved"
    assert point["field_binding"]["path"] == "IsEncrypted"
    assert "fully managed" in " ".join(point["steps"])
    assert "source-encrypted" in " ".join(point["steps"])
    assert "cannot be made encrypted in place" in " ".join(point["caveats"])


def test_c2b_elasticache_public_subnet_repair_keeps_nat_egress():
    for suffix in ("cluster_public_subnet", "cluster_public_subnet_prowler"):
        rule = rules()[f"aws.c2b.elasticache.{suffix}"]
        assert "GatewayId=igw-*" in rule["field_binding"]["path"]
        assert "NAT-only" in _public_guidance_prose(f"aws.c2b.elasticache.{suffix}")
        assert "must not be removed" in " ".join(rule["caveats"])
        assert "implicit main table" in rule["cli"][3]["label"]


def test_c2b_efs_repair_distinguishes_file_system_class_and_subnet_setting():
    multi = rules()["aws.c2b.efs.multi_az_mount_targets"]
    assert "One Zone" in " ".join(multi["caveats"])
    assert "cannot accept another" in " ".join(multi["caveats"])
    assert "For Regional EFS only" in multi["cli"][2]["label"]
    subnet = rules()["aws.c2b.efs.mount_target_subnet_no_auto_public_ip"]
    assert "joined subnet.MapPublicIpOnLaunch=true" in subnet["field_binding"]["path"]
    assert "does not prove" in " ".join(subnet["caveats"])
    assert "--no-map-public-ip-on-launch" in subnet["cli"][2]["code"]
    root = rules()["aws.c2b.efs.access_point_root_directory"]
    assert "RootDirectory.Path=/" in root["field_binding"]["path"]
    assert "--cli-input-json file://<REVIEWED_ACCESS_POINT_JSON>" in root["cli"][1]["code"]
    user = rules()["aws.c2b.efs.access_point_user_identity"]
    assert "--posix-user Uid=<APPROVED_UID>,Gid=<APPROVED_GID>" in user["cli"][1]["code"]
    aggregate = rules()["aws.c2b.efs.access_points_no_root_directory"]
    assert "No access points is not applicable" in " ".join(aggregate["caveats"])
    assert "Joins filesystem access points" in description_for("aws.c2b.efs.access_points_no_root_directory")["description"]
    target = rules()["aws.c2b.efs.no_public_mount_targets"]
    assert "one mount target per Availability Zone" in " ".join(target["caveats"])
    assert "forcibly breaks mounts" in " ".join(target["caveats"])


def test_c2b_dax_replacement_and_replica_placement_are_distinct():
    for suffix in ("encryption_at_rest", "encryption_in_transit"):
        rule = rules()[f"aws.c2b.dax.{suffix}"]
        assert "cannot enable" in " ".join(rule["caveats"])
        assert "create-cluster --cli-input-json file://<REVIEWED_DAX_CLUSTER_JSON>" in rule["cli"][1]["code"]
        assert "old resource pass" in " ".join(rule["caveats"])
    multi = rules()["aws.c2b.dax.multi_az"]
    assert "distinct Nodes[].AvailabilityZone count < 2" == multi["field_binding"]["path"]
    assert "increase-replication-factor" in multi["cli"][1]["code"]
    assert "--availability-zones <REVIEWED_AZ_LIST>" in multi["cli"][1]["code"]


def test_c2b_directory_cert_rotation_and_snapshot_deletion_require_owner_review():
    snapshot = rules()["aws.c2b.directoryservice.manual_snapshot_quota"]
    assert "LimitReached=true" in snapshot["field_binding"]["path"]
    assert "irreversible" in " ".join(snapshot["caveats"])
    assert "--snapshot-id <REVIEWED_SNAPSHOT_ID>" in snapshot["cli"][2]["code"]
    for suffix in ("ldap_certificate_over_90_days", "certificate_not_within_90_days"):
        cert = rules()[f"aws.c2b.directoryservice.{suffix}"]
        assert "any registered certificate" in " ".join(cert["caveats"])
        assert "new certificate alone does not clear" in " ".join(cert["caveats"])
        assert "register-certificate --cli-input-json file://<REVIEWED_DS_CERTIFICATE_JSON>" in cert["cli"][1]["code"]
        assert "deregister-certificate" in cert["cli"][2]["code"]


def test_c2b_codebuild_age_review_does_not_start_synthetic_build():
    invoked = rules()["aws.c2b.codebuild.invoked_last_90_days"]
    built = rules()["aws.c2b.codebuild.built_within_90_days"]
    assert "floor-days>90" in invoked["field_binding"]["path"]
    assert "floor-days>=90" in built["field_binding"]["path"]
    for rule in (invoked, built):
        assert "IN_PROGRESS passes" in rule["field_binding"]["path"]
        assert "do not run an unreviewed build as a compliance shortcut" in " ".join(rule["caveats"])
        assert all("start-build" not in cli["code"] for cli in rule["cli"])


def test_c2b_directconnect_redundancy_requires_separate_locations_and_connections():
    connection = rules()["aws.c2b.directconnect.connection_redundancy"]
    vif = rules()["aws.c2b.directconnect.virtual_interface_redundancy"]
    assert connection["field_binding"]["target"] == vif["field_binding"]["target"] == "scope"
    assert "two distinct locations" in " ".join(connection["steps"] + connection["caveats"])
    assert "two distinct VIF IDs" in " ".join(vif["steps"] + vif["caveats"])
    assert "two connection IDs" in " ".join(vif["steps"] + vif["caveats"])
    for rule in (connection, vif):
        assert "NOT_APPLICABLE" in " ".join(rule["steps"] + rule["caveats"])
        assert "failover test" in " ".join(rule["steps"] + rule["caveats"])
        assert all("create-" not in cli["code"] for cli in rule["cli"])


def test_c2b_acm_and_private_ca_key_replacement_require_distinct_cutovers():
    acm = rules()["aws.c2b.acm.in_use_secure_key_algorithm"]
    pca = rules()["aws.c2b.acmpca.pqc_key_algorithm"]
    assert "InUseBy" in " ".join(acm["caveats"])
    assert "ACM reimport cannot change a certificate's key type or size" in " ".join(acm["caveats"])
    assert "old in-use ARN keeps failing until detached" in " ".join(acm["caveats"])
    assert "skips only DELETED CAs" in " ".join(pca["caveats"])
    assert "ML_DSA_44, ML_DSA_65 or ML_DSA_87" in " ".join(pca["caveats"])
    assert "every other status fails unless" in " ".join(pca["caveats"])
    assert "Do not disable or delete the old CA until every dependent" in " ".join(pca["caveats"])
    for rule in (acm, pca):
        assert all("create-" not in cli["code"] for cli in rule["cli"])


def test_c2b_dms_expired_certificate_retires_only_after_endpoint_cutover():
    rule = rules()["aws.c2b.dms.certificate_not_expired"]
    codes = [item["code"] for item in rule["cli"]]
    assert "--cli-input-json file://<REVIEWED_DMS_CERTIFICATE_JSON>" in codes[2]
    assert "--endpoint-arn <REVIEWED_ENDPOINT_ARN> --certificate-arn <NEW_CERTIFICATE_ARN>" in codes[3]
    assert codes[4].startswith("aws dms delete-certificate --certificate-arn <RESOURCE_ARN>")
    assert "irreversible" in " ".join(rule["caveats"])
    assert "importing a new certificate alone cannot clear" in " ".join(rule["caveats"])


def test_c2b_documentdb_multi_az_adds_a_reviewed_second_zone_replica():
    rule = rules()["aws.c2b.documentdb.multi_az"]
    assert rule["field_binding"]["path"] == "MultiAZ"
    assert "create-db-instance --db-cluster-identifier <RESOURCE_NAME>" in rule["cli"][2]["code"]
    assert "--availability-zone <REVIEWED_SECOND_AZ>" in rule["cli"][2]["code"]
    assert "MultiAZ boolean" in " ".join(rule["caveats"])
    assert "distinct supported Availability Zone" in " ".join(rule["caveats"])
    assert "compute charges" in " ".join(rule["caveats"])


def test_c2b_documentdb_encryption_uses_restore_not_unencrypted_snapshot_copy():
    for check_id in ("aws.c2b.docdb.instance_storage_encrypted", "aws.c2b.documentdb.storage_encrypted"):
        rule = rules()[check_id]
        codes = [item["code"] for item in rule["cli"]]
        assert any("create-db-cluster-snapshot" in code for code in codes)
        assert any("restore-db-cluster-from-snapshot --cli-input-json file://<REVIEWED_DOCDB_RESTORE_JSON>" in code for code in codes)
        assert any("create-db-instance --cli-input-json file://<REVIEWED_DOCDB_INSTANCE_JSON>" in code for code in codes)
        assert all("copy-db-cluster-snapshot" not in code for code in codes)
        assert "cannot encrypt an unencrypted cluster snapshot by copying" in " ".join(rule["caveats"])
        assert "old unencrypted" in " ".join(rule["steps"])


def test_c2b_classic_elb_scheme_replacement_and_listener_migration_are_distinct():
    scheme = rules()["aws.c2b.classic_elb.not_internet_facing"]
    listeners = rules()["aws.c2b.classic_elb.ssl_listeners_only"]
    assert scheme["field_binding"]["path"] == "Scheme"
    assert "Scheme cannot be changed in place" in " ".join(scheme["caveats"])
    assert "old internet-facing resource continues to fail" in " ".join(scheme["caveats"])
    assert all("create-load-balancer" not in cli["code"] for cli in scheme["cli"])
    assert "--listeners file://<REVIEWED_HTTPS_LISTENERS_JSON>" in listeners["cli"][1]["code"]
    assert "--load-balancer-ports <REVIEWED_OLD_LISTENER_PORTS>" in listeners["cli"][2]["code"]
    assert "cannot replace a different listener on the same port" in " ".join(listeners["caveats"])
    assert "load balancer without listeners passes" in _public_guidance_prose("aws.c2b.classic_elb.ssl_listeners_only")


def test_c2b_cloudformation_rollback_and_cdk_bootstrap_use_real_owner_updates():
    rollback = rules()["aws.c2b.cloudformation.rollback_enabled"]
    bootstrap = rules()["aws.c2b.cloudformation.cdktoolkit_bootstrap_version"]
    assert rollback["field_binding"]["path"] == "DisableRollback"
    assert "update-stack --cli-input-json file://<REVIEWED_STACK_UPDATE_JSON>" in rollback["cli"][1]["code"]
    assert "DisableRollback=false" in " ".join(rollback["caveats"])
    assert "Do not fabricate a template change solely to clear this finding" in " ".join(rollback["caveats"])
    assert bootstrap["field_binding"]["path"] == "StackName=CDKToolkit; Outputs[].OutputKey=BootstrapVersion -> OutputValue"
    assert "Missing/no version is NOT_APPLICABLE" in " ".join(bootstrap["caveats"])
    assert "Do not edit only the CloudFormation output value" in " ".join(bootstrap["caveats"])


def test_c2b_cloudfront_missing_s3_origin_updates_exact_full_distribution():
    rule = rules()["aws.c2b.cloudfront.s3_origin_bucket_exists"]
    prose = _public_guidance_prose("aws.c2b.cloudfront.s3_origin_bucket_exists")
    assert "only a HeadBucket 404 fails" in prose
    assert "missing probes remain UNKNOWN" in prose
    assert "--if-match <CURRENT_ETAG> --distribution-config file://<REVIEWED_DISTRIBUTION_JSON>" in rule["cli"][2]["code"]
    assert "updating the behaviors" in prose
    assert "403 does not establish ownership" in prose
    assert "do not create or claim a bucket name" in " ".join(rule["caveats"]).lower()


def test_c2b_bedrock_data_source_and_logging_destinations_are_exactly_bound():
    sources = rules()["aws.c2b.bedrock.knowledge_base_data_sources_cmk"]
    logs = rules()["aws.c2b.bedrock.invocation_logs_encrypted"]
    assert sources["field_binding"]["target"] == "resource"
    assert "update-data-source --cli-input-json file://<REVIEWED_BEDROCK_DATA_SOURCE_JSON>" in sources["cli"][3]["code"]
    assert "complete name and dataSourceConfiguration" in " ".join(sources["caveats"])
    source_prose = _public_guidance_prose("aws.c2b.bedrock.knowledge_base_data_sources_cmk")
    assert "every collected" in source_prose and "serverSideEncryptionConfiguration.kmsKeyArn" in source_prose
    assert logs["field_binding"]["target"] == "scope"
    assert "matching bucket.Encryption" in logs["field_binding"]["path"]
    assert "matching log_group.kmsKeyId" in logs["field_binding"]["path"]
    assert "put-bucket-encryption --bucket <REVIEWED_LOG_BUCKET_NAME>" in logs["cli"][3]["code"]
    assert "associate-kms-key --log-group-name <REVIEWED_LOG_GROUP_NAME>" in logs["cli"][4]["code"]
    assert "S3 automatically encrypts new objects with SSE-S3" in " ".join(logs["caveats"])


def test_c2b_ecr_latest_scannable_digest_does_not_infer_clean_from_missing_scan_data():
    rule = rules()["aws.c2b.ecr.latest_image_no_medium_plus_findings"]
    prose = _public_guidance_prose("aws.c2b.ecr.latest_image_no_medium_plus_findings")
    assert "newest scannable non-signature image by imagePushedAt" in prose
    assert "exact digest" in prose
    assert "a failed scan also fails" in prose
    assert "medium-or-higher findings" in prose
    assert "complete pagination remains UNKNOWN" in prose
    assert "Basic Scanning needs exact-digest scan details, not DescribeImages alone" in prose
    assert "completion time" in prose
    assert all("batch-get-image" not in item["code"] and "put-image" not in item["code"] for item in rule["cli"])


def test_c2b_drs_guidance_tracks_current_source_replication_state():
    rule = rules()["aws.c2b.drs.region_has_job"]
    assert rule["review_status"] == "approved"
    assert template("aws.c2b.drs.region_has_job") == rule
    assert rule["field_binding"]["kind"] == "drs_source_server"
    assert "dataReplicationState" in rule["field_binding"]["path"]
    assert "STOPPED, STALLED or DISCONNECTED" in description_for("aws.c2b.drs.region_has_job")["description"]
    assert "historical recovery jobs cannot establish" in " ".join(rule["caveats"])
    assert "NOT_APPLICABLE" in " ".join(rule["steps"] + rule["caveats"])
    assert "restarts billing" in " ".join(rule["caveats"])
    assert all("start-recovery" not in item["code"] for item in rule["cli"])
    assert "<STOPPED_SOURCE_SERVER_ID>" in rule["cli"][1]["code"]


def test_cloud_sql_incoming_public_address_guidance_keeps_outgoing_and_unknown_separate():
    rule = template("gcp.ports.sql_private_ip_assignments")
    prose = _public_guidance_prose("gcp.ports.sql_private_ip_assignments")
    assert "PRIMARY or MIGRATED_1ST_GEN" in prose
    assert "OUTGOING is an outbound source" in prose
    assert "Do not remove OUTGOING" in prose
    assert "does not establish private connectivity" in prose
    assert "Unknown address types remain UNKNOWN" in prose
    assert "Migrate clients before removing public incoming addresses" in prose
    check = finding("gcp", "gcp.ports.sql_private_ip_assignments", "cloud-sql-prod", "cloud-sql-prod", "projects/project-123")
    command = bind_command(rule["cli"][1]["code"], check)
    assert command == "gcloud sql instances patch cloud-sql-prod --project=project-123 --no-assign-ip"
    check["resource_name"] = "bad;rm -rf /"
    check["native_resource_id"] = "bad;rm -rf /"
    assert "<RESOURCE_NAME>" in bind_command(rule["cli"][1]["code"], check)


def test_aws_named_targets_and_s3_arn_are_bound_only_for_matching_kind():
    bucket = finding("aws", "aws.s3.public_access_block", "arn:aws:s3:::audit-data.example", "audit-data.example", "123456789012/us-east-1")
    assert identity_bindings(bucket)["BUCKET_NAME"] == "audit-data.example"
    assert identity_bindings(bucket)["RESOURCE_ARN"] == "arn:aws:s3:::audit-data.example"
    assert identity_bindings(finding("aws", "aws.iam.no_full_admin", "arn:aws:iam::123456789012:policy/ServicePolicy", "ServicePolicy", "123456789012"))["POLICY_ARN"] == "arn:aws:iam::123456789012:policy/ServicePolicy"
    repository = finding("aws", "aws.ecr.immutable_tags", "arn:aws:ecr:us-east-1:123456789012:repository/team/app", None, "123456789012/us-east-1")
    assert identity_bindings(repository)["REPOSITORY_NAME"] == "team/app"
    unsafe = finding("aws", "aws.s3.public_access_block", "name$(touch /tmp/bad)", "bad; rm -rf /", "123456789012")
    assert "RESOURCE_NAME" not in identity_bindings(unsafe)
    assert bind_command("aws s3api get-bucket-encryption --bucket <RESOURCE_NAME>", unsafe).endswith("<RESOURCE_NAME>")
    assert "RESOURCE_NAME" not in identity_bindings(finding("aws", "aws.s3.public_access_block", "x" * 513, "x" * 513))
    wrong_account = finding("aws", "aws.iam.no_full_admin", "arn:aws:iam::999999999999:policy/Other", "Other", "123456789012")
    assert "RESOURCE_ARN" not in identity_bindings(wrong_account)


def test_cloud_and_k8s_identity_binding_is_bounded():
    azure = finding("azure", "azure.storage.no_blob_public_access",
                    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/auditacct",
                    "ignored", "/subscriptions/12345678-1234-1234-1234-123456789abc")
    assert identity_bindings(azure)["RESOURCE_GROUP"] == "prod-rg"
    assert identity_bindings(azure)["RESOURCE_NAME"] == "auditacct"
    gcp = finding("gcp", "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only", "fw-admin", "fw-admin", "projects/project-123/regions/us-central1")
    gcp["location"] = "us-east1"
    assert identity_bindings(gcp)["LOCATION"] == "us-east1"
    gcp["resource_name"] = "bad;firewall"
    assert identity_bindings(gcp)["RESOURCE_NAME"] == "fw-admin"
    k8s = finding("k8s", "k8s.pod.no_privileged_containers", "k8s://prod/pod/workloads/uid-123", "api-pod", "prod")
    assert identity_bindings(k8s)["RESOURCE_NAME"] == "api-pod"
    k8s["resource_name"] = "bad;name"
    assert "RESOURCE_NAME" not in identity_bindings(k8s)


def test_global_aws_and_numeric_gcp_scopes_bind_only_known_owner_ids():
    global_aws = finding("aws", "aws.iam.no_full_admin", "arn:aws:iam::123456789012:policy/Approved", "Approved", "123456789012/global")
    bound = identity_bindings(global_aws)
    assert bound["ACCOUNT_ID"] == "123456789012"
    assert bound["RESOURCE_ARN"] == "arn:aws:iam::123456789012:policy/Approved"
    assert "REGION" not in bound
    wrong = dict(global_aws, native_resource_id="arn:aws:iam::999999999999:policy/Other")
    assert "RESOURCE_ARN" not in identity_bindings(wrong)
    assert "ACCOUNT_ID" not in identity_bindings(dict(global_aws, scope="123456789012/global;id"))
    org = finding("gcp", "gcp.reviewed.compute.deletion_protection", "safe-name", "safe-name", "organizations/123456789012")
    assert identity_bindings(org)["ORGANIZATION_ID"] == "123456789012"
    assert "PROJECT_ID" not in identity_bindings(org)
    folder = dict(org, scope="folders/234567890123")
    assert identity_bindings(folder)["FOLDER_ID"] == "234567890123"
    numeric_project = dict(org, scope="projects/345678901234/zones/us-central1-a")
    assert identity_bindings(numeric_project)["PROJECT_NUMBER"] == "345678901234"
    assert identity_bindings(numeric_project)["PROJECT_ID_OR_NUMBER"] == "345678901234"
    assert identity_bindings(numeric_project)["LOCATION"] == "us-central1-a"
    assert "PROJECT_ID" not in identity_bindings(numeric_project)
    assert bind_command("gcloud projects get-iam-policy <PROJECT_ID_OR_NUMBER>", numeric_project).endswith("345678901234")
    for bad_scope in ("organizations/123;touch", "folders/0", "projects/345678901234$(id)", "projects/345678901234/zones/a;id"):
        assert not any(k in identity_bindings(dict(org, scope=bad_scope)) for k in ("ORGANIZATION_ID", "FOLDER_ID", "PROJECT_NUMBER", "PROJECT_ID"))


def test_snapshot_and_ami_resource_ids_are_kind_specific_and_strict():
    snapshot = finding("aws", "aws.claude_a.ebs.snapshot_encrypted", "snap-0123456789abcdef0", scope="123456789012/us-east-1")
    image = finding("aws", "aws.claude_a.ec2.ami_not_public", "ami-0123456789abcdef0", scope="123456789012/us-east-1")
    assert identity_bindings(snapshot)["RESOURCE_ID"] == "snap-0123456789abcdef0"
    assert identity_bindings(image)["RESOURCE_ID"] == "ami-0123456789abcdef0"
    assert "RESOURCE_ID" not in identity_bindings(dict(snapshot, check_id=image["check_id"]))
    assert "RESOURCE_ID" not in identity_bindings(dict(image, check_id=snapshot["check_id"]))
    for bad in ("snap-123", "snap-0123456789abcdef0;id", "ami-0123456789abcdef0$(id)"):
        assert "RESOURCE_ID" not in identity_bindings(dict(snapshot, native_resource_id=bad))


def test_template_is_factored_once_and_markdown_is_readable():
    templates = report_templates(["aws.iam.no_full_admin"] * 100, "aws")
    assert list(templates) == ["aws.iam.no_full_admin"]
    row = finding("aws", "aws.iam.no_full_admin", "arn:aws:iam::123456789012:policy/ServicePolicy", "ServicePolicy", "123456789012")
    rendered = "\n".join(_remediation_lines(row, templates))
    assert "Replace unnecessary full-administrator statements" in rendered
    assert "aws iam list-entities-for-policy" in rendered
    assert "https://docs.aws.amazon.com/" in rendered
    assert "Legacy guidance" in "\n".join(_remediation_lines(row, {}))
    injected = dict(row, remediation_details={"summary": "[click](https://bad.example) <script>",
            "steps": ["**unsafe**"], "cli": [], "references": []})
    escaped = "\n".join(_remediation_lines(injected, {}))
    assert "\\[click\\]\\(https://bad\\.example\\)" in escaped
    assert "&lt;script&gt;" in escaped


def test_schema_10_and_11_keep_legacy_string_without_inventing_a_template():
    row = dict(finding("aws", "aws.iam.no_full_admin", "arn:aws:iam::123456789012:policy/ServicePolicy", "ServicePolicy", "123456789012"),
               id="f1", category="least_privilege", title="Broad policy", service="iam", severity="high", status="FAIL",
               resource_id="resource1", frameworks=[], evidence={"full_admin_statements": 1})
    report = {"schema_version": "1.0", "provider": "aws", "snapshot_id": "s1", "scopes": ["123456789012"],
              "created_at": "2026-01-01T00:00:00Z", "stats": {}, "coverage": [], "resources": [], "graphs": {},
              "findings": [row, dict(row, id="f2", resource_id="resource2")]}
    compact = compact_report(report)
    assert compact["remediation_templates"] == {}, "historical reports cannot acquire today's template"
    assert all("remediation_details" not in item for item in compact["findings"])
    expanded = expand_report(compact, {"snapshot_id": "s1", "provider": "aws", "scopes": [], "collections": []})
    assert all(item["remediation"] == "Legacy guidance" for item in expanded["findings"])
    rendered = render_markdown(compact)
    assert rendered.count("Remediation: Legacy guidance") == 2
    assert "#### Defensive remediation" not in rendered
    assert "Legacy guidance" in render_markdown({**report, "findings": [dict(row, check_id="unreviewed")], "remediation_templates": {}})


def test_verified_description_fields_factor_once_and_render_readably(monkeypatch):
    from peaso.checks import catalog
    reviewed = {"description": "Reads the declared ingress source; reachability is separate.",
                "evaluated": ["IpPermissions[].IpRanges[].CidrIp", "IpPermissions[].FromPort"],
                "pass_when": "No matching world-open rule is declared.",
                "fail_when": "A matching world-open rule is declared.",
                "not_applicable_when": "No security group was collected."}
    monkeypatch.setattr(catalog, "description_for", lambda check_id: reviewed if check_id == "check-one" else None)
    rows = [{"check_id": "check-one", "title": "Ingress", "remediation": "Legacy review", "service": "ec2",
             "category": "exposure", "severity": "high", **reviewed} for _ in range(2)]
    meta = attach_reviewed_description_meta(factor_check_meta(rows))
    assert meta["check-one"]["evaluated"] == reviewed["evaluated"]
    assert meta["check-one"]["rationale"] == reviewed["description"]
    assert all("evaluated" not in row and "description" not in row for row in rows)
    hydrated = hydrate_finding(rows[0], None, meta)
    assert hydrated["description"] == reviewed["description"]
    assert hydrated["evaluated"] == reviewed["evaluated"]
    report = {"schema_version": "1.1", "provider": "aws", "snapshot_id": "s1", "created_at": "2026-01-01",
              "scopes": [], "stats": {}, "coverage": [], "resources": [], "graphs": {}, "findings": [
                  dict(rows[0], id="f1", provider="aws", resource_id="sg-12345678", scope="s", status="FAIL", frameworks=[], evidence={})],
              "check_meta": meta}
    markdown = render_markdown(report)
    assert "What this check evaluates" in markdown
    assert "IpPermissions\\[\\]" in markdown
    assert "A matching world-open rule is declared" in markdown

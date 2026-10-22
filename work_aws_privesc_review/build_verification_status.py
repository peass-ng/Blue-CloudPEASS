"""Build the per-technique AWS privilege-escalation validation register."""

import csv
import hashlib
import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REVIEW = Path(__file__).with_name("technique-status.tsv")
OUTPUT = Path(__file__).with_name("verification-status.tsv")
DRIFT_OUTPUT = Path(__file__).with_name("static-parity-source-drift.tsv")
PROOF_REVIEW = Path(__file__).with_name("proof-route-status.tsv")

# Each name is a catalog precondition whose evaluator reads
# aws_privesc_challenge_evidence before accepting the role effect.
PROOF_PRECONDITIONS = set("""
agentcore_new_harness_generated_scope_and_role_ready
agentcore_new_runtime_generated_scope_and_role_ready
agentcore_existing_runtime_update_and_invoke
autoscaling_created_launch_input_role_effect_reviewed
cloudformation_extension_package_and_invocation
cloudformation_new_stack_with_role
cloudformation_new_changeset_with_role
cloudformation_existing_stack_updatable_with_role
cloudformation_attached_role_stack_updatable
cloudformation_attached_role_changeset_executable
cloudformation_service_managed_stackset_targetable
codepipeline_existing_project_update_buildspec
config_automatic_remediation_effect_unverified
datapipeline_existing_customer_role_pair_and_runnable_ec2
deadline_fleet_worker_bounded_authority_reviewed
devicefarm_existing_test_spec_role_effect_reviewed
elasticbeanstalk_environment_role_effect_reviewed
emr_new_cluster_instance_role_effect_reviewed
emr_serverless_job_route
eventbridge_subscriber_has_active_bus_and_bound_permissions
gameliftstreams_controlled_application_role_session
glue_existing_job_has_runnable_trigger
glue_job_role_and_execution_bind
glue_job_override_arguments_available
kafkaconnect_plugin_execution_unverified
m2_existing_environment_new_application_deploy
mgh_automation_unit_home_region_target_and_run
mwaa_existing_environment_update_with_dag_code
mwaa_serverless_new_workflow_definition_and_start
migrationhub_orchestrator_bound_workflow_script_and_managed_target
created_org_access_role_assumable
ec2_runinstances_instance_role_effect_reviewed
sagemaker_hyperpod_custom_ami_group_role_effect
servicecatalog_new_artifact_effect_unverified
ec2_spot_fleet_instance_role_effect_reviewed
ec2_spot_request_instance_role_effect_reviewed
ssm_jit_approved_online_instance
workspaces_instances_bound_launch_role_effect
stepfunctions_teststate_privileged_task_unverified
sfn_role_sdk_effect_reviewed
codebuild_ssm_debug_session_role_effect_reviewed
ssm_existing_automation_runtime_role_effect_reviewed
bedrock_agent_actiongroup_lambda_execution_unverified
ec2_userdata_restart_execution_reviewed
ec2_instance_connect_same_running_role_host
amplify_service_role_build_effect_unverified
amplify_compute_role_ssr_effect_unverified
emr_cluster_session_runtime_role
emr_containers_job_route
emr_containers_endpoint_route
emr_containers_pod_identity_job_route
""".split())

# These focused helper tests pass without the global conftest. They exercise
# proof binding and rejection; they do not exercise catalog-to-graph wiring.
FOCUSED_HELPER_TESTS = {
    "aws-m2-passrole-createapplication-deploy": "tests/test_aws_m2_role_effect.py",
    "aws-mgh-passrole-automation-unit": "tests/test_aws_mgh_automation_role_effect.py",
    "aws-migrationhub-orchestrator-workflow-step": "tests/test_aws_orchestrator_role_effect.py",
    "aws-mwaa-passrole-updateenvironment": "tests/test_aws_mwaa_role_effect.py",
    "aws-mwaa-serverless-passrole-createworkflow": "tests/test_aws_mwaa_role_effect.py",
    "aws-organizations-createaccount-principalorgid-trust": "tests/test_aws_org_created_member_role_effect.py",
    "aws-sagemaker-updateclustersoftware-custom-ami": "tests/test_aws_sagemaker_hyperpod_role_effect.py",
    "aws-servicecatalog-associateprincipal-createartifact-provision": "tests/test_aws_servicecatalog_role_effect.py",
    "aws-servicecatalog-createprovisioningartifact-provisionproduct": "tests/test_aws_servicecatalog_role_effect.py",
    "aws-ssm-jit-startaccessrequest-getaccesstoken": "tests/test_aws_ssm_jit_role_effect.py",
    "aws-workspaces-instances-passrole-createworkspaceinstance": "tests/test_aws_workspaces_instances_role_effect.py",
}

ISOLATED_GRAPH_TESTS = {
    "aws-emr-getclustersessioncredentials-runtime-role": (
        "tests/test_peaso_privesc_emr_cluster_endpoint_role_effect.py"
    ),
    "aws-ec2-passrole-runinstances": "tests/test_peaso_privesc_runinstances_role_effect.py",
    "aws-iam-addusertogroup": "tests/test_peaso_privesc_iam_add_user_to_group.py",
    "aws-glue-passrole-createsession": "tests/test_peaso_privesc_new_workload_role_paths.py",
    "aws-sagemaker-passrole-createnotebookinstance": "tests/test_peaso_privesc_new_workload_role_paths.py",
    "aws-lambda-updatefunctioncode": "tests/test_peaso_privesc_lambda_code_update_paths.py",
    "aws-lambda-codesigning-bypass-updatefunctioncode": "tests/test_peaso_privesc_lambda_code_update_paths.py",
    "aws-lambda-putresourcepolicy-grant-updatefunctioncode": "tests/test_peaso_privesc_lambda_code_update_paths.py",
    "aws-grafana-existing-admin-serviceaccount-token": "tests/test_peaso_privesc_grafana_existing_admin_token.py",
    "aws-synthetics-startcanarydryrun-replacement-code": "tests/test_peaso_privesc_synthetics_dry_run.py",
    "aws-iam-putuserpermissionsboundary-self-admin": "tests/test_peaso_privesc_iam_boundary_gain.py",
    "aws-iam-putrolepermissionsboundary-self-admin": "tests/test_peaso_privesc_iam_role_boundary_gain.py",
    "aws-iam-putrolepermissionsboundary-assumable-admin": "tests/test_peaso_privesc_iam_role_boundary_gain.py",
    "aws-flink-updateapplication-inline-code-existing-role": "tests/test_peaso_privesc_flink_existing_inline_code.py",
    "aws-sagemaker-attach-studio-lifecycle-config-shared-space": "tests/test_peaso_privesc_sagemaker_shared_space_lcc.py",
    "aws-ecs-eventbridge-scheduled-task-role": "tests/test_peaso_privesc_ecs_eventbridge_schedule.py",
    "aws-iam-createrole-satisfy-cross-account-trust": "tests/test_peaso_privesc_iam_cross_account_new_role.py",
}

# The shared CloudFormation precondition calls the proof helper only when
# attaching a new role. These two techniques use the role already on the stack.
PROOF_FREE_ATTACHED_ROLE_TECHNIQUES = {
    "aws-cloudformation-updatestack-attached-role",
    "aws-cloudformation-changeset-attached-role",
}


def main():
    catalog = {}
    for path in sorted((ROOT / "peaso/privesc/catalog/aws").glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        for entry in yaml.safe_load(path.read_text()) or []:
            assert entry["id"] not in catalog, entry["id"]
            catalog[entry["id"]] = entry

    with REVIEW.open(newline="") as stream:
        reviewed = list(csv.DictReader(stream, delimiter="\t"))
    assert len(reviewed) == len(catalog)
    assert {row["id"] for row in reviewed} == set(catalog)
    with PROOF_REVIEW.open(newline="") as stream:
        proof_rows = {row["id"]: row for row in csv.DictReader(stream, delimiter="\t")}
    assert len(proof_rows) == 58
    test_texts = {str(path.relative_to(ROOT)): path.read_text(errors="replace")
                  for path in sorted((ROOT / "tests").glob("test_*.py"))}
    manifest = json.loads((ROOT / "peaso/server/evidence_static_source_manifest.json").read_text())
    drift = []
    for path, expected in sorted(manifest.items()):
        source = ROOT / path
        actual = hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else "missing"
        if actual != expected:
            drift.append({"path": path, "pinned_sha256": expected, "current_sha256": actual})

    records = []
    for row in reviewed:
        entry = catalog[row["id"]]
        selector = entry.get("target", {}).get("selector", {})
        matching = sorted(set(entry.get("preconditions", [])) & PROOF_PRECONDITIONS)
        if row["id"] in PROOF_FREE_ATTACHED_ROLE_TECHNIQUES:
            matching = []
        if selector.get("aws_challenge_fact"):
            matching.append("selector:aws_challenge_fact")
        if selector.get("assumable_by_pivot_role"):
            matching.append("selector:assumable_by_pivot_role")
        if row["id"] == "aws-ec2-passrole-associate-instance-profile":
            matching.append("ec2_profile_association:_proof")
        reviewed_proof = proof_rows.get(row["id"])
        assert bool(matching) == bool(reviewed_proof), row["id"]
        proof_mode = reviewed_proof["current_evaluator_disposition"] if reviewed_proof else "none"
        test_refs = sorted(set(re.findall(r"tests/[\w.-]+\.py", row["review_evidence"])))
        assert all((ROOT / path).is_file() for path in test_refs), row["id"]
        literal_refs = sorted(path for path, text in test_texts.items() if row["id"] in text)
        located_refs = sorted(set(test_refs) | set(literal_refs))
        pending = ["Audit exact positive and negative cases for this technique; run the frozen final suite"]
        if proof_mode == "external_proof_required_for_conditional":
            pending.insert(0, "Verify trusted live-effect evidence import and absent-evidence UNKNOWN behavior")
        elif proof_mode == "native_conditional_or_external_proof":
            pending.insert(0, "Verify native conditional path and external-proof fallback")
        if not located_refs:
            pending.append("Locate or add positive and negative tests for this exact technique")
        records.append({
            "id": row["id"],
            "service": row["service"],
            "catalog_review": row["status"],
            "external_proof_route": "yes" if matching else "no",
            "proof_dependency": proof_mode,
            "proof_route": ", ".join(matching),
            "named_test_file": ", ".join(test_refs),
            "literal_test_file": ", ".join(literal_refs),
            "located_test_file": ", ".join(located_refs),
            "focused_helper_test": FOCUSED_HELPER_TESTS.get(row["id"], ""),
            "focused_helper_result": "passed_normal_pytest" if row["id"] in FOCUSED_HELPER_TESTS else "not_run_in_current_audit",
            "isolated_graph_test": ISOLATED_GRAPH_TESTS.get(row["id"], ""),
            "isolated_graph_result": "passed_normal_pytest" if row["id"] in ISOLATED_GRAPH_TESTS else "not_run_in_current_audit",
            "end_to_end_suite": "pending_final_suite_after_source_freeze",
            "work_done": row["review_evidence"],
            "remaining_work": "; ".join(pending),
        })

    assert sum(r["external_proof_route"] == "yes" for r in records) == 58
    assert all(r["located_test_file"] for r in records)
    assert sum(r["focused_helper_result"] == "passed_normal_pytest" for r in records) == 11
    assert sum(r["isolated_graph_result"] == "passed_normal_pytest" for r in records) >= 8
    with OUTPUT.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=records[0].keys(), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    with DRIFT_OUTPUT.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("path", "pinned_sha256", "current_sha256"), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(drift)
    print(f"{len(records)} entries; 58 external proof routes; all with a located test file; "
          f"{len(drift)} presentation source pins pending; final suite pending")


if __name__ == "__main__":
    main()

"""Build the per-technique AWS privilege-escalation validation register."""

import csv
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REVIEW = Path(__file__).with_name("technique-status.tsv")
OUTPUT = Path(__file__).with_name("verification-status.tsv")

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
    assert len(reviewed) == len(catalog) == 211
    assert {row["id"] for row in reviewed} == set(catalog)

    records = []
    for row in reviewed:
        entry = catalog[row["id"]]
        selector = entry.get("target", {}).get("selector", {})
        matching = sorted(set(entry.get("preconditions", [])) & PROOF_PRECONDITIONS)
        if selector.get("aws_challenge_fact"):
            matching.append("selector:aws_challenge_fact")
        if selector.get("assumable_by_pivot_role"):
            matching.append("selector:assumable_by_pivot_role")
        if row["id"] == "aws-ec2-passrole-associate-instance-profile":
            matching.append("ec2_profile_association:_proof")
        test_refs = sorted(set(re.findall(r"tests/[\w.-]+\.py", row["review_evidence"])))
        pending = ["Unblock pytest import and run the full suite with this technique covered"]
        if matching:
            pending.insert(0, "Resolve external evidence supply or mark the route manual; verify present and absent evidence end to end")
        if not test_refs:
            pending.append("Record the positive and negative test file for this technique")
        records.append({
            "id": row["id"],
            "service": row["service"],
            "catalog_review": row["status"],
            "external_proof_route": "yes" if matching else "no",
            "proof_route": ", ".join(matching),
            "named_test_file": ", ".join(test_refs),
            "end_to_end_suite": "blocked_before_collection",
            "remaining_work": "; ".join(pending),
        })

    assert sum(r["external_proof_route"] == "yes" for r in records) == 60
    assert sum(bool(r["named_test_file"]) for r in records) == 111
    with OUTPUT.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=records[0].keys(), delimiter="\t")
        writer.writeheader()
        writer.writerows(records)
    print(f"{len(records)} entries; 60 external proof routes; 111 with named test file; 211 suite blocked")


if __name__ == "__main__":
    main()

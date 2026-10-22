"""Current reports resolve, while earlier strict cards retain their exact catalog."""

from peaso.privesc import versioned_catalog as catalog
from peaso.privesc.finding_explanation import evidence_summary
from tests.test_peaso_privesc_finding_explanations_review import admin_projected


def test_current_catalog_binding_resolves_new_technique():
    binding = catalog.current_binding()
    entries, status = catalog.lookup_entries(["aws-flink-studio-presigned-url"], binding)
    assert status == "exact_strict_privesc"
    assert set(entries) == {"aws-flink-studio-presigned-url"}


def test_stepfunctions_passrole_service_binding_preserves_previous_catalog():
    ids = ["aws-stepfunctions-createstatemachine-passrole-start",
           "aws-stepfunctions-updatestatemachine-passrole"]
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc"
    for ident in ids:
        passrole = next(req for req in current[ident]["requires"]["all_of"]
                        if req["action"] == "iam:PassRole")
        assert passrole["request_context"] == {"iam:PassedToService": "states.amazonaws.com"}

    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current"
    assert set(previous) == set(ids)
    for ident in ids:
        passrole = next(req for req in previous[ident]["requires"]["all_of"]
                        if req["action"] == "iam:PassRole")
        assert "request_context" not in passrole
    assert len(catalog._verified_stepfunctions_passrole_689_previous()) == 689


def test_organizations_generated_access_role_binding_preserves_previous_catalog():
    ident = "aws-organizations-createaccount-principalorgid-trust"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["requires"]["all_of"] == [
        {"action": "organizations:CreateAccount", "resource": "*"}]
    assert "created_org_access_role_assumable" in current[ident]["preconditions"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.ORG_ACCESS_ROLE_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert any(req["action"] == "sts:AssumeRole"
               for req in previous[ident]["requires"]["all_of"])
    assert len(catalog._verified_org_access_role_689_previous()) == 689


def test_servicecatalog_artifact_effect_binding_preserves_previous_catalog():
    ids = ("aws-servicecatalog-createprovisioningartifact-provisionproduct",
           "aws-servicecatalog-associateprincipal-createartifact-provision")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert all("servicecatalog_new_artifact_effect_unverified" in current[ident]["preconditions"]
               for ident in ids)
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SERVICECATALOG_EFFECT_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids)
    assert all("preconditions" not in previous[ident] for ident in ids)
    assert len(catalog._verified_servicecatalog_effect_689_previous()) == 689


def test_config_remediation_binding_preserves_previous_catalog():
    ident = "aws-config-passrole-automatic-remediation"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    entry = current[ident]
    assert "config_automatic_remediation_effect_unverified" in entry["preconditions"]
    requirements = {req["action"]: req for req in entry["requires"]["all_of"]}
    assert requirements["iam:PassRole"]["request_context"] == {
        "iam:PassedToService": "ssm.amazonaws.com"}
    assert requirements["config:PutRemediationConfigurations"]["resource"].endswith(
        ":remediation-configuration/*")
    assert requirements["ssm:CreateDocument"]["resource"].endswith(":document/*")
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.CONFIG_REMEDIATION_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]
    assert len(catalog._verified_config_remediation_689_previous()) == 689


def test_elasticbeanstalk_role_execution_binding_preserves_previous_catalog():
    ident = "aws-elasticbeanstalk-passrole-create-environment"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    entry = current[ident]
    assert "elasticbeanstalk_environment_role_execution_unverified" in entry["preconditions"]
    assert entry["requires"]["all_of"][0]["request_context"] == {
        "iam:PassedToService": "ec2.amazonaws.com"}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]
    assert len(catalog._verified_elasticbeanstalk_effect_689_previous()) == 689


def test_emr_runtime_role_binding_preserves_previous_catalog():
    ids = ("aws-emr-passrole-runjobflow",
           "aws-emr-getclustersessioncredentials-runtime-role",
           "aws-emr-addjobflowsteps-runtime-role")
    current, status = catalog.lookup_entries(ids, catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == set(ids)
    assert current[ids[0]]["requires"]["all_of"][0]["request_context"] == {
        "iam:PassedToService": "ec2.amazonaws.com"}
    assert "emr_new_cluster_role_execution_unverified" in current[ids[0]]["preconditions"]
    assert "emr_cluster_endpoint_role_effect_unverified" in current[ids[1]]["preconditions"]
    assert "emr_existing_cluster_runtime_step_role" in current[ids[2]]["preconditions"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.EMR_RUNTIME_689_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.EMR_RUNTIME_689_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries(ids, old)
    assert status == "exact_previous_current" and set(previous) == set(ids[:2])
    assert "preconditions" not in previous[ids[0]]
    assert len(catalog._verified_emr_runtime_689_previous()) == 689


def test_deadline_queue_binding_preserves_previous_catalog():
    ident = "aws-deadline-existing-queue-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_QUEUE_683_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_QUEUE_683_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_queue_683_previous()) == 683


def test_deadline_fleet_scope_correction_preserves_previous_catalog():
    ident = "aws-deadline-passrole-fleet-createworker"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ident]["preconditions"] == ["deadline_fleet_worker_binding_unverified"]
    assert current[ident]["severity"] == "high"
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_FLEET_684_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_FLEET_684_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "preconditions" not in previous[ident]
    assert previous[ident]["severity"] == "critical"
    assert len(catalog._verified_deadline_fleet_684_previous()) == 684


def test_deadline_existing_worker_binding_preserves_previous_catalog():
    ident = "aws-deadline-existing-worker-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_WORKER_684_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_WORKER_684_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_worker_684_previous()) == 684


def test_deadline_new_worker_binding_preserves_previous_catalog():
    ident = "aws-deadline-new-worker-existing-fleet-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_NEW_WORKER_685_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current" and previous == {}
    assert len(catalog._verified_deadline_new_worker_685_previous()) == 685


def test_deadline_worker_dependency_binding_preserves_previous_catalog():
    ident = "aws-deadline-new-worker-existing-fleet-role-vend"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "dependent permissions" in current[ident]["summary"]
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert "dependent permissions" not in previous[ident]["summary"]
    assert len(catalog._verified_deadline_dependencies_686_previous()) == 686


def test_cloudfront_creation_binding_retains_previous_update_only_catalog():
    ident = "aws-cloudfront-lambda-edge-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "new or existing distribution" in current[ident]["title"]
    previous_binding = {"schema": catalog.BINDING_SCHEMA,
                        "manifest_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST,
                        "effective_tree_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_TREE,
                        "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], previous_binding)
    assert status == "exact_previous_current"
    assert previous[ident]["title"] == "Associate a new Lambda@Edge function with a passed role to a distribution"
    assert len(catalog._verified_cloudfront_create_683_previous()) == 683


def test_intermediate_strict_binding_uses_retained_660_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.INTERMEDIATE_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.INTERMEDIATE_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-addjobflowsteps", "aws-flink-studio-presigned-url"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-addjobflowsteps"}
    assert len(catalog._verified_intermediate_current()) == 660


def test_previous_strict_binding_uses_retained_633_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.PREVIOUS_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.PREVIOUS_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-passrole-runjobflow", "aws-emr-addjobflowsteps"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-passrole-runjobflow"}
    assert len(catalog._verified_previous_current()) == 633


def test_quicksight_self_promotion_binding_preserves_scheduler_catalog():
    ident = "aws-quicksight-updateuser-admin"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {ident}
    old = {"schema": catalog.BINDING_SCHEMA,
           "manifest_sha256": catalog.SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST,
           "effective_tree_sha256": catalog.SCHEDULER_UPDATE_687_PREVIOUS_TREE,
           "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident, "aws-scheduler-passrole-updateschedule-self-grant"], old)
    assert status == "exact_previous_current"
    assert set(previous) == {"aws-scheduler-passrole-updateschedule-self-grant"}
    assert len(catalog._verified_scheduler_update_687_previous()) == 687


def test_azure_and_kubernetes_finding_explanations_load():
    for provider in ("azure", "k8s"):
        for confidence in ("derived", "conditional", "unknown"):
            text = evidence_summary(admin_projected(provider, confidence))
            assert text and len(text.splitlines()) == 3

"""ECScape reaches only roles carried by tasks on the source's EC2 host."""

from peaso.privesc import schema
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc import versioned_catalog

from test_peaso_privesc_aws_followups import (
    ECSCAPE, NODE_ARN, ecs_snap, placed_cluster, role_arn,
)


ENTRY = next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == ECSCAPE)


def _targets(cluster):
    model = AwsModel(ecs_snap(cluster))
    edges = Evaluator(model, [ENTRY], include_unknown=False).run()
    return {role for edge in edges if edge.source.id == NODE_ARN for role in edge.targets}


def test_colocated_execution_role_and_task_role_are_both_reachable():
    assert _targets(placed_cluster()) == {role_arn("app"), role_arn("app-execution")}


def test_execution_role_on_another_host_is_not_reachable():
    cluster = placed_cluster()
    cluster["Tasks"][0]["containerInstanceArn"] = cluster["Tasks"][1]["containerInstanceArn"]
    assert _targets(cluster) == set()


def test_task_level_execution_role_override_replaces_definition_role():
    cluster = placed_cluster()
    cluster["Tasks"][0]["overrides"] = {"executionRoleArn": role_arn("far")}
    assert _targets(cluster) == {role_arn("app"), role_arn("far")}


def test_current_and_previous_catalog_bindings_remain_exact():
    current, status = versioned_catalog.lookup_entries([ECSCAPE], versioned_catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "execution roles" in current[ECSCAPE]["target"]["aggregate_as"].lower()
    previous = dict(versioned_catalog.current_binding(),
        manifest_sha256=versioned_catalog.ECSCAPE_PREVIOUS_MANIFEST,
        effective_tree_sha256=versioned_catalog.ECSCAPE_PREVIOUS_TREE)
    old, status = versioned_catalog.lookup_entries([ECSCAPE], previous)
    assert status == "exact_previous_current"
    assert "execution roles" not in old[ECSCAPE]["target"]["aggregate_as"].lower()

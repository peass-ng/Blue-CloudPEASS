"""Image Builder component publication and execution must bind to one pipeline."""

from peaso.privesc import schema, versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, pol, role, user


SCOPE = f"{ACCOUNT}/us-east-1"
BASE = f"arn:aws:imagebuilder:us-east-1:{ACCOUNT}"
PIPELINE_A = BASE + ":image-pipeline/a"
PIPELINE_B = BASE + ":image-pipeline/b"
COMPONENT = BASE + ":component/app"
TARGET = f"arn:aws:iam::{ACCOUNT}:role/builder"
ENTRY = next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"]
             if row["id"] == "aws-imagebuilder-component-version-hijack")


def _model(*, component=COMPONENT + "/1.x.x", create=COMPONENT + "/*",
           start=PIPELINE_A, second=None, recipe_status="collected"):
    actor = user("alice", {"Effect": "Allow", "Action": "imagebuilder:CreateComponent", "Resource": create},
                 {"Effect": "Allow", "Action": "imagebuilder:StartImagePipelineExecution", "Resource": start})
    builder = role("builder", pol({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                   "Action": "sts:AssumeRole"}),
                   {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}, profile=True)
    pipelines = [{"arn": PIPELINE_A, "InstanceProfileName": "builder",
                  "RecipeComponents": {"collection_status": recipe_status, "items": [component]}}]
    if second:
        pipelines.append({"arn": PIPELINE_B, "InstanceProfileName": "builder",
                          "RecipeComponents": {"collection_status": "collected", "items": [second]}})
    return AwsModel(aws_snap([actor], [builder], [("imagebuilder_pipeline", SCOPE, pipelines)]))


def _verdict(model):
    return model.precondition("imagebuilder_component_publish_and_pipeline_start",
                              {TARGET: model.principals[TARGET]}, model.principals[ALICE]).get(TARGET)


def test_same_pipeline_unpinned_component_reaches_profile_role():
    model = _model()
    assert _verdict(model) == ("conditional", "imagebuilder_same_pipeline_component_publish_and_start")
    edges = Evaluator(model, [ENTRY], include_unknown=False).run()
    assert {target for edge in edges if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_exact_semantic_version_without_build_is_still_mutable():
    assert _verdict(_model(component=COMPONENT + "/1.2.3", create=COMPONENT + "/1.2.3/*")) == (
        "conditional", "imagebuilder_same_pipeline_component_publish_and_start")


def test_pinned_build_and_fixed_build_permission_do_not_prove_route():
    assert _verdict(_model(component=COMPONENT + "/1.2.3/1")) is None
    assert _verdict(_model(create=COMPONENT + "/1.2.3/1"))[0] == "unknown"


def test_create_and_start_grants_for_different_pipelines_do_not_mix():
    model = _model(component=BASE + ":component/other/1.x.x", create=COMPONENT + "/*",
                   start=PIPELINE_A, second=COMPONENT + "/1.x.x")
    assert _verdict(model)[0] == "unknown"
    assert Evaluator(model, [ENTRY], include_unknown=False).run() == []


def test_missing_recipe_is_unresolved():
    assert _verdict(_model(recipe_status="denied"))[0] == "unknown"


def test_current_and_previous_catalog_meanings_are_exact():
    current = versioned_catalog.current_binding()
    entries, state = versioned_catalog.lookup_entries([ENTRY["id"]], current)
    assert state == "exact_strict_privesc" and "imagebuilder_component_publish_and_pipeline_start" in entries[ENTRY["id"]]["preconditions"]
    old = dict(current, manifest_sha256=versioned_catalog.IMAGEBUILDER_PREVIOUS_MANIFEST,
               effective_tree_sha256=versioned_catalog.IMAGEBUILDER_PREVIOUS_TREE)
    entries, state = versioned_catalog.lookup_entries([ENTRY["id"]], old)
    assert state == "exact_previous_current" and not entries[ENTRY["id"]].get("preconditions")

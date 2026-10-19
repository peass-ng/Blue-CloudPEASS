"""Audit explicit policy recipes, SDK update decisions and generated coverage."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def audit_resource_types(recipes, reference, mappings=None):
    """Require a reviewed decision for every resource type in the SAR receipt."""
    families = {recipe.id for recipe in recipes}
    by_id = {recipe.id: recipe for recipe in recipes}
    if mappings is None:
        mappings = json.loads((ROOT / 'peaso/collectors/aws_resource_policy_permissions.json').read_text())["mappings"]
    targets = ancestors = 0
    for action, metadata in reference["policy_actions"].items():
        declared = set(metadata["resource_types"])
        reviewed = metadata.get("resource_type_review", {})
        assert set(reviewed) == declared, f"Unreviewed policy resource types: {action}"
        assert metadata.get("source", "").startswith("https://servicereference.us-east-1.amazonaws.com/")
        assert len(metadata.get("sha256", "")) == 64
        for resource_type, decision in reviewed.items():
            if decision["status"] == "covered":
                selected = decision.get("families", [])
                assert selected and set(selected) <= families, f"Missing attachment family: {action}/{resource_type}"
                expected = decision.get("equivalent_read", action)
                if expected != action:
                    assert decision.get("reason"), f"Unexplained equivalent read: {action}/{resource_type}"
                for family in selected:
                    recipe = by_id[family]
                    actual = mappings.get(recipe.service + "/" + str(recipe.operation))
                    assert actual == expected, f"Wrong policy attachment read: {action}/{resource_type}/{family}"
                targets += 1
            else:
                assert decision["status"] == "authorization_ancestor" and decision.get("reason"), f"Unreviewed attachment: {action}/{resource_type}"
                ancestors += 1
        if not declared:
            selected = metadata.get("account_or_wildcard_authorized_families", [])
            assert selected and set(selected) <= families, f"Missing account policy family: {action}"
    return {"reviewed_actions": len(reference["policy_actions"]),
            "covered_resource_types": targets, "authorization_ancestor_types": ancestors}


def audit_service_support(recipes, reference):
    review = reference["iam_service_support_review"]
    assert set(review["supported_services"]) == set(review["reviewed_services"]), "Unreviewed IAM support-table services"
    by_id = {recipe.id: recipe.service for recipe in recipes}
    by_id.update({"base-sns-topics": "sns", "base-sqs-queues": "sqs",
                  "base-ecr-repositories": "ecr", "base-lambda-functions": "lambda"})
    covered = exceptions = 0
    for name, decision in review["reviewed_services"].items():
        if decision["status"] == "covered":
            selected = decision.get("families", [])
            assert selected and all(by_id.get(family) in decision["sdk_services"] for family in selected), f"Missing service policy coverage: {name}"
            covered += 1
        else:
            assert decision["status"] in {"named_identity_sharing", "certificate_identity_policies"} and decision.get("reason") and decision.get("source"), f"Unreviewed service exception: {name}"
            exceptions += 1
    return {"reviewed_services": covered + exceptions, "policy_services": covered,
            "typed_identity_exceptions": exceptions}


def audit():
    import botocore.session
    from botocore import xform_name
    from peaso.collectors.aws_resource_policy_families import RECIPES, READ_ACTIONS
    from peaso.collectors.aws_resource_policy_native import READ_ACTIONS as ALL_READS
    from scripts.peaso_deploy_customer_policy import iam_action
    receipt = json.loads((ROOT / 'peaso/collectors/aws_resource_policy_exclusions.json').read_text())
    covered = ALL_READS | {tuple(pair.split('/', 1)) for pair in receipt['equivalent_reads']}
    excluded = {tuple(pair.split('/', 1)) for pair in receipt['excluded']}
    session = botocore.session.get_session()
    candidates = {(service, xform_name(op)) for service in session.get_available_services()
                  for op in session.get_service_model(service).operation_names
                  if op.startswith(('Get', 'Describe')) and ('Policy' in op or 'Policies' in op)}
    assert not candidates - covered - excluded, f'Unreviewed policy APIs: {sorted(candidates - covered - excluded)}'
    assert not excluded - candidates, f'Stale policy exclusions: {sorted(excluded - candidates)}'
    assert len({r.id for r in RECIPES}) == len(RECIPES), 'Duplicate recipe IDs'
    for pair in READ_ACTIONS:
        iam_action(*pair)
    target_reference = json.loads((ROOT / 'peaso/collectors/aws_resource_policy_targets.json').read_text())
    resource_type_review = audit_resource_types(RECIPES, target_reference)
    service_support_review = audit_service_support(RECIPES, target_reference)
    rows = [{'family': r.id, 'service': r.service, 'steps': [op for op, _, _ in r.steps],
             'policy_operation': r.operation, 'policy_path': r.document,
             'resource': r.resource, 'endpoint': r.region or 'selected region'} for r in RECIPES]
    return {'service_support_review': service_support_review, 'resource_type_review': resource_type_review, 'families': len(rows) + 4, 'sdk_services': len({r.service for r in RECIPES} | {'sns', 'sqs', 'lambda', 'ecr'}),
            'policy_api_candidates': len(candidates), 'explicit_exclusions': len(excluded),
            'base_families': ['sns topics', 'sqs queues', 'lambda functions', 'ecr repositories'], 'recipes': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = audit()
    target = ROOT / 'docs/aws-resource-policy-coverage.json'
    content = json.dumps(data, indent=2) + '\n'
    if args.write:
        target.write_text(content)
    elif not target.exists() or target.read_text() != content:
        raise SystemExit('Policy coverage report is stale; run with --write')
    print(json.dumps({key: value for key, value in data.items() if key != 'recipes'}))


if __name__ == '__main__':
    main()

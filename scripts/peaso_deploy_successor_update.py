"""Fail-closed review of one e937-to-successor CSPM update plan.

This module reads only private state, refresh evidence, a saved plan and a
reviewed contract. It never invokes Terraform or a cloud provider.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

try:
    import peaso_deploy_current_update as previous
except ModuleNotFoundError:
    from scripts import peaso_deploy_current_update as previous


ACCOUNT = previous.ACCOUNT
BACKEND = previous.BACKEND
STATE_LINEAGE = "07a58930-bf9f-7350-17e9-5e4d275a308a"
STATE_SERIAL = 26
MANAGED_COUNT = 75
MANAGED_ADDRESSES_SHA256 = "5dbfcee92b413b0da4a42cda161ff23022f84fd66c2a5c287c34ae3f3d9474b6"
REFRESH_JSON_SHA256 = "9786b988f8a976d2fc266f30e72b27dfa8652076046658f36cc8c9a3608b2a9f"
REVIEWED_DRIFT = {
    'aws_ecs_task_definition.tasks["analyzer"]': (
        'e41cb06974526b405c31eb8dc58a4d37f2b880aa6aacf9d18605ea50bee739b3',
        '06bcf1cf155dbfefc924eda8afde429005b4764afe23d181f01d2b886d8b12fa',
        '1daad9309a07ca41e4fb6808391fe837f3a2b1a12788ae8814b79df5ab428557'),
    'aws_ecs_task_definition.tasks["collector"]': (
        '1914f337d7d0a21e3a0591ba5baebe1f0d02ef6900e108686d206b75e8849178',
        'a89d1c4569a9bc194ed01fa19f25c2afbff316abbd6ca27dc74604d0ea8e8404',
        'ae469b22aa6a9c6183114bfac11d2efadc7b60fb927b304f14f2d98746773f4b'),
    'aws_iam_role.api': (
        '595e2fe6d42f753af6493c4358486aa05978ebc62ac30055d8a969da2ff0a071',
        '0d9da37a721d5b4cedd8150120cc1def4307762d7547020282f369907ea0fb2b',
        '6e8a747a359b4e4316721584161fe75098a15391400a15e3af3df089b68f208a'),
    'aws_iam_role.workflow': (
        '486e30ebb059474e48135c209b9991300f0504ec1e2ac305ea77304ba0218e92',
        '0282994fb9b8843f9a5d1ad65a78edc973bb3ebb67260afb9b1221d02cdb28cc',
        '5414b976def9700c6d1033e5d9d040e9235f7c1d79c80b9bd38c6f97992c01a0'),
    'aws_s3_bucket.templates[0]': (
        'a39fc901681a0448370d98c2386d3636a2561ba10770ab6cff30d3f8a5b84a8b',
        'a59c6771ddf9e01eb343150cab315bf1c197783e7d182090459a689b8d3c71cf',
        'b75ab92a35317a475105d8be097ab47a83ba4ede917efcb9ab7a4f6a49b9af85'),
    'aws_s3_object.customer_role_template["04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a"]': (
        '9783a155540565bad1620c566b8c93a54a3de134c3074a49a4fa88df81a817a5',
        'db29ca8e7849187389f8a205876241f89b5014bce85b3a7e583c1bdd4e2bcaef',
        '38799e1bcd6385b0cc58634bfe76dad57ea85a08a4c494016891ca57515bf739'),
    'aws_s3_object.customer_role_template["25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17"]': (
        '8327eea89ec5eeabc875848e8d52c653c943fe53a71025ed54bd4ef3ba09679b',
        '53e064a6f6d3bfb2c597e5ee59be0152f444331888572019d93e038394db08b3',
        '1b661642c98af1dedda7d61e06697ba726cf8212599b33806b22ef84ed4d582e'),
    'aws_s3_object.customer_role_template["9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f"]': (
        '5c742616b9a52d7e6f6e7ab2f6de6b8719db0dba8a0b6d216c290f9ece69641f',
        '5e0ec9b2f99a8168f6f658622da8042d74ad308c955e939711de43856f466f2c',
        '1b8601197548a480c3a14a0123b6565686994f470e0e4ac233718eeb6a321c3f'),
}
UPDATE_ACTIONS = {
    'aws_lambda_function.api': ['update'],
    'aws_lambda_function.scheduler': ['update'],
    'aws_ecs_task_definition.tasks["collector"]': ['delete', 'create'],
    'aws_ecs_task_definition.tasks["analyzer"]': ['delete', 'create'],
    'aws_iam_role_policy.workflow': ['update'],
    'aws_sfn_state_machine.scan': ['update'],
}
FIELDS = {key: previous.FIELDS[key] for key in UPDATE_ACTIONS}
UNKNOWN_FIELDS = {key: previous.UNKNOWN_FIELDS[key] for key in UPDATE_ACTIONS}
digest = previous.digest
canonical = previous.canonical
unknown = previous.unknown
changed_fields = previous.changed_fields
json_document = previous.json_document


def state_resources(state: dict) -> dict:
    if state.get('lineage') != STATE_LINEAGE or state.get('serial') != STATE_SERIAL:
        raise RuntimeError('Successor state epoch differs from e937')
    resources = {}
    for resource in state.get('resources', []):
        if resource.get('mode') != 'managed':
            continue
        if resource.get('module'):
            raise RuntimeError('Successor state has a child module')
        instances = resource.get('instances')
        if not isinstance(instances, list):
            raise RuntimeError('Successor state instance inventory is malformed')
        for instance in instances:
            address = f"{resource.get('type')}.{resource.get('name')}"
            if 'index_key' in instance:
                address += '[' + json.dumps(instance['index_key'], separators=(',', ':')) + ']'
            values = instance.get('attributes')
            if (address in resources or instance.get('deposed') or instance.get('status') == 'tainted' or
                    not isinstance(values, dict)):
                raise RuntimeError('Successor state has duplicate, tainted or malformed identity')
            if address == 'random_bytes.credential_key':
                if values.get('length') != 32 or not isinstance(values.get('hex'), str) or len(values['hex']) != 64:
                    raise RuntimeError('Successor random credential identity is malformed')
            elif not isinstance(values.get('id'), str) or not values['id']:
                raise RuntimeError('Successor state identity is missing')
            resources[address] = values
    names = '\n'.join(sorted(resources)) + '\n'
    if len(resources) != MANAGED_COUNT or digest(names.encode()) != MANAGED_ADDRESSES_SHA256:
        raise RuntimeError('Successor state managed-address inventory differs from e937')
    return resources


def reviewed_drift(rows: object, raw_resources: dict, approved: object) -> tuple[dict, list]:
    """Require the eight measured AWS 6.68.0 e937 refresh rows exactly."""
    if not isinstance(rows, list) or not isinstance(approved, dict) or set(approved) != set(REVIEWED_DRIFT):
        raise RuntimeError('Successor drift approval differs from eight reviewed rows')
    by_address = {row.get('address'): row for row in rows if isinstance(row, dict)}
    if len(by_address) != len(rows) or set(by_address) != set(REVIEWED_DRIFT):
        raise RuntimeError('Successor provider drift differs from eight reviewed rows')
    refreshed = dict(raw_resources)
    for address, row in by_address.items():
        change = row.get('change')
        if (row.get('mode') != 'managed' or row.get('module_address') or
                not isinstance(change, dict) or change.get('actions') != ['update'] or
                change.get('before') != raw_resources[address] or
                not isinstance(change.get('after'), dict) or unknown(change.get('after_unknown') or {})):
            raise RuntimeError('Successor drift identity or values differ')
        before, after = change['before'], change['after']
        expected = dict(zip(('before_sha256', 'after_sha256', 'change_sha256'), REVIEWED_DRIFT[address]))
        observed = {'before_sha256': digest(canonical(before)), 'after_sha256': digest(canonical(after)),
                    'change_sha256': digest(canonical(change))}
        if observed != expected or approved[address] != expected:
            raise RuntimeError('Successor drift differs from reviewed value hashes')
        field = 'inline_policy' if address.startswith('aws_iam_role.') else (
            'policy' if address == 'aws_s3_bucket.templates[0]' else 'tags')
        if changed_fields(change) != [field]:
            raise RuntimeError('Successor drift changed an unrelated field')
        if field == 'tags':
            if before.get('tags') is not None or after.get('tags') != {}:
                raise RuntimeError('Successor tag representation differs')
        else:
            child_address = {'aws_iam_role.api': 'aws_iam_role_policy.api',
                             'aws_iam_role.workflow': 'aws_iam_role_policy.workflow',
                             'aws_s3_bucket.templates[0]': 'aws_s3_bucket_policy.templates[0]'}[address]
            child = raw_resources[child_address]
            parent_policy = after.get('policy') if field == 'policy' else (
                after.get('inline_policy') or [{}])[0].get('policy')
            if json_document(parent_policy, 'refreshed parent policy') != json_document(
                    child.get('policy'), 'owned child policy'):
                raise RuntimeError('Successor parent policy drift differs from owned child')
            if field == 'inline_policy':
                old, new = before.get(field), after.get(field)
                if (not isinstance(old, list) or not isinstance(new, list) or len(old) != 1 or len(new) != 1 or
                        old[0].get('name') != new[0].get('name') or new[0].get('name') != child.get('name')):
                    raise RuntimeError('Successor inline policy identity differs')
            if address == 'aws_iam_role.api':
                previous.check_api_policy({'policy': before['inline_policy'][0]['policy']},
                                          {'policy': after['inline_policy'][0]['policy']})
            elif address == 'aws_iam_role.workflow':
                if not previous.task_refs_equal(before['inline_policy'][0]['policy'],
                                                after['inline_policy'][0]['policy']):
                    raise RuntimeError('Successor workflow role drift differs from owned task revisions')
            else:
                previous.check_template_policy({'policy': before['policy']},
                                               {'policy': after['policy']}, raw_resources)
        refreshed[address] = after
    return refreshed, rows


def check_change(row: dict, resources: dict) -> None:
    address, change = row['address'], row['change']
    if change.get('actions') != UPDATE_ACTIONS[address]:
        raise RuntimeError('Successor action differs from its owned address')
    before, after, markers = change.get('before'), change.get('after'), change.get('after_unknown') or {}
    if before != resources.get(address) or not isinstance(after, dict) or not isinstance(markers, dict):
        raise RuntimeError('Successor changed resource is not the refreshed owned resource')
    if {key for key, value in markers.items() if unknown(value)} - UNKNOWN_FIELDS[address]:
        raise RuntimeError('Successor plan defers security or identity values')
    fields = set(changed_fields(change))
    if fields - FIELDS[address]:
        raise RuntimeError('Successor plan changes fields outside the owned allowlist')
    if address.startswith('aws_lambda_function.'):
        if not {'source_code_hash', 'environment'} <= fields:
            raise RuntimeError('Successor Lambda source and version must both change')
        previous.check_lambda(before, after)
        old = (before.get('environment') or [{}])[0].get('variables')
        new = (after.get('environment') or [{}])[0].get('variables')
        if {key for key in old if old[key] != new[key]} - {'PEASO_SOURCE_VERSION', 'PEASO_SOURCE_URL'}:
            raise RuntimeError('Successor Lambda changed a customer-role or unrelated environment value')
    elif address.startswith('aws_ecs_task_definition.'):
        if 'container_definitions' not in fields:
            raise RuntimeError('Successor worker image and source must change')
        previous.check_task(before, after)
        previous.check_ecs_defaults(before, after, markers)
    elif address in {'aws_iam_role_policy.workflow', 'aws_sfn_state_machine.scan'}:
        field = 'policy' if address == 'aws_iam_role_policy.workflow' else 'definition'
        if field not in fields:
            raise RuntimeError('Successor workflow task references must change')
        if unknown(markers.get(field, False)):
            if markers.get(field) is not True or not isinstance(before.get(field), str):
                raise RuntimeError('Successor task references have malformed unknown marker')
        elif not previous.task_refs_equal(before.get(field), after.get(field)):
            raise RuntimeError('Successor task references changed beyond owned revisions')


def review(data: dict, contract: dict, state: dict, refresh: dict, infra: Path) -> dict:
    if (data.get('errored') is not False or data.get('applyable') is not True or
            data.get('complete') is not True or data.get('terraform_version') != '1.14.3'):
        raise RuntimeError('Successor saved plan is incomplete, errored or from another Terraform version')
    if set(contract) != {'schema', 'account', 'backend', 'state', 'refresh', 'plan', 'release',
                         'approved_changes', 'approved_drift'}:
        raise RuntimeError('Successor contract has missing or unreviewed fields')
    if (contract.get('schema') != 'peaso-successor-update-v1' or contract.get('account') != ACCOUNT or
            contract.get('backend') != BACKEND):
        raise RuntimeError('Successor contract scope differs')
    raw_resources = state_resources(state)
    refresh_rows = refresh.get('resource_drift')
    if (refresh.get('errored') is not False or refresh.get('terraform_version') != '1.14.3' or
            not isinstance(refresh_rows, list)):
        raise RuntimeError('Successor refresh evidence is malformed or from another Terraform version')
    if data.get('resource_drift') != refresh_rows:
        raise RuntimeError('Successor saved plan drift differs from exact refresh evidence')
    resources, drift_rows = reviewed_drift(refresh_rows, raw_resources, contract.get('approved_drift'))
    state_meta = contract.get('state') or {}
    if (set(state_meta) != {'path', 'sha256', 'lineage', 'serial', 'managed_address_sha256'} or
            state_meta.get('lineage') != STATE_LINEAGE or state_meta.get('serial') != STATE_SERIAL or
            state_meta.get('managed_address_sha256') != MANAGED_ADDRESSES_SHA256):
        raise RuntimeError('Successor state contract identity differs')
    prior_root = data.get('prior_state', {}).get('values', {}).get('root_module', {})
    if prior_root.get('child_modules'):
        raise RuntimeError('Successor saved plan has child modules')
    prior = prior_root.get('resources')
    if (not isinstance(prior, list) or len(prior) != MANAGED_COUNT + len(previous.PRIOR_DATA_SOURCES) or
            any(not isinstance(row, dict) or row.get('mode') not in {'managed', 'data'} for row in prior)):
        raise RuntimeError('Successor prior inventory differs')
    previous.check_prior_data_sources(state, [row for row in prior if row['mode'] == 'data'])
    prior_managed = [row for row in prior if row['mode'] == 'managed']
    prior_values = {row['address']: row.get('values') for row in prior_managed}
    if len(prior_values) != MANAGED_COUNT or prior_values != resources:
        raise RuntimeError('Successor prior values differ from reviewed state plus drift')
    prior_identity = {row['address']: row for row in prior_managed}
    for address, row in prior_identity.items():
        base = f"{row.get('type')}.{row.get('name')}"
        indexed = base + '[' + json.dumps(row['index'], separators=(',', ':')) + ']' if 'index' in row else base
        expected_provider = ('registry.terraform.io/hashicorp/random' if row.get('type') == 'random_bytes'
                             else 'registry.terraform.io/hashicorp/aws')
        if (address != indexed or row.get('provider_name') != expected_provider or
                not isinstance(row.get('schema_version'), int)):
            raise RuntimeError('Successor prior resource identity or provider differs')
    rows = data.get('resource_changes')
    if (not isinstance(rows, list) or any(not isinstance(row, dict) or row.get('mode') != 'managed' or
                                          row.get('module_address') for row in rows)):
        raise RuntimeError('Successor plan has unmanaged or child-module changes')
    by_address = {row.get('address'): row for row in rows}
    if len(by_address) != MANAGED_COUNT or len(by_address) != len(rows) or set(by_address) != set(resources):
        raise RuntimeError('Successor plan managed-address inventory differs')
    approved = contract.get('approved_changes')
    if not isinstance(approved, dict) or set(approved) != set(UPDATE_ACTIONS):
        raise RuntimeError('Successor contract must approve exactly six owned actions')
    observed = {}
    for address, row in by_address.items():
        prior_row = prior_identity[address]
        for key in ('mode', 'type', 'name', 'index', 'provider_name'):
            if row.get(key) != prior_row.get(key):
                raise RuntimeError('Successor changed-row resource identity differs from prior state')
        change = row.get('change')
        if not isinstance(change, dict):
            raise RuntimeError('Successor resource change is malformed')
        if address not in UPDATE_ACTIONS:
            if (change.get('actions') != ['no-op'] or change.get('before') != resources[address] or
                    change.get('after') != resources[address] or unknown(change.get('after_unknown') or {})):
                raise RuntimeError('Successor unrelated address is not an exact no-op')
            continue
        check_change(row, resources)
        expected = {'actions': change['actions'], 'changed_fields': changed_fields(change),
                    'change_sha256': digest(canonical(change))}
        if approved[address] != expected:
            raise RuntimeError('Successor approved action differs from exact plan values')
        observed[address] = expected
    return {'state': state, 'resources': resources, 'drift_rows': drift_rows,
            'approved_changes': observed, 'lineage': STATE_LINEAGE, 'serial': STATE_SERIAL}


def load_context(plan: Path, raw_json: bytes, data: dict, contract_path: Path,
                 approved_sha256: str, infra: Path, build: Path) -> dict:
    contract = json_document(previous.private_artifact(contract_path, approved_sha256).decode(),
                             'successor approved contract')
    plan_meta, state_meta, refresh_meta = (contract.get(key) or {} for key in ('plan', 'state', 'refresh'))
    if (set(plan_meta) != {'sha256', 'json_sha256', 'json_path'} or
            plan_meta['sha256'] != digest(plan.read_bytes()) or plan_meta['json_sha256'] != digest(raw_json) or
            previous.private_artifact(Path(plan_meta['json_path']), plan_meta['json_sha256']) != raw_json):
        raise RuntimeError('Successor saved binary or JSON differs from approved bytes')
    if (set(refresh_meta) != {'path', 'sha256'} or refresh_meta.get('sha256') != REFRESH_JSON_SHA256):
        raise RuntimeError('Successor refresh evidence digest differs from e937')
    refresh = json_document(previous.private_artifact(Path(refresh_meta['path']), REFRESH_JSON_SHA256).decode(),
                            'e937 refresh evidence')
    state = json_document(previous.private_artifact(Path(state_meta.get('path', '')),
                                                    state_meta.get('sha256', '')).decode(), 'private state')
    release_meta = contract.get('release') or {}
    if set(release_meta) != {'source_version', 'release_json_sha256', 'source_zip_sha256',
                            'api_zip_sha256', 'frontend_manifest_sha256', 'worker_image'}:
        raise RuntimeError('Successor release contract is incomplete')
    release_path = build / 'release.json'
    if digest(release_path.read_bytes()) != release_meta['release_json_sha256']:
        raise RuntimeError('Successor release manifest changed')
    release = json_document(release_path.read_text(), 'successor release')
    files = release.get('files')
    root = infra.parent.parent
    required = {'scripts/peaso_deploy.py', 'scripts/peaso_deploy_successor_update.py',
                'scripts/peaso_deploy_current_update.py', 'infra/aws/versions.tf',
                'infra/aws/storage.tf', 'infra/aws/.terraform.lock.hcl', 'infra/aws/sdk-constraints.txt'}
    if not isinstance(files, dict) or not required.issubset(files):
        raise RuntimeError('Successor frozen source manifest is incomplete')
    for name, expected in files.items():
        path = root / name
        if (not isinstance(name, str) or not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected) or
                not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or
                digest(path.read_bytes()) != expected):
            raise RuntimeError(f'Successor frozen source differs: {name}')
    version = release.get('source_version')
    if (not isinstance(version, str) or not re.fullmatch(r'[a-f0-9]{64}', version) or
            version != release_meta.get('source_version')):
        raise RuntimeError('Successor release version differs')
    artifacts = {'source_zip_sha256': build / f'peaso-source-{version}.zip',
                 'api_zip_sha256': build / 'api.zip',
                 'frontend_manifest_sha256': build / 'frontend-build.json'}
    for key, path in artifacts.items():
        if digest(path.read_bytes()) != release_meta.get(key):
            raise RuntimeError(f'Successor release artifact differs: {key}')
    variables = json_document((infra / 'deployment.auto.tfvars.json').read_text(), 'deployment variables')
    image = release_meta.get('worker_image')
    if (not isinstance(image, str) or not re.fullmatch(
            rf'{ACCOUNT}\.dkr\.ecr\.us-east-1\.amazonaws\.com/hacktricks-cspm-worker@sha256:[a-f0-9]{{64}}', image) or
            variables.get('worker_image') != image or variables.get('source_version') != version or
            Path(variables.get('api_zip', '')) != artifacts['api_zip_sha256']):
        raise RuntimeError('Successor image, source or API ZIP variables differ')
    context = review(data, contract, state, refresh, infra)
    context.update({'contract_path': str(contract_path), 'contract_sha256': approved_sha256,
                    'state_sha256': state_meta['sha256'], 'release': release_meta})
    if (digest(previous.private_artifact(contract_path, approved_sha256)) != approved_sha256 or
            digest(plan.read_bytes()) != plan_meta['sha256']):
        raise RuntimeError('Successor approval or saved plan changed during review')
    return context


def check_resolved_documents(resources: dict, planned_rows: dict, workflow: dict,
                             workflow_policy: dict, api_policy: dict, template_policy: dict,
                             revisions: dict) -> None:
    """Read back complete unchanged policies and exact new task references."""
    if set(revisions) != {'collector', 'analyzer'}:
        raise RuntimeError('Successor resolved task revisions are incomplete')
    expected_arns = set(revisions.values())
    for address, actual in (('aws_sfn_state_machine.scan', workflow),
                            ('aws_iam_role_policy.workflow', workflow_policy)):
        field = 'definition' if address == 'aws_sfn_state_machine.scan' else 'policy'
        text = json.dumps(actual, sort_keys=True)
        before = resources[address].get(field)
        if not previous.task_refs_equal(before, text):
            raise RuntimeError('Successor resolved workflow changes beyond owned task references')
        found = {match.group(0) for match in previous.OWNED_TASK_ARN.finditer(text)}
        if found != expected_arns:
            raise RuntimeError('Successor resolved workflow points to another task revision')
        planned = planned_rows[address]['change']
        if not unknown((planned.get('after_unknown') or {}).get(field, False)) and json_document(
                planned['after'].get(field), 'planned task references') != json_document(text, 'resolved task references'):
            raise RuntimeError('Successor resolved task references differ from plan')
    for address, actual in (('aws_iam_role_policy.api', api_policy),
                            ('aws_s3_bucket_policy.templates[0]', template_policy)):
        expected = json_document(resources[address].get('policy'), 'unchanged owned policy')
        if actual != expected:
            raise RuntimeError('Successor resolved unchanged policy differs from baseline')

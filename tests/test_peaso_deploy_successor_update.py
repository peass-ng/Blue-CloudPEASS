"""Exact e937 successor drift and six-action review, using private QA inputs.

Set PEASO_SUCCESSOR_QA_STATE and PEASO_SUCCESSOR_QA_REFRESH to the reviewed
mode-0600 state and refresh JSON paths for the local release gate. The test
contains no state, policy, credential, or provider response bytes itself.
"""
from __future__ import annotations

import copy
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from scripts import peaso_deploy as deploy
from scripts import peaso_deploy_successor_update as successor


def private_inputs():
    state_path = os.environ.get('PEASO_SUCCESSOR_QA_STATE')
    refresh_path = os.environ.get('PEASO_SUCCESSOR_QA_REFRESH')
    if not state_path or not refresh_path:
        raise unittest.SkipTest('Exact private e937 state and refresh QA paths were not supplied')
    paths = (Path(state_path), Path(refresh_path))
    for path in paths:
        if not path.is_absolute() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError('Successor QA input must be an existing absolute mode-0600 file')
    if successor.digest(paths[1].read_bytes()) != successor.REFRESH_JSON_SHA256:
        raise AssertionError('Successor QA refresh JSON differs from the pinned review')
    return json.loads(paths[0].read_text()), json.loads(paths[1].read_text())


def normal_plan_fixture(state, refresh):
    """Conserve real 75/7 prior values and add only reviewed six source changes."""
    data = copy.deepcopy(refresh)
    rows = []
    for prior in data['prior_state']['values']['root_module']['resources']:
        if prior['mode'] != 'managed':
            continue
        address = prior['address']
        before = copy.deepcopy(prior['values'])
        after = copy.deepcopy(before)
        markers = {}
        actions = ['no-op']
        if address in successor.UPDATE_ACTIONS:
            actions = successor.UPDATE_ACTIONS[address]
            if address.startswith('aws_lambda_function.'):
                after['source_code_hash'] = 'TmV3U291cmNlU2hhMjU2Qnl0ZXM='
                after['environment'][0]['variables']['PEASO_SOURCE_VERSION'] = 'f' * 64
            elif address.startswith('aws_ecs_task_definition.'):
                container = json.loads(after['container_definitions'])
                container[0]['image'] = '202533532952.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker@sha256:' + 'f' * 64
                for item in container[0]['environment']:
                    if item['name'] == 'PEASO_SOURCE_VERSION':
                        item['value'] = 'f' * 64
                after['container_definitions'] = json.dumps(container)
                after['enable_fault_injection'] = None
                after['ipc_mode'] = None
                after['pid_mode'] = None
                after['tags'] = None
                after['volume'][0].pop('configure_at_launch')
                markers = {'enable_fault_injection': True,
                           'volume': [{'configure_at_launch': True,
                                       'docker_volume_configuration': [],
                                       'efs_volume_configuration': [],
                                       'fsx_windows_file_server_volume_configuration': [],
                                       's3files_volume_configuration': []}]}
            else:
                field = 'policy' if address == 'aws_iam_role_policy.workflow' else 'definition'
                after[field] = after[field].replace('hacktricks-cspm-collector:6', 'hacktricks-cspm-collector:7').replace(
                    'hacktricks-cspm-analyzer:6', 'hacktricks-cspm-analyzer:7')
        change = {'actions': actions, 'before': before, 'after': after, 'after_unknown': markers}
        row = {key: prior[key] for key in ('address', 'mode', 'type', 'name', 'provider_name')}
        if 'index' in prior:
            row['index'] = prior['index']
        row['change'] = change
        rows.append(row)
    data['resource_changes'] = rows
    data['resource_drift'] = copy.deepcopy(refresh['resource_drift'])
    data.update({'errored': False, 'applyable': True, 'complete': True, 'terraform_version': '1.14.3'})
    approved = {}
    for row in rows:
        if row['address'] in successor.UPDATE_ACTIONS:
            change = row['change']
            approved[row['address']] = {'actions': change['actions'],
                                        'changed_fields': successor.changed_fields(change),
                                        'change_sha256': successor.digest(successor.canonical(change))}
    contract = {'schema': 'peaso-successor-update-v1', 'account': successor.ACCOUNT,
                'backend': successor.BACKEND,
                'state': {'path': '/private/state.json', 'sha256': '0' * 64,
                          'lineage': successor.STATE_LINEAGE, 'serial': successor.STATE_SERIAL,
                          'managed_address_sha256': successor.MANAGED_ADDRESSES_SHA256},
                'refresh': {'path': '/private/refresh.json', 'sha256': successor.REFRESH_JSON_SHA256},
                'plan': {'sha256': '1' * 64, 'json_sha256': '2' * 64, 'json_path': '/private/plan.json'},
                'release': {'source_version': 'f' * 64, 'release_json_sha256': '3' * 64,
                            'source_zip_sha256': '4' * 64, 'api_zip_sha256': '5' * 64,
                            'frontend_manifest_sha256': '6' * 64, 'worker_image': 'fixture'},
                'approved_changes': approved,
                'approved_drift': {address: dict(zip(('before_sha256', 'after_sha256', 'change_sha256'), digests))
                                   for address, digests in successor.REVIEWED_DRIFT.items()}}
    return data, contract


class SuccessorActualShape(unittest.TestCase):
    def setUp(self):
        self.state, self.refresh = private_inputs()
        self.data, self.contract = normal_plan_fixture(self.state, self.refresh)

    def review(self):
        return successor.review(self.data, self.contract, self.state, self.refresh, Path('/private/infra'))

    def test_real_seventy_five_resource_eight_drift_six_action_shape(self):
        context = self.review()
        self.assertEqual(len(context['resources']), 75)
        self.assertEqual(len(context['drift_rows']), 8)
        self.assertEqual(set(context['approved_changes']), set(successor.UPDATE_ACTIONS))
        self.assertEqual(sum(row['change']['actions'] == ['no-op'] for row in self.data['resource_changes']), 69)

    def test_unreviewed_drift_or_policy_action_fails_even_if_action_hash_is_changed(self):
        self.data['resource_drift'][0]['change']['after']['tags'] = {'unexpected': 'value'}
        with self.assertRaisesRegex(RuntimeError, 'drift'):
            self.review()
        self.data, self.contract = normal_plan_fixture(self.state, self.refresh)
        api = next(row for row in self.data['resource_changes'] if row['address'] == 'aws_iam_role_policy.api')
        api['change']['after']['policy'] = json.dumps({'Version': '2012-10-17', 'Statement': []})
        with self.assertRaisesRegex(RuntimeError, 'exact no-op'):
            self.review()

    def test_foreign_address_unknown_security_field_and_old_state_fail(self):
        self.data['resource_changes'].append({'mode': 'managed', 'address': 'aws_s3_bucket.wiki',
                                              'change': {'actions': ['create'], 'before': None, 'after': {}}})
        with self.assertRaisesRegex(RuntimeError, 'managed-address inventory'):
            self.review()
        self.data, self.contract = normal_plan_fixture(self.state, self.refresh)
        api = next(row for row in self.data['resource_changes'] if row['address'] == 'aws_lambda_function.api')
        api['change']['after_unknown']['role'] = True
        self.contract['approved_changes'][api['address']]['change_sha256'] = successor.digest(
            successor.canonical(api['change']))
        with self.assertRaisesRegex(RuntimeError, 'defers security'):
            self.review()
        self.data, self.contract = normal_plan_fixture(self.state, self.refresh)
        self.state['serial'] = 25
        with self.assertRaisesRegex(RuntimeError, 'state epoch'):
            self.review()

    def test_outer_plan_summary_routes_full_actual_shape_to_successor_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / 'successor.tfplan'
            plan.write_bytes(b'private offline successor fixture')
            package = Path(folder) / 'api.zip'
            package.write_bytes(b'private offline package fixture')
            code_hash = base64.b64encode(hashlib.sha256(package.read_bytes()).digest()).decode()
            for row in self.data['resource_changes']:
                if row['address'] in {'aws_lambda_function.api', 'aws_lambda_function.scheduler'}:
                    row['change']['after']['filename'] = str(package)
                    row['change']['after']['source_code_hash'] = code_hash
                    self.contract['approved_changes'][row['address']] = {
                        'actions': row['change']['actions'],
                        'changed_fields': successor.changed_fields(row['change']),
                        'change_sha256': successor.digest(successor.canonical(row['change']))}
            reviewed = self.review()
            reviewed.update({'contract_path': '/private/successor.json', 'contract_sha256': 'a' * 64,
                             'state_sha256': 'b' * 64, 'release': self.contract['release']})
            by_address = {row['address']: row for row in self.data['resource_changes']}
            sizes = {stage: {key: int(by_address[f'aws_ecs_task_definition.tasks["{stage}"]']['change']['after'][key])
                             for key in ('cpu', 'memory')}
                     for stage in ('collector', 'analyzer')}
            workers = {}
            for stage in sizes:
                container = json.loads(by_address[f'aws_ecs_task_definition.tasks["{stage}"]']['change']['after'][
                    'container_definitions'])[0]
                workers[stage] = {item['name']: item['value'] for item in container['environment']}
            api = by_address['aws_lambda_function.api']['change']['after']['environment'][0]['variables']
            expectations = {'worker_image': json.loads(by_address[
                'aws_ecs_task_definition.tasks["collector"]']['change']['after']['container_definitions'])[0]['image'],
                'worker_resources': sizes, 'worker_environments': workers,
                'api_environment': api, 'api_zip': str(package)}
            with (patch.object(deploy, 'terraform', return_value=SimpleNamespace(stdout=json.dumps(self.data))),
                  patch.object(deploy, 'deployment_expectations', return_value=expectations),
                  patch.object(deploy.successor_update, 'load_context', return_value=reviewed),
                  contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaisesRegex(RuntimeError, 'Destructive plan refused'):
                    deploy.plan_summary(plan)
                result = deploy.plan_summary(plan, successor_update_contract=Path('/private/successor.json'),
                                             successor_update_sha256='a' * 64)
            self.assertEqual(result, hashlib.sha256(plan.read_bytes()).hexdigest())
            summary = json.loads(plan.with_suffix('.review.json').read_text())
            self.assertEqual(summary['successor_update']['serial'], successor.STATE_SERIAL)
            self.assertEqual(len(summary['successor_update']['approved_addresses']), 6)

    def test_outer_preapply_compares_full_state_and_exact_eight_drift_rows(self):
        context = self.review()
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / 'successor.tfplan'
            plan.write_bytes(b'private offline successor fixture')
            session = MagicMock()
            session.client('sts').get_caller_identity.return_value = {'Account': successor.ACCOUNT}
            session.client('stepfunctions').list_executions.return_value = {'executions': []}
            session.client('ecs').list_tasks.return_value = {'taskArns': []}
            session.client('dynamodb').get_item.return_value = {}
            session.client('dynamodb').scan.return_value = {'Count': 0}
            def terraform(*args, **_kwargs):
                if args[0] == 'state': return SimpleNamespace(stdout=json.dumps(self.state))
                if args[0] == 'plan': return SimpleNamespace(stdout='')
                if args[0] == 'show':
                    return SimpleNamespace(stdout=json.dumps(
                        self.refresh if 'never-apply-refresh' in str(args[-1]) else self.data))
                raise AssertionError('Unexpected Terraform command')
            contract = json.dumps({'plan': {'sha256': hashlib.sha256(plan.read_bytes()).hexdigest()}}).encode()
            with (patch.object(deploy, 'BUILD', Path(folder)),
                  patch.object(deploy, 'verify_backend'),
                  patch.object(deploy, 'terraform', side_effect=terraform),
                  patch.object(deploy.successor_update, 'load_context', return_value=context),
                  patch.object(deploy.current_update, 'private_artifact', return_value=contract)):
                deploy.verify_current_update_live(plan, Path('/private/successor.json'), 'a' * 64,
                                                  session, successor=True)
                altered = copy.deepcopy(self.refresh)
                altered['resource_drift'][0]['change']['after']['tags'] = {'foreign': 'yes'}
                def changed_terraform(*args, **kwargs):
                    if args[0] == 'show' and 'never-apply-refresh' in str(args[-1]):
                        return SimpleNamespace(stdout=json.dumps(altered))
                    return terraform(*args, **kwargs)
                with patch.object(deploy, 'terraform', side_effect=changed_terraform):
                    with self.assertRaisesRegex(RuntimeError, 'exact reviewed drift'):
                        deploy.verify_current_update_live(plan, Path('/private/successor.json'), 'a' * 64,
                                                          session, successor=True)

    def test_outer_resolved_branch_reads_unchanged_policies_and_immutable_objects(self):
        context = self.review()
        by_address = {row['address']: row for row in self.data['resource_changes']}
        workflow = json.loads(by_address['aws_sfn_state_machine.scan']['change']['after']['definition'])
        revisions = {stage: f'arn:aws:ecs:us-east-1:{successor.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:7'
                     for stage in ('collector', 'analyzer')}
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / 'successor.tfplan'
            plan.write_bytes(b'private offline successor fixture')
            session = MagicMock()
            iam = session.client('iam')
            def get_role_policy(*, RoleName, PolicyName):
                address = 'aws_iam_role_policy.api' if RoleName.endswith('-api') else 'aws_iam_role_policy.workflow'
                text = (context['resources'][address]['policy'] if address.endswith('.api') else
                        by_address[address]['change']['after']['policy'])
                return {'PolicyDocument': json.loads(text)}
            iam.get_role_policy.side_effect = get_role_policy
            s3 = session.client('s3')
            s3.get_bucket_policy.return_value = {'Policy': context['resources']['aws_s3_bucket_policy.templates[0]']['policy']}
            source = Path(__file__).resolve().parents[1] / 'infra/aws'
            def get_object(*, Bucket, Key, **_kwargs):
                name = ('customer-role-9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f.json'
                        if Key == deploy.CUSTOMER_ROLE_DOWNLOAD_KEY else Key)
                content = (source / name).read_bytes()
                digest = hashlib.sha256(content).hexdigest()
                response = {'Body': io.BytesIO(content), 'ContentLength': len(content),
                            'ContentType': 'application/json',
                            'ContentDisposition': 'attachment; filename="customer-role.json"',
                            'ServerSideEncryption': 'AES256', 'StorageClass': 'STANDARD',
                            'BucketKeyEnabled': False, 'ChecksumType': 'FULL_OBJECT',
                            'ChecksumSHA256': base64.b64encode(hashlib.sha256(content).digest()).decode()}
                if Key != deploy.CUSTOMER_ROLE_DOWNLOAD_KEY:
                    response.update({'Metadata': {'sha256': digest},
                                     'CacheControl': 'public,max-age=31536000,immutable'})
                return response
            s3.get_object.side_effect = get_object
            s3.get_object_acl.return_value = {'Owner': {'ID': 'owned'}, 'Grants': [
                {'Grantee': {'ID': 'owned', 'Type': 'CanonicalUser'}, 'Permission': 'FULL_CONTROL'}]}
            with (patch.object(deploy, 'terraform', return_value=SimpleNamespace(stdout=json.dumps(self.data))),
                  patch.object(deploy.successor_update, 'load_context', return_value=context)):
                deploy.verify_current_update_resolved(session, plan, Path('/private/successor.json'),
                                                      'a' * 64, workflow, revisions, successor=True)
                bad = copy.deepcopy(context['resources']['aws_iam_role_policy.api'])
                bad['policy'] = '{"Statement":[]}'
                iam.get_role_policy.side_effect = lambda **kw: (
                    {'PolicyDocument': json.loads(bad['policy'])} if kw['RoleName'].endswith('-api')
                    else get_role_policy(**kw))
                with self.assertRaisesRegex(RuntimeError, 'unchanged policy'):
                    deploy.verify_current_update_resolved(session, plan, Path('/private/successor.json'),
                                                          'a' * 64, workflow, revisions, successor=True)


class SuccessorStateSerialization(unittest.TestCase):
    def test_full_validation_row_multiset_and_only_proven_two_object_order(self):
        rows = [{'object_kind': 'var', 'config_addr': f'var.owned_{index}', 'status': 'pass',
                 'objects': [{'object_addr': f'var.owned_{index}', 'status': 'pass'}]}
                for index in range(6)]
        rows.append({'object_kind': 'resource', 'config_addr': 'aws_s3_object.customer_role_template',
                     'status': 'pass', 'objects': [
                         {'object_addr': 'aws_s3_object.customer_role_template["old-a"]', 'status': 'pass'},
                         {'object_addr': 'aws_s3_object.customer_role_template["old-b"]', 'status': 'pass'}]})
        state = {'lineage': successor.STATE_LINEAGE, 'serial': successor.STATE_SERIAL,
                 'resources': [{'instances': [{'attributes': {'id': 'owned', 'enabled': False}}]}],
                 'check_results': rows}
        reordered = copy.deepcopy(state)
        reordered['check_results'].reverse()
        reordered['check_results'][0]['objects'].reverse()
        self.assertTrue(deploy.successor_live_state_matches(reordered, state))
        for mutation in ('status', 'object', 'duplicate', 'serial', 'resource', 'five-objects'):
            changed = copy.deepcopy(reordered)
            if mutation == 'status': changed['check_results'][0]['status'] = 'fail'
            elif mutation == 'object': changed['check_results'][0]['objects'][0]['status'] = 'fail'
            elif mutation == 'duplicate': changed['check_results'][1] = copy.deepcopy(changed['check_results'][0])
            elif mutation == 'serial': changed['serial'] += 1
            elif mutation == 'resource': changed['resources'][0]['instances'][0]['attributes']['enabled'] = 0
            else:
                extra = [{'object_addr': f'aws_s3_object.customer_role_template["new-{i}"]', 'status': 'pass'}
                         for i in range(3)]
                changed['check_results'][0]['objects'].extend(extra)
                baseline = copy.deepcopy(state)
                baseline['check_results'][-1]['objects'].extend(extra)
                self.assertFalse(deploy.successor_live_state_matches(changed, baseline))
                continue
            with self.subTest(mutation=mutation):
                self.assertFalse(deploy.successor_live_state_matches(changed, state))


if __name__ == '__main__':
    unittest.main()

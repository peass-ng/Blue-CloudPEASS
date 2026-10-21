"""Full metadata scope allowlists preserve bounded optional content selection."""
from copy import deepcopy
import importlib
import unittest
NAMES = (
    'aws_lambda_environment_secret_indicators',
    'aws_selected_configuration_secret_indicators',
    'aws_s3_selected_source_secret_indicators',
    'aws_workload_command_source_20261020',
)
NEW = {name: importlib.import_module('peaso.collectors.' + name) for name in NAMES}

REGIONS = ('us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1',
           'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
           'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
           'ap-northeast-2', 'ap-south-1', 'sa-east-1', 'ca-central-1',
           'af-south-1')
ACCOUNT = '123456789012'
SCOPES = [ACCOUNT + '/' + region for region in REGIONS]
LARGE_SCOPES = [f'{123456789012 + i:012d}/us-east-1' for i in range(850)]


def target(name, scope):
    account, region = scope.split('/')
    if name == NAMES[0]:
        return f'arn:aws:lambda:{region}:{account}:function:Example'
    if name == NAMES[1]:
        return {'surface': 'ecs_environment', 'scope': scope,
                'resource_id': f'arn:aws:ecs:{region}:{account}:task-definition/Example:1'}
    if name == NAMES[2]:
        return {'scope': scope, 'bucket': 'example-source-bucket',
                'key': 'source.txt', 'format': 'text'}
    return {'scope': scope, 'service': 'ecs',
            'definition_arn': f'arn:aws:ecs:{region}:{account}:task-definition/Example:1'}


def options(name, targets):
    module = NEW[name]
    if name == NAMES[3]:
        return {'check_id': module.CHECK, 'content_secret_scans': True,
                'content_secret_scan_grants': [module.GRANT], module.OPTION: targets}
    return {'content_secret_scans': True, '_content_secret_scan_kinds': [module.KIND],
            module.OPTION: targets}


def select(module, name, opts, scopes):
    if name == NAMES[3]:
        return module.prepare(opts, scopes)
    return module.selected_targets(opts, scopes)


class ScopePreflight(unittest.TestCase):
    def test_full_connector_allowlist_with_one_target(self):
        for name in NAMES:
            for scopes in (SCOPES, LARGE_SCOPES[:257], LARGE_SCOPES):
                with self.subTest(name=name, count=len(scopes)):
                    value = target(name, scopes[0]); opts = options(name, [value])
                    before = deepcopy((opts, scopes))
                    self.assertTrue(select(NEW[name], name, opts, scopes))
                    self.assertEqual((opts, scopes), before)

    def test_invalid_scope_lists_and_foreign_targets(self):
        for name in NAMES:
            with self.subTest(name=name):
                module = NEW[name]
                opts = options(name, [target(name, SCOPES[0])])
                invalid_lists = (SCOPES + [SCOPES[0]], SCOPES + ['bad'],
                                 SCOPES + [['unhashable']], SCOPES + [{'unhashable': 1}])
                for scopes in invalid_lists:
                    with self.assertRaises(ValueError):
                        select(module, name, opts, scopes)
                foreign = options(name, [target(name, '999999999999/us-east-1')])
                with self.assertRaises(ValueError):
                    select(module, name, foreign, SCOPES)
                duplicate = options(name, [target(name, SCOPES[0])] * 2)
                with self.assertRaises(ValueError):
                    select(module, name, duplicate, SCOPES)

    def test_selected_region_bounds_and_arn_binding(self):
        for name, count in ((NAMES[1], 9), (NAMES[3], 5)):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    select(NEW[name], name,
                           options(name, [target(name, scope) for scope in SCOPES[:count]]), SCOPES)
        for name in (NAMES[0], NAMES[1], NAMES[3]):
            with self.subTest(name=name):
                bad = target(name, SCOPES[0])
                if isinstance(bad, str):
                    bad = bad.replace('123456789012', '999999999999')
                else:
                    field = 'resource_id' if name == NAMES[1] else 'definition_arn'
                    bad[field] = bad[field].replace('123456789012', '999999999999')
                with self.assertRaises(ValueError):
                    select(NEW[name], name, options(name, [bad]), SCOPES)

    def test_default_off(self):
        for name in NAMES[:3]:
            with self.subTest(name=name):
                self.assertEqual(NEW[name].selected_targets({}, SCOPES), [])
        with self.assertRaisesRegex(ValueError, 'explicit_grant_required'):
            NEW[NAMES[3]].prepare({NEW[NAMES[3]].OPTION: [target(NAMES[3], SCOPES[0])]}, SCOPES)


if __name__ == '__main__':
    unittest.main()

"""Conservative evaluation of selected, native-bound offline AWS image scans.

Registration and catalog/source admission are owned by the finite release epoch.
This module never registers itself on import or reads credentials or cloud APIs.
"""
from copy import deepcopy
import hashlib
import json
from peaso.aws_image_selection_20261021 import KIND, OPTION, ENABLE, CHECK, selections, partition

DECLARATION = {
    'id': CHECK, 'provider': 'aws', 'category': 'hardening', 'kind': KIND,
    'title': 'Selected ECR or Lambda container image has no HIGH or CRITICAL vulnerabilities',
    'severity': 'high', 'control': 'security_configuration',
    'remediation': 'Update vulnerable packages and select or redeploy a reviewed immutable image digest.',
    'target': 'resource', 'dependencies': (KIND,), 'allow_incomplete_failure': True,
}
DESCRIPTION = {
    'description': 'Inspects an explicitly selected ECR digest, or the resolved image digest of a selected Lambda function, with the pinned offline vulnerability scanner. This does not prove execution, reachability or exploitability.',
    'evaluated': ['native caller account and exact ECR digest', 'complete config and layer bytes with matching content digests',
                  'revalidated Lambda function revision and resolved digest when selected', 'fresh offline HIGH/CRITICAL vulnerability findings'],
    'pass_when': 'Every native binding and byte check succeeds and the complete fresh scan contains no HIGH or CRITICAL vulnerabilities.',
    'fail_when': 'The bound immutable image scan reports at least one typed HIGH or CRITICAL vulnerability, including when remaining coverage is incomplete.',
    'not_applicable_when': None,
}
READ_ACTIONS = ('sts:GetCallerIdentity', 'lambda:GetFunction', 'ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer')


def evaluate(item, index):
    from peaso.image_findings import build_report
    try:
        context = index['context']
        metadata, scope = context['metadata'], context['scope']
        if context['provider'] != 'aws' or not isinstance(metadata.get(OPTION), list):
            raise ValueError()
        collection, = [c for c in index['collections'][KIND] if c['scope'] == scope]
        if collection['status'] not in ('collected', 'partial') or item not in collection['items']:
            raise ValueError()
        if len(metadata[OPTION]) > 8 or len(json.dumps(item, allow_nan=False)) > 2_000_000:
            raise ValueError()
        row = deepcopy(item['ImageVulnerabilityReview'])
        target = row['selection']
        selected = deepcopy(metadata[OPTION])
        targets = selections({ENABLE: True, OPTION: selected}, list(dict.fromkeys(t['scope'] for t in selected)))
        if target not in targets or target['scope'] != scope or row.get('runtime_image_proven') is not False:
            raise ValueError()
        observed = row['observation']
        if observed['provider'] != 'aws' or observed['scope'] != target['scope']:
            raise ValueError()
        account, region = scope.split('/')
        suffix = 'amazonaws.com.cn' if partition(region) == 'aws-cn' else 'amazonaws.com'
        if not observed['scan']['image']['immutable_reference'].startswith(
                f'{account}.dkr.ecr.{region}.{suffix}/'):
            raise ValueError()
        if 'function_arn' in target:
            if observed['asset_id'] != target['function_arn'] or observed['asset_kind'] != 'lambda_function':
                raise ValueError()
            binding = row['function_binding']
            if (set(binding) != {'function_arn', 'revision', 'image_uri'}
                    or binding['function_arn'] != target['function_arn'] or not binding['revision']
                    or binding['image_uri'] != observed['scan']['image']['immutable_reference']
                    or row['association'] != 'lambda_resolved_image'):
                raise ValueError()
        else:
            reference = f'{account}.dkr.ecr.{region}.{suffix}/' + target['repository_name'] + '@' + target['image_digest']
            if (observed['scan']['image']['manifest_digest'] != target['image_digest']
                    or observed['scan']['image']['immutable_reference'] != reference
                    or observed['asset_kind'] != 'ecr_image' or row['association'] != 'selected_immutable_image'
                    or observed['asset_id'] != f'arn:{partition(region)}:ecr:{region}:{account}:repository/'
                       + target['repository_name'] + '@' + target['image_digest']):
                raise ValueError()
        ledger = row['source_ledger']
        if (type(ledger) is not list or not ledger or any(r.get('status') != 'collected' for r in ledger)
                or not {'sts:get_caller_identity', 'ecr:batch_get_image', 'ecr:get_download_url_for_layer',
                        'ecr:signed_layer_download'} <= {r.get('operation') for r in ledger}):
            raise ValueError()
        if any(r.get('account') != scope.split('/')[0] for r in ledger if r['operation'] == 'sts:get_caller_identity'):
            raise ValueError()
        manifests = [r for r in ledger if r['operation'] == 'ecr:batch_get_image']
        if len(manifests) < 3 or any(r.get('digest') != observed['scan']['image']['manifest_digest'] for r in manifests):
            raise ValueError()
        if 'function_arn' in target:
            bindings = [r for r in ledger if r['operation'] == 'lambda:get_function']
            expected = hashlib.sha256(repr(sorted(row['function_binding'].items())).encode()).hexdigest()
            if len(bindings) < 3 or any(r.get('binding_sha256') != expected for r in bindings):
                raise ValueError()
        report = build_report([observed], selected=True)
        if report['invalid_observations'] or report['invalid_vulnerabilities']:
            raise ValueError()
        status = 'FAIL' if report['rows'] else 'PASS' if report['complete'] and row.get('scope_complete') is not False else 'UNKNOWN'
        return status, {'Image': observed['scan']['image'], 'Vulnerabilities': report['rows'],
            'Coverage': report['coverage'], 'Association': row['association'],
            'RuntimeImageProven': False}
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'Reason': 'selected_native_image_vulnerability_evidence_unavailable'}

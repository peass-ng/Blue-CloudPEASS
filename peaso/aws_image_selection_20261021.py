"""Credential-free validation for explicit AWS immutable-image CVE inspection."""
from copy import deepcopy
import re

ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_aws_image_vulnerabilities'
CHECK = 'aws.review.ecr.selected_image_vulnerabilities'
KIND = 'ecr_selected_image_vulnerabilities'
MAX_TARGETS = 8
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
REPO = re.compile(r'[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


def partition(region):
    if '-iso' in region:
        raise ValueError('unsupported_image_partition')
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def selections(options, scopes):
    if type(options) is not dict or type(scopes) is not list:
        raise ValueError('invalid_aws_image_selection')
    if ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('image_vulnerability_scans_must_be_boolean')
    if OPTION not in options and options.get(ENABLE) is not True:
        return []
    targets = options.get(OPTION)
    # The connector can inventory many Regions. Only the content targets, not
    # the metadata allowlist, are limited to eight selected image scopes.
    if (not scopes
            or any(type(s) is not str or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes)
            or type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS
            or any(options.get(k) for k in ('all_accounts', 'all_regions', 'discover_organization', 'organization_role_name'))):
        raise ValueError('exact_aws_image_scopes_and_targets_required')
    seen = set()
    for row in targets:
        if type(row) is not dict or row.get('scope') not in scopes:
            raise ValueError('invalid_aws_image_selection')
        account, region = row['scope'].split('/')
        part = partition(region)
        if set(row) == {'scope', 'repository_name', 'image_digest'}:
            repo, digest = row['repository_name'], row['image_digest']
            if (type(repo) is not str or not 2 <= len(repo) <= 256 or not REPO.fullmatch(repo)
                    or type(digest) is not str or not DIGEST.fullmatch(digest)):
                raise ValueError('exact_ecr_repository_and_digest_required')
            key = row['scope'], repo, digest
        elif set(row) == {'scope', 'function_arn'}:
            arn = row['function_arn']
            if type(arn) is not str or not re.fullmatch(
                    re.escape(f'arn:{part}:lambda:{region}:{account}:function:') + r'[A-Za-z0-9_-]{1,64}', arn):
                raise ValueError('exact_unqualified_lambda_arn_required')
            key = row['scope'], arn
        else:
            raise ValueError('closed_aws_image_target_required')
        if key in seen:
            raise ValueError('duplicate_aws_image_target')
        seen.add(key)
    if len({row['scope'] for row in targets}) > MAX_TARGETS:
        raise ValueError('selected_aws_image_scope_bound')
    return deepcopy(targets)


def validate_request(connector, request):
    options = connector.get('options', {})
    if OPTION not in options and (connector.get('provider') != 'aws' or ENABLE not in options) and CHECK not in (request.get('checks') or []):
        return
    if connector.get('provider') != 'aws':
        raise ValueError('selected_aws_images_require_aws')
    selections(options, connector.get('scopes', []))

"""Pure exact ECR Public image selection, safe for API preflight."""
from copy import deepcopy
import re

OPTION = 'selected_aws_ecr_public_images'
SECRET_CHECK = 'aws.review.ecr_public.selected_image_secret_indicators'
VULN_CHECK = 'aws.review.ecr_public.selected_image_high_vulnerabilities'
KIND = 'ecr_public_selected_image_content'
ACCOUNT = re.compile(r'[0-9]{12}\Z')
SCOPE = re.compile(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+\Z')
ALIAS = re.compile(r'[a-z][a-z0-9]+(?:[._-][a-z0-9]+)*\Z')
REPO = re.compile(r'(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAX_TARGETS = 2


def selected_targets(options, scopes):
    """Validate even disabled supplied selectors; never accept tags or implicit account."""
    if type(options) is not dict or any(k in options and type(options[k]) is not bool
                                     for k in ('content_secret_scans', 'image_vulnerability_scans')):
        raise ValueError('invalid_ecr_public_selection')
    if OPTION not in options:
        return []
    targets = options[OPTION]
    if (type(scopes) is not list or not scopes or len(set(scopes)) != len(scopes)
            or any(type(s) is not str or not SCOPE.fullmatch(s) for s in scopes)
            or any(options.get(k) for k in ('all_accounts','all_regions','discover_organization','organization_role_name'))
            or type(targets) is not list or not 1 <= len(targets) <= MAX_TARGETS):
        raise ValueError('invalid_ecr_public_selection')
    seen = set()
    for target in targets:
        if type(target) is not dict or set(target) != {'scope', 'registry_alias', 'repository_name', 'image_digest'}:
            raise ValueError('invalid_ecr_public_selection')
        scope, alias, repo, digest = (target[k] for k in ('scope','registry_alias','repository_name','image_digest'))
        if (type(scope) is not str or scope not in scopes or not scope.endswith('/us-east-1')
                or type(alias) is not str or not 2 <= len(alias) <= 50
                or not ALIAS.fullmatch(alias) or type(repo) is not str or not 2 <= len(repo) <= 205
                or not REPO.fullmatch(repo) or type(digest) is not str or not DIGEST.fullmatch(digest)):
            raise ValueError('invalid_ecr_public_selection')
        identity = (scope, alias, repo, digest)
        if identity in seen:
            raise ValueError('duplicate_ecr_public_selection')
        seen.add(identity)
    return deepcopy(targets)


def enabled(options, named):
    return (options.get('content_secret_scans') is True and SECRET_CHECK in named,
            options.get('image_vulnerability_scans') is True and VULN_CHECK in named)

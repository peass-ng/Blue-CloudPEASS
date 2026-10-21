"""Pure hosted-request validation for exact selected ACR image digests."""
from copy import deepcopy
import re

ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_azure_acr_image_vulnerabilities'
MAX_IMAGES = 4
_GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_SCOPE = re.compile(r'/subscriptions/' + _GUID + r'\Z', re.I)
_REGISTRY = re.compile(r'(/subscriptions/' + _GUID + r')/resourceGroups/'
    r'([A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-])'
    r'/providers/Microsoft\.ContainerRegistry/registries/([A-Za-z0-9]{5,50})\Z', re.I)
_REPOSITORY = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z')
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def selected_targets(options, scopes):
    """Keep the runtime selector's exact syntax, scope binding and casing."""
    if type(options) is not dict or ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('invalid_acr_vulnerability_selection')
    if OPTION not in options and options.get(ENABLE) is not True:
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not _SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_IMAGES):
        raise ValueError('invalid_acr_vulnerability_selection')
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {'registry_id', 'repository', 'digest'}:
            raise ValueError('invalid_acr_vulnerability_selection')
        registry, repo, digest = target['registry_id'], target['repository'], target['digest']
        match = _REGISTRY.fullmatch(registry) if isinstance(registry, str) else None
        if (not match or len(registry) > 512 or match[1].casefold() not in {s.casefold() for s in scopes}
                or not isinstance(repo, str) or not 1 <= len(repo) <= 256 or not _REPOSITORY.fullmatch(repo)
                or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            raise ValueError('invalid_acr_vulnerability_selection')
        key = (registry.casefold(), repo, digest)
        if key in seen:
            raise ValueError('invalid_acr_vulnerability_selection')
        seen.add(key)
    return deepcopy(targets)

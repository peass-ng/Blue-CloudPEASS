"""Unregistered native SAS-expiry declaration; no token-issuance assertion."""
import re
from .azure_native_contract_closure_20261020 import _owned
from .facts import Unavailable, get

CHECK = 'azure.review.storage.blocking_sas_expiry_policy_declared'
DECLARATION = {
    'id': CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': 'storage_account',
    'severity': 'medium', 'finding_type': 'secrets', 'dependencies': ['storage_account'],
    'title': 'Storage account declares a blocking SAS expiration policy',
    'remediation': 'Review client requirements and configure a suitable SAS expiration policy with the Block action.',
    'registered': False, 'requirements': [],
}
LIMIT = 'This checks the declared policy, not issued tokens or SAS types exempt from its enforcement.'


def evaluate(item, index):
    try:
        _owned(item,index,'storage_account')
        props=get(item,'properties',dict)
        # _owned requires a complete successful native full GET, including its
        # tenant/capture/version binding. A projection or list is insufficient.
        if 'sasPolicy' not in props or props['sasPolicy'] is None:
            get(props,'sasPolicy') if 'sasPolicy' in props.get('_coverage',{}) else None
            return 'FAIL',{'observed':'No SAS expiration policy is configured. '+LIMIT,
                          'sas_expiry_policy_declared':False,'token_issuance_verified':False}
        policy=get(props,'sasPolicy',dict)
        duration=get(policy,'sasExpirationPeriod',str)
        match=re.fullmatch(r'([0-9]{1,8})\.([0-9]{1,2}):([0-9]{2}):([0-9]{2})',duration)
        if match is None:raise Unavailable('SAS policy duration is malformed or unsupported')
        days,hours,minutes,seconds=map(int,match.groups())
        total=days*86400+hours*3600+minutes*60+seconds
        if days>10675199 or hours>23 or minutes>59 or seconds>59 or not 0<total<=922337203685:
            raise Unavailable('SAS policy duration is outside the supported positive interval')
        action=get(policy,'expirationAction',str) if 'expirationAction' in policy or 'expirationAction' in policy.get('_coverage',{}) else 'Log'
        if action not in ('Log','Block'):raise Unavailable('SAS policy expiration action is unsupported')
        good=action=='Block'
        if 'expirationAction' not in policy:
            observed=f'The SAS policy omits its action, so the documented Log default applies to its {duration} interval.'
        else:
            observed=(f'The SAS policy declares Block for intervals longer than {duration}.' if good else
                      f'The SAS policy declares Log for intervals longer than {duration}; out-of-policy requests remain allowed.')
        return ('PASS' if good else 'FAIL'),{'observed':observed+' '+LIMIT,
            'sas_expiry_policy_declared':True,'expiration_action':action,
            'maximum_interval_seconds':total,'token_issuance_verified':False}
    except (Unavailable,TypeError,ValueError,KeyError,AttributeError):
        return 'UNKNOWN',{'observed':'The native storage-account identity, full read or SAS policy fields could not be established.',
                          'token_issuance_verified':False}

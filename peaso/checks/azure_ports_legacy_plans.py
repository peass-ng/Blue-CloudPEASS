"""Read legacy Defender plan states without recommending blocked new enrollment."""
from . import register, result, unknown
from .azure_ports_defender import _pricing, _tier, _non_subscription, _fixture, _plan_row
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {'security_center_defender_for_servers_enabled': 'azure.port.securitycenter_azure_defender_on_for_server'}
PLANS = {
    'securitycenter_azure_defender_on_for_containerregistry': ('ContainerRegistry', 'Containers'),
    'securitycenter_azure_defender_on_for_dns': ('Dns', 'VirtualMachines'),
    'securitycenter_azure_defender_on_for_k8s': ('KubernetesService', 'Containers'),
}


def _register(query, plan, replacement):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    @register(cid, 'azure', 'hardening', 'security_pricing', 'Existing legacy Defender ' + plan + ' pricing is Standard', 'medium', 'SI-4',
              'Review existing legacy coverage and migration to ' + replacement + '; new enrollment in the legacy plan is blocked by Microsoft.',
              target='scope', dependencies=['security_pricing'])
    def evaluate(item, index):
        if _non_subscription(item):
            return 'NOT_APPLICABLE', {'reason': 'Pricing is subscription-scoped'}
        pricing = _pricing(item, index)
        if plan not in pricing:
            return unknown('Legacy plan not returned; applicability is unproven and supported replacement is a separate check', plan=plan, replacement=replacement)
        tier = _tier(pricing[plan])
        return result(tier != 'Standard', plan=plan, pricing_tier=tier, replacement=replacement,
                      semantics='Pinned legacy-plan configuration only; no replacement equivalence, enrollment or sensor claim')
    CASES[cid] = {'pass': {'scope': '/subscriptions/sub'}, 'fail': {'scope': '/subscriptions/sub'},
                  'pass_index': _fixture('security_pricing', [_plan_row(plan, 'Standard')]),
                  'fail_index': _fixture('security_pricing', [_plan_row(plan, 'Free')])}


for query, spec in PLANS.items():
    _register(query, *spec)

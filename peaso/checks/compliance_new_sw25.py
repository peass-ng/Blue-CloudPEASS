"""Registration entrypoint for the fifteen signed sw25 Azure predicates."""
from __future__ import annotations

from dataclasses import replace
from . import CHECKS, register
from .facts import Unavailable, get
from .compliance_new_sw25_facts import (
    SPECS, IDS, REPORT_ID, ROUTING_ID, GUEST_PRIV_ID, MONTHLY_ID, REGULAR_ID,
    NONPRIV_ID, PRIV_ID, TENANT_ID, CAPACITY_ID, GATEWAY_ID, SETTINGS_ID,
    REQUIRED_ID, LIMITS_ID, APPARMOR_ID, IMAGES_ID, REVIEW_IDS, FAMILIES,
    ARM_TYPES, _scope,
)
from .compliance_new_sw25_identity import _reviews
from .compliance_new_sw25_native_identity import native_guest_reviews
from .compliance_new_sw25_monitoring import (
    _critical_reporting, _routing, _capacity, _gateway_health, _metric_settings,
    _required_metrics,
)
from .compliance_new_sw25_pods import _limits, _apparmor, _images

DEPENDENCIES = {
    **{cid: ('access_review_subject', 'access_review_definition', 'access_review_instance', 'access_review_decision') for cid in REVIEW_IDS},
    REPORT_ID: ('failure_reporting_window', 'critical_failure_event', 'failure_delivery_record', 'failure_reporting_coverage'),
    ROUTING_ID: FAMILIES,
    CAPACITY_ID: ('azure_resource', 'capacity_record', 'capacity_change_record'),
    GATEWAY_ID: ('application_gateway', *FAMILIES, 'action_group', 'gateway_alert_semantics', 'gateway_health_evidence'),
    SETTINGS_ID: ('metric_alert', 'action_group'), REQUIRED_ID: ('metric_alert', 'azure_resource'),
    LIMITS_ID: ('kubernetes_scope', 'pod', 'pod_runtime', 'limit_range'),
    APPARMOR_ID: ('kubernetes_scope', 'pod', 'pod_runtime'), IMAGES_ID: ('kubernetes_scope', 'pod'),
}
for _guest_id in (MONTHLY_ID, REGULAR_ID):
    DEPENDENCIES[_guest_id] = (*DEPENDENCIES[_guest_id], 'directory_group')

DISPATCH = {REPORT_ID: _critical_reporting, ROUTING_ID: _routing, CAPACITY_ID: _capacity,
            GATEWAY_ID: _gateway_health, SETTINGS_ID: _metric_settings, REQUIRED_ID: _required_metrics,
            LIMITS_ID: _limits, APPARMOR_ID: _apparmor, IMAGES_ID: _images}


def _register(cid):
    spec = SPECS[cid]
    # Copy wave-1's signed-category adapter for the registry's older allowlist.
    category = spec['category'] if spec['category'] in ('hardening', 'exposure', 'least_privilege', 'iam_graph', 'network') else 'hardening'
    @register(cid, 'azure', category, spec['resource_kind'], spec['title'], spec['severity'],
              'CM-6', spec['remediation_hint'], target='scope', dependencies=DEPENDENCIES[cid],
              allow_incomplete_failure=(cid in (GATEWAY_ID, SETTINGS_ID)),
              empty_applicability_dependencies=('application_gateway',) if cid == GATEWAY_ID else ())
    def evaluate(item, index):
        if get(item, 'scope', str).casefold() != _scope(index).casefold():
            raise Unavailable('scope subject differs from snapshot context')
        if cid in REVIEW_IDS:
            native = native_guest_reviews(cid, index)
            if native is not None:
                return native
            return _reviews(cid, index)
        return DISPATCH[cid](index)
    evaluate.proposed_spec_sha256 = spec['proposed_spec_sha256']
    CHECKS[-1] = replace(CHECKS[-1], category=spec['category'])
    return CHECKS[-1]


REGISTERED = {cid: _register(cid) for cid in IDS}
EVALUATORS = {cid: check.evaluate for cid, check in REGISTERED.items()}
PROPOSED_SPEC_SHA256 = {cid: spec['proposed_spec_sha256'] for cid, spec in SPECS.items()}

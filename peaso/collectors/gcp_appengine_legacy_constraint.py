"""Read-only evidence for the legacy App Engine actAs exception."""
from __future__ import annotations

from .gcp import ReadError


CONSTRAINT = "appengine.enforceServiceAccountActAsCheck"


def list_constraint(collector, scope):
    name = None
    constraint_default = None
    request = None
    for rows, request_id in collector.pages(
            f"https://orgpolicy.googleapis.com/v2/{scope}/constraints", scope,
            key="constraints"):
        request = request_id
        for row in rows:
            raw = row.get("name")
            if not isinstance(raw, str) or not raw.startswith(scope + "/constraints/"):
                raise ReadError("malformed", "malformed_appengine_constraint_identity")
            if raw.endswith("/constraints/" + CONSTRAINT):
                if name is not None:
                    raise ReadError("malformed", "duplicate_appengine_constraint")
                name = raw
                constraint_default = row.get("constraintDefault")
    if name is None:
        yield [{"name": f"{scope}/constraints/{CONSTRAINT}", "visible": False,
                "_representation": "partial"}], request
        return
    endpoint = f"https://orgpolicy.googleapis.com/v2/{scope}/policies/{CONSTRAINT}:getEffectivePolicy"
    for rows, request_id in collector.pages(endpoint, scope, single=True):
        policy, = rows
        policy_name = policy.get("name")
        if policy_name != f"{scope}/policies/{CONSTRAINT}":
            raise ReadError("malformed", "malformed_appengine_effective_policy")
        yield [{"name": name, "visible": True, "constraintDefault": constraint_default, "effectivePolicy": {
                    "name": policy_name, "spec": policy.get("spec")},
                "_representation": "partial"}], request_id

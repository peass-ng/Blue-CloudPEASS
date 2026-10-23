"""Exact existing-backend route for Firebase App Hosting identity changes."""
from __future__ import annotations

import re

from . import inventory_status, items


_BACKEND = re.compile(r"projects/[^/]+/locations/[^/]+/backends/[^/]+")
_ACTIONS = ("firebaseapphosting.backends.update",
            "firebaseapphosting.builds.create",
            "firebaseapphosting.rollouts.create")


def select(model, candidates, source):
    if source is None:
        return {}
    status = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, "firebase_apphosting_backend").items()}
    backends = {}
    invalid = set()
    for scope, item in items(model.snapshot, "firebase_apphosting_backend"):
        project = model._norm_scope(scope)
        if not project.startswith("projects/") or not isinstance(item, dict):
            invalid.add(project)
            continue
        name = item.get("name")
        if (not isinstance(name, str) or not _BACKEND.fullmatch(name)
                or not name.startswith(project + "/locations/")):
            invalid.add(project)
            continue
        if name in backends:
            invalid.add(project)
            continue
        backends[name] = item

    out = {}
    for ident, target in candidates.items():
        if target.kind != "gcp_service_account" or target.attrs.get("disabled"):
            continue
        project = model._norm_scope(target.scope)
        if status.get(project) not in ("collected", "empty") or project in invalid:
            out[ident] = ("unknown", "apphosting_backend_inventory_incomplete")
            continue
        uncertain = False
        for name, backend in backends.items():
            if not name.startswith(project + "/locations/") or backend.get("deleteTime"):
                continue
            if backend.get("reconciling") is True:
                uncertain = True
                continue
            model.parents.setdefault(name, project)
            grants = [model.check(source, {"action": action}, name) for action in _ACTIONS]
            if any(grant is None for grant in grants):
                continue
            if any(grant.confidence == "unknown" for grant in grants):
                uncertain = True
                continue
            runner_role = any(role == "roles/firebaseapphosting.computeRunner"
                              and node in model.ancestors(project) and not condition
                              for node, role, condition, _ in target.attrs.get("grants", ()))
            if not runner_role:
                uncertain = True  # Equivalent custom runner grants may also work.
                continue
            out[ident] = ("conditional", "exact_apphosting_backend_retarget_and_code_delivery")
            break
        else:
            if uncertain:
                out[ident] = ("unknown", "apphosting_backend_reconciling_or_permission_unresolved")
    return out

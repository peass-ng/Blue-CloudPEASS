"""Match FIC child write authority to an exact user-assigned identity."""
from __future__ import annotations

import re

from . import items


UAMI = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+"
)
FIC = re.compile(UAMI.pattern + r"/federatedidentitycredentials/[^/]+")
WRITE = {"action": "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write"}


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    known = {}
    for _, row in items(model.snapshot, "managed_identity_federated_credential"):
        rid = row.get("id") if isinstance(row, dict) else None
        if isinstance(rid, str) and FIC.fullmatch(rid.casefold()):
            parent = rid.casefold().rsplit("/federatedidentitycredentials/", 1)[0]
            known.setdefault(parent, set()).add(rid.casefold())
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned":
            continue
        resource = target.attrs.get("uai_resource")
        if not isinstance(resource, str) or not UAMI.fullmatch(resource.casefold()):
            continue
        resource = resource.casefold()
        children = known.get(resource, set())
        # A new child is possible below the 20-credential limit. At the limit,
        # an existing child may still be replaced through create-or-update.
        refs = set(children)
        if len(children) < 20:
            refs.add(resource + "/federatedidentitycredentials/peaso-candidate")
        for ref in refs:
            grant = model.cached_check(source, WRITE, ref)
            if grant is not None and grant.confidence != "unknown":
                out[tid] = ("conditional", "writable_federated_credential_on_exact_uami")
                break
    return out

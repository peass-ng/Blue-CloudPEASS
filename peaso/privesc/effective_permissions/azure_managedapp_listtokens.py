"""Bind listTokens authority to the managed application carrying the identity."""
from __future__ import annotations

import re


APPLICATION = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.solutions/applications/[^/]+"
)
LIST_TOKENS = {"action": "microsoft.solutions/applications/listtokens/action"}


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for host in target.attrs.get("hosts") or ():
            if (isinstance(host, str) and APPLICATION.fullmatch(host)
                    and model.resources.get(host, {}).get("type") == "microsoft.solutions/applications"):
                grant = model.cached_check(source, LIST_TOKENS, host)
                if grant is not None and grant.confidence != "unknown":
                    out[tid] = None
                    break
    return out

"""Signed EASM workspace presence check; pure snapshot evaluation."""
from __future__ import annotations
import re
from peaso.checks import register, result
from peaso.checks.facts import Unavailable, complete_items, get, list_of_objects, memoized

EASM = "azure.cis.defender_external_attack_surface_monitoring_easm"
SIGNED_SPEC_SHA256 = "6aac61eb97ebac681f9cd05c27f0fa013f1e510ac9fd61f848ea3ff2b9563722"
EASM_TYPE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.easm/workspaces/[^/]+", re.I)
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def _scope(index, tenant=False):
    ctx = get(index, "context", dict)
    if get(ctx, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(ctx, "scope", str)
    prefix = "tenants" if tenant else "subscriptions"
    if not re.fullmatch(r"/" + prefix + r"/[A-Za-z0-9._-]+", scope, re.I):
        raise Unavailable("incorrect scope")
    return scope.casefold()


def _inventory(index, kind, tenant=False):
    scope = _scope(index, tenant)
    def build():
        envelopes = get(index, "collections", dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable("missing or ambiguous inventory")
        env = envelopes[0]
        if env.get("type") != kind or str(env.get("scope", "")).casefold() != scope or env.get("status") not in ("collected", "empty"):
            raise Unavailable("incomplete or foreign inventory")
        rows = list_of_objects(get(env, "items", list))
        if (env["status"] == "empty") != (not rows) or rows != complete_items(index, kind):
            raise Unavailable("inventory/projection contradiction")
        seen = set()
        for row in rows:
            rid = get(row, "id", str)
            normalized = rid.casefold()
            if normalized in seen:
                raise Unavailable("duplicate resource identity")
            seen.add(normalized)
            if tenant:
                if not GUID.fullmatch(rid):
                    raise Unavailable("malformed application identity")
                proof = get(row, "_provenance", dict)
                if str(proof.get("tenant_id", "")).casefold() != scope.split("/")[-1] or proof.get("tenant_verified") is not True:
                    raise Unavailable("unverified application tenant")
            elif not normalized.startswith(scope + "/") or not EASM_TYPE.fullmatch(rid):
                raise Unavailable("foreign EASM workspace")
        return rows
    return memoized(index, ("azure_remaining", scope, kind), build)


@register(EASM, "azure", "hardening", "easm_workspace", "Defender EASM workspace is provisioned", "medium", "CM-6",
          "Review the subscription's Defender EASM workspace provisioning state.", target="scope", dependencies=("easm_workspace",))
def easm(item, index):
    rows = _inventory(index, "easm_workspace")
    states = []
    for row in rows:
        state = get(row, "properties.provisioningState", str)
        if state not in ("NotSpecified", "Accepted", "Creating", "Succeeded", "Failed", "Canceled",
                         "ProvisioningResources", "InstallingApplication", "ConfiguringApplication",
                         "MigratingApplicationData", "RunningValidations", "CreatingArtifacts", "DeletingArtifacts"):
            raise Unavailable("unknown workspace provisioning state")
        states.append(state)
    return result("Succeeded" not in states, workspace_count=len(rows), succeeded_count=states.count("Succeeded"))



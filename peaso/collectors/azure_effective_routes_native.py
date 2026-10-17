"""Read-only, bounded effective-route and security-admin inventories."""
from __future__ import annotations

from .azure_nsg_ingress_native import NetworkQueries


def collect(reader, transport, scopes, wanted):
    if not {"effective_route", "security_admin_rule"}.intersection(wanted):
        return
    from .azure import AzureReadError

    jobs = []
    proofs = {}
    for scope in scopes:
        for kind, parent_kind, query_kind, suffix, field in (
            ("effective_route", "nic", "routes", "effectiveRoutes", "nic_id"),
            ("security_admin_rule", "vnet", "admin", "effectiveSecurityAdminRules", "vnet_id"),
        ):
            if kind not in wanted:
                continue
            parents = [c for c in reader.collections if c["type"] == parent_kind and c["scope"] == scope]
            if len(parents) != 1 or parents[0]["status"] not in {"collected", "empty"}:
                reader.unavailable(kind, scope, "Microsoft.Network", AzureReadError(parent_kind + "_inventory_incomplete"))
                continue
            parent_ids = [item["id"] for item in parents[0]["items"]]

            def pages(scope=scope, parent_ids=parent_ids, query_kind=query_kind, suffix=suffix, field=field, kind=kind):
                query = NetworkQueries(reader, transport, scope)
                try:
                    for parent_id in parent_ids:
                        index = 0
                        for page in query.pages(query_kind, parent_id):
                            output = []
                            for value in page:
                                output.append({"id": f"{parent_id}/{suffix}/{index}", field: parent_id,
                                    "rule" if query_kind == "admin" else "route": value,
                                    "_provenance": {"source_operation": "listNetworkManagerEffectiveSecurityAdminRules"
                                        if query_kind == "admin" else "effectiveRouteTable", "read_only": True,
                                        field: parent_id}})
                                index += 1
                            yield output
                finally:
                    proofs[(kind, scope)] = list(query.proofs)

            jobs.append((kind, scope, "Microsoft.Network", pages))
    if jobs:
        reader.run(jobs)
    for collection in reader.collections:
        key = (collection["type"], collection["scope"])
        if key in proofs:
            collection["source_evidence"] = proofs[key]

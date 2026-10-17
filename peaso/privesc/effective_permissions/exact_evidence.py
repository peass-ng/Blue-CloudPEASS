"""Exact, externally reviewed challenge facts for paths absent from routine inventory.

An evidence record is a scoped attestation, never a permission inference. Importers
must verify the technique-specific join before setting VerifiedPreconditions.
"""
from __future__ import annotations

from . import Node, inventory_status, items

_AZURE_PRINCIPALS = frozenset({"azure_user", "azure_service_principal", "azure_managed_identity"})


class ExactEvidenceMixin:
    def load_exact_evidence(self, collection, allowed_kinds):
        self.exact_collection = collection
        self.exact_status = inventory_status(self.snapshot, collection)
        self.exact_evidence = {}
        self.exact_sources_by_technique = {}
        for collection_scope, item in items(self.snapshot, collection):
            if not isinstance(item, dict):
                continue
            fields = tuple(item.get(k) for k in
                           ("TechniqueId", "SourceId", "TargetKind", "TargetId", "TargetScope"))
            if not all(isinstance(v, str) and v and "*" not in v for v in fields):
                continue
            tid, source, kind, target, scope = fields
            if kind not in allowed_kinds or scope.lower() != str(collection_scope).lower():
                continue
            self.exact_evidence.setdefault(fields, []).append(item)
            self.exact_sources_by_technique.setdefault(tid, set()).add(source)

    def exact_source_matches(self, technique, source):
        """Never speculate that every inventoried principal owns a missing exploit input."""
        if self.provider == "azure":
            from .azure_disclosure_effects import UNSUPPORTED_DISCLOSURES
            if technique in UNSUPPORTED_DISCLOSURES:
                return False
        return source.id in self.exact_sources_by_technique.get(technique, ())

    def exact_targets_for(self, kind, selector):
        tid = next((v for k, v in (selector or {}).items() if k.endswith("_challenge_fact")), None)
        if not tid:
            return None
        if self.provider == "azure":
            from .azure_disclosure_effects import UNSUPPORTED_DISCLOSURES
            if tid in UNSUPPORTED_DISCLOSURES:
                self.add_coverage("adapter", "*", "not_collected",
                                  f"{tid}: {UNSUPPORTED_DISCLOSURES[tid].partition(':')[0]}",
                                  UNSUPPORTED_DISCLOSURES[tid])
                return []
        if self.provider == "azure":
            from .azure_disclosure_effects import CONTRACT as disclosure_contract
            if tid in disclosure_contract:
                from .azure_disclosure_effects import native_binding, valid
                supported=set()
                for (fact_tid,source,_,target,scope),records in self.exact_evidence.items():
                    if fact_tid==tid and any(native_binding(self.snapshot,r.get('_provenance'),source)
                                            and valid(self,tid,r,source,target,scope) for r in records):
                        supported.add(scope)
                if supported:
                    for scope in sorted(supported):
                        self.add_coverage("adapter",scope,"partial",f"{tid}: optional source-bound native metadata witness available",
                                          "Positive metadata witness only; remaining credentials and resources are not exhaustively examined")
                else:
                    self.add_coverage("adapter", "*", "not_collected",
                                      f"{tid}: standard native disclosure proof adapter unavailable",
                                      "Only separately reviewed metadata can establish this terminal effect; ordinary Azure inventory cannot prove configured credential/customer joins")
        out = {}
        for (fact_tid, _, fact_kind, target, scope), records in self.exact_evidence.items():
            if fact_tid != tid or fact_kind != kind or all(r.get("Status") == "disproven" for r in records):
                continue
            if kind in _AZURE_PRINCIPALS:
                principal = self.principals.get(target)
                if principal is None or principal.kind != kind:
                    self.add_coverage("selector", scope, "not_collected",
                                      f"exact target principal {target} not in snapshot",
                                      "A reviewed fact names a principal absent from directory or identity inventory; no principal edge is drawn")
                    continue
                out[target] = principal
                continue
            # The technique is part of the node ID so distinct bounded authorities
            # cannot accidentally be merged by the graph builder.
            ident = f"exact:{tid}:{scope}:{target}"
            entity = kind.endswith("_verified_authority")
            out[ident] = Node(ident, kind, self.provider, scope, target,
                              attrs={"resource": target, "scope": scope}, entity=entity)
        return list(out.values())

    def exact_unknown_target_scopes(self):
        scopes = {scope for _, _, _, _, scope in self.exact_evidence}
        scopes.update(getattr(self, "exact_scopes", getattr(self, "scopes", ())))
        if not scopes and self.snapshot.get("scope"):
            scopes.add(self.snapshot["scope"])
        return {scope: self.exact_status.get(scope, "not_collected") for scope in scopes
                if self.exact_status.get(scope) not in ("collected", "empty")}

    def exact_selector(self, technique, candidates, source):
        if source is None:
            return None
        out = {}
        for ident, node in candidates.items():
            if node.kind in _AZURE_PRINCIPALS:
                matches = [(scope, records) for (tid, sid, kind, target, scope), records
                           in self.exact_evidence.items()
                           if tid == technique and sid == source.id and kind == node.kind and target == node.id]
            else:
                resource = node.attrs.get("resource")
                matches = ([(node.scope, self.exact_evidence.get(
                    (technique, source.id, node.kind, resource, node.scope), ()))]
                    if isinstance(resource, str) else [])
            matches = [(scope, records) for scope, records in matches if records]
            if not matches:
                continue
            if len(matches) != 1:
                out[ident] = ("unknown", "exact_target_scope_ambiguous")
                continue
            scope, records = matches[0]
            if self.provider == "azure":
                from .azure_self_grants import CONTRACT as self_grant_contract, valid as self_grant_valid
                if technique in self_grant_contract and (len(records) != 1 or not self_grant_valid(
                        technique, records[0], source.id, node.attrs.get("resource"), scope)):
                    if any(r.get("Status") != "disproven" for r in records):
                        out[ident] = ("unknown", "self_permission_grant_evidence_incomplete")
                    continue
                from .azure_deployment_pivots import CONTRACT as deployment_contract, valid as deployment_valid
                if technique in deployment_contract and (len(records) != 1 or not deployment_valid(
                        self, technique, records[0], source.id, node.id, scope)):
                    if any(r.get("Status") != "disproven" for r in records):
                        out[ident] = ("unknown", "deployment_identity_evidence_incomplete")
                    continue
                from .azure_datafactory_identity import CONTRACT as datafactory_contract, valid as datafactory_valid
                if technique in datafactory_contract and (len(records) != 1 or not datafactory_valid(
                        self, technique, records[0], source.id, node.id, scope)):
                    # An incomplete token or pipeline review cannot name an
                    # identity path, even as an unknown target edge.
                    continue
            from .bounded_evidence import CONTRACT as bounded_contract, valid as bounded_valid
            if technique in bounded_contract and (len(records) != 1 or not bounded_valid(technique, records[0], source.id, node.attrs.get("resource"), scope)):
                if any(r.get("Status") != "disproven" for r in records): out[ident] = ("unknown", "bounded_effect_evidence_incomplete")
                continue
            from .azure_disclosure_effects import CONTRACT as disclosure_contract, valid as disclosure_valid
            if technique in disclosure_contract and (len(records) != 1 or not disclosure_valid(self, technique, records[0], source.id, node.attrs.get("resource"), scope)):
                if any(r.get("Status") != "disproven" for r in records):
                    out[ident] = ("unknown", "disclosure_effect_evidence_incomplete")
                continue
            if self.exact_status.get(scope) not in ("collected", "empty"):
                out[ident] = ("unknown", "exact_evidence_collection_incomplete")
            elif len(records) == 1 and records[0].get("Status") == "verified" and \
                    records[0].get("VerifiedPreconditions") is True and \
                    isinstance(records[0].get("EvidenceRef"), str) and records[0]["EvidenceRef"]:
                out[ident] = ("conditional", "exact_reviewed_prerequisites")
            elif any(r.get("Status") != "disproven" for r in records):
                out[ident] = ("unknown", "exact_prerequisites_incomplete")
        return out

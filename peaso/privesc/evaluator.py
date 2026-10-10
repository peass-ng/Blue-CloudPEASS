"""Evaluate catalog techniques against a provider model.

Pipeline per technique (entry):
  1. compile: expand requires into alternatives (all_of + one any_of group),
     classify each requirement as static (source-only), pivot or per-target,
     and turn *_covered_by / resource_permission_covers_target selectors into
     extra per-target requirements;
  2. candidates: the target inventory filtered by static selectors (cached per
     (kind, selector) and shared between techniques);
  3. sources: an inverted index (requirement key -> principals that may hold it)
     intersected over the requirements of an alternative, so a 10k-principal
     snapshot only evaluates the few principals that can possibly match;
  4. exact checks per source (cached by permission-equivalence key), then the
     source-dependent selectors and the target scope rule.

The result is a list of Reach objects consumed by graph.py.
"""
from __future__ import annotations

import hashlib
import re

from .effective_permissions import ANY, CONF_RANK, AllTargets, Grant, best, combine, downgrade
from .schema import EVALUATED_BLOCKERS, FACTS_NEEDED, MODEL_BLOCKERS

_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")
# Selectors that depend on the source (or the pivot) and are evaluated per source.
DYNAMIC_SELECTORS = {
    "same_as_source", "trust_allows_principal_of_source", "source_kind", "source_group_covered_by",
    "source_attached_policy_covered_by", "via_assumable_role_covered_by", "custom_role_assigned_to_source",
    "entra_source_is_owner_of_application", "entra_source_is_owner_of_service_principal", "entra_source_is_owner_of_group",
    "entra_custom_role_assigned_to_source", "entra_pim_eligible_for_source", "entra_dynamic_rule_attributes_writable_by_source",
    "entra_role_assignment_scope_covers_target", "entra_reset_matrix_column", "ml_compute_assigned_to_source",
    "k8s_sa_cloud_binding", "trust_allows_k8s_sa_oidc_subject", "gcp_workload_identity_user_granted_to_k8s_sa",
    "azure_fic_matches_k8s_sa", "k8s_node_cloud_identity", "k8s_nodes_mapped_to_cloud_identity",
    "gcp_custom_role_bound_to_source", "azure_deployer_of_pivot", "azure_host_linked_to_pivot",
    "k8s_node_hosting_pods_with_sa", "k8s_node_hosting_pods_in_namespace", "k8s_node_hosting_privileged_pod_in_namespace",
    "credential_stored_in_scope", "kube2iam_namespace_permits_role", "gcp_implicit_delegation_chain",
    "assumable_by_pivot_role",
}
# Multi-valued target placeholders: when several requirements reference the same one, they must all hold
# on the SAME resolved resource (intersection), not each on some resource.
SHARED_PLACEHOLDERS = {"target.resource_arn", "target.attached_resource_arn", "target.host_resource",
                       "target.artifact_arn", "target.consumer_input_arn"}
# Selectors that are an extra "the source holds <action> on <resource>" requirement.
COVERED_BY = {
    "resource_permission_covers_target": None,
    "gcp_actas_granted_on_target": "{target.email}",
    "attached_resource_covered_by": "{target.attached_resource_arn}",
    "source_group_covered_by": "{source.group_arn}",
    "source_attached_policy_covered_by": "{source.attached_policy_arn}",
    "trust_allows_saml_provider_covered_by": "{target.saml_provider_arn}",
}
LOCALIZING_SELECTORS = {"gcp_sa_in_scope_of_permission", "azure_identity_assignable_in_scope"}
LOCALIZING_SCOPES = {"same_namespace", "same_project"}


class CReq:
    __slots__ = ("raw", "key", "template", "mode", "localized")

    def __init__(self, raw, key, template, mode, localized=False):
        self.raw, self.key, self.template, self.mode, self.localized = raw, key, template, mode, localized


class CandidateSet:
    """Static candidates of one (kind, static selector) combination."""
    __slots__ = ("id", "kind", "members", "floor", "by_scope", "label", "unknown_scopes")

    def __init__(self, ident, kind, members, floor, label, unknown_scopes):
        self.id, self.kind, self.members, self.floor, self.label = ident, kind, members, floor, label
        self.unknown_scopes = unknown_scopes
        self.by_scope = {}
        for node in members.values():
            self.by_scope.setdefault(node.scope, set()).add(node.id)


class AllOf:
    """Every static candidate (optionally only in `scopes`) is reached with `grant`."""
    __slots__ = ("grant", "scopes", "unknown")

    def __init__(self, grant, scopes, unknown):
        self.grant, self.scopes, self.unknown = grant, scopes, unknown

    def __bool__(self):
        return True

    def expand(self, cset, exclude=None):
        """Materialise {target id: grant} (only used for small sets and tests)."""
        out = {}
        for scope, ids in cset.by_scope.items():
            if self.scopes is not None and scope not in self.scopes:
                continue
            for tid in ids:
                if tid == exclude:
                    continue
                floor = cset.floor.get(tid)
                out[tid] = downgrade(self.grant, floor[0], floor[1]) if floor else self.grant
        out.update(self.unknown)
        return out


class Reach:
    """One technique reaching a set of targets from one source."""
    __slots__ = ("entry", "source", "targets", "cset", "source_group")

    def __init__(self, entry, source, targets, cset, source_group=None):
        self.entry, self.source, self.targets, self.cset = entry, source, targets, cset
        self.source_group = source_group  # list of source nodes when sources are aggregated (unknown facts)


def _template_kind(template):
    names = _PH.findall(template) if isinstance(template, str) else []
    if any(n == "pivot" or n.startswith("pivot.") for n in names):
        return "pivot"
    if any(n.startswith("target.") or n in ("target",) for n in names):
        return "target"
    return "static"


class Evaluator:
    def __init__(self, model, entries, *, include_unknown=True):
        self.model = model
        self.entries = [e for e in entries if e["provider"] == model.provider or (
            model.provider == "azure" and e["provider"] == "azure")]
        self.include_unknown = include_unknown
        self._csets = {}
        self._noted = set()
        self.compiled = [self._compile(e) for e in self.entries]
        # Every requirement key must be known before possible() is computed (prefilter index).
        model.catalog_keys.update(r.key for c in self.compiled for alt in c["alternatives"] for r in alt)
        self._index()

    # ---------------------------------------------------------------- compile
    def _compile(self, entry):
        model = self.model
        target = entry.get("target") or {}
        selector = dict(target.get("selector") or {})
        scope_rule = target.get("scope", "any")
        localize = bool(LOCALIZING_SELECTORS & set(selector)) or scope_rule in LOCALIZING_SCOPES
        requires = entry.get("requires") or {}
        base = list(requires.get("all_of") or [])
        groups = [list(g) for g in (requires.get("any_of") or [])] or [[]]
        extra = []
        for key, template in COVERED_BY.items():
            if key not in selector:
                continue
            action = selector[key]
            req = model.covered_by_requirement(key, action, template, target.get("kind"))
            if req is not None:
                extra.append(req)
        alternatives = []
        for group in groups:
            reqs, seen = [], set()
            for raw in base + group + extra:
                key = model.requirement_key(raw)
                template = model.requirement_template(raw)
                ident = (key, template)
                if ident in seen:
                    continue
                seen.add(ident)
                mode = _template_kind(template) if template is not None else "static"
                localized = False
                if mode == "static" and localize and model.localizable(raw):
                    mode, localized = "target", True
                reqs.append(CReq(raw, key, template, mode, localized))
            alternatives.append(reqs)
        if target.get("kind") in ("azure_dataplane_admin", "k8s_cluster_admin") and model.provider == "azure":
            first = next((r.raw for alt in alternatives for r in alt if "action" in r.raw), None)
            if first is not None:
                selector["_resource_type_from_action"] = first["action"]
        static_sel, dynamic_sel = {}, {}
        for key, value in selector.items():
            if key in COVERED_BY and key != "trust_allows_saml_provider_covered_by":
                continue
            if key in LOCALIZING_SELECTORS:
                continue
            text = repr(value)
            if key in DYNAMIC_SELECTORS or "{source" in text or "{pivot" in text or "{target" in text:
                dynamic_sel[key] = value
            else:
                static_sel[key] = value
        blockers = [b if isinstance(b, str) else b.get("id") for b in entry.get("blockers") or []]
        model_blockers = [b for b in blockers if b in MODEL_BLOCKERS.get(model.provider, ())]
        return {"entry": entry, "alternatives": alternatives, "static": static_sel, "dynamic": dynamic_sel,
                "kind": target.get("kind"), "scope": scope_rule, "selector": selector,
                "floor": entry.get("confidence", "derived"),
                "blockers_not_evaluated": [b for b in blockers if b and b not in EVALUATED_BLOCKERS and b not in model_blockers],
                "model_blockers": model_blockers,
                "source_kind": entry.get("source_kind"), "source_selector": entry.get("source_selector") or {}}

    # ------------------------------------------------------------ candidates
    def note(self, kind, scope, status, reason, impact):
        key = (kind, scope, reason)
        if key not in self._noted:
            self._noted.add(key)
            self.model.add_coverage(kind, scope, status, reason, impact)

    def candidates(self, compiled):
        kind = compiled["kind"]
        model = self.model
        variant = model.target_variant(kind, compiled["selector"])
        key = (kind, tuple(sorted((k, repr(v)) for k, v in compiled["static"].items())), variant)
        if key in self._csets:
            return self._csets[key]
        members = {n.id: n for n in model.targets_for(kind, compiled["selector"])}
        floor = {}
        for sel_key, value in sorted(compiled["static"].items()):
            if not members:
                break
            verdict = model.selector(sel_key, value, members, None)
            if verdict is None:
                self.note("selector", "*", "not_evaluated", f"selector {sel_key} not evaluated",
                          "Targets kept with unknown confidence; needs " + FACTS_NEEDED.get(sel_key, "facts not in snapshot"))
                for tid in members:
                    floor[tid] = _worse(floor.get(tid), ("unknown", f"selector_{sel_key}_not_evaluated"))
                continue
            members = {tid: n for tid, n in members.items() if tid in verdict}
            for tid, why in verdict.items():
                if why:
                    floor[tid] = _worse(floor.get(tid), why)
        unknown_scopes = model.unknown_target_scopes(kind)
        for scope, status in unknown_scopes.items():
            self.note("targets", scope, status, f"{kind} inventory {status}",
                      "Targets of this kind in this scope are unknown; techniques reaching them are reported with unknown confidence")
        digest = hashlib.sha1(repr(key).encode()).hexdigest()[:10]
        label = compiled["entry"]["target"].get("aggregate_as") or kind
        cset = CandidateSet(f"{kind}:{digest}", kind, members, floor, label, unknown_scopes)
        self._csets[key] = cset
        return cset

    # ----------------------------------------------------------------- index
    def _index(self):
        model = self.model
        self.by_key, self.universal = {}, set()
        for node in model.sources():
            keys, universal = model.possible(node)
            if universal:
                self.universal.add(node.id)
            for key in keys:
                self.by_key.setdefault(key, set()).add(node.id)
        self.all_sources = {n.id: n for n in model.sources()}

    def _alt_sources(self, reqs):
        sets, unknown = [], []
        for req in reqs:
            reason = self.model.global_unknown(req.raw)
            if reason:
                unknown.append((req, reason))
                sets.append(self.model.unknown_holders(req.raw))
                continue
            sets.append(self.by_key.get(req.key, set()) | self.universal)
        if not sets:
            return set(self.all_sources), unknown
        sets.sort(key=len)
        result = set(sets[0])
        for other in sets[1:]:
            result &= other
            if not result:
                break
        return result, unknown

    # --------------------------------------------------------------- evaluate
    def run(self):
        reaches = []
        for compiled in self.compiled:
            reaches.extend(self.evaluate(compiled))
        return reaches

    def evaluate(self, compiled):
        model = self.model
        cset = self.candidates(compiled)
        if not cset.members and not cset.unknown_scopes:
            return []
        model.current_selector = compiled["selector"]
        model.current_entry = compiled["entry"]
        results = {}
        grouped_unknown = {}
        for index, reqs in enumerate(compiled["alternatives"]):
            sources, unknown_reqs = self._alt_sources(reqs)
            if unknown_reqs:
                for req, reason in unknown_reqs:
                    self.note("requirement", "*", "not_collected", f"{req.key} facts not collected",
                              "Techniques requiring it are reported with unknown confidence for aggregated sources; needs " + reason)
                if not self.include_unknown:
                    continue
            known = [r for r in reqs if not any(r is u for u, _ in unknown_reqs)]
            for sid in sources:
                source = self.all_sources[sid]
                if not model.source_matches(source, compiled["source_kind"], compiled["source_selector"]):
                    continue
                reached = self._evaluate_source(compiled, known, source, cset)
                if reached and compiled["model_blockers"]:
                    reached = self._apply_blockers(compiled, source, reached)
                if not reached:
                    continue
                if unknown_reqs:
                    # Group "may reach" sources by what they would reach, without materialising targets.
                    if isinstance(reached, AllOf):
                        sig = ("all", None if reached.scopes is None else frozenset(reached.scopes), frozenset(reached.unknown))
                    else:
                        sig = ("set", frozenset(reached))
                    group = grouped_unknown.setdefault((index, sig), {"sources": [], "reached": reached,
                                                                       "why": unknown_reqs})
                    group["sources"].append(source)
                    continue
                previous = results.get(sid)
                if previous is None:
                    results[sid] = reached
                    continue
                if isinstance(previous, AllOf) and isinstance(reached, AllOf) and previous.scopes == reached.scopes:
                    results[sid] = AllOf(best(previous.grant, reached.grant), previous.scopes, {**reached.unknown, **previous.unknown})
                    continue
                previous = previous.expand(cset, sid) if isinstance(previous, AllOf) else previous
                reached = reached.expand(cset, sid) if isinstance(reached, AllOf) else reached
                merged = dict(previous)
                for tid, grant in reached.items():
                    merged[tid] = best(merged.get(tid), grant)
                results[sid] = merged
        out = [Reach(compiled, self.all_sources[sid], targets, cset) for sid, targets in results.items() if targets]
        for group in grouped_unknown.values():
            why = "requirement_facts_not_collected:" + ",".join(r.key for r, _ in group["why"])
            # Sources that already reach this technique with known facts are not repeated as "may reach".
            sources = [src for src in group["sources"] if src.id not in results]
            if not sources:
                continue
            reached = group["reached"]
            if isinstance(reached, AllOf):
                targets = AllOf(downgrade(reached.grant, "unknown", why), reached.scopes,
                                {tid: downgrade(g, "unknown", why) for tid, g in reached.unknown.items()})
            else:
                targets = {tid: downgrade(g, "unknown", why) for tid, g in reached.items()}
            out.append(Reach(compiled, sources[0], targets, cset, source_group=sources if len(sources) > 1 else None))
        model.current_selector = None
        return out

    def _apply_blockers(self, compiled, source, reached):
        """Model-evaluated blockers: 'blocked' drops the reach, None (facts missing) annotates it."""
        for blocker in compiled["model_blockers"]:
            verdict = self.model.blocker(blocker, source, compiled)
            if verdict == "blocked":
                return None
            if verdict is None:
                why = f"blocker_{blocker}_not_evaluated"
                self.note("blocker", "*", "not_evaluated", f"blocker {blocker} not evaluated",
                          "Edges kept; needs " + FACTS_NEEDED.get(blocker, "facts not in snapshot"))
                reached = _map_grants(reached, lambda g: downgrade(g, g.confidence, why))
        return reached

    @staticmethod
    def _steps(per_target):
        """Per-target requirements in evaluation order; requirements sharing a multi-valued placeholder are joined."""
        groups, steps = {}, []
        for req in sorted(per_target, key=lambda r: 0 if not r.localized else 1):
            shared = sorted(set(_PH.findall(req.template or "")) & SHARED_PLACEHOLDERS) if not req.localized else []
            if shared:
                groups.setdefault(shared[0], []).append(req)
            else:
                steps.append(req)
        for name, reqs in sorted(groups.items()):
            if len(reqs) == 1:
                steps.insert(0, reqs[0])
            else:
                steps.insert(0, (name, reqs))
        return steps

    def _evaluate_source(self, compiled, reqs, source, cset):
        model = self.model
        static = [r for r in reqs if r.mode == "static"]
        pivot = [r for r in reqs if r.mode == "pivot"]
        per_target = [r for r in reqs if r.mode == "target"]
        grant = Grant(compiled["floor"] if compiled["floor"] in CONF_RANK else "derived")
        grants = [grant]
        for req in static:
            refs, floor = model.resolve(req.template, source, None)
            got = None
            for ref in refs:
                got = best(got, model.cached_check(source, req.raw, ref))
            if got is None:
                return None
            grants.append(downgrade(got, floor[0], floor[1]) if floor else got)
        pivot_values = None
        if pivot:
            got, pivot_values = self._pivot(source, pivot)
            if got is None:
                return None
            grants.append(got)
        base = combine(*grants)
        members = cset.members
        if not members:
            # Inventory unavailable: one unknown reach to the "unknown targets" placeholder.
            return {f"unknown:{cset.id}:{s}": downgrade(base, "unknown", f"target_inventory_{st}")
                    for s, st in cset.unknown_scopes.items()} if self.include_unknown else None
        current = AllTargets(base)
        for req in self._steps(per_target):
            if isinstance(req, tuple):
                name, joined = req
                candidates = members.values() if isinstance(current, AllTargets) else [members[t] for t in current]
                got = model.check_targets_shared(source, [r.raw for r in joined], [r.template for r in joined], name, candidates)
            elif isinstance(current, AllTargets) and model.scope_only(req.raw, req.template, req.localized):
                # The requirement depends on the target only through its scope: check one target per scope.
                reps = {next(iter(ids)): scope for scope, ids in cset.by_scope.items() if ids}
                got = model.check_targets(source, req.raw, req.template, [members[t] for t in reps], localized=req.localized)
                if not isinstance(got, AllTargets):
                    held = {reps[t]: g for t, g in got.items()}
                    if len(held) < len(reps):
                        got = {tid: g for scope, g in held.items() for tid in cset.by_scope[scope]}
                    elif len({id(g) for g in held.values()}) == 1:
                        got = AllTargets(next(iter(held.values())))
                    else:
                        got = {tid: g for scope, g in held.items() for tid in cset.by_scope[scope]}
            else:
                candidates = members.values() if isinstance(current, AllTargets) else [members[t] for t in current]
                if not candidates:
                    return None
                got = model.check_targets(source, req.raw, req.template, candidates, localized=req.localized)
            if isinstance(got, AllTargets):
                if isinstance(current, AllTargets):
                    current = AllTargets(combine(current.grant, got.grant))
                else:
                    current = {t: combine(g, got.grant) for t, g in current.items()}
            else:
                if isinstance(current, AllTargets):
                    current = {t: combine(current.grant, g) for t, g in got.items()}
                else:
                    current = {t: combine(g, got[t]) for t, g in current.items() if t in got}
            if not current:
                return None
        scope_rule = compiled["scope"]
        unknown = {}
        if self.include_unknown and cset.unknown_scopes and not compiled["selector"].get("same_as_source"):
            unknown = {f"unknown:{cset.id}:{s}": downgrade(base, "unknown", f"target_inventory_{st}")
                       for s, st in cset.unknown_scopes.items()}
        if isinstance(current, AllTargets) and not compiled["dynamic"]:
            # Symbolic "every candidate" result: graph.py aggregates without materialising members.
            return AllOf(current.grant, model.allowed_scopes(scope_rule, source), unknown)
        if isinstance(current, AllTargets):
            current = {tid: current.grant for tid in members}
        for key, value in compiled["dynamic"].items():
            subset = {tid: members[tid] for tid in current}
            verdict = model.selector(key, value, subset, source, pivot=pivot_values)
            if verdict is None:
                self.note("selector", "*", "not_evaluated", f"selector {key} not evaluated",
                          "Targets kept with unknown confidence; needs " + FACTS_NEEDED.get(key, "facts not in snapshot"))
                current = {tid: downgrade(g, "unknown", f"selector_{key}_not_evaluated") for tid, g in current.items()}
                continue
            current = {tid: (downgrade(g, *verdict[tid]) if verdict[tid] else g) for tid, g in current.items() if tid in verdict}
            if not current:
                return None
        result = {}
        for tid, g in current.items():
            target = members[tid]
            if not model.scope_allows(scope_rule, source, target):
                continue
            if tid == source.id and not compiled["selector"].get("same_as_source"):
                continue
            floor = cset.floor.get(tid)
            result[tid] = downgrade(g, floor[0], floor[1]) if floor else g
        result.update(unknown)
        return result

    def _pivot(self, source, reqs):
        """Find a pivot (resource / namespace) on which every pivot requirement holds."""
        model = self.model
        candidates = model.pivot_candidates(source)
        if candidates is None:
            grants = []
            for req in reqs:
                got = model.cached_check(source, req.raw, ANY)
                if got is None:
                    return None, None
                grants.append(got)
            return downgrade(combine(*grants), "conditional", "pivot_resource_not_verified"), None
        winner, values = None, []
        for pivot in candidates:
            grants = []
            for req in reqs:
                refs, floor = model.resolve(req.template, source, None, pivot=pivot)
                got = None
                for ref in refs:
                    got = best(got, model.cached_check(source, req.raw, ref))
                if got is None:
                    break
                grants.append(downgrade(got, floor[0], floor[1]) if floor else got)
            else:
                values.append(pivot)
                winner = best(winner, combine(*grants))
        if winner is None:
            return None, None
        return downgrade(winner, "conditional", "pivot_resource_may_need_creation") if model.pivot_is_conditional else winner, values


def _map_grants(reached, fn):
    if isinstance(reached, AllOf):
        return AllOf(fn(reached.grant), reached.scopes, {k: fn(v) for k, v in reached.unknown.items()})
    return {k: fn(v) for k, v in reached.items()}

def _worse(current, new):
    if current is None:
        return new
    return new if CONF_RANK[new[0]] > CONF_RANK[current[0]] else current

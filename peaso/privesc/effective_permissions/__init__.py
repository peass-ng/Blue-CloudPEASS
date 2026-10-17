"""Provider effective-permission models shared by the privilege-escalation evaluator.

Each provider model normalises a snapshot once into:
  * principals (sources) and target candidates per target kind,
  * an index of which catalog requirement keys each principal can possibly hold
    (cheap prefilter), and
  * exact checks of one requirement against one resource / every target of a
    candidate set (with an ALL fast path so that "Resource: *" never
    materialises N per-target results).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache

CONF_RANK = {"derived": 0, "conditional": 1, "unknown": 2}
MAX_REFS = 12


class _Any:
    def __repr__(self):
        return "ANY"


ANY = _Any()  # "the permission on at least one resource"


class Grant:
    """Why a requirement holds: confidence + bounded evidence refs + condition notes."""
    __slots__ = ("confidence", "refs", "conditions")

    def __init__(self, confidence="derived", refs=(), conditions=()):
        self.confidence = confidence
        self.refs = tuple(refs)[:MAX_REFS]
        self.conditions = tuple(dict.fromkeys(conditions))

    def __repr__(self):
        return f"Grant({self.confidence}, {len(self.refs)} refs, {self.conditions})"


def combine(*grants):
    """All of the grants are needed: worst confidence, union of evidence."""
    grants = [g for g in grants if g is not None]
    if not grants:
        return None
    if len(grants) == 1:
        return grants[0]
    confidence = max((g.confidence for g in grants), key=CONF_RANK.__getitem__)
    refs, conditions = [], []
    for g in grants:
        refs.extend(r for r in g.refs if r not in refs)
        conditions.extend(g.conditions)
    return Grant(confidence, refs, conditions)


def best(a, b):
    """Either grant suffices: keep the most certain one."""
    if a is None:
        return b
    if b is None:
        return a
    return a if CONF_RANK[a.confidence] <= CONF_RANK[b.confidence] else b


def downgrade(grant, confidence, condition=None):
    if grant is None:
        return None
    if CONF_RANK[confidence] <= CONF_RANK[grant.confidence] and not condition:
        return grant
    level = max(grant.confidence, confidence, key=CONF_RANK.__getitem__)
    return Grant(level, grant.refs, grant.conditions + ((condition,) if condition else ()))


class AllTargets:
    """Every candidate passed to check_targets is covered by the same grant."""
    __slots__ = ("grant",)

    def __init__(self, grant):
        self.grant = grant


@dataclass(eq=False)
class Node:
    id: str
    kind: str                     # target kind vocabulary (aws_role, gcp_scope_owner, ...)
    provider: str
    scope: str                    # account / project / subscription / namespace / cluster
    label: str
    attrs: dict = field(default_factory=dict)
    entity: bool = False
    perm_key: object = None       # principals with equal perm_key hold identical permissions
    incomplete: list = field(default_factory=list)  # reasons the permission picture is incomplete

    def public(self):
        return {"id": self.id, "label": self.label, "type": self.kind, "provider": self.provider,
                "scope": self.scope, "kind": "entity" if self.entity else "principal"}


@lru_cache(maxsize=65536)
def glob_regex(pattern, ignore_case=True):
    return re.compile(fnmatch.translate(pattern), re.I if ignore_case else 0)


def glob_match(pattern, value, ignore_case=True):
    if pattern == "*":
        return True
    if "*" not in pattern and "?" not in pattern:
        return pattern.lower() == value.lower() if ignore_case else pattern == value
    return glob_regex(pattern, ignore_case).match(value) is not None


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def collections(snapshot, kind):
    return [c for c in snapshot.get("collections", []) if c.get("type") == kind]


def items(snapshot, kind):
    for collection in collections(snapshot, kind):
        for item in collection.get("items", []):
            if isinstance(item, dict):
                yield collection["scope"], item


def inventory_status(snapshot, kind):
    """{scope: status} for a collection type; {} when the type was never requested."""
    return {c["scope"]: c.get("status", "unknown") for c in collections(snapshot, kind)}


def unavailable(statuses):
    return {scope: status for scope, status in statuses.items() if status not in ("collected", "empty")}


class Model:
    """Base class; providers override the documented hooks."""
    provider = ""
    #: target kinds whose candidates are scopes rather than identities
    entity_kinds = ()

    def __init__(self, snapshot, catalog_keys=()):
        self.snapshot = snapshot
        self.principals = {}
        self.coverage = []
        self.catalog_keys = set(catalog_keys)
        self._check_cache = {}

    # ---- coverage -------------------------------------------------------
    def add_coverage(self, kind, scope, status, reason, impact):
        self.coverage.append({"level": "privesc", "provider": self.provider, "kind": kind, "scope": scope,
                              "status": status, "reason": reason, "impact": impact})

    def require_collections(self, kinds, impact):
        for kind in kinds:
            statuses = inventory_status(self.snapshot, kind)
            if not statuses:
                self.add_coverage("collection", "*", "not_collected", f"{kind} not in snapshot", impact.get(kind, ""))
            for scope, status in unavailable(statuses).items():
                self.add_coverage("collection", scope, status, f"{kind} collection {status}", impact.get(kind, ""))

    # ---- hooks ----------------------------------------------------------
    current_selector = None
    current_cset = None  # the evaluator's candidate set for the technique being evaluated (index caches)
    current_entry = None
    pivot_is_conditional = True

    def sources(self):
        return list(self.principals.values())

    def requirement_key(self, req):
        raise NotImplementedError

    def requirement_template(self, req):
        """The resource template of a requirement or None for 'any resource'."""
        raise NotImplementedError

    def localizable(self, req):
        """True when a '*' requirement should be evaluated on the target's scope in localized entries."""
        return self.requirement_template(req) is None

    def global_unknown(self, req):
        """Reason string when the facts for this requirement are not in the snapshot at all."""
        return None

    def unknown_holders(self, req):
        """Principal ids that could plausibly hold a requirement whose facts are missing."""
        return set(self.principals)

    def covered_by_requirement(self, key, action, template, kind):
        """Requirement equivalent of a *_covered_by selector (None to ignore)."""
        if key == "resource_permission_covers_target":
            template = {"aws_role": "{target.arn}", "aws_user": "{target.arn}", "aws_group": "{target.arn}"}.get(kind, "{target.id}")
        if key == "gcp_actas_granted_on_target":
            action = "iam.serviceAccounts.actAs"
        if template is None or not isinstance(action, str):
            return None
        return {"action": action, "resource": template}

    def source_matches(self, source, kinds, selector):
        if kinds and source.kind not in as_list(kinds):
            return False
        return True

    def allowed_scopes(self, rule, source):
        """Scopes a target may live in under the entry's scope rule (None = any)."""
        return None

    def scope_allows(self, rule, source, target):
        scopes = self.allowed_scopes(rule, source)
        return scopes is None or target.scope in scopes

    def pivot_candidates(self, source):
        """Values for {pivot}/{pivot.*} placeholders to try, or None (pivot treated as ANY, conditional)."""
        return None

    def possible(self, principal):
        """(set of requirement keys principal may hold, universal flag)."""
        raise NotImplementedError

    def check(self, principal, req, ref):
        raise NotImplementedError

    def resolve(self, template, source, target, pivot=None):
        """Resolve a requirement template -> (list of refs, floor or None)."""
        raise NotImplementedError

    def localize(self, req, target):
        """Resource ref meaning 'within the target's scope' for '*' requirements."""
        return ANY

    def targets(self, kind):
        """Candidate nodes for a target kind."""
        return []

    def service_managed(self, node):
        """True for identities only their own provider service can use (AWS service-linked roles, Google-managed
        service agents, Microsoft first-party service principals); excluded from target sets by default."""
        return False

    def managed_source(self, node):
        """True for identities that are never escalation sources (only their provider / control plane holds their
        credentials). Defaults to service_managed(); a model may keep such identities as targets (K8s)."""
        return self.service_managed(node)

    def include_service_managed(self, compiled):
        """True when the entry explicitly targets service-managed identities (target.include_service_managed)."""
        target = (compiled.get("entry") or {}).get("target") or {}
        return bool(target.get("include_service_managed"))

    def source_memo_key(self, source):
        """Hashable key such that sources with equal keys get identical per-target verdicts for any technique whose
        requirements and selectors do not name the source; None (default) evaluates every source individually."""
        return None

    # Source-dependent selector keys whose verdict is a function of source_memo_key() alone (so techniques using
    # them can still be evaluated once per memo key). Empty by default.
    memo_safe_selectors = frozenset()

    def precondition(self, pid, candidates, source):
        """Machine-checked precondition (schema.PRECONDITIONS) -> {id: None | (confidence, why)} for the candidates
        that satisfy it (or may: ("unknown", why) makes them unresolved); None when the model cannot evaluate it."""
        return None

    def target_variant(self, kind, selector):
        """Discriminator when an entry's selector needs a different candidate inventory of the same kind."""
        return None

    def targets_for(self, kind, selector):
        return self.targets(kind)

    def set_related(self, snapshots):
        """Related snapshots of other providers (cross-snapshot joins); ignored by default."""

    def cross_edges(self):
        """[(source node, target public dict, Grant)] joining this snapshot's nodes to related snapshots."""
        return []

    def unknown_target_scopes(self, kind):
        """{scope: status} where the candidate inventory for kind is unavailable."""
        return {}

    def selector(self, key, value, candidates, source, pivot=None):
        """Filter candidates for one selector key -> {id: None | (confidence, why)}; None when unsupported."""
        return None

    def admin_targets(self, principal):
        """[(entity node, Grant)] the principal already controls (admin-equivalent)."""
        return []

    def scope_within(self, inner, outer):
        return inner == outer

    def scope_only(self, req, template, localized):
        """True when a per-target requirement depends on the target only through target.scope."""
        return False

    def resolve_for(self, template, source, target):
        """resolve() with the provider's current entry context (AWS needs the selector)."""
        return self.resolve(template, source, target)

    def blocker(self, blocker, source, compiled):
        """'blocked' (drop the edge), 'clear' (evaluated, does not apply) or None (facts missing)."""
        return None

    def blocker_verdict(self, blocker, source, compiled, pivots=None, reached=None, cset=None):
        """Verdict for one source's reach: 'clear', None (facts missing), ('possibly_blocked', evidence) or
        ('blocked', evidence); or {target id: verdict} when the blocker depends on the target. pivots: the pivot
        values (e.g. {"pivot.namespace": ...}) on which the pivot requirements hold, or None. Default: blocker()."""
        return self.blocker(blocker, source, compiled)

    def _held(self, principal, req, template, target):
        refs, floor = self.resolve_for(template, principal, target)
        grant = None
        for ref in refs:
            grant = best(grant, self.cached_check(principal, req, ref))
        if grant is None:
            return None
        return downgrade(grant, floor[0], floor[1]) if floor else grant

    def check_bound(self, principal, reqs, templates):
        """Requirements sharing a `bind` name must hold on ONE common resource the source picks (usually one it
        creates). Default: each must hold on its own pattern; a common resource is not proven, so the result is
        conditional (bound_resource_not_verified). Providers that can intersect resource patterns override this."""
        grants = []
        for req, template in zip(reqs, templates):
            got = self._held(principal, req, template, None)
            if got is None:
                return None
            grants.append(got)
        return downgrade(combine(*grants), "conditional", "bound_resource_not_verified")

    def check_targets_shared(self, principal, reqs, templates, name, candidates):
        """Every requirement must hold on the SAME value of the multi-valued placeholder `name`."""
        token = "{" + name + "}"
        result = {}
        for target in candidates:
            values, floor = self.resolve_for(token, principal, target)
            if values == [ANY]:
                # Placeholder not resolvable from the snapshot: independent checks carry the unknown floor.
                grants = [self._held(principal, req, template, target) for req, template in zip(reqs, templates)]
                if all(g is not None for g in grants):
                    result[target.id] = combine(*grants)
                continue
            winner = None
            for value in values[:200]:
                grants = []
                for req, template in zip(reqs, templates):
                    got = self._held(principal, req, template.replace(token, value), target)
                    if got is None:
                        break
                    grants.append(got)
                else:
                    got = combine(*grants)
                    winner = best(winner, Grant(got.confidence, ({"shared_resource": value},) + got.refs, got.conditions))
            if winner is not None:
                result[target.id] = winner
        return result

    def cached_check(self, principal, req, ref):
        key = (principal.perm_key if principal.perm_key is not None else principal.id, self.requirement_key(req), ref)
        if key not in self._check_cache:
            self._check_cache[key] = self.check(principal, req, ref)
        return self._check_cache[key]

    def check_targets(self, principal, req, template, candidates, localized=False):
        """Default: resolve per target and check with a cache. Providers add fast paths."""
        result = {}
        for target in candidates:
            if localized:
                refs, floor = [self.localize(req, target)], None
            else:
                refs, floor = self.resolve(template, principal, target)
            grant = None
            for ref in refs:
                grant = best(grant, self.cached_check(principal, req, ref))
            if grant is not None:
                result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
        return result

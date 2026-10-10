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
    def sources(self):
        return list(self.principals.values())

    def requirement_key(self, req):
        raise NotImplementedError

    def requirement_template(self, req):
        """The resource template of a requirement or None for 'any resource'."""
        raise NotImplementedError

    def possible(self, principal):
        """(set of requirement keys principal may hold, universal flag)."""
        raise NotImplementedError

    def check(self, principal, req, ref):
        raise NotImplementedError

    def resolve(self, template, source, target):
        """Resolve a requirement resource template to a provider resource ref."""
        raise NotImplementedError

    def localize(self, target):
        """Resource ref meaning 'within the target's scope' for '*' requirements."""
        return ANY

    def targets(self, kind):
        """Candidate nodes for a target kind."""
        return []

    def unknown_target_scopes(self, kind):
        """{scope: status} where the candidate inventory for kind is unavailable."""
        return {}

    def selector(self, key, value, candidates, source):
        """Filter candidates for one selector key -> dict id -> confidence or None (unsupported)."""
        return None

    def static_selector(self, key):
        return key not in {"same_as_source", "trust_allows_principal_of_source"} and not (
            key == "k8s_sa_in_namespace")

    def admin_targets(self, principal):
        """[(entity node, Grant)] the principal already controls (admin-equivalent)."""
        return []

    def scope_within(self, inner, outer):
        return inner == outer

    def placeholder(self, name, node):
        attrs = node.attrs
        if name in ("arn", "id"):
            return attrs.get(name) or node.id
        if name in ("email", "name", "namespace", "account", "project"):
            return attrs.get(name) or (node.scope if name in ("account", "project", "namespace") else node.label)
        if name == "scope":
            return attrs.get("scope", node.scope)
        return None

    def substitute(self, template, source, target):
        def repl(match):
            name = match.group(1)
            owner, _, attr = name.partition(".")
            if not attr:
                owner, attr = "source", owner
            node = target if owner == "target" else source
            if node is None:
                return match.group(0)
            value = self.placeholder(attr, node)
            return str(value) if value is not None else match.group(0)
        return re.sub(r"\{([^{}]+)\}", repl, template)

    def cached_check(self, principal, req, ref):
        key = (principal.perm_key if principal.perm_key is not None else principal.id, self.requirement_key(req), ref)
        if key not in self._check_cache:
            self._check_cache[key] = self.check(principal, req, ref)
        return self._check_cache[key]

    def check_targets(self, principal, req, template, candidates):
        """Default: resolve per target and check with a cache. Providers add fast paths."""
        result = {}
        for target in candidates:
            ref = self.resolve(template, principal, target)
            grant = self.cached_check(principal, req, ref) if ref is not None else None
            if grant is not None:
                result[target.id] = grant
        return result

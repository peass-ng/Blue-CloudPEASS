"""Build the Privilege Escalation Map (nodes, aggregated edges) and findings from Reach results.

Aggregation rules (keep the graph readable at 10k+ principals):
  * a technique result covering every candidate of one scope (>= 2 members) points
    to one aggregate node per (candidate set, scope) shared by all techniques;
  * a partial result with more than SUBSET_MIN members of one scope points to a
    subset aggregate keyed by its member hash;
  * results spanning more than GLOBAL_SCOPES scopes with full coverage point to a
    single global aggregate of the candidate set;
  * otherwise direct principal -> principal edges.
Aggregates are split by confidence, so one edge never mixes derived and unknown
targets. Edges are unique per (source, target): every technique reaching the pair is
listed in `technique_details` (own confidence, evidence and mitigation) and findings
stay per technique, pointing at their edges through evidence.edge_ids. Entity targets (account admin, scope owner, cluster-admin, Entra role)
are pruned to the top-most scope per technique and source.
"""
from __future__ import annotations

import hashlib
import re

from .effective_permissions import CONF_RANK, Grant, downgrade
from .evaluator import UNRESOLVED_PREFIX, AllOf
from .grant_evidence import permission_evidence, administrative_basis

SUBSET_MIN = 5
GLOBAL_SCOPES = 10
MAX_EVIDENCE = 20
MAX_FINDING_TARGETS = 50
MEMBER_SAMPLE = 20
ADMIN_TECHNIQUE = "admin-equivalent"
ADMIN_TITLE = "Principal already holds admin-equivalent control"
CROSS_TECHNIQUE = "cloud-identity-join"
CROSS_TITLE = "Cloud identity resolved to a principal of a related snapshot"
FRAMEWORKS = ["HackTricks Cloud Best Practices"]
_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")


def _ref_key(value):
    """Hashable identity of an evidence ref or condition (dicts compare by content)."""
    try:
        hash(value)
        return value
    except TypeError:
        return repr(sorted(value.items())) if isinstance(value, dict) else repr(value)


def _hash(values):
    return hashlib.sha1("\n".join(sorted(values)).encode()).hexdigest()[:12]


def _label(template, scope, source, cset):
    def repl(match):
        name = match.group(1)
        bare = name[len("target."):] if name.startswith("target.") else name
        if bare in ("account", "scope", "project", "namespace", "subscription", "cluster"):
            return scope  # the group's own scope (cluster, cluster/namespace, account, ...)
        if name.startswith("source."):
            attr = name.split(".", 1)[1]
            if source is None:
                return "the source"
            return str(source.attrs.get(attr) or (source.label if attr == "name" else source.scope))
        return name.split(".")[-1]
    return _PH.sub(repl, template or cset.kind)


class GraphBuilder:
    def __init__(self, model, *, include_admin_sources=False):
        self.model = model
        self.include_admin_sources = include_admin_sources
        self.nodes, self.edges, self.findings = {}, {}, []
        self.suppressed = 0
        self.admin_scopes = {}
        self._suppress_cache = {}
        self.cross_edges = 0
        self.related_ids = set()   # nodes that belong to a related snapshot (cross-snapshot endpoints)

    # ----------------------------------------------------------------- nodes
    def node(self, node):
        if node.id not in self.nodes:
            data = node.public()
            data.update(self._attrs(node))
            if node.attrs.get("related_snapshot"):
                self.related_ids.add(node.id)
                data.setdefault("attrs", {})["related_snapshot"] = True
            self.nodes[node.id] = data
        return node.id

    def _attrs(self, node):
        keep = ("arn", "email", "namespace", "cluster", "mi_type", "upn", "account", "project", "type", "template_id", "name")
        out = {k: node.attrs[k] for k in keep if node.attrs.get(k) not in (None, "", [])}
        if node.kind == "azure_storage_local_user":
            out["storage_account"] = node.attrs["storage_account"]
            out["effective_rights"] = node.attrs.get("effective_rights", [])
        if node.incomplete:
            out["incomplete"] = sorted(set(node.incomplete))[:10]
        if node.kind in self._admin_kinds():
            out["admin"] = True
        return {"attrs": out} if out else {}

    @staticmethod
    def _admin_kinds():
        return ("aws_account_admin", "gcp_scope_owner", "azure_scope_owner", "k8s_cluster_admin")

    def aggregate(self, ident, cset, scope, members, source, confidence, subset=False, label=None):
        if ident not in self.nodes:
            ids = sorted(members)
            sample = [self.model_node_public(cset, m) for m in ids[:MEMBER_SAMPLE]]
            nodes = [cset.members.get(m) for m in ids]
            related = bool(nodes) and all(n is not None and n.attrs.get("related_snapshot") for n in nodes)
            providers = {n.provider for n in nodes if n is not None}
            provider = providers.pop() if related and len(providers) == 1 else self.model.provider
            if related:
                self.related_ids.add(ident)
            self.nodes[ident] = {
                "id": ident, "kind": "aggregate", "type": cset.kind, "provider": provider, "scope": scope,
                "label": label or _label(cset.label, scope, source, cset) + (" (subset)" if subset else ""),
                "underlying_count": len(ids), "members": ids, "member_sample": sample, "confidence": confidence,
                "candidate_set": cset.id, "subset": subset}
        return ident

    def model_node_public(self, cset, member_id):
        node = cset.members.get(member_id)
        return node.public() if node is not None else {"id": member_id}

    # ----------------------------------------------------------------- edges
    def edge(self, source_id, target_id, technique, grant, finding_id, entry=None, title=None, mitigation=None):
        """One edge per (source, target): every technique reaching that pair is listed in technique_details
        with its own evidence, confidence and mitigation; the edge confidence is the strongest of them."""
        key = (source_id, target_id)
        edge = self.edges.get(key)
        if edge is None:
            edge = self.edges[key] = {"id": f"e:{_hash([source_id, target_id])}", "source": source_id, "target": target_id,
                                      "techniques": [], "confidence": grant.confidence, "evidence_refs": [], "findings": [],
                                      "technique_details": []}
        if technique not in edge["techniques"]:
            edge["techniques"].append(technique)
        if CONF_RANK[grant.confidence] < CONF_RANK[edge["confidence"]]:
            edge["confidence"] = grant.confidence
        for ref in grant.refs:
            if len(edge["evidence_refs"]) >= MAX_EVIDENCE:
                break
            if ref not in edge["evidence_refs"]:
                edge["evidence_refs"].append(ref)
        if finding_id and finding_id not in edge["findings"]:
            edge["findings"].append(finding_id)
        detail = next((d for d in edge["technique_details"] if d["id"] == technique), None)
        if detail is None:
            detail = {"id": technique, "title": title or (entry or {}).get("title") or technique,
                      "severity": (entry or {}).get("severity"), "confidence": grant.confidence,
                      "evidence_refs": list(grant.refs[:MAX_EVIDENCE]), "conditions": list(grant.conditions),
                      "granting_permissions": permission_evidence(self.model, grant),
                      "mitigation": mitigation or (entry or {}).get("mitigation") or "", "finding": finding_id}
            if entry:
                detail.update(_outcome(entry))
            edge["technique_details"].append(detail)
        elif CONF_RANK[grant.confidence] < CONF_RANK[detail["confidence"]]:
            detail.update(confidence=grant.confidence, evidence_refs=list(grant.refs[:MAX_EVIDENCE]),
                          conditions=list(grant.conditions),
                          granting_permissions=permission_evidence(self.model, grant))
        edge["technique_details"].sort(key=lambda d: (CONF_RANK[d["confidence"]], d["id"]))
        return edge["id"]

    # ------------------------------------------------------------ cross-snapshot
    def add_cross(self, model=None):
        """Edges joining this snapshot's nodes to principals of related snapshots (cloud_identity -> IAM principal)."""
        model = model or self.model
        added = 0
        for node, joined, grant in model.cross_edges():
            self.node(node)
            if joined["id"] not in self.nodes:
                self.nodes[joined["id"]] = dict(joined)
            self.related_ids.add(joined["id"])
            self.edge(node.id, joined["id"], CROSS_TECHNIQUE, grant, None, title=CROSS_TITLE,
                      mitigation="Review which workloads can use this cloud identity; it carries every permission of the joined principal.")
            added += 1
        self.cross_edges = added
        return added

    # ----------------------------------------------------------------- admin
    def add_admin(self, principals, precomputed=None):
        for principal in principals:
            found = precomputed.get(principal.id, []) if precomputed is not None else self.model.admin_targets(principal)
            for entity, grant in found:
                scopes = self.admin_scopes.setdefault(principal.id, [])
                if entity.scope not in scopes:
                    scopes.append(entity.scope)
                self.node(principal)
                self.node(entity)
                fid = f"privesc:{ADMIN_TECHNIQUE}:{principal.id}:{entity.scope}"
                remediation = "Review why this principal needs full administrative control; prefer scoped, time-bound access."
                eid = self.edge(principal.id, entity.id, ADMIN_TECHNIQUE, grant, fid, title=ADMIN_TITLE, mitigation=remediation)
                self.findings.append(self._finding(fid, ADMIN_TECHNIQUE, ADMIN_TITLE, principal, "iam", "high",
                    remediation, grant, [entity.public()], 1, None, [], edge_ids=[eid]))

    def _suppressed(self, source, target_scope, target_kind=None):
        if self.include_admin_sources or target_kind == "k8s_remote_cluster":
            return False
        scopes = self.admin_scopes.get(source.id)
        if not scopes:
            return False
        key = (source.id, target_scope)
        hit = self._suppress_cache.get(key)
        if hit is None:
            hit = self._suppress_cache[key] = any(self.model.scope_within(target_scope, s) for s in scopes)
        return hit

    # ---------------------------------------------------------------- reaches
    def add(self, reach):
        compiled, cset = reach.entry, reach.cset
        entry = compiled["entry"]
        technique = entry["id"]
        source = reach.source
        groups = self._groups(reach)
        if not groups:
            return
        if reach.source_group:
            members = [s.id for s in reach.source_group]
            sid = f"agg:sources:{technique}:{_hash(members)}"
            if sid not in self.nodes:
                self.nodes[sid] = {"id": sid, "kind": "aggregate", "type": "principal_group", "provider": self.model.provider,
                                   "scope": "*", "label": f"{len(members)} principals that may satisfy {entry['title']}",
                                   "underlying_count": len(members), "members": sorted(members),
                                   "member_sample": [s.public() for s in reach.source_group[:MEMBER_SAMPLE]],
                                   "confidence": "unknown", "candidate_set": None, "subset": False}
        else:
            sid = self.node(source)
        fid = f"privesc:{technique}:{sid}"
        targets_public, count, grants, edge_ids = [], 0, [], []
        for target_id, grant, size in groups:
            edge_ids.append(self.edge(sid, target_id, technique, grant, fid, entry=entry))
            grants.append(grant)
            count += size
            if len(targets_public) < MAX_FINDING_TARGETS:
                node = self.nodes.get(target_id) or {"id": target_id}
                targets_public.append({k: node.get(k) for k in ("id", "label", "type", "kind", "scope", "underlying_count") if k in node})
        confidence = min((g.confidence for g in grants), key=CONF_RANK.__getitem__)
        refs, conditions, permission_refs, seen_refs, seen_conditions = [], [], [], set(), set()
        for g in grants:
            for r in g.refs:
                if len(refs) >= MAX_EVIDENCE:
                    break
                key = _ref_key(r)
                if key not in seen_refs:
                    seen_refs.add(key)
                    refs.append(r)
            for c in g.conditions:
                key = _ref_key(c)
                if key not in seen_conditions:
                    seen_conditions.add(key)
                    conditions.append(c)
            for pair in getattr(g, "permission_refs", ()):
                if pair not in permission_refs:
                    permission_refs.append(pair)
        merged = Grant(confidence, refs, conditions, permission_refs)
        src = source if not reach.source_group else None
        self.findings.append(self._finding(fid, technique, entry["title"], src, entry.get("service"), entry.get("severity", "medium"),
                                           entry.get("mitigation"), merged, targets_public, count, entry, compiled["blockers_not_evaluated"],
                                           source_group=reach.source_group, group_id=sid if reach.source_group else None,
                                           edge_ids=edge_ids))

    def _groups(self, reach):
        """[(target node id, grant, underlying count)] after aggregation, pruning and suppression."""
        cset, source = reach.cset, reach.source
        targets = reach.targets
        unknown = {}
        if isinstance(targets, AllOf):
            unknown = dict(targets.unknown)
            per_scope = {}
            for scope, ids in cset.by_scope.items():
                if targets.scopes is not None and scope not in targets.scopes:
                    continue
                for tid in ids:
                    if tid == source.id and not reach.source_group:
                        continue
                    floor = cset.floor.get(tid)
                    grant = downgrade(targets.grant, floor[0], floor[1]) if floor else targets.grant
                    per_scope.setdefault((scope, grant.confidence), {})[tid] = grant
        else:
            per_scope = {}
            for tid, grant in targets.items():
                if tid.startswith(("unknown:", UNRESOLVED_PREFIX)):
                    unknown[tid] = grant
                    continue
                node = cset.members.get(tid)
                if node is None:
                    continue
                per_scope.setdefault((node.scope, grant.confidence), {})[tid] = grant
        out = []
        # Candidate sets are shared by techniques with the same target kind and static selector; a group node's
        # identity and label are per technique template (and per source when the template names the source).
        template = (reach.entry["entry"].get("target") or {}).get("aggregate_as") or cset.label
        source_dep = "{source." in (template or "")
        tag = "" if template == cset.label and not source_dep else \
            ":" + _hash([template, source.id if source_dep and not reach.source_group else ""])
        src_for_label = None if reach.source_group else source
        is_entity = bool(cset.members) and next(iter(cset.members.values())).entity
        if is_entity:
            reached = {tid for group in per_scope.values() for tid in group}
            scopes = {cset.members[t].scope: t for t in reached}
            for (scope, conf), group in sorted(per_scope.items()):
                for tid, grant in group.items():
                    node = cset.members[tid]
                    if any(other != node.scope and self.model.scope_within(node.scope, other) for other in scopes):
                        continue  # a broader scope of the same kind is already reached
                    if self._suppressed(source, node.scope, cset.kind) and not reach.source_group:
                        self.suppressed += 1
                        continue
                    self.node(node)
                    out.append((tid, grant, 1))
        else:
            full_scopes = [k for k, g in per_scope.items() if len(g) == len(cset.by_scope.get(k[0], ())) - (1 if source.id in cset.by_scope.get(k[0], ()) else 0)]
            if len(per_scope) > GLOBAL_SCOPES and len(full_scopes) == len(per_scope) and len({k[1] for k in per_scope}) == 1:
                members = {tid for g in per_scope.values() for tid in g}
                live = {tid for tid in members if not self._suppressed(source, cset.members[tid].scope, cset.kind)}
                self.suppressed += len(members) - len(live)
                if live:
                    conf = next(iter(per_scope))[1]
                    grant = next(iter(next(iter(per_scope.values())).values()))
                    ident = (f"agg:{cset.id}:*:{conf}" if live == members else f"agg:{cset.id}:sub:{_hash(live)}:{conf}") + tag
                    shown = {tid for k in per_scope for tid in cset.by_scope[k[0]]} if live == members else live
                    self.aggregate(ident, cset, "*", shown, source, conf, subset=live != members,
                                   label=_label(template, "all scopes", src_for_label, cset) + (" (subset)" if live != members else ""))
                    out.append((ident, grant, len(live)))
            else:
                for (scope, conf), group in sorted(per_scope.items()):
                    if self._suppressed(source, scope, cset.kind) and not reach.source_group:
                        self.suppressed += len(group)
                        continue
                    best_grant = _best_of(group.values())
                    full = len(group) >= 2 and len(group) == len(cset.by_scope.get(scope, ())) - (1 if source.id in cset.by_scope.get(scope, ()) else 0)
                    if full:
                        # "Every candidate in the scope" is one shared node: list every candidate, not this
                        # source's view of it (which omits the source itself and would depend on who came first).
                        ident = f"agg:{cset.id}:{scope}:{conf}{tag}"
                        self.aggregate(ident, cset, scope, cset.by_scope[scope], source, conf,
                                       label=_label(template, scope, src_for_label, cset))
                        out.append((ident, best_grant, len(group)))
                    elif len(group) > SUBSET_MIN:
                        ident = f"agg:{cset.id}:{scope}:sub:{_hash(group)}:{conf}{tag}"
                        self.aggregate(ident, cset, scope, group, source, conf, subset=True,
                                       label=_label(template, scope, src_for_label, cset) + " (subset)")
                        out.append((ident, best_grant, len(group)))
                    else:
                        for tid, grant in group.items():
                            self.node(cset.members[tid])
                            out.append((tid, grant, 1))
        placeholders = []  # (scope, grant, why, inventory_status or None)
        for tid, grant in unknown.items():
            if tid.startswith(UNRESOLVED_PREFIX):
                scope = tid[len(UNRESOLVED_PREFIX) + len(cset.id) + 1:] or "*"
                why = cset.unresolved.get(scope) or (grant.conditions[-1] if grant.conditions else "selector_facts_missing")
                status = None
            else:
                scope = tid.split(":", 3)[-1] if tid.count(":") >= 3 else "*"
                why, status = None, cset.unknown_scopes.get(scope, "unknown")
            if self._suppressed(source, scope, cset.kind) and not reach.source_group:
                self.suppressed += 1
                continue
            placeholders.append((scope, grant, why, status))
        if len(placeholders) == 1:
            scope, grant, why, status = placeholders[0]
            if status is None:
                tid = f"{UNRESOLVED_PREFIX}{cset.id}:{scope}{tag}"
                if tid not in self.nodes:
                    self.nodes[tid] = {"id": tid, "kind": "aggregate", "type": cset.kind, "provider": self.model.provider,
                                       "scope": scope, "label": "Unresolved: " + _label(template, scope, src_for_label, cset),
                                       "underlying_count": 0, "members": [], "member_sample": [], "confidence": "unknown",
                                       "candidate_set": cset.id, "subset": False, "unresolved": True,
                                       "unresolved_reason": why, "facts_needed": _facts_needed(why)}
            else:
                tid = f"unknown:{cset.id}:{scope}"
                if tid not in self.nodes:
                    missing = "review evidence unavailable" if status and status.startswith("review_evidence_") else "inventory unavailable"
                    self.nodes[tid] = {"id": tid, "kind": "aggregate", "type": cset.kind, "provider": self.model.provider,
                                       "scope": scope, "label": f"Unknown {cset.kind} targets in {scope} ({missing})",
                                       "underlying_count": None, "members": [], "member_sample": [], "confidence": "unknown",
                                       "candidate_set": cset.id, "subset": False}
            out.append((tid, grant, 0))
        elif placeholders:
            # Targets that cannot be resolved in several scopes: ONE memberless node for the whole set (one edge per
            # source or holder group), never one edge per scope.
            scopes = sorted({p[0] for p in placeholders})
            reasons = sorted({p[2] or f"target_inventory_{p[3]}" for p in placeholders})
            tid = f"{UNRESOLVED_PREFIX}{cset.id}:scopes:{_hash(scopes)}{tag}"
            if tid not in self.nodes:
                shown = scopes[0] if len(scopes) == 1 else f"{len(scopes)} scopes"
                self.nodes[tid] = {"id": tid, "kind": "aggregate", "type": cset.kind, "provider": self.model.provider,
                                   "scope": "*", "scopes": scopes, "label": "Unresolved: " + _label(template, shown, src_for_label, cset),
                                   "underlying_count": 0, "members": [], "member_sample": [], "confidence": "unknown",
                                   "candidate_set": cset.id, "subset": False, "unresolved": True,
                                   "unresolved_reason": reasons[0] if len(reasons) == 1 else ",".join(reasons),
                                   "facts_needed": "; ".join(sorted({_facts_needed(r) if not r.startswith("target_inventory_")
                                                                     else f"{cset.kind} inventory ({r[len('target_inventory_'):]})"
                                                                     for r in reasons}))}
            out.append((tid, _best_of(p[1] for p in placeholders), 0))
        return out

    # --------------------------------------------------------------- findings
    def _finding(self, fid, technique, title, source, service, severity, remediation, grant, targets, count, entry, blockers,
                 source_group=None, group_id=None, edge_ids=None):
        # Only derived edges (every fact proven by the snapshot) FAIL; conditional ones need a human to decide the
        # unevaluated condition (MANUAL) and unknown ones lack facts (UNKNOWN).
        status = {"derived": "FAIL", "conditional": "MANUAL"}.get(grant.confidence, "UNKNOWN")
        source_public = source.public() if source is not None else {
            "id": group_id, "kind": "aggregate", "label": f"{len(source_group or [])} principals",
            "members": [s.id for s in (source_group or [])][:MAX_FINDING_TARGETS]}
        resource = source.id if source is not None else group_id
        scope = source.scope if source is not None else "*"
        granting = [r for r in grant.refs]
        evidence = {
            "technique": {"id": technique, "title": title,
                          "source": entry.get("source") if entry else None,
                          "source_revision": entry.get("source_revision") if entry else None,
                          "summary": entry.get("summary") if entry else None},
            "source": source_public, "targets": targets, "target_count": count,
            "granting_statements": granting,
            "granting_permissions": permission_evidence(self.model, grant),
            "conditions": list(grant.conditions),
            "confidence": grant.confidence,
            # Edges this finding contributes to; several techniques on one (source, target) share one edge.
            "edge_ids": list(edge_ids or [])[:MAX_FINDING_TARGETS],
        }
        if technique == ADMIN_TECHNIQUE:
            evidence["technique"]["summary"] = administrative_basis(evidence["granting_permissions"])
            evidence["required_permissions"] = sorted({pair["permission"] for pair in evidence["granting_permissions"]})
        if status == "UNKNOWN":
            # Every UNKNOWN names what the snapshot lacked, so it is actionable rather than a bare unknown.
            missing = [c for c in grant.conditions if not c.startswith("blocker_")] or ["facts_missing"]
            evidence["reason"] = "missing_facts: " + ", ".join(sorted(set(missing)))
            evidence["facts_needed"] = "; ".join(sorted({_facts_needed(c) for c in missing}))
        if entry:
            evidence["technique"].update(_outcome(entry))
        if entry and entry.get("conditions"):
            evidence["technique_conditions"] = entry["conditions"]
        if blockers:
            evidence["blockers_not_evaluated"] = blockers
        verdicts = [c for c in grant.conditions if c.startswith("blocker_") and ("_possibly_enforced" in c or "_lifted_via_" in c)]
        if verdicts:
            evidence["blocker_verdicts"] = verdicts
        return {"id": fid, "category": "privesc", "check_id": technique, "title": title, "provider": self.model.provider,
                "service": service or "iam", "resource_id": resource, "scope": scope, "severity": severity, "status": status,
                "frameworks": list(FRAMEWORKS), "remediation": remediation or "", "evidence": evidence}

    def result(self):
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values())}

    def cross_snapshot_count(self):
        """Edges with an endpoint in a related snapshot: cloud-identity joins (K8s -> cloud principal) and
        techniques reaching principals of a joined snapshot (GCP container.* -> KSAs of the joined cluster)."""
        return sum(1 for e in self.edges.values() if e["source"] in self.related_ids or e["target"] in self.related_ids)

    def path_stats(self):
        """Distinct escalation paths (deduplicated edges) vs. per-technique findings."""
        edges = [e for e in self.edges.values() if e["techniques"] != [CROSS_TECHNIQUE]]
        multi = [e for e in edges if len(e["techniques"]) > 1]
        return {"distinct_paths": len(edges), "multi_technique_edges": len(multi),
                "max_techniques_per_edge": max((len(e["techniques"]) for e in edges), default=0),
                "technique_edge_pairs": sum(len(e["techniques"]) for e in edges)}


def _outcome(entry):
    """What the source obtains (schema target.outcome / target.grants; inferred from the kind when not authored)."""
    from .schema import default_outcome
    target = entry.get("target") or {}
    out = {"outcome": target.get("outcome") or default_outcome(target)}
    if not target.get("outcome"):
        out["outcome_inferred"] = True
    if target.get("grants"):
        out["grants"] = list(target["grants"])
    if target.get("removes_blockers"):
        out["removes_blockers"] = list(target["removes_blockers"])
    return out


def _facts_needed(why):
    from .schema import FACTS_NEEDED
    match = re.match(r"selector_(.+?)_(?:not_evaluated|unknown)$", str(why))
    key = match.group(1) if match else None
    return FACTS_NEEDED.get(key) or "facts not in snapshot: " + str(why)


def _best_of(grants):
    best = None
    for g in grants:
        if best is None or CONF_RANK[g.confidence] < CONF_RANK[best.confidence]:
            best = g
    return best

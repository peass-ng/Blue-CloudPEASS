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
from .evaluator import AllOf

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


def _hash(values):
    return hashlib.sha1("\n".join(sorted(values)).encode()).hexdigest()[:12]


def _label(template, scope, source, cset):
    def repl(match):
        name = match.group(1)
        if name in ("account", "scope", "project", "target.scope", "namespace", "subscription"):
            return scope
        if name == "cluster":
            return scope.split("/", 1)[0]
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
        self.cross_edges = 0

    # ----------------------------------------------------------------- nodes
    def node(self, node):
        if node.id not in self.nodes:
            data = node.public()
            data.update(self._attrs(node))
            self.nodes[node.id] = data
        return node.id

    def _attrs(self, node):
        keep = ("arn", "email", "namespace", "cluster", "mi_type", "upn", "account", "project", "type", "template_id", "name")
        out = {k: node.attrs[k] for k in keep if node.attrs.get(k) not in (None, "", [])}
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
            self.nodes[ident] = {
                "id": ident, "kind": "aggregate", "type": cset.kind, "provider": self.model.provider, "scope": scope,
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
                      "mitigation": mitigation or (entry or {}).get("mitigation") or "", "finding": finding_id}
            edge["technique_details"].append(detail)
        elif CONF_RANK[grant.confidence] < CONF_RANK[detail["confidence"]]:
            detail.update(confidence=grant.confidence, evidence_refs=list(grant.refs[:MAX_EVIDENCE]),
                          conditions=list(grant.conditions))
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
            self.edge(node.id, joined["id"], CROSS_TECHNIQUE, grant, None, title=CROSS_TITLE,
                      mitigation="Review which workloads can use this cloud identity; it carries every permission of the joined principal.")
            added += 1
        self.cross_edges = added
        return added

    # ----------------------------------------------------------------- admin
    def add_admin(self, principals):
        for principal in principals:
            for entity, grant in self.model.admin_targets(principal):
                self.admin_scopes.setdefault(principal.id, []).append(entity.scope)
                self.node(principal)
                self.node(entity)
                fid = f"privesc:{ADMIN_TECHNIQUE}:{principal.id}:{entity.scope}"
                remediation = "Review why this principal needs full administrative control; prefer scoped, time-bound access."
                eid = self.edge(principal.id, entity.id, ADMIN_TECHNIQUE, grant, fid, title=ADMIN_TITLE, mitigation=remediation)
                self.findings.append(self._finding(fid, ADMIN_TECHNIQUE, ADMIN_TITLE, principal, "iam", "high",
                    remediation, grant, [entity.public()], 1, None, [], edge_ids=[eid]))

    def _suppressed(self, source, target_scope):
        if self.include_admin_sources:
            return False
        scopes = self.admin_scopes.get(source.id)
        if not scopes:
            return False
        return any(self.model.scope_within(target_scope, s) for s in scopes)

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
        refs, conditions = [], []
        for g in grants:
            refs.extend(r for r in g.refs if r not in refs)
            conditions.extend(c for c in g.conditions if c not in conditions)
        merged = Grant(confidence, refs[:MAX_EVIDENCE], conditions)
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
                if tid.startswith("unknown:"):
                    unknown[tid] = grant
                    continue
                node = cset.members.get(tid)
                if node is None:
                    continue
                per_scope.setdefault((node.scope, grant.confidence), {})[tid] = grant
        out = []
        is_entity = bool(cset.members) and next(iter(cset.members.values())).entity
        if is_entity:
            reached = {tid for group in per_scope.values() for tid in group}
            scopes = {cset.members[t].scope: t for t in reached}
            for (scope, conf), group in sorted(per_scope.items()):
                for tid, grant in group.items():
                    node = cset.members[tid]
                    if any(other != node.scope and self.model.scope_within(node.scope, other) for other in scopes):
                        continue  # a broader scope of the same kind is already reached
                    if self._suppressed(source, node.scope) and not reach.source_group:
                        self.suppressed += 1
                        continue
                    self.node(node)
                    out.append((tid, grant, 1))
        else:
            full_scopes = [k for k, g in per_scope.items() if len(g) == len(cset.by_scope.get(k[0], ())) - (1 if source.id in cset.by_scope.get(k[0], ()) else 0)]
            if len(per_scope) > GLOBAL_SCOPES and len(full_scopes) == len(per_scope) and len({k[1] for k in per_scope}) == 1:
                members = {tid for g in per_scope.values() for tid in g}
                live = {tid for tid in members if not self._suppressed(source, cset.members[tid].scope)}
                self.suppressed += len(members) - len(live)
                if live:
                    conf = next(iter(per_scope))[1]
                    grant = next(iter(next(iter(per_scope.values())).values()))
                    ident = f"agg:{cset.id}:*:{conf}" if live == members else f"agg:{cset.id}:sub:{_hash(live)}:{conf}"
                    self.aggregate(ident, cset, "*", live, source, conf, subset=live != members,
                                   label=_label(cset.label, "all scopes", source, cset))
                    out.append((ident, grant, len(live)))
            else:
                for (scope, conf), group in sorted(per_scope.items()):
                    if self._suppressed(source, scope) and not reach.source_group:
                        self.suppressed += len(group)
                        continue
                    best_grant = _best_of(group.values())
                    full = len(group) >= 2 and len(group) == len(cset.by_scope.get(scope, ())) - (1 if source.id in cset.by_scope.get(scope, ()) else 0)
                    if full:
                        ident = f"agg:{cset.id}:{scope}:{conf}"
                        self.aggregate(ident, cset, scope, group, source, conf)
                        out.append((ident, best_grant, len(group)))
                    elif len(group) > SUBSET_MIN:
                        ident = f"agg:{cset.id}:{scope}:sub:{_hash(group)}:{conf}"
                        self.aggregate(ident, cset, scope, group, source, conf, subset=True)
                        out.append((ident, best_grant, len(group)))
                    else:
                        for tid, grant in group.items():
                            self.node(cset.members[tid])
                            out.append((tid, grant, 1))
        for tid, grant in unknown.items():
            scope = tid.split(":", 3)[-1] if tid.count(":") >= 3 else "*"
            if tid not in self.nodes:
                self.nodes[tid] = {"id": tid, "kind": "aggregate", "type": cset.kind, "provider": self.model.provider,
                                   "scope": scope, "label": f"Unknown {cset.kind} targets in {scope} (inventory unavailable)",
                                   "underlying_count": None, "members": [], "member_sample": [], "confidence": "unknown",
                                   "candidate_set": cset.id, "subset": False}
            out.append((tid, grant, 0))
        return out

    # --------------------------------------------------------------- findings
    def _finding(self, fid, technique, title, source, service, severity, remediation, grant, targets, count, entry, blockers,
                 source_group=None, group_id=None, edge_ids=None):
        status = "UNKNOWN" if grant.confidence == "unknown" else "FAIL"
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
            "granting_statements": granting, "conditions": list(grant.conditions),
            "confidence": grant.confidence,
            # Edges this finding contributes to; several techniques on one (source, target) share one edge.
            "edge_ids": list(edge_ids or [])[:MAX_FINDING_TARGETS],
        }
        if entry and entry.get("conditions"):
            evidence["technique_conditions"] = entry["conditions"]
        if blockers:
            evidence["blockers_not_evaluated"] = blockers
        return {"id": fid, "category": "privesc", "check_id": technique, "title": title, "provider": self.model.provider,
                "service": service or "iam", "resource_id": resource, "scope": scope, "severity": severity, "status": status,
                "frameworks": list(FRAMEWORKS), "remediation": remediation or "", "evidence": evidence}

    def result(self):
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values())}

    def path_stats(self):
        """Distinct escalation paths (deduplicated edges) vs. per-technique findings."""
        edges = [e for e in self.edges.values() if e["techniques"] != [CROSS_TECHNIQUE]]
        multi = [e for e in edges if len(e["techniques"]) > 1]
        return {"distinct_paths": len(edges), "multi_technique_edges": len(multi),
                "max_techniques_per_edge": max((len(e["techniques"]) for e in edges), default=0),
                "technique_edge_pairs": sum(len(e["techniques"]) for e in edges)}


def _best_of(grants):
    best = None
    for g in grants:
        if best is None or CONF_RANK[g.confidence] < CONF_RANK[best.confidence]:
            best = g
    return best

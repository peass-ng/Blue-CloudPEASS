"""Read-only privilege-escalation analysis: catalog x snapshot -> Privilege Escalation Map.

    from peaso import privesc
    result = privesc.analyze(snapshot)              # {"findings", "graph", "coverage", "stats"}
    privesc.queries.reach_admin(result["graph"])

Nothing here calls a cloud API; the snapshot is consumed as-is.
"""
from __future__ import annotations

import gc
import time
from functools import lru_cache
from pathlib import Path

from . import queries
from .effective_permissions.aws import AwsModel
from .effective_permissions.azure import AzureModel
from .effective_permissions.gcp import GcpModel
from .effective_permissions.k8s import K8sModel
from .evaluator import Evaluator
from .graph import GraphBuilder
from .schema import CATALOG_DIR, CatalogError, load_catalog

MODELS = {"aws": AwsModel, "gcp": GcpModel, "azure": AzureModel, "k8s": K8sModel}
__all__ = ["analyze", "load_catalog", "queries", "CatalogError", "MODELS"]


MAX_BLOCKED_RECORDS = 500


@lru_cache(maxsize=8)
def _cached_catalog(path):
    return load_catalog(path)


def catalog(catalog_dir=None):
    """Load (and cache) a catalog directory."""
    return _cached_catalog(str(Path(catalog_dir) if catalog_dir else CATALOG_DIR))


def analyze(snapshot, catalog_dir=None, *, entries=None, include_unknown=False, include_admin_sources=False,
            related_snapshots=None):
    """Evaluate every catalog technique of the snapshot's provider (see _analyze).

    The analysis allocates millions of short-lived, acyclic objects next to a large live snapshot; the cyclic
    garbage collector would rescan that heap many times (it dominated 10x-scale runs), so it is paused for the
    duration and re-enabled afterwards.
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        return _analyze(snapshot, catalog_dir, entries=entries, include_unknown=include_unknown,
                        include_admin_sources=include_admin_sources, related_snapshots=related_snapshots)
    finally:
        if was_enabled:
            gc.enable()


def _analyze(snapshot, catalog_dir=None, *, entries=None, include_unknown=False, include_admin_sources=False,
             related_snapshots=None):
    """Evaluate every catalog technique of the snapshot's provider.

    include_unknown: opt in to diagnostic, memberless unknown-confidence reaches for missing facts/inventories.
    include_admin_sources: keep edges from principals that already administer the target scope.
    related_snapshots: snapshots of other providers used for cross-snapshot joins (K8s cloud identities ->
        AWS/GCP/Azure principals; GCP GKE techniques -> KSAs of the joined K8s snapshot). Never fetched.
    """
    started = time.perf_counter()
    provider = snapshot.get("provider")
    model_cls = MODELS.get(provider)
    coverage = []
    if model_cls is None:
        return {"findings": [], "graph": {"nodes": [], "edges": []},
                "coverage": [{"level": "privesc", "provider": provider, "kind": "provider", "scope": "*",
                              "status": "unsupported", "reason": f"no privesc model for provider {provider!r}",
                              "impact": "No privilege-escalation analysis"}],
                "stats": {"techniques": 0}}
    loaded = None
    if entries is None:
        loaded = catalog(catalog_dir)
        entries = loaded["entries"]
        for error in loaded["errors"]:
            if not error.startswith(provider + "/"):
                continue
            coverage.append({"level": "privesc", "provider": provider, "kind": "catalog", "scope": "*", "status": "invalid",
                             "reason": error, "impact": "Technique not evaluated"})
    entries = [e for e in entries if e.get("provider") == provider]
    t0 = time.perf_counter()
    model = model_cls(snapshot)
    related = [r for r in (related_snapshots or ()) if isinstance(r, dict) and r is not snapshot]
    if related:
        model.set_related(related)
    t_model = time.perf_counter() - t0
    t0 = time.perf_counter()
    admin = {p.id: model.admin_targets(p) for p in model.sources()}
    admin_scopes = {} if include_admin_sources else {
        pid: sorted({entity.scope for entity, _ in found}) for pid, found in admin.items() if found}
    evaluator = Evaluator(model, entries, include_unknown=include_unknown, admin_scopes=admin_scopes)
    reaches = evaluator.run()
    t_eval = time.perf_counter() - t0
    t0 = time.perf_counter()
    builder = GraphBuilder(model, include_admin_sources=include_admin_sources)
    builder.add_admin(model.sources(), admin)
    for reach in reaches:
        builder.add(reach)
    if related:
        builder.add_cross(model)
    graph = builder.result()
    t_graph = time.perf_counter() - t0
    coverage.extend(_dedupe(model.coverage))
    by_conf = {"derived": 0, "conditional": 0, "unknown": 0}
    for edge in graph["edges"]:
        by_conf[edge["confidence"]] += 1
    stats = {
        "provider": provider, "techniques": len(entries),
        "principals": sum(node.kind not in ("aws_challenge_foothold", "gcp_challenge_foothold")
                          for node in model.principals.values()),
        "sources_evaluated": len(evaluator.all_sources), "reaches": len(reaches),
        "nodes": len(graph["nodes"]), "edges": len(graph["edges"]), "edges_by_confidence": by_conf,
        "findings": len(builder.findings), "suppressed_admin_edges": builder.suppressed,
        "admin_principals": len(builder.admin_scopes), "skipped_admin_source_evaluations": evaluator.skipped_admin,
        "skipped_service_managed_sources": evaluator.skipped_service_managed,
        "memoized_source_evaluations": evaluator.memo_hits,
        # Reaches a definitive blocker removed from the graph, with the evidence (never silently dropped).
        "blocked_reaches": len(evaluator.blocked), "blocked": evaluator.blocked[:MAX_BLOCKED_RECORDS],
        **builder.path_stats(), "cross_snapshot_edges": builder.cross_snapshot_count(),
        "related_snapshots": [r.get("provider") for r in related],
        "catalog_errors": len(loaded["errors"]) if loaded else 0,
        "timing_seconds": {"model": round(t_model, 4), "evaluate": round(t_eval, 4), "graph": round(t_graph, 4),
                           "total": round(time.perf_counter() - started, 4)},
    }
    return {"findings": builder.findings, "graph": graph, "coverage": coverage, "stats": stats}


def _dedupe(entries):
    seen, out = set(), []
    for entry in entries:
        key = (entry.get("kind"), entry.get("scope"), entry.get("reason"))
        if key not in seen:
            seen.add(key)
            out.append(entry)
    return out

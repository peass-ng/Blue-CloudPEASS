"""Optional DuckDB set evaluation of strict native scalar predicates.

The database is in-memory and receives JSON values only. Upstream SQL is never
executed. The Python semantic registry remains available without DuckDB.
"""
from __future__ import annotations
import json
import re
from time import perf_counter
from .facts import FIELD_SPECS


def _literal(value):
    # Values are trusted registry constants; quote SQL string constants explicitly.
    return "'" + str(value).replace("'", "''") + "'"


def _extract(path):
    return "json_extract_string(payload, " + _literal("$." + path) + ")"


def scalar_sql(check_id):
    spec = FIELD_SPECS[check_id]
    path = spec["path"]
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", path):
        raise ValueError("unsupported native scalar path")
    parents = [""] + [".".join(path.split(".")[:i]) for i in range(1, len(path.split(".")))]
    unavailable = []
    for parent in parents:
        prefix = parent + "." if parent else ""
        object_path = "$." + parent if parent else "$"
        unavailable.extend([
            "json_type(payload, " + _literal(object_path) + ") IS DISTINCT FROM 'OBJECT'",
            "coalesce(" + _extract(prefix + "collection_status") + ", 'collected') NOT IN ('collected', 'empty')",
            "coalesce(json_type(payload, " + _literal("$." + prefix + "_coverage") + "), 'OBJECT') <> 'OBJECT'",
        ])
    parts = path.split(".")
    for i, part in enumerate(parts):
        prefix = ".".join(parts[:i])
        coverage_path = (prefix + "." if prefix else "") + "_coverage." + part + ".status"
        coverage_object = coverage_path.removesuffix(".status")
        coverage_type = "json_type(payload, " + _literal("$." + coverage_object) + ")"
        unavailable.append("(" + coverage_type + " IS NOT NULL AND (" + coverage_type + " <> 'OBJECT' OR coalesce(" + _extract(coverage_path) + ", 'unknown') NOT IN ('collected', 'empty')))")
    expected = spec["expected"]
    kind = "BOOLEAN" if expected is bool else "VARCHAR" if expected is str else "BIGINT"
    types = "('BIGINT', 'UBIGINT')" if expected is int else "(" + _literal(kind) + ")"
    unavailable.append("coalesce(json_type(payload, " + _literal("$." + path) + "), 'NULL') NOT IN " + types)
    good = spec["good"] if isinstance(spec["good"], tuple) else (spec["good"],)
    convert = lambda value: str(value).lower() if type(value) is bool else str(value)
    if expected is str:
        known = good + (spec["bad"],)
        unavailable.append(_extract(path) + " NOT IN (" + ", ".join(_literal(value) for value in known) + ")")
    return "SELECT row_id, CASE WHEN " + " OR ".join(unavailable) + " THEN 'UNKNOWN' WHEN " + _extract(path) + " IN (" + ", ".join(_literal(convert(value)) for value in good) + ") THEN 'PASS' ELSE 'FAIL' END AS status, json_extract(payload, " + _literal("$." + path) + ") AS configured FROM facts ORDER BY row_id"


def evaluate_many(check_ids, items, backend="python"):
    from . import CHECKS
    registry = {c.id: c for c in CHECKS}
    if any(cid not in FIELD_SPECS for cid in check_ids):
        raise ValueError("batch backend supports registered strict scalar checks only")
    if backend == "python":
        return {cid: [registry[cid].evaluate(item, {}) for item in items] for cid in check_ids}
    if backend != "duckdb":
        raise ValueError("backend must be python or duckdb")
    try:
        import duckdb
    except ImportError as exc:
        raise RuntimeError("optional DuckDB backend requires peaso[analytics]") from exc
    payloads = json.dumps(items, separators=(",", ":"), allow_nan=False)
    output = {}
    with duckdb.connect(":memory:") as connection:
        connection.execute("CREATE TEMP TABLE facts AS SELECT key::BIGINT AS row_id, value AS payload FROM json_each(?::JSON)", [payloads])
        for cid in check_ids:
            path = FIELD_SPECS[cid]["path"]
            rows = connection.execute(scalar_sql(cid)).fetchall()
            output[cid] = [(status, {"reason": "missing, malformed or unavailable native fact", "field": path} if status == "UNKNOWN" else {"field": path, "configured": json.loads(value)}) for _, status, value in rows]
    return output


def benchmark(count=100000):
    """Fixed 100k-record fixture; timings include Python JSON conversion/DB loading."""
    from collections import Counter
    items = [{"VolumeId": "vol-" + str(i), **({"Encrypted": bool(i % 2)} if i % 3 else {}), **({"collection_status": "denied"} if i % 37 == 0 else {})} for i in range(count)]
    timings, counts, statuses = {}, {}, {}
    for backend in ("python", "duckdb"):
        start = perf_counter()
        output = evaluate_many(["aws.ebs.encryption"], items, backend)["aws.ebs.encryption"]
        timings[backend] = perf_counter() - start
        statuses[backend] = [status for status, _ in output]
        counts[backend] = dict(Counter(statuses[backend]))
    if statuses["python"] != statuses["duckdb"]:
        raise AssertionError("batch backend parity failed")
    return {"fixture_version": "1.0.0", "resources": count, "check": "aws.ebs.encryption", "timings_seconds": timings,
        "status_counts": counts, "parity": True, "cloud_calls": 0,
        "limitations": "Single-run local synthetic timing including setup; not a guarantee of backend speedup or provider collection throughput."}

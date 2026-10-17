"""Collection types the privesc evaluator reads, derived from the privesc models' own source.

peaso.privesc reads inventories only through the effective_permissions accessors (items, collections,
inventory_status, require_collections, _account_status). This module reads the collection-type literals
passed to them (directly, through loop variables, or through dict literals such as WORKLOAD_HOSTS), plus
any module-level REQUIRED_COLLECTIONS declaration. The collection plan then follows the evaluator as it
grows, so a new privesc input cannot be left out of the plan and reported as not_collected.
The source is parsed, never imported or executed."""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

MODELS = Path(__file__).resolve().parents[1] / "privesc" / "effective_permissions"
# Accessor name -> index of its collection-type argument.
ACCESSORS = {"items": 1, "collections": 1, "inventory_status": 1, "require_collections": 0, "_account_status": 0}
DECLARATION = "REQUIRED_COLLECTIONS"


def _strings(node, names):
    """String values an expression can take: literals, containers, dict values, named literals, subscripts."""
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else set()
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return set().union(set(), *(_strings(e, names) for e in node.elts))
    if isinstance(node, ast.Starred):
        return _strings(node.value, names)
    if isinstance(node, ast.Dict):
        return set().union(set(), *(_strings(v, names) for v in node.values if v is not None))
    if isinstance(node, ast.Name):
        return names.get(node.id, set())
    if isinstance(node, ast.Subscript):  # {...}[kind] or TABLE[kind] -> every value
        return _strings(node.value, names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("values", "items", "keys", "get"):
        return _strings(node.func.value, names) | (_keys(node.func.value, names) if node.func.attr in ("items", "keys") else set())
    return set()


def _keys(node, names):
    if isinstance(node, ast.Dict):
        return {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    if isinstance(node, ast.Name):
        return names.get("keys:" + node.id, set())
    return set()


def _bind(target, iterable, names):
    """Record the strings a loop target can take from its iterable."""
    if isinstance(target, ast.Name):
        names.setdefault(target.id, set()).update(_strings(iterable, names))
    elif isinstance(target, ast.Tuple):
        # for a, b in ((x, y), ..., *D.items()) / D.items(): each position takes its column, or D's keys/values.
        elements = iterable.elts if isinstance(iterable, (ast.Tuple, ast.List)) else [iterable]
        for position, element in enumerate(target.elts):
            if not isinstance(element, ast.Name):
                continue
            bucket = names.setdefault(element.id, set())
            for row in elements:
                row = row.value if isinstance(row, ast.Starred) else row
                if isinstance(row, (ast.Tuple, ast.List)) and position < len(row.elts):
                    bucket.update(_strings(row.elts[position], names))
                elif isinstance(row, ast.Call) and isinstance(row.func, ast.Attribute) and row.func.attr == "items":
                    bucket.update(_keys(row.func.value, names) if position == 0 else _strings(row.func.value, names))


def scan_source(text):
    tree = ast.parse(text)
    names, found = {}, set()
    # Two passes so that names bound later in the file (module tables, loop variables) resolve.
    for _ in range(2):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                names.setdefault(node.targets[0].id, set()).update(_strings(node.value, names))
                if isinstance(node.value, ast.Dict):
                    names.setdefault("keys:" + node.targets[0].id, set()).update(_keys(node.value, names))
            elif isinstance(node, (ast.For, ast.comprehension)):
                _bind(node.target, node.iter, names)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == DECLARATION for t in targets) and node.value is not None:
                found |= _strings(node.value, names) | _keys(node.value, names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in ACCESSORS and len(node.args) > ACCESSORS[name]:
                found |= _strings(node.args[ACCESSORS[name]], names)
    return found


@lru_cache(maxsize=None)
def privesc_collection_types(provider):
    """Collection types peaso.privesc reads for one provider (empty when its model is absent)."""
    path = MODELS / f"{provider}.py"
    try:
        return frozenset(scan_source(path.read_text(encoding="utf-8")))
    except (OSError, SyntaxError, ValueError):
        return frozenset()

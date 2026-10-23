"""Every selector key, source-selector key, placeholder and target kind the catalog uses must be implemented by the
evaluator / provider model (a name the evaluator never looks at silently degrades to 'unknown' or to no edge).
A name that is deliberately left unresolved must say which fact it needs (schema.FACTS_NEEDED), so the gap is reported
in coverage instead of silently. Literal presence in the model source is the implementation proxy."""
from __future__ import annotations

import pathlib
import re

import pytest

from peaso.privesc import schema
from peaso.privesc.schema import load_catalog

ROOT = pathlib.Path(schema.__file__).resolve().parent
_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")
# Placeholder attributes every model resolves generically (scope / id style attributes of any node).
GENERIC_PLACEHOLDER_ATTRS = {"scope", "id", "arn", "account", "project", "namespace", "name", "email", "resource"}
# Value-driven selectors whose values are themselves vocabulary the model must know.
VALUE_SELECTORS = ("via_resource_type", "attached_to_service")


def _source(provider):
    files = [ROOT / "evaluator.py", ROOT / "effective_permissions" / "__init__.py",
             ROOT / "effective_permissions" / f"{provider}.py", ROOT / "graph.py"]
    files += sorted((ROOT / "effective_permissions").glob(f"{provider}_*.py"))
    return "\n".join(f.read_text() for f in files if f.exists())


SOURCES = {p: _source(p) for p in ("aws", "gcp", "azure", "k8s")}
ALL_SOURCE = "\n".join(SOURCES.values())


def _literal(name, text):
    return f'"{name}"' in text or f"'{name}'" in text


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()["entries"]


def _used(catalog):
    selectors, sources, kinds, placeholders, values = set(), set(), set(), set(), set()
    for e in catalog:
        provider = e["provider"]
        target = e.get("target") or {}
        kinds.add((provider, target.get("kind")))
        for key, value in (target.get("selector") or {}).items():
            selectors.add((provider, key))
            if key in VALUE_SELECTORS:
                for v in (value if isinstance(value, list) else [value]):
                    values.add((provider, key, str(v)))
        for key in (e.get("source_selector") or {}):
            sources.add((provider, key))
        for text in _strings({k: e.get(k) for k in ("requires", "target", "source_selector", "preconditions")}):
            for name in _PH.findall(text):
                placeholders.add((provider, e["id"], name))
    return selectors, sources, kinds, placeholders, values


def test_every_catalog_selector_key_is_implemented(catalog):
    selectors, sources, _, _, _ = _used(catalog)
    missing = []
    for provider, key in sorted(selectors | sources):
        if key in schema.GENERIC_SELECTORS or key.startswith("precondition:"):
            continue
        if not (_literal(key, SOURCES[provider]) or _literal(key, ALL_SOURCE) or key in schema.FACTS_NEEDED):
            missing.append(f"{provider}:{key}")
    assert not missing, f"selector keys used by the catalog but never read by the evaluator: {missing}"


def test_every_catalog_target_kind_is_implemented(catalog):
    _, _, kinds, _, _ = _used(catalog)
    missing = [f"{p}:{k}" for p, k in sorted(kinds) if not _literal(k, ALL_SOURCE)]
    assert not missing, f"target kinds the models never build: {missing}"


def test_every_catalog_placeholder_is_resolved(catalog):
    _, _, _, placeholders, _ = _used(catalog)
    missing = set()
    for provider, eid, name in sorted(placeholders):
        assert name in schema.PLACEHOLDERS or name.startswith(("pivot", "target.host_resource")), (eid, name)
        attr = name.rsplit(".", 1)[-1]
        if "." not in name or attr in GENERIC_PLACEHOLDER_ATTRS:
            continue
        if not (_literal(attr, SOURCES[provider]) or _literal(name, SOURCES[provider]) or name in schema.FACTS_NEEDED):
            missing.add(f"{provider}:{name} ({eid})")
    assert not missing, f"placeholders the provider model never resolves: {sorted(missing)}"


def test_every_gcp_attached_to_service_value_is_mapped(catalog):
    """Every GCP attachment has a collected host, verified default agent, or explicit coverage gap."""
    from peaso.privesc.effective_permissions.gcp import SERVICE_HOSTS, UNCOLLECTED_ATTACHMENTS, VERTEX_DEFAULT_AGENTS
    _, _, _, _, values = _used(catalog)
    missing = sorted(v for p, k, v in values if p == "gcp" and k == "attached_to_service"
                     and v.lower() not in SERVICE_HOSTS and v.lower() not in VERTEX_DEFAULT_AGENTS
                     and v.lower() not in UNCOLLECTED_ATTACHMENTS)
    assert not missing, f"GCP attached_to_service values with no mapping: {missing}"


"""Exact binding for the additive principal-target v4 catalog and legacy cards."""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import tarfile
from pathlib import Path

import yaml

from .schema import CATALOG_DIR, CatalogError, load_catalog

BINDING_SCHEMA = "privesc-catalog-binding-v1"
LEGACY_MANIFEST = "fe767aecd3beee553441ec6e586fa5aa6a946345b7beca43397e4c4c7c6bb481"
LEGACY_REVISION = "0b3633117413069d93b713d2a98a9e16b1d189f3"
LEGACY_DELTA_SHA256 = "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a"
V4_MANIFEST = "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388"
V4_REVISION = "4913b6d88ced9972f72ccdd708d21641725a6fb5"
V4_EFFECTIVE_TREE = "413792ea4aec86e48c352ffab2c0bea9e82795bc234251342737ec0276b748d2"
LEGACY_DELTA = Path(__file__).resolve().parent / "catalog_versions/legacy-0b3633-delta.json"
BOUNDED_MANIFEST = "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c"
BOUNDED_TREE = "1a54bad4102d18f89c78f45c915964554a62f994c1bffa693844cac5e119cca8"
CURRENT_MANIFEST = '206b1895056780d15c6707bb434e46a25df4d53bf6c284e8bbb6d7d567a46806'
INTERMEDIATE_CURRENT_MANIFEST = 'eada56c3fbbbf06891601ef0711e3b2d2f216cdf8981e5e87e9501f7702ef868'
INTERMEDIATE_CURRENT_TREE = '9cace7c01a6cc13e22b369c99298cc0a4f6df6226aa13a7b63cfb6a4d1ad29e9'
INTERMEDIATE_CURRENT_ENTRY_COUNT = 660
INTERMEDIATE_CURRENT_EXCLUDED_COUNT = 3731
INTERMEDIATE_CURRENT_ARCHIVE_SHA256 = '24ef5805dc374d0b9163abe241dd86bf5edfb05e9e8746241bfab253e19634dd'
INTERMEDIATE_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-source-manifest.json'
INTERMEDIATE_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-catalog.tar.gz'
PREVIOUS_CURRENT_MANIFEST = '6d994be99fd3fd696c05dd0a352c0cb348da2dc62648e7caf99f03a113162f18'
PREVIOUS_CURRENT_TREE = '163c469428477120a0b2ff7aa9af4f0dfc82fb8dcf339165ddbae4d32f00914d'
PREVIOUS_CURRENT_ENTRY_COUNT = 633
PREVIOUS_CURRENT_EXCLUDED_COUNT = 3515
PREVIOUS_CURRENT_ARCHIVE_SHA256 = 'fad4c89765aa466f27831b6992a7e79059c28a118ee3707496a0e944b6335826'
PREVIOUS_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-source-manifest.json'
PREVIOUS_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-catalog.tar.gz'
PRIOR_CURRENT_MANIFEST = "eb459bc440cdad814f3acde244a36fa7f546119a351d5ce720ef0cd2281835bf"
PRIOR_DISCLOSURE_MANIFEST = "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45"
PRIOR_DISCLOSURE_TREE = "5091464bedcb10bb87301695ca733276dc67b865e544c408ccf72a5408176f0f"
PRIOR_DISCLOSURE_HISTORY = Path(__file__).resolve().parent / "catalog_versions/disclosure-v7-manifest.json"
CURRENT_TREE = 'd3dbaf40848dd14c4c2d199c8f7ec81126724f8311e23f9579282c02026c4f2f'
PRIOR_CURRENT_TREE = "99207e6469fc5e5b3daf21324e6860599b116ffcf7d30600643bd229b0f11494"
CURRENT_ENTRY_COUNT = 661
CURRENT_EXCLUDED_COUNT = 3730
CURRENT_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bulk-principal-v6-manifest.json"
PRIOR_CATALOG_ARCHIVE = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-catalog-20261016.tar.gz"
PRIOR_SOURCE_MANIFEST = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-source-manifest.json"
PRIOR_BOUNDED_MANIFEST = "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429"
PRIOR_BOUNDED_TREE = "695e38b0bc93df9ba031828ffefbabe8e10b60741580554a5f36b8f37aa05414"
BOUNDED_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bounded-v5-manifest.json"
V4_HISTORY = Path(__file__).resolve().parent / "catalog_versions/principal-v4-manifest.json"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _paths(catalog_dir=None, manifest_path=None, history_path=None):
    catalog_dir = Path(catalog_dir or CATALOG_DIR)
    manifest_path = Path(manifest_path or catalog_dir.parents[2] / "risk_rules/hacktricks-privesc-source.json")
    history_path = Path(history_path or LEGACY_DELTA)
    return catalog_dir, manifest_path, history_path


@lru_cache(maxsize=4)
def _verified_current(catalog_dir, manifest_path):
    root, manifest_path = Path(catalog_dir), Path(manifest_path)
    if _sha(manifest_path) != CURRENT_MANIFEST:
        raise ValueError("v4_catalog_manifest_mismatch")
    manifest = json.loads(manifest_path.read_text())
    wanted = manifest.get("sha256")
    actual = {str(path.relative_to(root)): _sha(path) for path in root.rglob("*.yaml")}
    if not isinstance(wanted, dict) or actual != wanted:
        raise ValueError("v4_catalog_file_mismatch")
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    if hashlib.sha256(tree.encode()).hexdigest() != CURRENT_TREE:
        raise ValueError("v4_catalog_tree_mismatch")
    loaded = load_catalog(root, strict=True)
    if len(loaded["entries"]) != CURRENT_ENTRY_COUNT or loaded["excluded"] != CURRENT_EXCLUDED_COUNT:
        raise ValueError("v4_catalog_counts_mismatch")
    return {entry["id"]: entry for entry in loaded["entries"]}


@lru_cache(maxsize=1)
def _verified_previous_current():
    """Keep the exact 633-entry catalog used by already stored report cards."""
    return _verified_archived_current(
        PREVIOUS_CURRENT_MANIFEST_PATH, PREVIOUS_CURRENT_ARCHIVE,
        PREVIOUS_CURRENT_MANIFEST, PREVIOUS_CURRENT_ARCHIVE_SHA256,
        PREVIOUS_CURRENT_TREE, PREVIOUS_CURRENT_ENTRY_COUNT, PREVIOUS_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_intermediate_current():
    """Keep the exact 660-entry catalog used before the next AWS recovery."""
    return _verified_archived_current(
        INTERMEDIATE_CURRENT_MANIFEST_PATH, INTERMEDIATE_CURRENT_ARCHIVE,
        INTERMEDIATE_CURRENT_MANIFEST, INTERMEDIATE_CURRENT_ARCHIVE_SHA256,
        INTERMEDIATE_CURRENT_TREE, INTERMEDIATE_CURRENT_ENTRY_COUNT, INTERMEDIATE_CURRENT_EXCLUDED_COUNT)


def _verified_archived_current(manifest_path, archive_path, manifest_digest, archive_digest,
                               tree_digest, entry_count, excluded_count):
    if _sha(manifest_path) != manifest_digest or _sha(archive_path) != archive_digest:
        raise ValueError("archived_current_changed")
    wanted = json.loads(manifest_path.read_text())["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith("catalog/"):
                raise ValueError("archived_current_path_mismatch")
            name = member.name.removeprefix("catalog/")
            if name not in wanted or name in actual:
                raise ValueError("archived_current_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.safe_load(payload) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("archived_current_duplicate_id")
                    entries[item["id"]] = item
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    if (actual != wanted or hashlib.sha256(tree.encode()).hexdigest() != tree_digest or
            len(entries) != entry_count or excluded != excluded_count):
        raise ValueError("archived_current_mismatch")
    return entries


@lru_cache(maxsize=1)
def _verified_prior():
    """Read the exact previous catalog so old report bindings keep their meanings."""
    if _sha(PRIOR_SOURCE_MANIFEST) != PRIOR_CURRENT_MANIFEST:
        raise ValueError("prior_catalog_manifest_mismatch")
    wanted = json.loads(PRIOR_SOURCE_MANIFEST.read_text())["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(PRIOR_CATALOG_ARCHIVE, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.removeprefix("catalog/")
            if name == member.name or name not in wanted:
                raise ValueError("prior_catalog_archive_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.safe_load(payload) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("prior_catalog_duplicate_id")
                    entries[item["id"]] = item
    if actual != wanted or len(entries) != 1234 or excluded != 2847:
        raise ValueError("prior_catalog_archive_mismatch")
    return entries, actual


def _principal_v4(entries, catalog_hashes):
    """Old cards retain their exact 244-file catalog and original 1,052 meanings."""
    if _sha(V4_HISTORY) != V4_MANIFEST:
        raise ValueError("principal_v4_history_mismatch")
    pins = json.loads(V4_HISTORY.read_text())["sha256"]
    if len(pins) != 244 or any(catalog_hashes.get(name) != digest for name, digest in pins.items()):
        raise ValueError("principal_v4_history_files_mismatch")
    retained = {ident: entry for ident, entry in entries.items()
                if str(entry.get("_file", "")) in pins}
    if len(retained) != 1052:
        raise ValueError("principal_v4_history_count_mismatch")
    return retained


@lru_cache(maxsize=4)
def _verified_history(history_path):
    if _sha(Path(history_path)) != LEGACY_DELTA_SHA256:
        raise ValueError("legacy_delta_sha_mismatch")
    history = json.loads(Path(history_path).read_text())
    if (history.get("schema") != "legacy-source0b-catalog-delta-v1" or
            history.get("baseline_manifest_sha256") != LEGACY_MANIFEST or
            history.get("baseline_revision") != LEGACY_REVISION or
            len(history.get("legacy_ids", [])) != 1004 or
            len(history.get("changed_shared_ids", [])) != 75 or
            len(history.get("retired_ids", [])) != 28 or
            len(history.get("old_entries", {})) != 103 or history.get("retired_aliases") != {}):
        raise ValueError("legacy_delta_mismatch")
    return history


def current_binding(*, catalog_dir=None, manifest_path=None):
    catalog_dir, manifest_path, _ = _paths(catalog_dir, manifest_path)
    _verified_current(str(catalog_dir), str(manifest_path))
    return {"schema": BINDING_SCHEMA, "manifest_sha256": CURRENT_MANIFEST,
            "effective_tree_sha256": CURRENT_TREE, "source_revision": V4_REVISION}


def lookup_entries(technique_ids, binding=None, *, tenant_id=None, catalog_dir=None,
                   manifest_path=None, history_path=None):
    """Return original entries plus lookup state; never reinterpret graph edges.

    Missing bindings use source0b labels as an explicitly uncertain legacy
    fallback. Unknown or contradictory bindings return no descriptions.
    """
    catalog_dir, manifest_path, history_path = _paths(catalog_dir, manifest_path, history_path)
    ids = tuple(dict.fromkeys(technique_ids))
    if binding is None:
        version, status = "legacy", "legacy_unversioned_fallback"
    elif not isinstance(binding, dict) or binding.get("schema") != BINDING_SCHEMA:
        return {}, "invalid_catalog_binding"
    elif tenant_id is not None and binding.get("tenant_id") != tenant_id:
        return {}, "tenant_binding_mismatch"
    elif (binding.get("manifest_sha256") == CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "current", "exact_strict_privesc"
    elif (binding.get("manifest_sha256") == PREVIOUS_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PREVIOUS_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "previous_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INTERMEDIATE_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == INTERMEDIATE_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "intermediate_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == PRIOR_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_current", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_DISCLOSURE_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_DISCLOSURE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_disclosure", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == V4_MANIFEST and
          binding.get("effective_tree_sha256") == V4_EFFECTIVE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "v4", "exact_additive_v4"
    elif (binding.get("manifest_sha256") == LEGACY_MANIFEST and
          binding.get("source_revision") == LEGACY_REVISION):
        version, status = "legacy", "exact_legacy"
    else:
        return {}, "unknown_catalog_manifest"
    try:
        if version == "current":
            current = _verified_current(str(catalog_dir), str(manifest_path))
            return {ident: current[ident] for ident in ids if ident in current}, status
        if version == "previous_current":
            previous = _verified_previous_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "intermediate_current":
            previous = _verified_intermediate_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        v4, prior_hashes = _verified_prior()
        if version == "prior_current":
            return {ident: v4[ident] for ident in ids if ident in v4}, status
        if version == "prior_disclosure":
            if _sha(PRIOR_DISCLOSURE_HISTORY) != PRIOR_DISCLOSURE_MANIFEST:
                raise ValueError("disclosure_history_changed")
            pins = json.loads(PRIOR_DISCLOSURE_HISTORY.read_text())["sha256"]
            if len(pins) != 253 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("disclosure_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1227:
                raise ValueError("disclosure_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "bounded":
            if _sha(CURRENT_HISTORY) != BOUNDED_MANIFEST:
                raise ValueError("bulk_principal_history_changed")
            pins = json.loads(CURRENT_HISTORY.read_text())["sha256"]
            if len(pins) != 251 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("bulk_principal_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1224:
                raise ValueError("bulk_principal_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "prior_bounded":
            if _sha(BOUNDED_HISTORY) != PRIOR_BOUNDED_MANIFEST: raise ValueError("bounded_history_changed")
            pins = json.loads(BOUNDED_HISTORY.read_text())["sha256"]
            if len(pins) != 249 or any(prior_hashes.get(name) != digest for name, digest in pins.items()): raise ValueError("bounded_history_files_changed")
            retained = {k:v for k,v in v4.items() if str(v.get("_file", "")) in pins}
            if len(retained) != 1126: raise ValueError("bounded_history_count_changed")
            return {k:retained[k] for k in ids if k in retained}, status
        if version == "v4":
            original = _principal_v4(v4, prior_hashes)
            return {ident: original[ident] for ident in ids if ident in original}, status
        history = _verified_history(str(history_path))
        allowed, old = set(history["legacy_ids"]), history["old_entries"]
        return {ident: old.get(ident, v4.get(ident)) for ident in ids if ident in allowed and
                (ident in old or ident in v4)}, status
    except (OSError, ValueError, KeyError, CatalogError):
        return {}, "catalog_unavailable"


def card_technique_ids(card, principal_id):
    """Select IDs only from edges bound to the requested card principal."""
    ids = set()
    aggregates = set(card.get("member_of_aggregates") or [])
    for edge in card.get("outgoing") or []:
        if edge.get("source") == principal_id:
            ids.update(edge.get("techniques") or [])
    for edge in card.get("incoming") or []:
        target = edge.get("target")
        if target == principal_id or (target in aggregates and edge.get("via_aggregate") == target):
            ids.update(edge.get("techniques") or [])
    return sorted(ident for ident in ids if isinstance(ident, str))

"""Exact source routing and immutable revision evidence, independent of runtime admission."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso" / "rulepacks"


def reviews():
    return [(path, json.loads(path.read_text())) for pattern in ("reviewed_gcp_ports*.json", "reviewed_k8s_ports*.json") for path in PACK.glob(pattern)]


def test_all_retained_source_ids_reviewed_once_without_claude_overlap():
    assigned = set(json.loads((PACK / "port_partitions.json").read_text())["partitions"]["gcp_k8s"]["check_ids"])
    transferred = {cid for partition in json.loads((PACK / "port_partitions_claude.json").read_text())["partitions"].values()
        if partition["from_partition"] == "gcp_k8s" for cid in partition["check_ids"]}
    written = [cid for _, rows in reviews() for cid in rows]
    assert len(written) == len(set(written))
    assert set(written) == assigned - transferred
    assert not set(written).intersection(transferred)


def test_each_review_has_exact_pinned_source_identity_and_substantive_disposition():
    upstream = {row["check_id"]: row for row in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}
    for path, rows in reviews():
        for cid, row in rows.items():
            notes = row["review_notes"]
            assert notes.get("revision", notes.get("source_revision")) == upstream[cid]["revision"], (path.name, cid)
            hash_value = notes.get("source_query_sha256") or notes.get("query_sha256") or notes.get("source_sha256")
            assert hash_value == upstream[cid]["upstream_evaluator"]["sha256"], (path.name, cid)
            assert row["disposition"] in ("ported", "merged", "rejected")
            assert row["reason"] and row["official_docs"]
            if row["disposition"] == "rejected":
                assert not row["native_checks"]
                if row.get("review_classification") == "manual_attestation":
                    assert row["manual_requirement"]["question"]
                else:
                    # Invalid source predicates may retain substantive manual
                    # remediation guidance rather than inventing an automatic
                    # replacement that the evidence cannot support.
                    assert row.get("review_classification") == "invalid_predicate" or "invalid" in row["reason"].lower()


def test_every_supported_or_replacement_identifier_has_real_native_implementation():
    from peaso.checks import CHECKS
    parent_ids = tuple(check.id for check in CHECKS)
    # Some retained source checks are not in the signed runtime registry. Import
    # them in a child so this source audit cannot add their IDs to the parent
    # process before the signed-registry equality test runs.
    child = """
import importlib, json
from pathlib import Path
from peaso.checks import CHECKS
imported_modules = []
for path in (Path.cwd() / 'peaso' / 'checks').glob('*_ports_*.py'):
    if path.name.startswith(('gcp_', 'k8s_')):
        importlib.import_module('peaso.checks.' + path.stem)
        imported_modules.append(path.stem)
print(json.dumps({'imported_modules': imported_modules,
                  'checks': {check.id: {'dependencies': bool(check.dependencies),
                                        'provider': check.provider} for check in CHECKS}}))
"""
    completed = subprocess.run([sys.executable, "-c", child], cwd=ROOT,
                               capture_output=True, text=True, check=True)
    result = json.loads(completed.stdout)
    assert result["imported_modules"], "the isolated source check must import actual port modules"
    registry = result["checks"]
    checked = 0
    for _, rows in reviews():
        for row in rows.values():
            for cid in row.get("native_checks", []) + row.get("replacement_checks", []):
                checked += 1
                assert cid in registry, cid
                assert registry[cid]["dependencies"] and registry[cid]["provider"] in ("gcp", "k8s")
    assert checked > 0, "the source review must validate actual native references"
    assert tuple(check.id for check in CHECKS) == parent_ids, "source test polluted the published parent registry"

"""The signed description pack must not depend on Python's hash seed."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso/rulepacks"
FIELD_ORDER = ("description", "fail_when", "evaluated", "not_applicable_when", "pass_when")
DESCRIPTION_SHA256 = '88def81cfac127eefbc9859eb677b3e2d3e1f592b5196edf0d698c32ab0bb989'


def _compile_into(tmp_path, seed):
    output = tmp_path / str(seed)
    output.mkdir()
    paths = {name: output / name for name in
             ("compliance_requirements.json", "compliance_lookup.json", "check_descriptions.json")}
    environment = os.environ.copy()
    environment.update(PYTHONHASHSEED=str(seed), PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "scripts/peaso_compliance_compile.py",
               "--ledger-root", "docs/compliance-ledgers",
               "--audit-matrix", "docs/handoff/compliance-requirements-matrix.json.gz",
               "--audit-summary", "docs/handoff/compliance-requirements-summary.json",
               "--native-catalog", str(PACK / "native_catalog.json"),
               "--requirements-output", str(paths["compliance_requirements.json"]),
               "--lookup-output", str(paths["compliance_lookup.json"]),
               "--descriptions-output", str(paths["check_descriptions.json"])]
    completed = subprocess.run(command, cwd=ROOT, env=environment, text=True,
                               capture_output=True, check=True, timeout=120)
    assert json.loads(completed.stdout) == {
        "descriptions": 3993, "frameworks": 160, "requirements": 22212,
        "states": {"automated": 10711, "manual": 5957, "not_applicable": 651, "partial": 4893},
    }
    return {name: path.read_bytes() for name, path in paths.items()}


def _edges_from_requirements(pack):
    return {(check_id, framework["id"], requirement["requirement_id"],
             requirement["decision"], requirement["runtime_status"])
            for framework in pack["frameworks"]
            for requirement in framework["requirements"]
            for check_id in requirement["native_checks"]}


def _edges_from_reverse(mapping):
    return {(check_id, tag["framework_id"], tag["requirement_id"],
             tag["decision"], tag["runtime_status"])
            for check_id, tags in mapping.items() for tag in tags}


def test_reviewed_compiler_outputs_are_identical_across_hash_seeds(tmp_path):
    first = _compile_into(tmp_path, 0)
    second = _compile_into(tmp_path, 167)
    assert first == second
    assert first["compliance_requirements.json"] == (PACK / "compliance_requirements.json").read_bytes()
    assert first["compliance_lookup.json"] == (PACK / "compliance_lookup.json").read_bytes()
    descriptions_bytes = first["check_descriptions.json"]
    assert hashlib.sha256(descriptions_bytes).hexdigest() == DESCRIPTION_SHA256
    compiled = json.loads(descriptions_bytes)["checks"]
    current = json.loads((PACK / "check_descriptions.json").read_bytes())["checks"]
    corrected = {"azure.iam.no_full_custom_role", "gcp.compute.restrict_internet_ingress"}
    assert set(current) == set(compiled)
    assert {check_id for check_id in compiled if compiled[check_id] != current[check_id]} == corrected
    native_by_id = {row["id"]: row for row in json.loads((PACK / "native_catalog.json").read_bytes())["checks"]}
    for check_id in corrected:
        assert all(current[check_id][field] == native_by_id[check_id][field]
                   for field in ("description", "pass_when", "fail_when"))

    descriptions = compiled
    supplemental = json.loads((ROOT / "docs/compliance-ledgers/descriptions/implemented-new-checks.json").read_bytes())
    assert len(descriptions) == 3993 and len(supplemental) == 881
    assert all(tuple(descriptions[check_id]) == FIELD_ORDER for check_id in supplemental)
    assert all(descriptions[check_id] == {field: source[field] for field in FIELD_ORDER}
               for check_id, source in supplemental.items())

    requirements = json.loads(first["compliance_requirements.json"])
    lookup = json.loads(first["compliance_lookup.json"])
    native = json.loads((PACK / "native_catalog.json").read_bytes())
    assert len(native["checks"]) == 3986
    assert len(requirements["frameworks"]) == 160
    assert sum(len(row["requirements"]) for row in requirements["frameworks"]) == 22212
    forward = _edges_from_requirements(requirements)
    assert len(forward) == 22953  # Original associations plus the 552 signed successor definitions.
    assert forward == _edges_from_reverse(requirements["by_check"])
    assert forward == _edges_from_reverse(lookup["by_check"])

# Compliance coverage ledgers

These are research outputs that record one decision for every requirement of every supported compliance framework version, plus verified "what it detects" descriptions for every native check. Product code consumes them only through `manifest.json`.

## Files
- `inputs/<slice>.json`: frozen input (matrix frameworks for the slice). `inputs/check-index.json` is the check catalogue snapshot. `inputs/desc-<chunk>.json` lists the check ids in each chunk.
- `<slice>.json`: the ledger. `<slice>.todo.md` is the human checklist. `<slice>.verify.md` is the adversarial verifier log.
- `descriptions/<chunk>.json`: check descriptions. `descriptions/<chunk>.verify.md` is the verifier log.
- `manifest.json`: written by the supervisor ONLY after the verifier pass and supervisor spot checks. It is the single completeness authority.

## Ledger schema (`<slice>.json`)
```
{ "slice": str, "generated_from": "inputs/<slice>.json",
  "frameworks": [ { "id": str, "name": str, "provider": "aws|gcp|azure|k8s",
    "requirements": [ { "requirement_id": str, "name": str,
      "decision": "MAPPED|MAPPING_FIX|PARTIAL|MANUAL|NOT_APPLICABLE|NEW_CHECK",
      "native_checks": [check id],      # final tag set for this requirement
      "removed_checks": [check id],     # previously mapped, rejected
      "reason": str, "evidence": ["path:line"],
      "new_checks": [ { "id","provider","resource_kind","data_source","predicate",
                        "severity","category","title","description","remediation_hint" } ] } ] } ],
  "summary": { "requirements_total", "mapped_verified", "mapping_fixed", "partial",
               "manual", "not_applicable", "new_check" } }
```
Status vocabulary:
- MAPPED: existing checks fully test the requirement.
- MAPPING_FIX: corrected using existing checks only.
- PARTIAL: existing checks plus new_checks and/or a stated manual remainder.
- NEW_CHECK: automatable read-only, not yet implemented.
- MANUAL: organizational evidence only. Reported as manual, never as passed.
- NOT_APPLICABLE: out of provider scope, with a reason.

Runtime treatment:
- A requirement's automated status may only come from `native_checks` ids that exist in the catalogue.
- Proposed `new_checks` ids that are not yet implemented make the requirement `not_assessed` for that part. They must never count as passing.

## Description schema (`descriptions/<chunk>.json`)
`{ "<check id>": { "description": str, "evaluated": [str], "pass_when": str, "fail_when": str, "not_applicable_when": str|null } }`

## Manifest and hash rules (`manifest.json`)
```
{ "version": 1, "check_index_sha256": hex,
  "slices": { "<slice>": { "path": "<slice>.json", "sha256": hex, "input_sha256": hex,
                           "requirements_total": int, "verified": true } },
  "descriptions": { "<chunk>": { "path": "descriptions/<chunk>.json", "sha256": hex,
                                 "input_sha256": hex, "checks": int, "verified": true } } }
```
Integration MUST:
1. Load only files listed in the manifest with `verified: true` and a matching sha256. Refuse unlisted, mismatched or extra files.
2. Fail the build if the union of slices does not cover every framework id in the compliance matrix, or if any slice's requirement count differs from its input.
3. Fail if any catalogue check lacks a description, once all chunks are in the manifest. Checks added after `check_index_sha256` need descriptions written by their implementer.
4. Treat the ledger as the source of truth for requirement-to-check tags, and generate the check-to-framework tags from it. The bidirectional test compares the two.

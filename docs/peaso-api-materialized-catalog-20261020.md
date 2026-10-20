# Materialized API catalog

Build with `python scripts/peaso_compliance_materialize.py --write`; run it again
without `--write` to check exact reproduction. The build verifies the full native
registry and existing reviewed packs before capturing API views and provider
selector indexes. Runtime catalog and scan selector validation load the generated
`peaso/rulepacks/api_catalog.json.gz` plus `api_catalog_manifest.json` and never
import `peaso.checks`, `peaso.analysis` or `peaso.engine`.

`GET /api/catalog/frameworks` and `GET /api/catalog?view=summary` preserve their
previous fields, order and values, including the privilege catalog binding.
The console uses the compact framework view. All catalog routes require the
same authentication and retain `Cache-Control: private, no-cache` and ETags;
unauthenticated conditional requests cannot obtain 304 responses.

`GET /api/catalog` now returns full metadata in explicit check pages. Use
`offset` (default 0) and `limit` (default 100, integer 1–500). The `pagination`
object includes `offset`, requested `limit`, `returned`, `total`, and `next_offset`.
Follow `next_offset` until it is null: the byte budget can return fewer checks
than requested, and no check is silently omitted. All non-check catalog metadata
is retained on each page. `GET /api/catalog/checks/{check_id}` returns the complete
metadata for one active check; unknown IDs return 404. Invalid pagination returns
422. JSON bodies are capped at 4 MiB and also checked against the 6 MiB Lambda
serialized-response envelope with 16 KiB reserved for headers/status. A document
or individual row that cannot fit fails closed with 503, rather than truncation.
Pages and check details are not added to the app's catalog response cache.

The gzip is deterministic (`mtime=0`) and binds exact native/framework/runtime
catalog, exclusion, and privilege source inputs. Runtime verifies compressed and
expanded digests and strict privilege manifest/tree identity before use. Missing,
corrupt, stale, oversized or mismatched artifacts return 503 without loading
native code as a fallback. The asset remains compressed on disk: no additional
23 MiB expanded API catalog is packaged.

`rulepacks/*.json.gz` is explicit wheel package data. Manual API ZIP assembly that
copies `peaso/` must retain both new files and the existing `risk_rules/` package
(the privilege source manifest), plus the existing `peaso/privesc/catalog/` YAML
files. The runtime adds no dependencies beyond existing FastAPI and standard
Python libraries; hosted tests use the existing Mangum extra. The server-only
validator binding changes; sealed `server/validation.py`, `catalog_view.py`,
evaluators and admission receipts remain unchanged.

The artifact also exposes exact reviewed description and framework-expansion
lookups for parity proof; findings retain their original native bindings.
Findings metadata initializes service lookup after annotation to preserve native
bootstrap order on a fresh detail request. Findings presentation, report
hydration, reachability evaluation and connector policy validation still load
native code, including collector policy validation on ordinary connector writes.
Those paths require separate hosted Linux memory and latency proof. Cold subprocess
proofs use synthetic authentication and SQLite with actual Mangum, denied native
imports and blocked outbound network calls; they are not hosted latency claims.

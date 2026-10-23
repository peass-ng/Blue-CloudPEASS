# Offline analysis startup

Importing IAM, network, principal projection or report-expansion helpers previously constructed collection-planning metadata and the analysis check catalog. The catalog's taxonomy lookups initialized the native check registry even when the requested task never ran native checks.

Metadata construction now lives in `peaso.analysis.catalog` and runs when `REQUIRED_TYPES` or `ANALYSIS_CHECKS` is explicitly requested. Its declarations and initialization retain the predecessor AST. Successful initialization caches the same public objects; registration failures still propagate and incomplete objects are not cached. Exposure-only projection does not request least-privilege collection metadata.

Already canonical `analysis.*` finding IDs read the existing hash-validated presentation taxonomy. Other IDs retain native alias resolution. The reviewed common-helper presentation binding changed only after source review, complete frozen evidence parity and tamper rejection. Native admission is unchanged.

Reproduce with `python -m examples.benchmark_peaso_analysis_startup --reference-root /path/to/predecessor --size 32`. The predecessor must contain the unchanged workflow fixture. The benchmark uses fresh interpreters, builds synthetic snapshots and runs complete offline IAM review, IAM graph, principal projection, network findings and topology. It compares all output digests and public export names, and verifies input snapshots remain unchanged.

One cold comparison on the loaded development host measured:

| Metric | Eager predecessor | Lazy initialization |
| --- | ---: | ---: |
| Process CPU | 42.052 s | 0.188 s |
| Elapsed | 104.295 s | 0.346 s |
| Peak process RSS | 229.6 MiB | 48.7 MiB |

Both variants emitted the same IAM findings (32), IAM nodes/edges (64/32), principal cards (32), network findings (32), and network nodes/edges (161/128). Native scans needing the catalog still pay its initialization cost; these measurements describe fresh offline tasks, not whole hosted scans. Host load particularly affects elapsed time.

Validation passed seven lazy/offline tests, the five applicable cold presentation checks including all 12,145 immutable witnesses, and 76 broader native-analysis and formatter integration tests. Coverage includes failed registration, public imports and overrides, explicit metadata initialization, exposure-only dispatch, native finding lookup, and archived/native evidence parity.

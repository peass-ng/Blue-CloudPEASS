# Findings-list request costs

The API keeps filtering, review application, distinct status counts, facets, grouping, tenant checks and page hydration. Small pages from large unordered result sets use bounded heap selection with the existing primary order and ascending ID ties. Small reports, deep pages, unusual archived IDs and apparently ordered inputs retain the original stable sorts.

Status counts retain one group-membership mask per identity instead of overlapping sets and temporary unions. Summary field names and string limits are shared constants; the accepted fields, truncation and detail privacy are unchanged.

Reproduce with `python -m examples.benchmark_peaso_finding_pages --rows 50000 --sort title`. The reference uses the former algorithms behind the same helper interfaces. Three interleaved complete HTTP requests measure elapsed and process CPU time; a separate request measures peak traced allocations. Fixture creation is excluded, the tenant-owned index is warm, and no cloud collection or native checks run. These are synthetic request results, not whole-scan or process-RSS claims.

| Query | Wall speedup | CPU speedup | Allocation reduction |
| --- | ---: | ---: | ---: |
| Title, first 100 of 50,000 | 1.32x | 1.15x | 21% |
| Default, first 100 of 50,000 | 1.34x | 1.20x | 21% |
| Severity descending, first 100 of 50,000 | 1.14x | 1.07x | 21% |
| Title, offset 20,000 of 50,000 | 1.20x | 1.19x | 10% |
| Title, first 100 of 1,000 | 1.07x | 1.00x | 4% |

Every measured response had identical bytes. The focused validation passed 134 tests, including full API parity for 15 query combinations, status unions with duplicate IDs and unknown states, sort ties, ordered inputs, summary caps, archived detail evidence and tenant isolation. Native evidence formatters and source admission are unchanged.

## Grouped views

Grouped lists, summaries and member details now skip sort cards for individual observations. Grouped lists still sort their final groups, and observation lists retain their existing order preparation. Run `python -m examples.benchmark_peaso_group_selection --rows 50000 --endpoint detail`; `list` and `summary` are also supported. The reference compiles the same application factory with the former eager selection at its three callers. Both clients share the same owned artifacts and data.

| Grouped request, 50,000 observations | Wall speedup | CPU speedup | Allocation reduction |
| --- | ---: | ---: | ---: |
| List | 1.43x | 1.27x | 33% |
| Summary | 1.49x | 1.29x | 25% |
| Group member detail | 1.31x | 1.44x | 68% |

All responses had identical bytes. The 38-test focused suite includes complete grouped-list, summary and member response comparisons, effective review statuses, archived evidence, filters, pagination, regular observation sorting and tenant isolation.

## Principal detail

Principal cards now select candidate findings from their stored category and principal ID before hydrating display metadata. Archived defaults apply only to missing fields; explicit null values and the existing resource-ID summary limit retain their behavior. The route still hydrates every matching finding, counts all matches before the 500-row response limit, and checks the tenant and graph principal before selection.

Run `python scripts/benchmark_api_principal_hydration.py --baseline /path/to/predecessor/app.py`. Two complete warm HTTP requests over 30,000 synthetic findings returned the same responses before and after the change. Process CPU fell from 0.128 to 0.015 seconds and from 0.137 to 0.020 seconds. Peak traced request allocations remained approximately 0.1 MB. These measurements exclude collection and startup; they describe principal-detail requests, not whole scans. Fourteen focused cases cover archived defaults, explicit nulls, long IDs, ordering, result limits, report revisions and tenant isolation.

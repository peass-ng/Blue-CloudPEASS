# AKS admitted resource-limit evidence

`azure.gap.kubernetes_cluster_container_cpu_and_memory_resource_limit` now consumes a narrow native `pod_runtime` projection from the existing complete, persisted AKS Pod LIST. No additional API, permission, dependency, mutation, execution, or credential retrieval is introduced. The signed predicate is unchanged.

Configure normative policy under `options.compliance_parameters.azure_aks_workloads.subscriptions[]`:

```json
{"scope":"/subscriptions/11111111-1111-1111-1111-111111111111","limits":{"maxCpu":"2","maxMemory":"2Gi","containerKinds":["containers","initContainers","ephemeralContainers"]}}
```

Existing endpoint, tenant, ARM cluster, explicit CA/token, namespace, pagination, native Pod UID/resourceVersion, and cluster-UID before/after checks remain mandatory. Owner inputs cannot supply runtime observations or claim admission resolution.

Only when every container in every present container kind has explicit, valid positive CPU and memory limits in the persisted post-admission Pod does the collector mark `admissionEffectsResolved: true`. Stored limits already include any defaults applied during admission. `limitRangeBindings: []` expresses an empty historical dependency set for this explicit-value calculation; it does not claim that no LimitRange existed. Current LimitRange defaults never substitute for missing persisted limits.

With complete evidence and an approved maximum, stored limits at or below the maximum pass; an excessive stored limit fails. Missing or malformed limits, unresolved admission defaults, or incomplete capture remain UNKNOWN. A native forbidden response remains DENIED. Foreign/duplicate identities, changed cluster UID, truncation, and resource/call budgets fail closed. The projector conservatively requires all present container kinds to be explicit even if the owner selected fewer kinds.

The projection does not expose node OS, AppArmor availability, runtime-default support, or Kubernetes version. AppArmor remains UNKNOWN without its independent native evidence. This resolves one control for the explicit stored-limit path; it does not close the shared `pod_runtime` evidence requirements of other controls or historical/default-dependent paths.

Directed tests: `tests/test_peaso_azure_aks_admitted_limits_native.py`. Transport fixtures exercise the public collector, planner, projected collections, and unchanged signed evaluation. They do not execute live provider calls.

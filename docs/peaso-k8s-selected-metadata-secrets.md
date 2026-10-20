# Selected Kubernetes labels and annotations

This optional local integration inspects only the top-level labels and annotations of one to eight exact selected objects. It is enabled only by `content_secret_scans: true`, the explicitly named `k8s.review.selected_metadata.secret_indicators` check, and `selected_k8s_metadata_resources` entries containing exactly `cluster_id`, `namespace`, `kind`, and `name`.

The existing authenticated Kubernetes SDK client and read budget are reused. No discovery, listing, credential loading, Secret read, log read, execution, external reference resolution, registry pull, or write is introduced. Ordinary GET responses may include other resource fields in memory; only the selected top-level metadata is extracted and inspected. Template metadata, specifications, ConfigMap values, and references are outside this criterion.

Supported kinds and read permissions:

| API group/version | Kinds | RBAC resources; verb |
| --- | --- | --- |
| core/v1 | Pod, ConfigMap, ReplicationController, PodTemplate | `pods`, `configmaps`, `replicationcontrollers`, `podtemplates`; `get` |
| apps/v1 | Deployment, DaemonSet, StatefulSet, ReplicaSet | `deployments`, `daemonsets`, `statefulsets`, `replicasets`; `get` |
| batch/v1 | Job, CronJob | `jobs`, `cronjobs`; `get` |

Grant only the selected kinds and exact names in each selected namespace. A minimal example for a single Pod is:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: selected-metadata-read
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["pods"]
    resourceNames: ["metadata-object"]
    verbs: ["get"]
```

Bind that Role to the existing scan identity through the operator's normal RBAC setup. The collector does not create or modify RBAC. It does not require `list`, `watch`, `get secrets`, `pods/log`, `exec`, node access, or cluster-wide permissions. Request scopes may already allow all namespaces, but every content request still names a specific namespace and resource; selectors cannot contain wildcards.

Two exact native GETs must agree on API version, kind, namespace/name, UID, resourceVersion, and the extracted metadata. The reader rejects partial responses, redirects, invalid JSON, duplicate JSON fields, changed identities or metadata, missing entries, malformed maps, unsupported content encoding, and debug-enabled native transports. It makes at most sixteen calls, reads at most 2 MiB per response and 8 MiB overall, and extracts at most 512 metadata entries, 64 KiB per value, and 256 KiB overall within a sixty-second local deadline and the caller's stricter budgets.

Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline without credential verification. A clean result requires both engines to complete and all selected coverage to be complete. A completed detector's trusted hit remains a potential exposure when another detector or a later selected object is unavailable; it is marked incomplete. A resource-limited fallback permits only FAIL after independent native receipt validation, and never asserts clean coverage of uncollected objects.

Detected values are represented by shared exact-value HMAC fingerprints and redacted leak locations. Callers must union the transient matches with all other selected-reader matches, then call the existing scrub function over scopes, metadata, and collections before snapshot sealing, caching, or export; it clears the transient set. No raw metadata or matches should be retained. Unrecognized secrets, arbitrary encodings, values outside the selected metadata, credential validity, and effective access are not established.

Primary contracts: [labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/), [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/), [API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/), and [resource-name RBAC restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).

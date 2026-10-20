# Optional selected Kubernetes container log samples

This reader is integrated locally. [Review progress](check-review/progress.json) tracks publication separately; ordinary metadata scans do not read logs.

The check `k8s.review.selected_container_logs.secret_indicators` requires both `content_secret_scans: true` and that exact named check. Select one to four exact targets with `selected_k8s_log_samples`, each containing `cluster_id`, `namespace`, `pod` and `container`. The cluster must match the existing authenticated connector, and every namespace must be an explicit requested scope; wildcards and arbitrary paths or query options are rejected.

For example, a target is `{"cluster_id":"my-cluster","namespace":"team-a","pod":"selected-pod","container":"main"}`. The reader uses Pod GET, current Pod log GET, then Pod GET again. It requires unchanged UID, resourceVersion, current container ID, restart count and state timestamps. Regular, init and ephemeral container identities are supported when their corresponding native status is available; waiting or unresolved instances remain UNKNOWN.

The log request fixes `follow=false`, `previous=false`, `tailLines=100`, `limitBytes=262144`, `timestamps=true`, `insecureSkipTLSVerifyBackend=false` and `sinceTime` at one hour before capture. No query can extend that window. The API provides no upper-time option: a returned record newer than capture makes the sample unresolved. Empty output, partial HTTP responses, an incomplete line or a reached byte limit cannot prove a clean sample.

Minimum namespace-scoped RBAC for each selected Pod:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: selected-pod-log-reader
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    resourceNames: ["selected-pod"]
    verbs: ["get"]
```

Bind that Role to the connector's existing identity using the cluster's normal access setup. Kubernetes authorizes the named Pod's log subresource; the sampler further restricts the container and sample bounds. It needs no list/watch, Secret, exec, attach, port-forward, node/proxy, host, registry, write or credential-verification permissions.

Both pinned offline engines must complete to report a clean returned sample. A completed detector's trusted hit remains a redacted failure if the other detector is unavailable, with incomplete coverage stated. The same exact value shares a process-local HMAC fingerprint with existing literal readers; union redaction covers detected values repeated in metadata before snapshot/cache/export. Neither plaintext logs nor Pod annotations, environment literals, raw identities or matched values are retained by this reader.

If a detected value is the namespace itself, the existing union scrub marks the changed scope unavailable. The strict consumer then returns UNKNOWN; it does not ignore lost scope proof to manufacture a clean result or a rebound finding.

SDK and urllib3 logger records are suppressed only for private reads on the collecting thread; unrelated logging continues. SDK wire debug, global HTTP wire debug or an already-pooled connection with wire debug enabled causes UNKNOWN before I/O. The reader does not change global debug settings. Concurrent arbitrary reconfiguration of logging, SDK clients or pool internals is outside this adapter's supported execution context.

Clean results concern only the finite returned sample and bound identity text. They do not establish absence in all logs, prior container instances, unselected containers, other namespaces or external log stores, and do not validate or revoke credentials. The API cannot make the three reads atomic or attach a Pod UID/container ID to each log line; stable native observations provide the stated sample binding.

Contracts: [Kubernetes v1.34 PodLogOptions and container status definitions](https://github.com/kubernetes/api/blob/v0.34.0/core/v1/types.go), [Pod API](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/), and [RBAC subresources and resourceNames](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).

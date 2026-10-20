# Selected Kubernetes image source association

This local helper associates one exact native declaration and, when supplied, one exact Pod container status with a qualified immutable image reference. It does no collection or scanning and adds no registered control, engine option, UI, cloud credential flow, or formal compliance mapping. A future byte-scanning integration belongs in the existing **Secrets** group after its native reader and detector binding are accepted.

The implementation is [k8s_image_source_association_20261020.py](../../peaso/checks/k8s_image_source_association_20261020.py); the source-bound review is [k8s-image-association-review-20261020.json](k8s-image-association-review-20261020.json). Tests are [test_k8s_image_source_association_20261020.py](../../tests/test_k8s_image_source_association_20261020.py).

## Pure calling contract

Pass already-decoded native Kubernetes JSON dictionaries to `resolve_image_source(selection, declaration, cluster_id=...)`. The caller supplies the authenticated cluster identifier separately. The exact selector has these eight keys:

```python
selection = {
    "cluster_id": "customer-cluster", "api_version": "v1", "kind": "Pod",
    "namespace": "team-a", "name": "selected-pod", "uid": "observed-pod-uid",
    "container_type": "regular", "container_name": "main",
}
association = resolve_image_source(selection, native_pod, cluster_id="customer-cluster")
```

`container_type` is `regular`, `init`, or `ephemeral`. Restartable init sidecars use `initContainerStatuses`. The selected name must occur exactly once across the declarations, and its status must occur in the corresponding status array. No list position, label, Pod phase, readiness flag, `imagePullPolicy`, `lastState`, or controller replica count substitutes for per-container status.

Supported declarations are `v1` Pod, PodTemplate and ReplicationController; `apps/v1` Deployment, ReplicaSet, DaemonSet and StatefulSet; and `batch/v1` Job and CronJob. Paths are respectively `/spec`, `/template/spec`, ordinary `/spec/template/spec`, and CronJob `/spec/jobTemplate/spec/template/spec`. Ephemeral declarations are accepted only on actual Pods.

For a controller, pass `pod=native_pod`, `pod_selection={"namespace": ..., "name": ..., "uid": ...}` and `owner_chain=[native_replicaset]` for Deployment or `[native_job]` for CronJob. Other owning controllers require an empty chain. Every link requires one native `controller: true` owner reference matching API version, kind, name and UID in the same namespace. The selected image declaration must agree in each intermediate object and the Pod. A PodTemplate supports declaration inspection only; it is not a controller. One associated Pod never proves coverage of all replicas or proves that the controller has converged.

The helper requires native object `metadata.uid` and `resourceVersion`, a selected current container instance ID, restart count, readiness boolean, and coherent running/terminated state timestamps. Waiting, missing, malformed, partial, duplicate, wrong-type or mismatched evidence cannot produce a scan target. A terminated init or application container is identified as terminated, without implying it runs now.

## Meaning of the result

| Status | Meaning | `immutable_reference` |
| --- | --- | --- |
| `associated` | The selected Pod status reports a qualified repository and SHA256 image ID consistent with the supplied declaration and status image. | Candidate for later authorized registry inspection |
| `declaration_only` | A controller/template declares an immutable image; no selected Pod status was supplied. | `null`; desired reference is separate |
| `unknown` | Mutable declaration, missing evidence, unsupported ID, or unresolved relationship. | `null` |
| `mismatch` | Exact selected identity, owner link, repository, container name/type or current desired declaration disagrees. | `null` |
| `invalid` | Malformed input or exceeded association bounds. | `null` |

The output separates `desired_image` and `desired_immutable_reference` from `status_image`, `status_image_id` and the associated candidate. It includes exact cluster/object/Pod UID and resourceVersion, container type/name/instance/restart/state, and declaration/status JSON paths. The helper is deterministic and does not mutate inputs. These are caller-supplied observations: the helper cannot authenticate JSON, recover duplicate JSON keys after decoding, or certify transport completeness or observation freshness.

Every result has `image_bytes_scanned: false`, `effective_deployment_proven: false` and `registry_access: "not_checked"`. There is no PASS/FAIL or secret-free result. Registry bytes and runtime execution are not established by API status. [Kubernetes' status definitions](https://github.com/kubernetes/api/blob/v0.34.0/core/v1/types.go) allow runtime resolution to change image fields.

The supported image ID forms are `registry/repository@sha256:<64 lowercase hex>` and `docker-pullable://registry/repository@sha256:<64 lowercase hex>`. Bare hashes, `docker://sha256:...`, `containerd://sha256:...`, arbitrary schemes and tags cannot establish a pullable manifest reference. Only documented Docker shorthand and `index.docker.io`/`docker.io` are normalized. Private aliases, mirrors, `registry-1.docker.io` aliases, custom default registries, IPv6 registries and other digest algorithms are unresolved or unsupported; they are never silently rewritten. An unqualified desired declaration uses the documented Docker default convention, which does not certify a custom runtime configuration.

A desired digest differing from the status digest remains UNKNOWN: the former can identify an index and the latter a platform manifest. Equality, an index-to-child relationship and supported byte content need independently verified registry descriptors. [OCI descriptors](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md) distinguish content identities; [distribution requests](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pull) retrieve manifests and blobs by reference. A tag plus digest preserves the tag as declaration context while the digest identifies the candidate. A tag alone, even with `Always`, never proves the image used by a container. [Kubernetes image semantics](https://kubernetes.io/docs/concepts/containers/images/) explain mutable tags and digest selection.

Bounds are one selector, one declaration, one optional Pod, one optional intermediate owner, eight owner references per link, 128 total declarations and 128 total statuses per inspected object, a 1,024-character image string and a 255-character normalized repository name. The helper examines only identity, image declaration, owner links and selected status fields. It never traverses environment values, annotations, volumes, Secret references, or arbitrary content. Serialized response size/depth, HTTP deadlines and strict JSON decoding belong to a future collection adapter, not this in-memory helper.

## Read permissions for a future adapter

No permissions are required to run the pure helper on local dictionaries. Future native collection can use exact named GETs:

| Native object | Read route | RBAC |
| --- | --- | --- |
| Selected Pod, including normal status fields | `/api/v1/namespaces/{ns}/pods/{name}` | `get` on `pods` |
| Selected apps controller / intermediate ReplicaSet | `/apis/apps/v1/namespaces/{ns}/{resource}/{name}` | `get` on the exact deployments/replicasets/daemonsets/statefulsets resource |
| Job / CronJob | `/apis/batch/v1/namespaces/{ns}/{jobs-or-cronjobs}/{name}` | `get` on exact jobs/cronjobs |
| ReplicationController / PodTemplate | `/api/v1/namespaces/{ns}/{resource}/{name}` | `get` on exact replicationcontrollers/podtemplates |

Normal Pod GET includes status; a separate `pods/status` permission is unnecessary. Select the Pod and intermediate names explicitly; this design adds no workload discovery, `list` or `watch`. For a single selected Pod, a namespace-scoped Role can contain:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: selected-image-association-read
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["pods"]
    resourceNames: ["selected-pod"]
    verbs: ["get"]
```

Add separate exact resource/name GET rules for selected controllers and intermediates only when needed. This document applies no Role or binding. [Resource-name RBAC restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources) scope these reads. Kubernetes RBAC does not authorize an external registry, and the workload's ability to pull an image does not establish the review identity's ability to read it. Never retrieve `imagePullSecrets`, ServiceAccount tokens, Kubernetes Secret payloads or node credentials as a shortcut.

## Exact next integration

1. Build a separate default-off selected native reader after approval of its scope. Require explicit content consent, a named check, exact selectors, an already-authenticated K8s connector, bounded HTTP/JSON reads and source receipts. Collect the selected Pod/controller/owner chain without discovery. Reject transport errors, redirects, duplicate JSON fields, oversized/deep input, partial responses and debug-enabled sensitive transports before association. Re-read the same exact objects around inspection and require unchanged UID/resourceVersion and relevant declaration/status/instance fields; this is a stability observation, not an atomic transaction or runtime attestation.
2. Independently select the registry connector and exact repository authorized by the customer. Resolve only `associated` candidates; never use desired tags or controller declarations to claim deployed bytes. Registry routing must bind native provider authority to the exact hostname/repository/digest and must not follow challenge-derived hosts or pass Kubernetes credentials to a registry.
3. For **GCP Artifact Registry**, validate the bare immutable `LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/IMAGE@sha256:...` through `gcp_image_secret_indicators.normalize_selected`, then the existing project/repository/DockerImage binding. Supply the separate configured Google registry-read identity. Existing `selected_artifact_images` and `gcp.review.artifact_image.content_secret_indicators` provide the reuse point. [Google registry authentication](https://docs.cloud.google.com/artifact-registry/docs/docker/authentication) describes independent access tokens and reader roles.
4. For **Azure ACR**, select `{registry_id, repository, digest}` through `azure_acr_image_secret_indicators.selected_targets`. Bind the candidate hostname to native ARM `loginServer` from the exact selected registry ID; do not infer an ARM ID from a hostname. Use `selected_azure_acr_images` and `azure.review.acr.selected_image_secret_indicators` with separate configured Entra credentials, ARM registry read and repository pull authority appropriate to the registry mode. [Microsoft's role overview](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-overview) separates registry management and repository access.
5. For **AWS ECR**, create an exact-selection adapter around the existing digest-bound `_image`/`project_response` path in `aws_package_content_indicators`. Its current `enrich` path chooses the uniquely latest pushed image, so calling it does not implement this association. Bind a customer-authorized native account/region/repository and preserve existing own-account restrictions unless a separately reviewed extension changes them; issue `BatchGetImage(imageIds=[{"imageDigest": digest}])` and digest-bound `GetDownloadUrlForLayer` reads through the existing guarded transport. Separate AWS credentials need the applicable repository read permissions. [BatchGetImage](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html) accepts an explicit digest and [GetDownloadUrlForLayer](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetDownloadUrlForLayer.html) provides layer download locations.
6. Preserve each scanner's manifest/config/layer digest and size validation, supported media/platform/format limits, byte/deadline budgets, pinned offline dual detectors, incomplete-coverage semantics, shared HMAC deduplication and whole-snapshot union redaction before cache/export. Unsupported indexes/children, aliases, authorization denial or missing bytes remain UNKNOWN for the affected source. A registry observation must join back to the same candidate digest and the same selected Pod/container receipt. Only then consider registration in **Secrets** with native positive/negative/UNKNOWN tests and existing provider admission requirements.

No cloud/authentication/registry requests, credential verification, full suite, commit or deployment were performed for this helper. The focused command is `python -m pytest --noconftest -q tests/test_k8s_image_source_association_20261020.py`. The review records the separate shared conftest receipt failure observed during normal collection.

## Metadata ledger correction and remaining surfaces

`secret-coverage.json`'s historical `service_surfaces[53]` fields still describe unsupported labels/annotations. Its current fields now correctly record `implemented_local_bounded_selected_top_level_metadata`, and `current_k8s_metadata_proposal` points to the accepted receipt. Treat historical fields as history rather than current capability. The review JSON gives exact field pointers and the current bounded interpretation; this worker does not edit the ledger.

The accepted optional metadata reader requires `content_secret_scans: true`, the exact `k8s.review.selected_metadata.secret_indicators` check and one to eight `selected_k8s_metadata_resources` targets. It reads only selected top-level labels/annotations for ten supported namespaced kinds, with two coherent native GETs, bounded content, offline detectors and union redaction. This does not scan template metadata, arbitrary object fields, mounted files or referenced resources. See the [accepted setup](../peaso-k8s-selected-metadata-secrets.md).

Remaining readonly API content is concrete: template labels/annotations; probe `httpGet.httpHeaders[].value` and `exec.command`; lifecycle hook `exec.command` and HTTP headers; named resource fields such as Event messages or selected Ingress/Gateway/CRD textual configuration; and exact explicitly selected ConfigMap keys reached from Pod `envFrom`, `configMapKeyRef`, volumes or projected sources. Each needs its own bounded field/API allowlist, exact identity and current-version/key binding and byte-scanner receipt. The current literal extractor reads container command/args and literal env values, so it does not establish probe or lifecycle-field coverage. Existing selected literal scans already cover selected PodSpecs/controller templates and ConfigMap supported text; existing selected log scans cover bounded current container samples. API references do not prove effective environment expansion or mounted bytes, and custom resources are not generically supported. Secret payload stores and Helm release Secrets remain excluded. Guest/PVC/CSI/host files, process memory, external Git/chart artifacts and historical or external log stores require other independently authorized readers; native object GET does not expose their bytes.

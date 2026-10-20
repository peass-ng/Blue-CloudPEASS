# Kubernetes content available to a read-only connector

The optional `k8s.review.selected_literals.secret_indicators` check scans explicitly
selected ConfigMap `data` and `binaryData`, including YAML files containing admission
configuration. Select the exact cluster, namespace and ConfigMap; grant `get` on that
ConfigMap and the metadata permissions described in the [collector setup](peaso-azure-k8s-collectors.md).
Both offline detectors inspect the returned content, and repeated detections of the
same value produce one finding.

This proves what the ConfigMap stored when read. It does not prove which version a
running process mounted or used. Kubernetes documents how [ConfigMap volumes](https://kubernetes.io/docs/concepts/storage/volumes/#configmap)
expose those separate API objects as files.

Pod, PersistentVolume and node metadata describe file locations and volume references;
they do not return arbitrary filesystem contents. The [Pod exec API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/)
executes commands, including when accessed through its GET endpoint. This collector
does not request exec, node proxy, new Pods or ephemeral containers to obtain files.
Files available only inside a container, node or external volume remain outside this
read-only content coverage. Registry image downloads require separate scoped pull
permissions; see [content permissions](secret-content-permissions.md).

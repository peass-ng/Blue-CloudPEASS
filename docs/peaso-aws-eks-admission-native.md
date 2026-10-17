# EKS image-verifier admission routing

`aws_eks_runtime_image_integrity` can now read native validating-webhook metadata for explicitly designated EKS clusters. Its existing signed predicate tests routing to an approved verifier Service, with fail-closed Pod CREATE rules and no narrowing selectors. It does not verify an image signature, invoke a webhook, inspect running containers, or prove runtime integrity.

Supply the existing owner-policy namespace and select the matching account and explicit regions:

```json
{
  "regions": ["us-east-1"],
  "compliance_policy": {
    "eks_image_integrity": {
      "status": "collected",
      "designated_cluster_arns": ["arn:aws:eks:us-east-1:111122223333:cluster/example"],
      "approved_verifier_services": [{"namespace": "security", "name": "verifier"}]
    }
  }
}
```

Account-only selections require each designated ARN region in `options.regions`; explicit `ACCOUNT/REGION` selections also work. These declarations identify approved scope and services, not observed webhook facts. Without this opt-in the producer performs no credential lookup or EKS/Kubernetes calls. Only the selected account/region's designated clusters are read; this is not discovery of every cluster or organization-wide completeness.

The existing AWS `eks:DescribeCluster` read validates the exact native ARN/name, ACTIVE state, public endpoint and CA. The collector locally presigns STS `GetCallerIdentity`, with the cluster name signed in `x-k8s-aws-id`, using the current SDK session's in-memory credentials. It makes no STS HTTP request and invokes no AWS CLI, process, exec credential helper or role assumption. The bearer token is kept in RAM and sent only over the native endpoint's hostname-checked, CA-bound HTTPS channel.

The only Kubernetes operation is paginated GET `/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations`. The caller must already have the EKS authentication mapping and cluster-wide Kubernetes `list` permission for this resource. The adapter grants neither. Unauthorized reads, private-only clusters, unsupported endpoint dialects/partitions, incomplete pages or unsupported native shapes remain UNKNOWN. Standard `arn:aws`/legacy `*.REGION.eks.amazonaws.com` public endpoints are supported; `api.aws`, China and GovCloud variants are currently unsupported rather than rewritten.

No proxy environment or redirects are permitted. Shared cancellation/deadline/call/page/resource limits remain active, with additional hard caps of 120 seconds, 32 pages, 4,096 configurations, 2 MB per page and 16 MB total. Native List kind/API version, stable resourceVersion, terminal continuation, native configuration UID/name and duplicate webhook identities are checked. Public CA, signed STS URL, bearer token and webhook CA bundles are not emitted by this adapter. URL-based webhook clients are represented only as `url: "[omitted]"` with explicit redaction provenance; the signed routing predicate ignores their URL values and no webhook URL is followed.

Complete native metadata can establish PASS for matching approved routing, or FAIL when no such routing exists. Unknown/denied metadata is never converted to an empty successful list. Native reads and owner criteria remain separate; current tests use inert SDK/HTTPS fixtures and do not claim live EKS authorization or runtime enforcement.

Primary contracts: [AWS EKS DescribeCluster](https://docs.aws.amazon.com/cli/latest/reference/eks/describe-cluster.html), [EKS API endpoint access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html), and the upstream [AWS IAM authenticator token protocol](https://github.com/kubernetes-sigs/aws-iam-authenticator).

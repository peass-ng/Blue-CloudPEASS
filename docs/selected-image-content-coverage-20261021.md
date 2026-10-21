# Selected image content and package findings

Image content reads are optional. Select the exact resources and immutable image digests in the connector options; metadata-only assessments do not download image content. Registry pull permissions are separate from account, project, subscription or cluster metadata permissions. See [content permissions](secret-content-permissions.md) and the service-specific setup pages.

Kingfisher and TruffleHog inspect the same bounded selected content. Matches of the same secret are merged by its fingerprint, including matches reported by both engines. Public findings hide the value. A clean secret result requires both pinned detectors to finish on the inspected content. A verified match remains a finding when another file or image child cannot be read.

Trivy inspects packages for HIGH and CRITICAL vulnerabilities. Its database is provisioned through the trusted runtime before the per-image scan deadline and retained during the offline scan. Connector JSON cannot select an arbitrary Trivy executable or database path. A missing, stale or incomplete database cannot produce a clean package result. A package scan failure does not discard independently confirmed secret findings.

## Image identity and architecture

Readers validate downloaded manifest, config and layer hashes against the selected digest. Where an OCI index or Docker manifest list is supported, they inspect the bounded supported Linux amd64/arm64 children and preserve each child's actual digest in package findings. They do not guess which architecture a workload runs. The selected parent resource remains bound to its native account, project, subscription or Pod before and after the read.

Unsupported platforms, missing children, changed owners, denied content reads and exhausted bounds prevent a clean result. A partial result can still contain verified secret or package findings. Ordinary single-manifest images retain their existing path. AWS Lambda's native single-platform image constraints remain separate from ECS and Batch index support.

## Coverage limits

Image readers do not execute containers, start workloads, read Kubernetes Secret objects or request deliberately stored secret-manager values. File, expanded archive, download, time and finding limits apply. A binary or nested archive that is not fully inspected is recorded as incomplete; it does not stop the reader from checking later bounded files. Symlink and native runtime behavior are not inferred from declarative image content.

Cancellation and assessment deadline errors propagate to the assessment rather than being converted to a clean result. Published image rows require the evaluated finding, correct resource identifier and scope; unavailable coverage remains visible as a gap. The Images Findings table groups the canonical package observations while retaining affected assets and immutable image identities.

This document describes the local implementation contract. The current release packet still requires its single integrated source, runtime and packaging acceptance before these latest changes are published. Offline native-shaped transport tests do not certify that every provider API was exercised live.

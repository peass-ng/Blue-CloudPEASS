# Pending Cloud Build and Cloud Run content integration

Two independently implemented source planners now have coordinator acceptance. Cloud Build binds supported pinned source objects and produced image digests to native build/project/repository metadata, while leaving artifact-manifest traversal and stored-log generation discovery explicit. Cloud Run identifies all positive-traffic and tagged revisions for explicitly selected services, verifies native identities/reconciliation and binds supported immutable single-container images.

Cloud Run now has [installed image inspection and native capture proof](cloudrun-image-integration.md). Cloud Build now has separate [output-manifest inspection](followup-content-integration.md) and [stored-log inspection](cloudbuild-log-integration.md) installed and accepted. The initial pure planner itself remains distinct from those readers. The initial source planners did not themselves inspect content. Multi-container and unsupported source relationships remain unavailable.

Coordinator tests: 45 source-planner/inventory tests passed, within the 63-test combined GCR/content acceptance. Workers were accepted and released after source/report review and directed pytest verification. [Source hashes, API references and exact integration limits](content-source-planners-review.json).

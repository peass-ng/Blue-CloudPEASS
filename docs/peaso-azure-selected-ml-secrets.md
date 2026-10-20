# Optional selected Machine Learning job secret scanning

This reader is integrated locally; publication is tracked separately in the
[review progress](check-review/progress.json). It scans returned command text and
literal environment variables from selected native **Command** jobs. It does not
execute jobs or inspect referenced code, environment assets or container images.

Select `azure.review.machine_learning.selected_command_job_secret_indicators`,
set `content_secret_scans: true`, and provide one to four exact job ARM IDs:

```json
{
  "content_secret_scans": true,
  "selected_azure_ml_command_jobs": [
    {"resource_id": "/subscriptions/<subscription-id>/resourceGroups/<group>/providers/Microsoft.MachineLearningServices/workspaces/<workspace>/jobs/<case-sensitive-job-name>"}
  ]
}
```

Include the subscription explicitly in the connector's scan scope. Selectors
accept no endpoint, script URI, token audience or credential. The existing Azure
credential must have these read actions, which ARM Reader includes:

| Resource | Read permission |
| --- | --- |
| Selected subscription | `Microsoft.Resources/subscriptions/read` |
| Selected ML workspace | `Microsoft.MachineLearningServices/workspaces/read` |
| Selected job | `Microsoft.MachineLearningServices/workspaces/jobs/read` |

No Contributor role, new role assignment, image pull, Storage or Key Vault payload
permission is needed for this declaration reader. Tokens target the existing ARM
audience. The subscription, workspace tenant and exact native job identity must
agree before content is inspected.

Both pinned offline detectors must complete for a clean result. A supported hit
is reported once even if both detectors find it; its value stays hidden and is
not validated. Denied, masked, malformed, empty, unsupported or incomplete clean
content remains unresolved. References are not followed. Limits are four targets,
12 native GETs, 2 MiB per response, 8 MiB total response bytes, 256 KiB projected
content per target and 128 environment entries. A 120-second checked reader
budget does not override the credential SDK's own OAuth timeout/retry behavior.

See the [native review and remaining source boundaries](check-review/azure-ml-databricks-secret-surface-audit-20261020.md)
for API versions, private-access limits and the separate permissions required for
Storage, ACR or a future Databricks notebook reader. The original proposal record
is retained there; this setup describes the locally admitted reader.

# Run checks from the CLI

Install Python 3.12 or newer in a virtual environment. CLI scans do not require a server, browser, platform account, subscription or Codex token:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[cloud]'
python -m peaso --help
```

`peaso`, `hacktricks-cspm` and `python -m peaso` run the same CLI. Start with a synthetic scan to verify the installation without cloud access:

```sh
peaso scan --provider aws --demo \
  --categories hardening exposure least_privilege \
  --snapshot-output /tmp/demo-snapshot.json --output /tmp/demo-report.json
```

## Choose checks and write JSON

Use `--categories hardening` for configuration checks, `exposure` for exposure checks, `least_privilege` for permission review, and `iam_graph` to include IAM relationships. Combine categories in one scan:

```sh
peaso scan --provider aws --profile auditor --scopes 123456789012 \
  --categories hardening exposure least_privilege iam_graph \
  --snapshot-output /tmp/aws-snapshot.json --output /tmp/aws-report.json
```

JSON is the default. Reports include `findings`, `coverage`, `stats`, framework mappings and selected graphs. Selecting `least_privilege` also adds `least_privilege.items`, `total` and `coverage`: the same principal-level recommendations and exposure context used by the web application. Removal advice requires provider evidence; a broad grant alone is a review candidate.

Omit `--output` to pipe one JSON object to another tool. Progress goes to stderr; `--quiet` suppresses it. Files created with `--output` and `--snapshot-output` have private permissions. Ctrl-C and termination signals cancel further provider reads and allow temporary-resource cleanup before exit (130 for Ctrl-C, 143 for termination).

Exit codes are 0 for a completed run (findings can still FAIL), 2 for invalid input or an operational error, and 3 when nothing could be read. A partial scan can exit 0; inspect coverage and limitations before trusting its completeness.

To run a checklist, select an exact framework ID from the catalog:

```sh
peaso catalog --output /tmp/catalog.json
jq -r '.framework_versions[] | select(.provider == "aws") | [.id, .name] | @tsv' /tmp/catalog.json
peaso scan --provider aws --profile auditor --scopes 123456789012 \
  --frameworks FRAMEWORK_ID_FROM_CATALOG --output /tmp/checklist.json
```

`--checks CHECK_ID ...` selects individual checks from the same catalog. Avoid mixing restrictive categories with a checklist unless that intersection is intended. Checklist results describe implemented checks and collection gaps, not compliance certification.

## Pass connector credentials

The CLI uses the same provider collectors as local connectors. Put the connector's **authentication object** in a private JSON/YAML file and pass `--auth-file`. Use `--request` for the complete connector and optional check selection. Secrets need not appear in command arguments:

```sh
chmod 600 /absolute/private/auth.json
peaso scan --provider gcp --auth-file /absolute/private/auth.json \
  --scopes example-audit-project --categories hardening exposure least_privilege \
  --output /tmp/gcp-report.json

# An external credential helper can supply JSON directly over stdin.
credential-helper-producing-json | peaso scan --provider gcp --auth-file - \
  --scopes example-audit-project --categories exposure --output /tmp/exposure.json
```

Use either `--auth-file -` or `--request -` for stdin, not both. Omit `--auth-file` to use the provider's supported SDK defaults and environment variables. `--profile` is an AWS shortcut; `--context` is a Kubernetes shortcut. Files referenced by credentials and vendor CLIs must exist on the machine running the CLI.

| Provider | Supported local connector methods | Where credentials come from |
| --- | --- | --- |
| AWS | `default`, `profile`, `sso`, `access_keys`, `assume_role`, `web_identity`, `container`, `instance` | SDK environment/default chain, named profiles, explicit key/session fields, configured role targets/chains, web identity, ECS or EC2 identity. SSO profiles must already be signed in. |
| GCP | `adc`, `gcloud`, `service-account`, `external-account`, `metadata`, `impersonation`, `token` | ADC/environment, gcloud account, service-account JSON/file, workload federation JSON/file, attached identity, explicit impersonation source, or bearer token. |
| Azure | `auto`, `az-cli`, `client-secret`, `client-cert`, `managed-identity`, `workload-identity`, `device-code`, `token` | Azure SDK environment/default chain, Azure CLI login, service-principal secret/certificate, managed identity, federation assertion/file, interactive device sign-in, or audience-specific bearer tokens. |
| Kubernetes | `kubeconfig`, `context`, `in-cluster`, `token`, `client-cert`, `inline` | Kubeconfig and its configured helpers, in-cluster service account, direct server/token or client certificate, or inline kubeconfig. |

Example authentication objects (replace illustrative values; keep actual secrets outside Git):

```json
{"method":"assume_role","profile":"auditor","role_arn":"arn:aws:iam::123456789012:role/ExampleAudit","external_id":"YOUR_EXTERNAL_ID"}
```

```json
{"method":"service-account","service_account_file":"/absolute/private/service-account.json"}
```

```json
{"method":"client-secret","tenant_id":"YOUR_TENANT_ID","client_id":"YOUR_CLIENT_ID","client_secret":"YOUR_SECRET"}
```

```json
{"method":"client-cert","server":"https://YOUR_CLUSTER_API","ca_cert":"/absolute/private/ca.crt","client_cert":"/absolute/private/client.crt","client_key":"/absolute/private/client.key"}
```

The complete request format is:

```json
{
  "connector": {
    "name": "Example audit",
    "provider": "aws",
    "auth": {"method": "profile", "profile": "auditor"},
    "scopes": ["123456789012"],
    "options": {"regions": ["us-east-1"]}
  },
  "categories": ["hardening", "exposure", "least_privilege"]
}
```

```sh
peaso scan --request /absolute/private/request.json --output /tmp/report.json
```

Hosted broker roles and the hosted shared GCP service account depend on operator configuration, not bundled credentials. For ordinary CLI use, supply your own equivalent credential. An operator explicitly selecting `platform-service-account` must configure `PEASO_GCP_PLATFORM_SA_SECRET_ARN`, `PEASO_GCP_PLATFORM_PROJECT`, `PEASO_GCP_PLATFORM_EMAIL` and the connector's project approval label; the CLI does not discover an internal secret or identity.

## Collection scope and permissions

Use audit identities and explicit target scopes. Scans use configuration reads and supported evidence queries; provider denials remain visible in coverage. AWS selections requiring Access Analyzer can create temporary analyzers, wait for initial analysis and delete the analyzers created by that scan. IAM evidence can also require generating credential/last-access reports. See the [AWS collection contract](peaso-aws-collector.md) before selecting these inventories.

For a bounded AWS permission review that excludes analyzer creation, use an options file containing the following. Missing analyzer, workload and network evidence remains a limitation, and no unused-permission removal advice is inferred:

```json
{"regions":["us-east-1"],"inventories":["iam_user","iam_group","iam_role","iam_policy"]}
```

```sh
peaso scan --provider aws --profile auditor --scopes 123456789012 \
  --categories least_privilege --options-file /absolute/private/iam-options.json \
  --output /tmp/iam-review.json
```

## Reevaluate saved evidence without credentials

```sh
peaso collect --provider gcp --scopes example-audit-project \
  --categories hardening exposure least_privilege --output /tmp/snapshot.json
peaso evaluate /tmp/snapshot.json --categories hardening exposure least_privilege \
  --output /tmp/report.json
peaso report /tmp/report.json --format markdown --output /tmp/report.md
```

`evaluate`, `report` and `diff` use local files. They do not contact clouds or resolve Codex credentials. Use `--embed-native` or `--embed-snapshot` on `scan` when a standalone report must carry raw sanitized evidence; otherwise save the separate snapshot for detailed offline analysis.

See the provider collection guides for additional authentication fields, scope formats, permissions and optional collection limits: [AWS](peaso-aws-collector.md), [GCP](peaso-gcp-collector.md), [Azure](peaso-azure-collector.md), [Kubernetes](peaso-azure-k8s-collectors.md).

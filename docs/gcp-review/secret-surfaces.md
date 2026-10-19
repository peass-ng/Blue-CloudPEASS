# GCP optional secret surfaces

Explicit selection and content opt-in are required. Negative results cover only the supported bytes actually scanned. Intended secret-store payloads are excluded.

| Service / surface | Status | Coverage |
| --- | --- | --- |
| Cloud Functions / Returned runtime and build literal env values | implemented | Returned Cloud Functions v2 runtime/build literal environment maps; managed references are not resolved. |
| Cloud Functions / Deployed source archives | implemented | Immutable GCS archive from native Functions v2 resolvedStorageSource with function/project/bucket authority; not a deployed image or runtime assessment. |
| Artifact Registry / Immutable OCI/Docker image config and layers | implemented | Explicit immutable Artifact Registry images in one project; supported manifest/config/layers only, with digest and size verification. |
| Artifact Registry / Selected repository package/build files | implemented | Exact selected Artifact Registry package files verified against native SHA256 metadata, expected digest and downloaded bytes; supported UTF8 or bounded ZIP/tar/gzip text only, no installation. |
| Container Registry / gcr.io / Explicit gcr.io image references | implemented | Explicit immutable native Artifact Registry DockerImage URIs on the four documented GCR hosts; native repository/project binding and digest-verified manifest/config/layers. No alias rewriting or legacy backend reconstruction. |
| Cloud Build / Stored build source and output artifacts | implemented | Explicit terminal same-project Builds: supported records in the observed native output manifest and their pinned GCS artifact generations. Does not establish historical build bytes or scan inputs, arbitrary artifact paths or images. |
| Cloud Build / Selected stored build log text | implemented | Explicit terminal same-project Builds with native logsBucket and generation-pinned GCS log objects. Covers only the observed object generation; complete historical logs and Cloud Logging-only backends are not covered. |
| Cloud Build / Inline literal build env/args/substitutions | implemented | Returned inline trigger/build substitutions, steps, arguments and environment literals; referenced source/artifacts are not fetched. |
| Cloud Storage / Explicit immutable selected object bytes | implemented | Exact selected generation-pinned UTF-8 objects, with native project and bucket ownership binding; no bucket enumeration. |
| Cloud Logging / Selected bounded application log messages | implemented | Bounded 15-minute application-log sample with query/window and message ordinal evidence; no complete-history claim. |
| Cloud Source Repositories / Selected legacy repository files at commit | implemented | Exact 1–8 selected regular UTF8 files at one immutable advertised commit in one native-bound repository. No whole-repository/history absence claim. |
| Dataform / Native repository files at commit | implemented | Explicit repository file at a full commit SHA via native readFile; no Git checkout or repository-wide traversal. |
| Dataform / Explicit workspace file selection | implemented | Explicit workspace file via native readFile; without a supplied revision, coverage is the returned file at collection time. |
| Cloud Composer / Explicit environment DAG/plugin objects | implemented | Complete bounded native DAG-prefix listing followed by immutable observed text-file generations, with exact environment/project/bucket authority; no whole-environment or concurrent-change absence claim. |
| App Engine / Explicit deployed version source objects | implemented | Exact selected standard App Engine versions: the complete supported native deployment.files manifest, generation-pinned GCS reads and required native SHA1 matches before offline detection. Runtime contents, containers, generated artifacts and unsupported manifests are outside scope. |
| Cloud Run / Explicit revision image or source-location artifacts | implemented | Explicit same-project services: all positive-traffic and tagged single-container revisions, native immutable image joins and dual offline content inspection with fresh service revalidation. No project-wide, historical or multi-container absence claim. |
| Cloud Run / Service/job literal env/args/config | implemented | Returned Cloud Run service/job literal environment, command and arguments; managed-secret references are not resolved. |
| GKE / Selected ConfigMap literal data | implemented | Explicit selected native GKE clusters and bounded namespaces: ConfigMap data/binaryData or Pod literal env/args/commands via pinned endpoint/CA and existing native Google token. Kubernetes Secret values are not read; cloud IAM metadata access alone does not prove Kubernetes RBAC. |
| GKE / Selected Pod literal env/args | implemented | Explicit selected native GKE clusters and bounded namespaces: ConfigMap data/binaryData or Pod literal env/args/commands via pinned endpoint/CA and existing native Google token. Kubernetes Secret values are not read; cloud IAM metadata access alone does not prove Kubernetes RBAC. |
| GKE / Referenced Kubernetes Secrets and service-account token volumes | unsupported | References and metadata can be assessed; intended Secret data is not a leak surface. |
| Compute Engine / VM/template literal metadata/startup config | implemented | Returned VM, template and project metadata literals including startup/shutdown scripts; external script URLs are not fetched. |
| Secret Manager / Intentionally stored secret payloads | unsupported | Secret metadata/IAM collector exists; intended payloads excluded. |
| Cloud KMS / Managed key material and decrypt operations | unsupported | KMS resource/version/policy metadata collected; managed key material excluded. |
| Managed service credentials / Database/Redis/etc managed password stores | unsupported | Intended managed password retrieval/reset is outside leak scanning. |
| Workflows / Selected workflow sourceContents | implemented | Returned deployed Workflows source bound to native name and discovered revision; no workflow execution. |
| Cloud Deploy / Selected release Skaffold/manifests | implemented | Explicit same-project Releases: complete supported text members of the observed native Skaffold source archive generation. Does not establish historical release bytes, rendered configuration, deployed images or runtime values. |
| Scheduler / Tasks / Explicit HTTP job/task literal bodies | implemented | Returned Scheduler target header/body and Pub/Sub attribute/data literals; no target execution or message pull. |
| App Engine / Returned App Engine version literal environment values | implemented | Bounded native full-version read restricted to envVariables/buildEnvVariables; no deployment-source traversal. |
| Cloud Storage / Explicit immutable archives | implemented | Exact selected generation-pinned ZIP/tar/gzip archives; bounded regular UTF-8 members only, no extraction or automatic service source traversal. |
| Dataflow job / Dataflow job literal configuration | implemented | Only returned bounded literal configuration and retained metadata inspected by both offline detectors, never whole-service absence or referenced content. |
| Batch job / Batch job literal configuration | implemented | Only returned bounded literal configuration and retained metadata inspected by both offline detectors, never whole-service absence or referenced content. |
| Dataproc cluster / Dataproc cluster literal configuration | implemented | Only returned bounded literal configuration and retained metadata inspected by both offline detectors, never whole-service absence or referenced content. |
| Dataproc job / Dataproc job literal configuration | implemented | Only returned bounded literal configuration and retained metadata inspected by both offline detectors, never whole-service absence or referenced content. |
| Cloud Composer / Cloud Composer returned literal configuration | implemented | Returned Cloud Composer configuration literals only; no DAG, package, notebook file or referenced script download. Known security switches remain independently usable; removed values have unavailable field coverage. |
| Workbench / Workbench returned literal configuration | implemented | Returned Workbench configuration literals only; no DAG, package, notebook file or referenced script download. Known security switches remain independently usable; removed values have unavailable field coverage. |

Exact selectors, read APIs, limits and evidence: [surface inventory](secret-surfaces.json).

# Portable GCP regression setup

Place the supplement's `tests/` files in the repository `tests/` directory after the final source archive has been admitted. They import the installed `peaso` modules directly and use the existing `tests/gcp_job_image_vulnerability_fixture_20261021.py` and `tests/test_gcp_cloudbuild_log_secret_review_20261019.py` fixture helpers. No source admission hook, credential guard, or collector is replaced by these tests.

## Separate opt-ins

The standalone immutable registry vulnerability test selects `gcp.review.artifact_image.selected_image_vulnerabilities`, sets `image_vulnerability_scans: true`, and supplies `selected_gcp_registry_image_vulnerabilities` with exact digest references in one project. Content secret scans use `content_secret_scans` and their own selected source paths; enabling either scan does not enable the other. Neither option automatically downloads images from every project or proves that any selected image is running in Cloud Run, GKE, or App Engine.

A live identity would need `resourcemanager.projects.get` for the Cloud Resource Manager project GET, `artifactregistry.repositories.get` for repository metadata, `artifactregistry.dockerimages.get` for DockerImage metadata, and `artifactregistry.repositories.downloadArtifacts` for immutable manifest, config, and layer bytes. `roles/artifactregistry.reader` includes the Artifact Registry reads; the project GET also needs project read access. The tests use synthetic native HTTP responses and do not perform cloud writes or live GCP calls. References: [CRM projects.get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get), [Artifact Registry roles](https://docs.cloud.google.com/iam/docs/roles-permissions/artifactregistry), [Artifact Registry access control](https://docs.cloud.google.com/artifact-registry/docs/access-control).

## Focused commands after final source admission

Use Python 3.12 with an explicit final repository root on `sys.path`. Run the following from the final repository root, replacing the interpreter path with its environment-specific Python 3.12 path:

```sh
python3.12 -I -c 'import sys,pytest;sys.path.insert(0,".");raise SystemExit(pytest.main(["tests/test_gcp_registry_trivy_portable.py","-q","--junitxml=gcp-registry-portable.xml"]))'
python3.12 -I -c 'import sys,pytest;sys.path.insert(0,".");raise SystemExit(pytest.main(["tests/test_gcp_image_stream_reader.py","tests/test_gcp_image_stream_inspection.py","tests/test_gcp_image_stream_real_detectors.py","tests/test_gcp_job_trivy_stream.py","tests/test_gcp_job_trivy_stream_real_cli.py","-q","--junitxml=gcp-stream-portable.xml"]))'
python3.12 -I -c 'import sys,pytest;sys.path.insert(0,".");raise SystemExit(pytest.main(["tests/test_multicontainer_declared_images.py","tests/test_multicontainer_source_proof.py","-q","--junitxml=gcp-multicontainer-portable.xml"]))'
python3.12 -I -c 'import sys,pytest;sys.path.insert(0,".");raise SystemExit(pytest.main(["tests/test_gcp_cloudbuild_logging_portable.py","-q","--junitxml=gcp-logging-portable.xml"]))'
```

The registry's real pinned Trivy case requires `PEASO_TEST_TRIVY_CLI` pointing to Trivy 0.68.1 and `PEASO_TEST_TRIVY_DB` pointing to an existing stale DB cache. The test fails when those variables are missing, and the scanner must return UNKNOWN for stale clean coverage. Run it with OS-level network denial; Trivy also has offline/update-disabled flags. The separate streaming CLI case uses `trivy` on `PATH` and the same DB cache variable; its synthetic image remains UNKNOWN. Other cases use only native fixture responses and local scratch.

The previous isolated proposal receipts are evidence for those proposal versions only: registry 35 passed, streaming 46 passed, multi-container 33 passed, Logging 36 passed. This portable supplement has passed syntax and path review but has not yet run against the final admitted runtime. Live IAM/download acceptance is still open.

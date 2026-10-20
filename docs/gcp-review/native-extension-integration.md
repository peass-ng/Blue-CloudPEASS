# Native GCP extension integration

New native GCP extensions after the original491 review, excluding the two Workbench settings and first Function environment check already individually joined by their reports. Source-bound fixtures, owner receipts and accumulated gate are distinct from live cloud proof.

| Check ID | Disposition | Native owner review |
| --- | --- | --- |
| `gcp.review.instance.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.instance_template.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.project.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.cloudrun_service.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.cloudrun_job.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.cloudbuild_build.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [configuration-secret-review.json](configuration-secret-review.json) |
| `gcp.review.logging.application_log_secret_indicators` | registered_native_fixture_checked_not_live | [log-secret-review.json](log-secret-review.json) |
| `gcp.review.storage.selected_object_secret_indicators` | registered_native_fixture_checked_not_live | [selected-object-secret-review.json](selected-object-secret-review.json) |
| `gcp.review.artifact_image.content_secret_indicators` | registered_native_fixture_checked_not_live | [image-secret-review.json](image-secret-review.json) |
| `gcp.review.storage.selected_archive_secret_indicators` | registered_native_fixture_checked_not_live | [selected-archive-secret-review.json](selected-archive-secret-review.json) |
| `gcp.review.scheduler_job.literal_target_secret_indicators` | registered_native_fixture_checked_not_live | [additional-literal-secret-review.json](additional-literal-secret-review.json) |
| `gcp.review.app_engine_version.literal_environment_secret_indicators` | registered_native_fixture_checked_not_live | [additional-literal-secret-review.json](additional-literal-secret-review.json) |
| `gcp.review.workflow.deployed_source_secret_indicators` | registered_native_fixture_checked_not_live | [additional-literal-secret-review.json](additional-literal-secret-review.json) |
| `gcp.review.dataform.selected_file_secret_indicators` | registered_native_fixture_checked_not_live | [dataform-secret-review.json](dataform-secret-review.json) |
| `gcp.review.dataflow_job.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [job-literal-secret-review.json](job-literal-secret-review.json) |
| `gcp.review.batch_job.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [job-literal-secret-review.json](job-literal-secret-review.json) |
| `gcp.review.dataproc_cluster.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [job-literal-secret-review.json](job-literal-secret-review.json) |
| `gcp.review.dataproc_job.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [job-literal-secret-review.json](job-literal-secret-review.json) |
| `gcp.review.gke_workload.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [gke-literal-secret-review.json](gke-literal-secret-review.json) |
| `gcp.review.composer_environment.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [notebook-airflow-secret-review.json](notebook-airflow-secret-review.json) |
| `gcp.review.workbench_instance.literal_configuration_secret_indicators` | registered_native_fixture_checked_not_live | [notebook-airflow-secret-review.json](notebook-airflow-secret-review.json) |
| `gcp.review.function.resolved_source_archive_secret_indicators` | registered_native_fixture_checked_not_live | [function-source-secret-review.json](function-source-secret-review.json) |
| `gcp.review.artifactregistry.selected_file_secret_indicators` | registered_native_fixture_checked_not_live | [artifact-file-secret-review.json](artifact-file-secret-review.json) |
| `gcp.review.composer.dag_source_secret_indicators` | registered_native_fixture_checked_not_live | [composer-source-secret-review.json](composer-source-secret-review.json) |
| `gcp.compute.os_config_fixable_vulnerabilities` | registered_native_fixture_checked_not_live | [os-security-update-review.json](os-security-update-review.json) |
| `gcp.review.cloudbuild.stored_log_secret_indicators` | registered_native_fixture_checked_not_live | [cloudbuild-log-secret-review.json](cloudbuild-log-secret-review.json) |
| `gcp.review.appengine.deployment_source_secret_indicators` | registered_native_fixture_checked_not_live | [appengine-source-secret-review.json](appengine-source-secret-review.json) |
| `gcp.review.cloudbuild.artifact_secret_indicators` | registered_native_fixture_checked_not_live | [cloudbuild-artifact-secret-review.json](cloudbuild-artifact-secret-review.json) |
| `gcp.review.clouddeploy.release_source_secret_indicators` | registered_native_fixture_checked_not_live | [clouddeploy-source-secret-review.json](clouddeploy-source-secret-review.json) |
| `gcp.review.sourcerepo.selected_file_secret_indicators` | registered_native_fixture_checked_not_live | [sourcerepo-secret-review.json](sourcerepo-secret-review.json) |

All current PASS/FAIL/UNKNOWN behavior fixtures evaluated as expected at this capture. No authenticated cloud validation or production publication is claimed. See [exact source hashes and examples](native-extension-integration.json).

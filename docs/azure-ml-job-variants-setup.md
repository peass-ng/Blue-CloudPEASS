# Selected Azure ML job literals

Select the existing optional check `azure.review.machine_learning.selected_command_job_secret_indicators`, set `content_secret_scans=true`, and provide 1–4 exact `selected_azure_ml_command_jobs` entries of the form `{"resource_id":"/subscriptions/.../resourceGroups/.../providers/Microsoft.MachineLearningServices/workspaces/.../jobs/CaseSensitiveName"}`. The existing kind and option names are retained for compatibility; the selected job may be Command, Sweep, or Pipeline.

The connector principal needs ARM read access to the selected subscription, `Microsoft.MachineLearningServices/workspaces/read`, and `Microsoft.MachineLearningServices/workspaces/jobs/read`. The collector performs subscription and workspace reads, then two GETs of each selected job through `management.azure.com` with the existing ARM token; it performs no data-plane, datastore, training, or credential read. The same explicit target and named check are required before any token request.

For Sweep, only returned `properties.trial.command` and `properties.trial.environmentVariables` are inspected. For Pipeline, only up to 16 inline `properties.jobs` children with explicit `jobType=Command` or `Sweep` are inspected; nested pipelines, component references, expressions, masked values, and any skipped child make a clean result unknown. A confirmed detector hit remains a failure even when later coverage or the second native read is incomplete.

Official schema: https://learn.microsoft.com/en-us/rest/api/azureml/jobs/get?view=rest-azureml-2024-04-01 . Pipeline child job types: https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/machine-learning/reference-yaml-job-pipeline.md .

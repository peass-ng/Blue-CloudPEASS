# AWS privilege-escalation coverage ledger

Upstream: hacktricks-cloud branch `feat/privesc-v3-challenge` at `5129659964f0c932367df87d11bd26dec2c150b5` (based on PR #468). Catalog: `peaso/privesc/catalog/aws/*.yaml`.
`tests/test_peaso_privesc_coverage_aws.py` checks it.

The historical review reconciled those headings with the catalog at that point. Newly relocated source headings follow HackTricks Cloud PR #482; historical headings remain listed with their exclusion reasons.

Scope: every heading of every page under `aws-privilege-escalation/**`, plus every heading elsewhere under `aws-security/` (post-exploitation, persistence, services, unauthenticated, basic information) whose heading or section mentions privilege escalation, PassRole, execution/instance-profile roles or role credentials.

Status legend: COVERED (catalog ids), EXCLUDED (an `_excluded*.yaml` line explains why it is not an edge), NEEDS SCHEMA (not expressible with the current schema, proposal below), STRUCTURAL (title, introduction, enumeration, example or reference heading of a technique mapped elsewhere), NOT PRIVESC (heading outside the privesc tree that does not give another principal's privileges).

## Summary

- COVERED: 180
- EXCLUDED: 658
- NEEDS SCHEMA: 0
- NOT PRIVESC: 133
- STRUCTURAL: 661
- Headings: 1632; distinct active catalog ids referenced: 177; AWS active catalog entries: 177

## Headings by page

### README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `privesc--exploiting` | Privesc & Exploiting |  | STRUCTURAL | Tool list (SkyArk, pacu, ...) for privesc discovery; no technique. |

### aws-basic-information/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `temporary-credentials-in-iam` | [Temporary credentials in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) <a href="#id_temp-creds" id="id_te |  | STRUCTURAL | Background on temporary credentials / credential_process; no technique. |
| `automating-temporary-credentials` | Automating temporary credentials |  | STRUCTURAL | Background on temporary credentials / credential_process; no technique. |

### aws-persistence/aws-agent-registry-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `agent-registryupdateregistry--persist-automatic-approval-of-malicious-records` | `agent-registry:UpdateRegistry` — persist automatic approval of malicious records | agent-registry:UpdateRegistry | NOT PRIVESC | Registry approval tampering (supply-chain of agent records); requires the registry admin permission and yields no IAM principal. |

### aws-persistence/aws-amplify-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `amplifycreatewebhook--persist-a-credential-less-build-trigger` | `amplify:CreateWebHook` — Persist a credential-less build trigger | amplify:CreateWebHook | NOT PRIVESC | Persistence of a build trigger after the build was already poisoned; the poisoning itself is the Amplify privesc entries. |

### aws-persistence/aws-appconfig-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `appconfigcreateextension--appconfigcreateextensionassociation--iampassrole` | `appconfig:CreateExtension` + `appconfig:CreateExtensionAssociation` + `iam:PassRole` | appconfig:CreateExtension, appconfig:CreateExtensionAssociation, iam:PassRole | NOT PRIVESC | The passed role only lets AppConfig invoke a Lambda extension that runs with its own role; configuration interception, not a privesc. |

### aws-persistence/aws-appstream-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `appstreamcreateuser--batchassociateuserstack--regional-user-pool-foothold` | `appstream:CreateUser` + `BatchAssociateUserStack` — regional user-pool foothold | appstream:BatchAssociateUserStack, appstream:CreateUser | EXCLUDED | Previously mapped to `aws-v3-39-appstream-user-pool-stack-login`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `appstreamupdatefleet--s3--recurring-system-session-scripts-on-an-existing-elastic-fleet` | `appstream:UpdateFleet` + S3 — recurring SYSTEM session scripts on an existing Elastic fleet | appstream:UpdateFleet | EXCLUDED | Excluded: The appstream_fleet resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. — Session-script variant of repointing an existing fleet with appstream:UpdateFleet; same permission and fleet-role target. |

### aws-persistence/aws-athena-result-redirection-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `athenaupdateworkgroup--redirect-future-query-results-to-attacker-readable-s3` | `athena:UpdateWorkGroup` — Redirect future query results to attacker-readable S3 | athena:UpdateWorkGroup | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-persistence/aws-cloudtrail-trail-redirection-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cloudtrailupdatetrail--redirect-future-audit-logs-to-attacker-readable-s3` | `cloudtrail:UpdateTrail` — Redirect future audit logs to attacker-readable S3 | cloudtrail:UpdateTrail | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-persistence/aws-cloudwatch-log-forwarding-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `observabilityadmincreates3tableintegration--logsassociatesourcetos3tableintegration--iampassrole--copy-future-logs-into-s3-tables` | `observabilityadmin:CreateS3TableIntegration` + `logs:AssociateSourceToS3TableIntegration` + `iam:PassRole` — copy future logs into S3 Table | observabilityadmin:CreateS3TableIntegration, logs:AssociateSourceToS3TableIntegration, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `logsputaccountpolicy--account-wide-subscription-filter-over-every-log-group` | `logs:PutAccountPolicy` — account-wide subscription filter over *every* log group | logs:PutAccountPolicy | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `logscreatescheduledquery--iampassrole--recurring-log-exfiltration-to-s3` | `logs:CreateScheduledQuery` + `iam:PassRole` — recurring log exfiltration to S3 | logs:CreateScheduledQuery, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `logsputsubscriptionfilter--forward-private-logs-through-a-preauthorized-destination` | `logs:PutSubscriptionFilter` — forward private logs through a preauthorized destination | logs:PutSubscriptionFilter | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-persistence/aws-cloudwatch-omni-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cloudwatchcreatealert--persist-an-autonomous-telemetry-query-through-an-existing-profile` | `cloudwatch:CreateAlert` — persist an autonomous telemetry query through an existing profile | cloudwatch:CreateAlert | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). CloudWatch Omni sessions/alerts use existing access profiles; no IAM principal is obtained. |

| `cloudwatchcreateaccessgrant--install-a-space-admin-principal` | `cloudwatch:CreateAccessGrant` — install a Space Admin principal | cloudwatch:CreateAccessGrant | EXCLUDED | Previously mapped to `aws-v3-40-cloudwatch-omni-space-admin`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-cognito-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cognito-idpcreateuserpoolclient--a-rogue-app-client-with-a-decade-long-refresh-token` | `cognito-idp:CreateUserPoolClient` — a rogue app client with a decade-long refresh token | cognito-idp:CreateUserPoolClient | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-persistence/aws-data-firehose-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `firehoseupdatedestination--persistently-redirect-future-records` | `firehose:UpdateDestination` — persistently redirect future records | firehose:UpdateDestination | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-persistence/aws-datasync-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `datasyncupdatetask--schedule-recurring-delegated-transfers` | `datasync:UpdateTask` — schedule recurring delegated transfers | datasync:UpdateTask | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-persistence/aws-eventbridge-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `bus-resource-policy-backdoor-eventsputpermission` | Bus resource-policy backdoor (`events:PutPermission`) | events:PutPermission | NOT PRIVESC | Event-injection backdoor into existing rules/targets; targets run with their own fixed roles and inputs, no principal is obtained (same-account self-grant is on the EventBridge privesc page). |
| `enhanced-bus-cross-account-backdoor-eventsputresourcepolicy` | Enhanced-bus cross-account backdoor (`events:PutResourcePolicy`) | events:PutResourcePolicy | NOT PRIVESC | Event-injection backdoor into existing rules/targets; targets run with their own fixed roles and inputs, no principal is obtained (same-account self-grant is on the EventBridge privesc page). |

### aws-persistence/aws-iam-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iam-roles-anywhere-trust-anchor-backdoor-rolesanywherecreatetrustanchor--createprofile` | IAM Roles Anywhere trust-anchor backdoor (`rolesanywhere:CreateTrustAnchor` + `CreateProfile`) | rolesanywhere:CreateTrustAnchor, rolesanywhere:CreateProfile, iam:PassRole | COVERED | `aws-rolesanywhere-createtrustanchor-createprofile-passrole` |
| `iamupdaterole--raise-a-roles-maxsessionduration` | `iam:UpdateRole` — raise a role's `MaxSessionDuration` | iam:UpdateRole | NOT PRIVESC | Lengthens future sessions of a role; requires prior access to the role. |

### aws-persistence/aws-lambda-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `lambdaputfunctioneventinvokeconfig--updatefunctioneventinvokeconfig--redirect-async-records-or-trigger-a-fixed-consumer` | `lambda:PutFunctionEventInvokeConfig` / `UpdateFunctionEventInvokeConfig` — redirect async records or trigger a fixed consumer | lambda:PutFunctionEventInvokeConfig | NOT PRIVESC | Redirects async invocation records of a function that keeps its own role and code; data exposure only. |

### aws-persistence/aws-managed-grafana-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `grafanaupdateworkspaceauthentication--attacker-controlled-saml-idp` | `grafana:UpdateWorkspaceAuthentication` — attacker-controlled SAML IdP | grafana:UpdateWorkspaceAuthentication | COVERED | App-plane only: grants access inside a service application or data plane (not an IAM principal).<br>`aws-grafana-updateworkspaceauthentication-saml-admin` |
| `grafanaupdatepermissions--iam-identity-center-administrator` | `grafana:UpdatePermissions` — IAM Identity Center administrator | grafana:UpdatePermissions | EXCLUDED | excluded: "Grant a controlled Identity Center identity Grafana administrator access"; UpdatePermissions can grant ADMIN to an Identity Center identity, but the source is not proved to control a credentialed member of that user/group. |

### aws-persistence/aws-medialive-output-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redirect-the-output--medialiveupdatechannel` | Redirect the output — `medialive:UpdateChannel` | medialive:UpdateChannel | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-persistence/aws-network-security-manager-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `network-security-managerputadminaccount--retain-delegated-network-security-administration` | `network-security-manager:PutAdminAccount` — retain delegated network-security administration | network-security-manager:PutAdminAccount | EXCLUDED | Previously mapped to `aws-v3-52-network-security-manager-delegate`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-q-in-connect-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `wisdomupdateassistantaiagent--persist-a-custom-ai-agent-as-the-assistant-default` | `wisdom:UpdateAssistantAIAgent` — persist a custom AI agent as the assistant default | wisdom:UpdateAssistantAIAgent | NOT PRIVESC | Persists a custom AI agent for Q in Connect sessions; application behaviour change, no IAM principal. |

### aws-persistence/aws-redshift-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redshift-serverlessupdatenamespace---reset-the-serverless-database-administrator` | `redshift-serverless:UpdateNamespace` - reset the Serverless database administrator | redshift-serverless:UpdateNamespace | EXCLUDED | Previously mapped to `aws-v3-48-redshift-serverless-admin-reset`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-sagemaker-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `sagemakerupdatenotebookinstancelifecycleconfig--stored-code-execution-as-the-notebook-role` | `sagemaker:UpdateNotebookInstanceLifecycleConfig` — stored code execution as the notebook role | sagemaker:UpdateNotebookInstanceLifecycleConfig | EXCLUDED | Excluded: The sagemaker:UpdateNotebookInstanceLifecycleConfig source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |

### aws-persistence/aws-secrets-manager-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `secretsmanagerrotatesecret--invoke-the-existing-rotation-lambda` | `secretsmanager:RotateSecret` — invoke the existing rotation Lambda | secretsmanager:RotateSecret | NOT PRIVESC | Triggers the existing rotation Lambda with fixed code and role; the caller cannot choose code or role. |

### aws-persistence/aws-security-agent-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `securityagentcreatemembership--retain-agent-space-web-application-access` | `securityagent:CreateMembership` — retain Agent Space web-application access | securityagent:CreateMembership | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-persistence/aws-ssm-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `ssmcreateactivation-iampassrole--a-long-lived-hybrid-activation-as-a-re-entry-credential` | `ssm:CreateActivation`, `iam:PassRole` — a long-lived hybrid activation as a re-entry credential | iam:PassRole, ssm:CreateActivation | COVERED | `aws-ssm-passrole-createactivation` — Persistence view of the SSM hybrid-activation technique. |

### aws-post-exploitation/aws-acm-pca-scep-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `pca-connector-scepcreatechallenge--getchallengepassword--mint-a-scep-enrollment-secret-rogue-device-certificate-backdoor` | `pca-connector-scep:CreateChallenge` / `GetChallengePassword` — mint a SCEP enrollment secret (rogue-device certificate backdoor) | pca-connector-scep:CreateChallenge | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-api-gateway-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `apigatewayupdateportal--apigatewaypublishportal--make-protected-api-documentation-public` | `apigateway:UpdatePortal` + `apigateway:PublishPortal` — make protected API documentation public | apigateway:UpdatePortal, apigateway:PublishPortal | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `apigatewaypatch-updatestage--silence-a-stages-logging-and-tracing` | `apigateway:PATCH` (`UpdateStage`) — silence a stage's logging and tracing | apigateway:PATCH | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-appconfig-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `appconfigstartdeployment--activate-or-roll-back-to-a-stored-version` | `appconfig:StartDeployment` — activate or roll back to a stored version | appconfig:StartDeployment | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-appstream-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `appstreamupdateimagepermissions--share-and-clone-a-private-golden-image-cross-account` | `appstream:UpdateImagePermissions` — share and clone a private golden image cross-account | appstream:UpdateImagePermissions | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `appstreamcreateexportimagetask--iampassrole--turn-a-private-image-into-an-ec2-ami` | `appstream:CreateExportImageTask` + `iam:PassRole` — turn a private image into an EC2 AMI | appstream:CreateExportImageTask, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `appstreamupdatestack--re-enable-client-data-transfer-channels` | `appstream:UpdateStack` — re-enable client data-transfer channels | appstream:UpdateStack | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-backup-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `backupstartrestorejob--iampassrole--clone-protected-data` | `backup:StartRestoreJob` + `iam:PassRole` — clone protected data | backup:StartRestoreJob, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-batch-data-disclosure-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `batchdescribejobs--read-per-run-commands-and-environment-overrides` | `batch:DescribeJobs` — read per-run commands and environment overrides | batch:DescribeJobs | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-bedrock-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `bedrockdeletemodelinvocationloggingconfiguration--bedrockputmodelinvocationloggingconfiguration--blind-out-the-promptcompletion-audit-trail` | `bedrock:DeleteModelInvocationLoggingConfiguration` \| `bedrock:PutModelInvocationLoggingConfiguration` — blind out the prompt/completion au | bedrock:DeleteModelInvocationLoggingConfiguration, bedrock:PutModelInvocationLoggingConfiguration | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

| `1-runtime-ssrf---mmds-credentials` | 1. Runtime SSRF -> MMDS credentials |  | EXCLUDED | Previously mapped to `aws-v3-07-agentcore-runtime-ssrf-to-its-execution-role-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-clean-rooms-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redirect-stored-sql-and-ml-output-destinations-with-passrole` | Redirect stored SQL and ML output destinations with `PassRole` |  | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-cloudwatch-log-data-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `logscreateexporttask--bulk-export-a-whole-log-groups-history-to-s3` | `logs:CreateExportTask` — bulk-export a whole log group's history to S3 | logs:CreateExportTask | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-cloudwatch-omni-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cloudwatchcreateonetimedeeplinkcode--mint-an-authenticated-omni-browser-session` | `cloudwatch:CreateOneTimeDeepLinkCode` — mint an authenticated Omni browser session | cloudwatch:CreateOneTimeDeepLinkCode | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). CloudWatch Omni sessions/alerts use existing access profiles; no IAM principal is obtained. |
| `cloudwatchupdateintegration--rebind-an-external-integration` | `cloudwatch:UpdateIntegration` — rebind an external integration | cloudwatch:UpdateIntegration | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). CloudWatch Omni sessions/alerts use existing access profiles; no IAM principal is obtained. |
| `cloudwatchupdatealert--hijack-a-scheduled-query-and-its-notifications` | `cloudwatch:UpdateAlert` — hijack a scheduled query and its notifications | cloudwatch:UpdateAlert | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). CloudWatch Omni sessions/alerts use existing access profiles; no IAM principal is obtained. |

### aws-post-exploitation/aws-cloudwatch-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `oamcreatelink--telemetry-service-link-actions--expose-observability-data-cross-account` | **`oam:CreateLink` + telemetry-service `Link` actions — expose observability data cross-account** | oam:CreateLink | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `cloudwatchdeletemetricstream--cloudwatchputmetricstream--cloudwatchputmetricdata` | **`cloudwatch:DeleteMetricStream` , `cloudwatch:PutMetricStream` , `cloudwatch:PutMetricData`** | cloudwatch:DeleteMetricStream, cloudwatch:PutMetricStream, cloudwatch:PutMetricData | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `observabilityadminupdatetelemetrypipeline--erase-or-rewrite-telemetry-before-storage` | **`observabilityadmin:UpdateTelemetryPipeline` — erase or rewrite telemetry before storage** | observabilityadmin:UpdateTelemetryPipeline | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-codebuild-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `codebuildupdateprojectvisibility--expose-a-private-projects-builds-to-the-internet` | `codebuild:UpdateProjectVisibility` — expose a private project's builds to the internet | codebuild:UpdateProjectVisibility | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-cognito-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cognito-idplistusers--cognito-idpadmingetuser--exfiltrate-the-user-directory` | `cognito-idp:ListUsers` \| `cognito-idp:AdminGetUser` — exfiltrate the user directory | cognito-idp:ListUsers, cognito-idp:AdminGetUser | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-config-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redirect-future-configuration-inventory-with-configputdeliverychannel` | Redirect future configuration inventory with `config:PutDeliveryChannel` | config:PutDeliveryChannel | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `force-a-fixed-custom-evaluator-with-configstartconfigrulesevaluation` | Force a fixed custom evaluator with `config:StartConfigRulesEvaluation` | config:StartConfigRulesEvaluation | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-databrew-stored-job-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `databrewstartjobrun--execute-a-stored-data-transfer` | `databrew:StartJobRun` — Execute a stored data transfer | databrew:StartJobRun | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-datasync-delegated-copy-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `expand-an-existing-locations-path-with-datasyncupdatelocations3` | Expand an existing location's path with `datasync:UpdateLocationS3` | datasync:UpdateLocationS3 | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `delegated-copy-with-datasyncstarttaskexecution` | Delegated copy with `datasync:StartTaskExecution` | datasync:StartTaskExecution | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-dlm-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `dlmcreatelifecyclepolicy-iampassrole--recurring-cross-account-ebs-snapshot-sharing` | `dlm:CreateLifecyclePolicy`, `iam:PassRole` — recurring cross-account EBS snapshot sharing | dlm:CreateLifecyclePolicy, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-dms-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `s3-target-redirection-with-dmsmodifyendpoint` | S3 target redirection with `dms:ModifyEndpoint` | dms:ModifyEndpoint | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `dmsstartreplicationtask--execute-a-fixed-migration-through-stored-endpoint-roles` | `dms:StartReplicationTask` — Execute a fixed migration through stored endpoint roles | dms:StartReplicationTask | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-drs-mgn-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `drsstartrecovery--drsupdatelaunchconfiguration--boot-a-copy-of-a-production-server` | `drs:StartRecovery` (+ `drs:UpdateLaunchConfiguration`) — boot a copy of a production server | drs:StartRecovery, drs:UpdateLaunchConfiguration | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-dynamodb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `dynamodbpartiqlselect` | `dynamodb:PartiQLSelect` | dynamodb:PartiQLSelect | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `dynamodbexporttabletopointintime-and-dynamodbupdatecontinuousbackups-if-pitr-is-disabled` | `dynamodb:ExportTableToPointInTime` (and `dynamodb:UpdateContinuousBackups` if PITR is disabled) | dynamodb:ExportTableToPointInTime, dynamodb:UpdateContinuousBackups | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `dynamodbrestoretablefrombackup-and-dynamodbcreatebackup-to-create-a-source-backup` | `dynamodb:RestoreTableFromBackup` (and `dynamodb:CreateBackup` to create a source backup) | dynamodb:RestoreTableFromBackup, dynamodb:CreateBackup | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `dynamodbenablekinesisstreamingdestination-continuous-exfiltration-via-kinesis-data-streams` | `dynamodb:EnableKinesisStreamingDestination` (Continuous exfiltration via Kinesis Data Streams) | dynamodb:EnableKinesisStreamingDestination | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `ssmmodifydocumentpermission--publish-an-ssm-document-to-the-world` | `ssm:ModifyDocumentPermission` — publish an SSM document to the world | ssm:ModifyDocumentPermission | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ec2-instance-connect-endpoint-backdoor.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `recover-instance-profile-credentials` | Recover instance profile credentials | ec2-instance-connect:SendSSHPublicKey | COVERED | `aws-ec2-instance-connect-sendsshpublickey` — Final step of the EC2 Instance Connect Endpoint path (SSH via SendSSHPublicKey + OpenTunnel, then IMDS credentials). |

### aws-post-exploitation/aws-ecs-data-access-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `ecsdescribetaskdefinition--read-container-environment-and-secret-references` | `ecs:DescribeTaskDefinition` — Read container environment and secret references | ecs:DescribeTaskDefinition | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-ecs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `steal-task-role-credentials-through-ecsexecutecommand` | Steal task-role credentials through `ecs:ExecuteCommand` | ecs:ExecuteCommand, ecs:DescribeTasks | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |

| `steal-the-container-instance-role-from-an-ecs-on-ec2-task` | Steal the container-instance role from an ECS-on-EC2 task |  | EXCLUDED | Previously mapped to `aws-v3-08-read-ec2-instance-profile-credentials-from-imds-inside`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `steal-co-located-task-credentials-after-compromising-the-container-instance` | Steal co-located task credentials after compromising the container instance |  | EXCLUDED | Previously mapped to `aws-v3-09-use-host-or-container-runtime-control-to-steal-credenti`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-efs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elasticfilesystemcreatereplicationconfiguration--replicate-into-a-prepared-cross-account-file-system` | `elasticfilesystem:CreateReplicationConfiguration` — replicate into a prepared cross-account file system | elasticfilesystem:CreateReplicationConfiguration | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-eks-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `eks-authassumeroleforpodidentity-with-a-stolen-pod-bound-token` | `eks-auth:AssumeRoleForPodIdentity` with a stolen Pod-bound token | eks-auth:AssumeRoleForPodIdentity | NOT PRIVESC | Requires an already stolen Pod Identity service-account token (prior workload compromise); the Kubernetes-to-cloud pivot belongs to the K8s cloud_pivot catalog. |

### aws-post-exploitation/aws-elastic-beanstalk-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elasticbeanstalkdeleteapplicationversion` | `elasticbeanstalk:DeleteApplicationVersion` | elasticbeanstalk:DeleteApplicationVersion | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `elasticbeanstalkterminateenvironment` | `elasticbeanstalk:TerminateEnvironment` | elasticbeanstalk:TerminateEnvironment | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `elasticbeanstalkdeleteapplication` | `elasticbeanstalk:DeleteApplication` | elasticbeanstalk:DeleteApplication | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-elasticache-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elasticachemodifyreplicationgroup--add-an-attacker-known-legacy-auth-token` | `elasticache:ModifyReplicationGroup` — add an attacker-known legacy AUTH token | elasticache:ModifyReplicationGroup | EXCLUDED | Previously mapped to `aws-v3-69-elasticache-legacy-auth-rotation`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-elb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elasticloadbalancingmodifyrule--redirect-matching-alb-traffic-to-an-existing-target` | `elasticloadbalancing:ModifyRule` — Redirect matching ALB traffic to an existing target | elasticloadbalancing:ModifyRule | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-elemental-inference-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elemental-inferenceexportdictionaryentries--steal-the-custom-vocabulary` | `elemental-inference:ExportDictionaryEntries` — steal the custom vocabulary | elemental-inference:ExportDictionaryEntries | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `elemental-inferenceupdatefeed--blindly-replace-output-configuration` | `elemental-inference:UpdateFeed` — blindly replace output configuration | elemental-inference:UpdateFeed | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-emr-serverless-configuration-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `emr-serverlessgetapplication--runtime-property-disclosure` | `emr-serverless:GetApplication` — runtime-property disclosure | emr-serverless:GetApplication | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-end-user-messaging-social-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `social-messagingsendwhatsappmessage---send-trusted-brand-whatsapp-messages` | `social-messaging:SendWhatsAppMessage` - Send trusted-brand WhatsApp messages | social-messaging:SendWhatsAppMessage | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-eventbridge-pipe-configuration-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `pipesdescribepipe--input-template-disclosure` | `pipes:DescribePipe` — input-template disclosure | pipes:DescribePipe | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-eventbridge-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `eventscreatesubscriber--replay-retained-enhanced-bus-events-to-a-new-target` | `events:CreateSubscriber` — replay retained enhanced-bus events to a new target | events:CreateSubscriber | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `eventsputtargets--silently-copy-an-event-stream-to-an-attacker-sink` | `events:PutTargets` — silently copy an event stream to an attacker sink | events:PutTargets | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `eventscreateconnection--eventscreateapidestination--exfiltrate-an-event-stream-straight-out-of-aws` | `events:CreateConnection` + `events:CreateApiDestination` — exfiltrate an event stream straight out of AWS | events:CreateConnection, events:CreateApiDestination | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `eventsupdatesubscriber--clear-filters-and-disable-delivery-logs` | `events:UpdateSubscriber` — clear filters and disable delivery logs | events:UpdateSubscriber | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `eventsupdatesubscriber--pause-and-discard-a-subscribers-retained-backlog` | `events:UpdateSubscriber` — pause and discard a subscriber's retained backlog | events:UpdateSubscriber | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `eventsupdateeventbus--truncate-enhanced-bus-retained-history` | `events:UpdateEventBus` — truncate enhanced-bus retained history | events:UpdateEventBus | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `eventsupdateconnection--eventsdeauthorizeconnection--break-or-rewrite-stored-api-credentials` | `events:UpdateConnection` / `events:DeauthorizeConnection` — break or rewrite stored API credentials | events:UpdateConnection, events:DeauthorizeConnection | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-eventbridge-scheduler-post-exploitation.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `schedulerdeleteschedule--destroy-scheduled-automation` | `scheduler:DeleteSchedule` — destroy scheduled automation | scheduler:DeleteSchedule | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `schedulerupdateschedule--iampassrole--disable-or-redirect-execution` | `scheduler:UpdateSchedule` + `iam:PassRole` — disable or redirect execution | iam:PassRole, scheduler:CreateSchedule, scheduler:UpdateSchedule | COVERED | `aws-scheduler-passrole-createschedule-or-updateschedule` — UpdateSchedule with a passed role trusting scheduler.amazonaws.com. |

### aws-post-exploitation/aws-inspector-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `inspector2createfindingsreport-inspector2createsbomexport` | `inspector2:CreateFindingsReport`, `inspector2:CreateSbomExport` | inspector2:CreateFindingsReport, inspector2:CreateSbomExport | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

| `inspector2disabledelegatedadminaccount-inspector2enabledelegatedadminaccount--organizationslistdelegatedadministrators--organizationsenableawsserviceaccess--iamcreateservicelinkedrole` | `inspector2:DisableDelegatedAdminAccount`, (`inspector2:EnableDelegatedAdminAccount` & `organizations:ListDelegatedAdministrators` & `organizations:EnableAWSServiceAccess` & `iam:CreateServiceLinkedRole`) | inspector2:EnableDelegatedAdminAccount | EXCLUDED | Previously mapped to `aws-v3-70-inspector-delegated-administrator`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-iot-core-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iotcreatetopicrule--iampassrole--durable-fleet-wide-mqtt-exfiltration` | `iot:CreateTopicRule` + `iam:PassRole` — durable fleet-wide MQTT exfiltration | iot:CreateTopicRule, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

| `cross-service-pivot-publish-into-an-existing-iot-rule-and-lambda` | Cross-service pivot: publish into an existing IoT rule and Lambda | iot:Publish | EXCLUDED | Previously mapped to `aws-v3-13-publish-to-an-iot-rule-whose-lambda-action-misuses-atta`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-kendra-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `kendracreatedatasource--updatedatasource--iampassrole--poison-or-repoint-ingestion` | `kendra:CreateDataSource` / `UpdateDataSource` (+ `iam:PassRole`) — poison or repoint ingestion | kendra:CreateDataSource, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `kendraputprincipalmapping--alter-group-resolution-for-acl-filtered-queries` | `kendra:PutPrincipalMapping` — alter group resolution for ACL-filtered queries | kendra:PutPrincipalMapping | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-lakeformation-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `lakeformationupdatelftagexpression--widen-existing-lf-tbac-grants` | `lakeformation:UpdateLFTagExpression` — widen existing LF-TBAC grants | lakeformation:UpdateLFTagExpression | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-lambda-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `lambdacreatemicrovmauthtoken--reach-lambda-microvm-application-ports` | `lambda:CreateMicrovmAuthToken` — reach Lambda MicroVM application ports | lambda:CreateMicrovmAuthToken | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `lambdaupdatenetworkconnector--change-lambda-microvm-private-network-egress` | `lambda:UpdateNetworkConnector` — change Lambda MicroVM private-network egress | lambda:UpdateNetworkConnector | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

| `lambda-durable-callback-result-injection` | Lambda durable callback result injection | lambda:SendDurableExecutionCallbackSuccess | EXCLUDED | Previously mapped to `aws-v3-30-inject-a-lambda-durable-callback-result-that-triggers-a`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

| `exfiltrate-lambda-credentials` | Exfiltrate Lambda Credentials |  | EXCLUDED | Previously mapped to `aws-v3-10-read-lambda-execution-role-credentials-from-runtime-env`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-lambda-post-exploitation/aws-lambda-event-source-mapping-hijack.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `lambdacreateeventsourcemapping--attach-a-source-to-an-existing-privileged-function` | `lambda:CreateEventSourceMapping` — attach a source to an existing privileged function | lambda:CreateEventSourceMapping | NOT PRIVESC | Feeds records to an unchanged function with fixed code and role; no caller-controlled code runs as the role (input injection depends on an application flaw). |

### aws-post-exploitation/aws-macie-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `macie2getsensitivedataoccurrences--updaterevealconfiguration--retrieve-the-actual-sensitive-values` | `macie2:GetSensitiveDataOccurrences` (+ `UpdateRevealConfiguration`) — retrieve the actual sensitive values | macie2:GetSensitiveDataOccurrences | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `macie2putclassificationexportconfiguration--redirect-the-sensitive-data-discovery-map-to-an-attacker-bucket` | `macie2:PutClassificationExportConfiguration` — redirect the sensitive-data discovery map to an attacker bucket | macie2:PutClassificationExportConfiguration | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-mainframe-modernization-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `m2getsignedbluinsightsurl---obtain-a-blu-insights-portal-session` | `m2:GetSignedBluinsightsUrl` - Obtain a Blu Insights portal session | m2:GetSignedBluinsightsUrl | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-marketplace-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-marketplaceputdeploymentparameter--poison-buyer-quick-launch-secrets` | `aws-marketplace:PutDeploymentParameter` — Poison buyer Quick Launch secrets | aws-marketplace:PutDeploymentParameter | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |
| `aws-marketplacebatchmeterusage--inflate-or-duplicate-saas-customer-usage` | `aws-marketplace:BatchMeterUsage` — inflate or duplicate SaaS customer usage | aws-marketplace:BatchMeterUsage | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |
| `aws-marketplacemeterusage--poison-a-buyer-workloads-hourly-usage-record` | `aws-marketplace:MeterUsage` — poison a buyer workload's hourly usage record | aws-marketplace:MeterUsage | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-mwaa-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-mwaa-execution-role-account-wildcard-vulnerability` | AWS MWAA Execution Role Account Wildcard Vulnerability |  | STRUCTURAL | Page title / references list |
| `mwaa-serverless-workflow-creation-as-a-passed-execution-role` | MWAA Serverless workflow creation as a passed execution role |  | STRUCTURAL | Section heading of the MWAA Serverless technique below. |
| `airflow-serverlesscreateworkflow--iampassrole--run-attacker-code-as-the-execution-role` | `airflow-serverless:CreateWorkflow` + `iam:PassRole` → run attacker code as the execution role | iam:PassRole, airflow-serverless:CreateWorkflow, airflow-serverless:StartWorkflowRun, iam:CreateServiceLinkedRole | COVERED | `aws-mwaa-serverless-passrole-createworkflow` |
| `classic-mwaa-airflowcreateweblogintoken--airflowcreateclitoken--code-execution-as-the-environment-execution-role` | Classic MWAA: `airflow:CreateWebLoginToken` / `airflow:CreateCliToken` → code execution as the environment execution role | airflow:CreateCliToken, airflow:CreateWebLoginToken | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `repoint-the-execution-role-airflowupdateenvironment--iampassrole` | Repoint the execution role: `airflow:UpdateEnvironment` + `iam:PassRole` | iam:PassRole, airflow:UpdateEnvironment | COVERED | `aws-mwaa-passrole-updateenvironment` |

### aws-post-exploitation/aws-network-security-manager-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `network-security-managerupdaterule--weaken-centrally-deployed-waf-protections` | `network-security-manager:UpdateRule` — weaken centrally deployed WAF protections | network-security-manager:UpdateRule | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-odb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `odbcreateautonomousdatabasewallet--export-fresh-database-client-material` | `odb:CreateAutonomousDatabaseWallet` — export fresh database client material | odb:CreateAutonomousDatabaseWallet | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-q-in-connect-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `wisdomlistmessages--wisdomlistspans--read-conversations-and-ai-agent-traces` | `wisdom:ListMessages` / `wisdom:ListSpans` — Read conversations and AI-agent traces | wisdom:ListMessages, wisdom:ListSpans | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-rds-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `harvest-db-credentials-via-rds-proxy-auth-secrets-rdsdescribedbproxies--secretsmanagergetsecretvalue` | Harvest DB credentials via RDS Proxy auth secrets (`rds:DescribeDBProxies` + `secretsmanager:GetSecretValue`) | rds:DescribeDBProxies, secretsmanager:GetSecretValue | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained.<br>`aws-pa-s03-4-rds-proxy-auth-secret` — conditional verified exact-target authority. |
| `rdsdownloaddblogfileportion` | `rds:DownloadDBLogFilePortion` | rds:DownloadDBLogFilePortion | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `rdsstartexporttask-iampassrole--export-a-snapshots-full-contents-to-attacker-s3` | `rds:StartExportTask`, `iam:PassRole` — export a snapshot's full contents to attacker S3 | rds:StartExportTask, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `rdsstartexporttask-iampassrole-kms-key-use-permissions` | `rds:StartExportTask`, `iam:PassRole`, KMS key-use permissions | rds:StartExportTask, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-resource-explorer-inventory-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `resource-explorer-2getview--search--cross-service-metadata-oracle` | `resource-explorer-2:GetView` + `Search` — cross-service metadata oracle | resource-explorer-2:GetView | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-resource-tag-inventory-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `taggetresources--cross-service-arn-and-tag-value-disclosure` | `tag:GetResources` — cross-service ARN and tag-value disclosure | tag:GetResources | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-route53-arc-routing-control-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `route53-recovery-clusterupdateroutingcontrolstates--reroute-traffic-and-override-safety-rules` | `route53-recovery-cluster:UpdateRoutingControlState(s)` — reroute traffic and override safety rules | route53-recovery-cluster:UpdateRoutingControlState | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-rtb-fabric-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `rtbfabricupdaterespondergateway--replace-a-managed-responder-backend` | `rtbfabric:UpdateResponderGateway` — replace a managed responder backend | rtbfabric:UpdateResponderGateway | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `rtbfabricupdatelinkmoduleflow--suppress-filter-or-alter-bid-traffic` | `rtbfabric:UpdateLinkModuleFlow` — suppress, filter or alter bid traffic | rtbfabric:UpdateLinkModuleFlow | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-s3-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `s3putreplicationconfiguration--continuous-exfiltration-via-bucket-replication` | `s3:PutReplicationConfiguration` — continuous exfiltration via bucket replication | s3:PutReplicationConfiguration | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `s3putbucketnotification--wire-future-objects-into-a-pre-authorized-lambda` | `s3:PutBucketNotification` — wire future objects into a pre-authorized Lambda | s3:PutBucketNotification | NOT PRIVESC | Routes objects to a pre-authorized Lambda with fixed code and role; no caller-controlled code runs as the role. |

### aws-post-exploitation/aws-sagemaker-configuration-access-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `sagemakerdescribemodel--inference-environment-secret-disclosure` | `sagemaker:DescribeModel` — inference-environment secret disclosure | sagemaker:DescribeModel | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `sagemakerdescribetrainingjob--read-training-configuration-and-environment-values` | `sagemaker:DescribeTrainingJob` — Read training configuration and environment values | sagemaker:DescribeTrainingJob | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-security-agent-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `securityagentstartcoderemediation--trigger-trusted-remediation-pull-requests` | `securityagent:StartCodeRemediation` — trigger trusted remediation pull requests | securityagent:StartCodeRemediation | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-security-lake-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `securitylakecreatesubscriber--updatesubscriber--external-cross-account-access` | `securitylake:CreateSubscriber` / `UpdateSubscriber` — external cross-account access | securitylake:CreateSubscriber | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-service-catalog-appregistry-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `poison-shared-application-metadata--servicecatalogupdateattributegroup` | Poison shared application metadata — `servicecatalog:UpdateAttributeGroup` | servicecatalog:UpdateAttributeGroup | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-ses-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `sesputidentitypolicy--sesv2putemailidentitypolicy--cross-account-sending-authorization-backdoor` | `ses:PutIdentityPolicy` / `sesv2:PutEmailIdentityPolicy` — cross-account sending-authorization backdoor | ses:PutIdentityPolicy, sesv2:PutEmailIdentityPolicy | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |

### aws-post-exploitation/aws-snowball-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `snowballgetjobmanifest--getjobunlockcode--recover-the-two-device-unlock-credentials` | `snowball:GetJobManifest` + `GetJobUnlockCode` — recover the two device-unlock credentials | snowball:GetJobManifest | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `snowballupdatelongtermpricing--re-enable-a-prepaid-contract-renewal` | `snowball:UpdateLongTermPricing` — re-enable a prepaid contract renewal | snowball:UpdateLongTermPricing | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-sns-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `snssetsmsattributes--account-wide-sms-tampering` | `sns:SetSMSAttributes` — account-wide SMS tampering | sns:SetSMSAttributes | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |
| `snssettopicattributes--alter-delivery-and-encryption-settings` | `sns:SetTopicAttributes` — alter delivery and encryption settings | sns:SetTopicAttributes | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-sqs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `sqssetqueueattributes--alter-delivery-and-encryption-settings` | `sqs:SetQueueAttributes` — alter delivery and encryption settings | sqs:SetQueueAttributes | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-stepfunctions-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `statesdescribestatemachine--definition-secret-disclosure` | `states:DescribeStateMachine` — definition-secret disclosure | states:DescribeStateMachine | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |
| `statesstartexecution---input-injection-into-dangerous-sinks` | `states:StartExecution` -> Input Injection Into Dangerous Sinks | states:StartExecution | EXCLUDED | Previously mapped to `aws-v3-28-reach-a-lambda-execution-role-through-unsafe-workflow-i`, `aws-v3-29-redirect-a-credentialed-step-functions-http-task-to-cap`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `statessendtasksuccess--inject-callback-output-into-a-privileged-next-state` | `states:SendTaskSuccess` — inject callback output into a privileged next state | states:SendTaskSuccess | EXCLUDED | Previously mapped to `aws-stepfunctions-activity-callback-output-injection`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-storage-gateway-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `storagegatewaycreatenfsfileshare--createsmbfileshare--iampassrole--expose-an-s3-bucket-through-a-file-share-and-mount-it` | `storagegateway:CreateNFSFileShare` / `CreateSMBFileShare` (+ `iam:PassRole`) — expose an S3 bucket through a file share and mount it | storagegateway:CreateNFSFileShare, iam:PassRole | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

### aws-post-exploitation/aws-sts-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `stsgetfederationtoken` | **`sts:GetFederationToken`** | sts:GetFederationToken | NOT PRIVESC | GetFederationToken credentials cannot exceed the calling IAM user permissions. |

### aws-post-exploitation/aws-transfer-family-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `transfertestidentityprovider--query-a-custom-idp-with-a-chosen-password-and-source-ip` | `transfer:TestIdentityProvider` — query a custom IdP with a chosen password and source IP | transfer:TestIdentityProvider | NOT PRIVESC | App-plane only: grants access inside a service application or data plane (not an IAM principal). |
| `transferupdateserver--disable-both-transfer-server-logging-paths` | `transfer:UpdateServer` — disable both Transfer server logging paths | transfer:UpdateServer | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-uxc-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `uxcupdateaccountcustomizations--hide-services-and-regions-from-console-navigation` | `uxc:UpdateAccountCustomizations` — hide services and Regions from console navigation | uxc:UpdateAccountCustomizations | NOT PRIVESC | Not a privesc: integrity, availability, logging or monitoring tampering; no principal's privileges are obtained. |

### aws-post-exploitation/aws-vpn-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `ec2modifyvpnconnection--ec2modifyvpntunneloptions--take-over-an-existing-site-to-site-vpn-peer` | `ec2:ModifyVpnConnection` + `ec2:ModifyVpnTunnelOptions` — take over an existing Site-to-Site VPN peer | ec2:ModifyVpnConnection, ec2:ModifyVpnTunnelOptions | NOT PRIVESC | Not a privesc: network-path or traffic manipulation; no IAM principal's privileges are obtained.<br>`aws-s05-ec2modifyvpnconnection-ec2modifyvpntunneloptions-take-over-an-existing` — conditional verified exact-target authority. |
| `ec2authorizeclientvpningress--broaden-an-authenticated-vpn-clients-network-access` | `ec2:AuthorizeClientVpnIngress` — broaden an authenticated VPN client's network access | ec2:AuthorizeClientVpnIngress | NOT PRIVESC | Not a privesc: network-path or traffic manipulation; no IAM principal's privileges are obtained.<br>`aws-s05-ec2authorizeclientvpningress-broaden-an-authenticated-vpn-clients-netw` — conditional verified exact-target authority. |
| `ec2associateclientvpntargetnetwork--ec2createclientvpnroute--attach-client-vpn-to-a-vpc-and-extend-reachable-networks` | `ec2:AssociateClientVpnTargetNetwork` + `ec2:CreateClientVpnRoute` — attach Client VPN to a VPC and extend reachable networks | ec2:AssociateClientVpnTargetNetwork, ec2:CreateClientVpnRoute | NOT PRIVESC | Not a privesc: network-path or traffic manipulation; no IAM principal's privileges are obtained.<br>`aws-s05-ec2associateclientvpntargetnetwork-ec2createclientvpnroute-attach-clie` — conditional verified exact-target authority. |
| `ec2applysecuritygroupstoclientvpntargetnetwork--rebind-client-vpn-to-a-trusted-security-group` | `ec2:ApplySecurityGroupsToClientVpnTargetNetwork` — rebind Client VPN to a trusted security group | ec2:ApplySecurityGroupsToClientVpnTargetNetwork | NOT PRIVESC | Not a privesc: network-path or traffic manipulation; no IAM principal's privileges are obtained.<br>`aws-s05-ec2applysecuritygroupstoclientvpntargetnetwork-rebind-client-vpn-to-a` — conditional verified exact-target authority. |
| `ec2modifyclientvpnendpoint--hijack-client-dnsrouting-and-suppress-connection-logs` | `ec2:ModifyClientVpnEndpoint` — hijack client DNS/routing and suppress connection logs | ec2:ModifyClientVpnEndpoint | NOT PRIVESC | Not a privesc: network-path or traffic manipulation; no IAM principal's privileges are obtained.<br>`aws-s05-ec2modifyclientvpnendpoint-hijack-client-dnsrouting-and-suppress-conne` — conditional verified exact-target authority. |

### aws-post-exploitation/aws-workmail-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `workmailmessageflowgetrawmessagecontent--putrawmessagecontent--steal-or-rewrite-in-transit-email` | `workmailmessageflow:GetRawMessageContent` / `PutRawMessageContent` — steal or rewrite in-transit email | workmailmessageflow:GetRawMessageContent | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained.<br>`aws-s05-workmailmessageflowgetrawmessagecontent-putrawmessagecontent-steal-or` — conditional verified exact-target authority. |

| `sending-paths--telemetry-gaps` | Sending paths & telemetry gaps | workmail:ResetPassword | EXCLUDED | Previously mapped to `aws-v3-71-workmail-resetpassword`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-privilege-escalation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---privilege-escalation` | AWS - Privilege Escalation |  | STRUCTURAL | Page title of the AWS privilege-escalation index. |
| `iam` | IAM |  | STRUCTURAL | Link to the IAM enumeration page. |
| `aws-privilege-escalation` | AWS Privilege Escalation |  | STRUCTURAL | General introduction (chaining escalations, the NotAction caution); techniques are on the per-service pages. |
| `mindmap` | Mindmap |  | STRUCTURAL | Embedded services mindmap PDF. |
| `tools` | Tools |  | STRUCTURAL | Links to external tools (aws_escalate.py, Pacu). |
| `references` | References |  | STRUCTURAL | References list. |

### aws-privilege-escalation/aws-account-management-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---account-management-privesc` | AWS - Account Management Privesc |  | STRUCTURAL | Page title / references list |
| `account-management` | Account Management |  | EXCLUDED | Service introduction and enumeration link; techniques are mapped under their own headings. |
| `accountputcontactinformation--startprimaryemailupdate--account-recovery-and-root-email-takeover` | `account:PutContactInformation` / `StartPrimaryEmailUpdate` — account-recovery and root-email takeover | account:StartPrimaryEmailUpdate, account:AcceptPrimaryEmailUpdate, iam:UpdateAccountEmailAddress | EXCLUDED | Previously mapped to `aws-account-startprimaryemailupdate-member-root`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-amplify-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---amplify-hosting-privesc` | AWS - Amplify Hosting Privesc |  | STRUCTURAL | Page title / references list |
| `amplify` | Amplify |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `amplifygetapp-amplifybackendcreatetoken--mint-an-amplify-studio-login` | `amplify:GetApp`, `amplifybackend:CreateToken` — Mint an Amplify Studio login | amplify:GetApp, amplifybackend:CreateToken | COVERED | `aws-amplifybackend-createtoken-studio-admin` — application-plane administrator (`aws_service_plane_admin`) over collected `amplify_app` Gen 1 backends; the amplifybackend requirement is on the token resource `{target.amplifybackend_token_arn}` (`/backend/<AppId>/challenge/*`); unresolved per-account placeholder where apps/backends are not collected. |
| `amplifygetapp-amplifybackendgettoken--recover-a-live-studio-login` | `amplify:GetApp`, `amplifybackend:GetToken` — Recover a live Studio login | amplify:GetApp, amplifybackend:GetToken | EXCLUDED | Excluded: GetToken requires an existing live Studio session id known to the source; no collected exact token/session or credential usability is joined to the app. — application-plane administrator (`aws_service_plane_admin`) over collected `amplify_app` Gen 1 backends; the amplifybackend requirement is on the token resource `{target.amplifybackend_token_arn}` (`/backend/<AppId>/challenge/*`); unresolved per-account placeholder where apps/backends are not collected. |
| `amplifygetapp-amplifygetbranch-amplifylistapps-amplifylistbranches-amplifygetjob--read-deployment-variables-and-build-logs` | `amplify:GetApp`, `amplify:GetBranch`, `amplify:ListApps`, `amplify:ListBranches`, `amplify:GetJob` — Read deployment variables and build lo | amplify:GetApp, amplify:GetBranch, amplify:ListApps, amplify:ListBranches, amplify:GetJob | EXCLUDED | Pure data read (secrets exposure); Least Privilege / Exposure.<br>`aws-amplify-config-credential` — conditional verified exact-target authority. |
| `amplifygetartifacturl--download-end-to-end-test-artifacts` | `amplify:GetArtifactUrl` — Download end-to-end test artifacts | amplify:GetArtifactUrl | STRUCTURAL | Historical pointer to the relocated bounded operation in AWS post exploitation. |
| `amplifyupdateapp-amplifystartjob` | `amplify:UpdateApp`, `amplify:StartJob` | amplify:UpdateApp, amplify:StartJob | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `amplifyupdatebranch-amplifystartjob--branch-scoped-build-code-execution` | `amplify:UpdateBranch`, `amplify:StartJob` — Branch-scoped build code execution | amplify:UpdateBranch, amplify:StartJob | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `amplifyupdateapp--iampassrole--repoint-the-app-onto-a-more-privileged-role` | `amplify:UpdateApp` + `iam:PassRole` — repoint the app onto a more-privileged role | iam:PassRole, amplify:UpdateApp, amplify:StartJob | COVERED | `aws-amplify-updateapp-passrole`; `aws-amplify-updateapp-passrole-ssr` (SSR compute-role variant) |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-apigateway-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---apigateway-privesc` | AWS - Apigateway Privesc |  | STRUCTURAL | Page title / references list |
| `api-gateway` | API Gateway |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `apigateway` | Apigateway |  | STRUCTURAL | Section heading explaining the HTTP-verb IAM action names; techniques are rows of their own. |
| `apigatewaypost` | `apigateway:POST` | apigateway:POST | EXCLUDED | Creates API keys for API access; application-level, no IAM identity. |
| `apigatewayget` | `apigateway:GET` | apigateway:GET | STRUCTURAL | Historical pointer to bounded data access in AWS post exploitation. |
| `apigatewayupdaterestapipolicy--apigatewaypatch` | `apigateway:UpdateRestApiPolicy` / `apigateway:PATCH` | apigateway:UpdateRestApiPolicy, apigateway:PATCH | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `apigatewayput-apigatewaypost-and-sometimes-iampassrole` | `apigateway:PUT`, `apigateway:POST` (and sometimes `iam:PassRole`) | apigateway:PUT, apigateway:POST, iam:PassRole | EXCLUDED | The demonstrated integration invokes a Lambda function, but does not give the caller the integration role or the function execution role; an exact privileged backend action is not joined. See `_excluded_apigateway_generic_integration.yaml`. |
| `apigatewaypatch-apigatewaypost` | `apigateway:PATCH`, `apigateway:POST` | apigateway:PATCH, apigateway:POST | EXCLUDED | Bypasses API authorization of backend apps; application-level, no IAM identity gained. |
| `http-apis--apigatewayv2-variant` | HTTP APIs / `apigatewayv2` variant |  | EXCLUDED | Same application-level authorizer/route manipulation as REST variant. |
| `apigatewaypatch-on-a-rest-vpc-link-does-not-permit-nlb-redirection` | `apigateway:PATCH` on a REST VPC link does not permit NLB redirection | apigateway:PATCH | EXCLUDED | HackTricks itself documents this as not exploitable. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-appconfig-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---appconfig-privesc` | AWS - Appconfig Privesc |  | STRUCTURAL | Page title / references list |
| `appconfig` | AppConfig |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `privilege-escalation-use-a-passed-retrieval-role-to-read-another-service` | Privilege escalation: use a passed retrieval role to read another service |  | STRUCTURAL | Parent heading of the CreateConfigurationProfile + PassRole subsection, excluded as a bounded delegated read. |
| `appconfigcreateconfigurationprofile--iampassrole--deploymentread-permissions` | `appconfig:CreateConfigurationProfile` + `iam:PassRole` + deployment/read permissions | appconfig:CreateConfigurationProfile, iam:PassRole | EXCLUDED | Previously mapped to `aws-appconfig-passrole-createconfigurationprofile`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-appflow-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---appflow-privilege-escalation` | AWS - AppFlow Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `appflow` | AppFlow |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `createflowupdateflow--iampassrole-to-aws-glue-catalog-authority` | `CreateFlow`/`UpdateFlow` + `iam:PassRole` to AWS Glue catalog authority | iam:PassRole | EXCLUDED | Previously mapped to `aws-appflow-passrole-glue-catalog`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `redshift-and-custom-connector-boundaries` | Redshift and custom-connector boundaries |  | EXCLUDED | Hardening guidance: Redshift connector roles are used only for the connector's data operations and custom connectors invoke a Lambda through its resource policy without a passed role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-apprunner-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---apprunner-privesc` | AWS - AppRunner Privesc |  | STRUCTURAL | Page title / references list |
| `app-runner` | App Runner |  | EXCLUDED | Service introduction and enumeration link; techniques are mapped under their own headings. |
| `apprunner` | AppRunner |  | STRUCTURAL | Section heading grouping the App Runner techniques mapped below. |
| `apprunnerdescribeservice--read-plaintext-runtime-variables` | `apprunner:DescribeService` — read plaintext runtime variables | apprunner:DescribeService | COVERED | Pure data read (plaintext env vars). Historical EXCLUDED data read remains so without an exact usable IAM-user key; reviewed conditional credential variant `aws-apprunner-plaintext-credential`. |
| `iampassrole-apprunnercreateservice` | `iam:PassRole`, `apprunner:CreateService` | iam:PassRole, apprunner:CreateService | COVERED | `aws-apprunner-passrole-createservice` |
| `mutable-private-ecr-tag-with-automatic-deployments` | Mutable private-ECR tag with automatic deployments | ecr:PutImage, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:BatchGetImage | EXCLUDED | Excluded: The ecr:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. — Covered by aws-ecr-push-consumed-tag (refresh boundary recorded there). |
| `apprunnerupdateservice` | `apprunner:UpdateService` | apprunner:UpdateService | COVERED | `aws-apprunner-updateservice-passrole` remains active; the existing-role variant is excluded because its resource-to-role attachment is not collected. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-appstream-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---appstream-20-privesc` | AWS - AppStream 2.0 Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-appstream-20` | Amazon AppStream 2.0 |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `appstream-20` | AppStream 2.0 |  | STRUCTURAL | Service introduction (machine-role model); techniques are mapped under their own headings. |
| `appstreamcreatestreamingurl--enter-an-existing-fleet-under-its-machine-role` | `appstream:CreateStreamingURL` — enter an existing fleet under its machine role | appstream:CreateStreamingURL | COVERED | `aws-appstream-createstreamingurl-existing-fleet` |
| `appstreamupdatestack--streaming-url--agentaccess-mcp--headless-desktop-control` | `appstream:UpdateStack` + streaming URL + `agentaccess-mcp` — headless desktop control | appstream:UpdateStack | EXCLUDED | Variant of the streaming-session entries (aws-appstream-createstreamingurl-existing-fleet): enabling headless agent access on a stack still yields the fleet role through a session. |
| `appstreamcreateentitlement--updateentitlement--grant-a-saml-identity-every-stack-application` | `appstream:CreateEntitlement` / `UpdateEntitlement` — grant a SAML identity every stack application | appstream:CreateEntitlement | EXCLUDED | Grants SAML users application entitlements on a stack; the fleet role reach is the same as the streaming-session entries and requires a federated user session, not an AWS principal escalation by itself. |
| `appstreamcreateimagebuilderstreamingurl--administratorroot-access-to-an-existing-builder` | `appstream:CreateImageBuilderStreamingURL` — administrator/root access to an existing builder | appstream:CreateImageBuilderStreamingURL | EXCLUDED | Excluded: The appstream_image_builder resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `appstreamcreateappblockbuilderstreamingurl--take-over-an-existing-app-package-builder` | `appstream:CreateAppBlockBuilderStreamingURL` — take over an existing app-package builder | appstream:CreateAppBlockBuilderStreamingURL | EXCLUDED | Excluded: The appstream_app_block_builder resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `appstreamupdateapplication--poison-an-elastic-fleet-application-launch` | `appstream:UpdateApplication` — poison an Elastic-fleet application launch | appstream:UpdateApplication | EXCLUDED | Excluded: The appstream:UpdateApplication source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `appstreamupdatefleet--replace-an-existing-fleet-image-while-retaining-its-role` | `appstream:UpdateFleet` — replace an existing fleet image while retaining its role | appstream:UpdateFleet | EXCLUDED | Excluded: The appstream_fleet resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `appstreamcreateimagebuilder--createfleet--iampassrole--session-with-the-passed-roles-credentials` | `appstream:CreateImageBuilder` / `CreateFleet` + `iam:PassRole` → session with the passed role's credentials | iam:PassRole, appstream:CreateImageBuilder, appstream:CreateImageBuilderStreamingURL, appstream:CreateFleet, appstream:CreateStack, appstream:AssociateFleet, appstream:CreateStreamingURL | COVERED | `aws-appstream-passrole-createimagebuilder-createfleet`, `aws-appstream-passrole-createimagebuilder`, `aws-appstream-passrole-createappblockbuilder`, `aws-appstream-passrole-updatefleet`, `aws-appstream-passrole-updateappblockbuilder` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-appsync-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---appsync-privesc` | AWS - AppSync Privesc |  | STRUCTURAL | Page title / references list |
| `appsync` | AppSync |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `appsynccreatedatasource-iampassrole--drive-an-arbitrary-role-through-a-graphql-field` | `appsync:CreateDataSource`, `iam:PassRole` — drive an arbitrary role through a GraphQL field | iam:PassRole, appsync:CreateDataSource, appsync:CreateResolver, appsync:UpdateResolver, appsync:UpdateDataSource | EXCLUDED | Excluded: Create/UpdateDataSource and resolver changes do not prove the source can call a field under the API authorization mode; callable API/field control is only prose. |
| `appsyncupdategraphqlapi--appsynccreateapikey` | `appsync:UpdateGraphqlApi` + `appsync:CreateApiKey` | appsync:UpdateGraphqlApi, appsync:CreateApiKey | EXCLUDED | Switches the API's primary auth to API_KEY: application-level data access through existing resolvers, not an AWS principal escalation. |
| `appsyncupdatedatasource--appsyncupdateresolver--iampassrole` | `appsync:UpdateDataSource` + `appsync:UpdateResolver` + `iam:PassRole` | appsync:UpdateDataSource, appsync:UpdateResolver, iam:PassRole | EXCLUDED | Duplicate primitive; covered by aws-appsync-passrole-datasource-sigv4 (third any_of group, existing data source). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-athena-spark-role-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---athena-spark-execution-role-privesc` | AWS - Athena Spark execution role Privesc |  | STRUCTURAL | Page title / references list |
| `athena` | Athena |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `athenacreateworkgroup--athenastartsession--run-spark-code-as-an-arbitrary-passed-execution-role` | `athena:CreateWorkGroup` + `athena:StartSession` — run Spark code as an arbitrary passed execution role | iam:PassRole, athena:CreateWorkGroup, athena:StartSession, athena:StartCalculationExecution | COVERED | `aws-athena-passrole-createworkgroup-spark` |
| `athenastartcalculationexecution--execute-code-in-an-existing-spark-session` | `athena:StartCalculationExecution` — Execute code in an existing Spark session | athena:StartCalculationExecution | EXCLUDED | Excluded: The athena_workgroup resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `athenagetsessionendpoint--take-over-an-active-spark-connect-session` | `athena:GetSessionEndpoint` — Take over an active Spark Connect session | athena:GetSessionEndpoint | EXCLUDED | Excluded: The athena_workgroup resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `athenacreatepresignednotebookurl--take-over-a-running-spark-notebook` | `athena:CreatePresignedNotebookUrl` — Take over a running Spark notebook | athena:CreatePresignedNotebookUrl | EXCLUDED | Excluded: The athena_workgroup resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-athena-stored-query-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---athena-stored-query-privesc` | AWS - Athena stored query Privesc |  | STRUCTURAL | Page title / references list |
| `athena` | Athena |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `athenaupdatepreparedstatement--poison-a-query-executed-by-another-principal` | `athena:UpdatePreparedStatement` — Poison a query executed by another principal | athena:UpdatePreparedStatement | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `athenaupdatenamedquery--poison-saved-sql-consumed-by-another-principal` | `athena:UpdateNamedQuery` — Poison saved SQL consumed by another principal | athena:UpdateNamedQuery | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `athenaupdatenotebook--poison-a-spark-notebook-executed-later` | `athena:UpdateNotebook` — Poison a Spark notebook executed later | athena:UpdateNotebook | EXCLUDED | Excluded: The athena_workgroup resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-aurora-dsql-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---aurora-dsql-privesc` | AWS - Aurora DSQL Privesc |  | STRUCTURAL | Page title / references list |
| `aurora-dsql` | Aurora DSQL |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `dsqldbconnectadmin--database-administrator-access` | `dsql:DbConnectAdmin` — database administrator access | dsql:DbConnectAdmin | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `dsqlputclusterpolicy--self-grant-database-administrator-access` | `dsql:PutClusterPolicy` — self-grant database administrator access | dsql:PutClusterPolicy | EXCLUDED | Self-grant of database-plane administrator access through the cluster resource policy; no IAM principal is obtained. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-batch-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---batch-privesc` | AWS - Batch Privesc |  | STRUCTURAL | Page title / references list |
| `batch` | Batch |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `batchregisterjobdefinition-iampassrole--batchsubmitjob--run-a-container-as-a-passed-role` | `batch:RegisterJobDefinition`, `iam:PassRole` (+ `batch:SubmitJob`) — run a container as a passed role | iam:PassRole, batch:RegisterJobDefinition, batch:SubmitJob | COVERED | `aws-batch-registerjobdefinition-passrole-submitjob` |
| `batchsubmitjob` | `batch:SubmitJob` | batch:SubmitJob | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `mutable-ecr-tag-poisoning-of-an-existing-job-definition` | Mutable ECR tag poisoning of an existing job definition | ecr:PutImage, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:BatchGetImage | EXCLUDED | Excluded: The ecr:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. — Covered by aws-ecr-push-consumed-tag. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-bedrock-agentcore-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---bedrock-agentcore-privesc` | AWS - Bedrock AgentCore Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-bedrock-agentcore` | Amazon Bedrock AgentCore |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `bedrock-agentcore` | Bedrock AgentCore |  | STRUCTURAL | Service overview of AgentCore primitives; each technique is its own heading. |
| `enumeration` | Enumeration |  | STRUCTURAL | Enumeration commands only. |
| `bedrock-agentcorecreateharness-iampassrole-invokeagentruntimecommand--root-shell-as-a-role` | `bedrock-agentcore:CreateHarness`, `iam:PassRole`, `InvokeAgentRuntimeCommand` — root shell as a role | iam:PassRole, bedrock-agentcore:CreateHarness, bedrock-agentcore:CreateAgentRuntime, bedrock-agentcore:CreateAgentRuntimeEndpoint, bedrock-agentcore:InvokeAgentRuntimeCommand, bedrock-agentcore:InvokeAgentRuntime | COVERED | `aws-bedrock-agentcore-createharness-passrole` remains active; the existing-role variant is excluded because its resource-to-role attachment is not collected. |
| `bedrock-agentcorecreateagentruntime--createagentruntimeendpoint-iampassrole--run-an-attacker-container-as-a-role` | `bedrock-agentcore:CreateAgentRuntime` (+ `CreateAgentRuntimeEndpoint`), `iam:PassRole` — run an attacker container as a role | iam:PassRole, bedrock-agentcore:CreateAgentRuntime, bedrock-agentcore:CreateAgentRuntimeEndpoint, bedrock-agentcore:InvokeAgentRuntime | COVERED | `aws-bedrock-agentcore-createagentruntime-passrole` |
| `bedrock-agentcorecreatecodeinterpreter--createbrowser-iampassrole--code-execution-sandbox-as-a-role` | `bedrock-agentcore:CreateCodeInterpreter` / `CreateBrowser`, `iam:PassRole` — code-execution sandbox as a role | bedrock-agentcore:CreateCodeInterpreter, iam:PassRole, bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter | COVERED | `aws-bedrock-agentcore-createcodeinterpreter-passrole` |
| `bedrock-agentcoreupdateagentruntime--updategateway-iampassrole--repoint-an-existing-resources-role` | `bedrock-agentcore:UpdateAgentRuntime` / `UpdateGateway`, `iam:PassRole` — repoint an existing resource's role | iam:PassRole, bedrock-agentcore:UpdateAgentRuntime, bedrock-agentcore:InvokeAgentRuntime | COVERED | `aws-bedrock-agentcore-updateagentruntime-passrole` |
| `credential-vend--getworkloadaccesstoken--getresourceapikey--getresourceoauth2token--steal-the-third-party-secrets-agents-use` | Credential vend — `GetWorkloadAccessToken*` → `GetResourceApiKey` / `GetResourceOauth2Token` — steal the third-party secrets agents use |  | EXCLUDED | Vends third-party (SaaS/OAuth) secrets used by agents, not AWS principals; also needs secretsmanager:GetSecretValue on the provider secret. |
| `references` | References |  | STRUCTURAL | Page title / references list |
| `aws---agentcore-harness-rce-via-indirect-prompt-injection` | AWS - AgentCore Harness RCE via Indirect Prompt Injection |  | EXCLUDED | Excluded: The bedrock-agentcore_harness resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |

### aws-privilege-escalation/aws-bedrock-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---bedrock-privesc` | AWS - Bedrock PrivEsc |  | STRUCTURAL | Page title / references list |
| `bedrock` | Bedrock |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `amazon-bedrock-agentcore` | Amazon Bedrock AgentCore |  | STRUCTURAL | Section heading grouping the AgentCore techniques below. |
| `bedrock-agentcorestartcodeinterpretersession--bedrock-agentcoreinvokecodeinterpreter---code-interpreter-execution-role-pivot` | `bedrock-agentcore:StartCodeInterpreterSession` + `bedrock-agentcore:InvokeCodeInterpreter` - Code Interpreter Execution-Role Pivot | bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `preconditions-common-misconfiguration` | Preconditions (common misconfiguration) | bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter, bedrock-agentcore:CreateCodeInterpreter, iam:PassRole | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `recon-identify-custom-interpreters-and-execution-role-usage` | Recon (identify custom interpreters and execution role usage) |  | STRUCTURAL | Enumeration step of the Code Interpreter pivot. |
| `step-1---start-a-session-this-returns-a-sessionid-not-an-interactive-shell` | Step 1 - Start a session (this returns a `sessionId`, not an interactive shell) | bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `step-2---invoke-code-execution-boto3-or-signed-https` | Step 2 - Invoke code execution (Boto3 or signed HTTPS) | bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `impact` | Impact |  | STRUCTURAL | Impact description of the Code Interpreter pivot. |
| `bedrock-agentcorecreateagentruntime--createagentruntimeendpoint-iampassrole---agent-runtime-execution-role-pivot` | `bedrock-agentcore:CreateAgentRuntime` (+ `CreateAgentRuntimeEndpoint`, `iam:PassRole`) - Agent Runtime Execution-Role Pivot | bedrock-agentcore:CreateAgentRuntime, iam:PassRole | EXCLUDED | Duplicate of the AgentCore page heading modelled as aws-bedrock-agentcore-createagentruntime-passrole. |
| `amazon-bedrock-agents` | Amazon Bedrock Agents |  | STRUCTURAL | Section heading grouping the Bedrock Agents technique below. |
| `lambdaupdatefunctioncode-bedrockinvokeagent---agent-tool-hijacking-via-lambda` | `lambda:UpdateFunctionCode`, `bedrock:InvokeAgent` - Agent Tool Hijacking via Lambda | lambda:UpdateFunctionCode, bedrock:InvokeAgent | COVERED | `aws-bedrock-agent-lambda-actiongroup-hijack` |
| `preconditions-common-misconfiguration-1` | Preconditions (common misconfiguration) | lambda:UpdateFunctionCode, bedrock:InvokeAgent | COVERED | `aws-bedrock-agent-lambda-actiongroup-hijack` — Preconditions of the action-group Lambda hijack. |
| `recon` | Recon |  | STRUCTURAL | Enumeration step of the action-group Lambda hijack. |
| `exploitation` | Exploitation | lambda:UpdateFunctionCode, bedrock:InvokeAgent | COVERED | `aws-bedrock-agent-lambda-actiongroup-hijack` — Exploitation step (UpdateFunctionCode then InvokeAgent). |
| `impact-1` | Impact |  | STRUCTURAL | Impact description of the action-group Lambda hijack. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-braket-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---amazon-braket-privilege-escalation` | AWS - Amazon Braket Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `amazon-braket` | Amazon Braket |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `braketcreatejob--iampassrole` | `braket:CreateJob` + `iam:PassRole` | iam:PassRole, braket:CreateJob | COVERED | `aws-braket-passrole-createjob` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-budgets-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---budgets-privesc` | AWS - Budgets Privesc |  | STRUCTURAL | Page title / references list |
| `budgets` | Budgets |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `aws-budgets` | AWS Budgets |  | STRUCTURAL | Service introduction (budget action types); techniques are mapped under their own headings. |
| `budgetscreatebudgetaction-iampassrole--budgetsexecutebudgetaction--self-attach-an-admin-policy--scp--run-code-as-a-passed-role` | `budgets:CreateBudgetAction`, `iam:PassRole` (+ `budgets:ExecuteBudgetAction`) — self-attach an admin policy / SCP / run code as a passed ro | iam:PassRole, budgets:CreateBudgetAction | EXCLUDED | Previously mapped to `aws-budgets-passrole-createbudgetaction`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-chatbot-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---chatbot-privesc` | AWS - Chatbot Privesc |  | STRUCTURAL | Page title / references list |
| `chatbot` | Chatbot |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `aws-chatbot--q-developer-in-chat-applications` | AWS Chatbot / Q Developer in chat applications |  | STRUCTURAL | Service introduction (channel IAM role model); techniques are mapped under their own headings. |
| `chatbotcreateslackchannelconfiguration--createmicrosoftteamschannelconfiguration--iampassrole` | `chatbot:CreateSlackChannelConfiguration` / `CreateMicrosoftTeamsChannelConfiguration` + `iam:PassRole` | iam:PassRole, chatbot:CreateSlackChannelConfiguration, chatbot:CreateMicrosoftTeamsChannelConfiguration, chatbot:UpdateSlackChannelConfiguration, chatbot:UpdateMicrosoftTeamsChannelConfiguration | EXCLUDED | Previously mapped to `aws-chatbot-passrole-create-channel-configuration`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-chime-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---chime-sdk-privesc` | AWS - Chime SDK Privesc |  | STRUCTURAL | Page title / references list |
| `chime-sdk` | Chime SDK |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `chimecreateappinstanceuser--chimecreateappinstanceadmin` | `chime:CreateAppInstanceUser` + `chime:CreateAppInstanceAdmin` | chime:CreateAppInstanceAdmin, chime:CreateAppInstanceUser | EXCLUDED | Previously mapped to `aws-v3-36-chime-createappinstanceuser-admin`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `chimecreatemediainsightspipelineconfiguration--iampassrole` | `chime:CreateMediaInsightsPipelineConfiguration` + `iam:PassRole` | chime:CreateMediaInsightsPipelineConfiguration, iam:PassRole | EXCLUDED | Previously mapped to `aws-chime-passrole-mediainsightspipelineconfiguration`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `chimecreatemediacapturepipeline--optional-iampassrole` | `chime:CreateMediaCapturePipeline` + optional `iam:PassRole` | chime:CreateMediaCapturePipeline, iam:PassRole | EXCLUDED | Meeting capture into S3; the sink role is a constrained S3/KMS proxy, not an escalation to the role. |
| `legacy-chimecreateapikey` | Legacy `chime:CreateApiKey` | chime:CreateApiKey | EXCLUDED | Creates a SCIM key for an Amazon Chime account (application-level, no IAM identity); HackTricks marks it TODO and AWS ended Amazon Chime support on 2026-02-20. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloud-control-handler-role-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloud-control-api-handler-role-privesc` | AWS - Cloud Control API handler role Privesc |  | STRUCTURAL | Page title / references list |
| `cloud-control-api` | Cloud Control API |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `getresource--listresources--iampassrole--read-through-a-resource-handler-role` | `GetResource` / `ListResources` + `iam:PassRole` — read through a resource-handler role | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloudcontrol-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloud-control-api-privesc` | AWS - Cloud Control API Privesc |  | STRUCTURAL | Page title / references list |
| `cloud-control-api` | Cloud Control API |  | STRUCTURAL | Service introduction (Cloud Control actions use the cloudformation prefix); the technique below is mapped to aws-cloudcontrol-passrole-createresource. |
| `cloudformationcreateresource-or-updateresource--iampassrole` | `cloudformation:CreateResource` (or `UpdateResource`) + `iam:PassRole` | iam:PassRole, cloudformation:CreateResource, cloudformation:UpdateResource | COVERED | `aws-cloudcontrol-passrole-createresource` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloudformation-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloudformation-privesc` | AWS - Cloudformation Privesc |  | STRUCTURAL | Page title / references list |
| `cloudformation` | CloudFormation |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `cloudformation-1` | cloudformation |  | STRUCTURAL | Section heading grouping the CloudFormation techniques mapped below. |
| `iampassrole-cloudformationcreatestack` | `iam:PassRole`, `cloudformation:CreateStack` | iam:PassRole, cloudformation:CreateStack | COVERED | `aws-cloudformation-passrole-createstack` |
| `iampassrole-cloudformationupdatestack-and-where-needed-cloudformationsetstackpolicy` | `iam:PassRole`, `cloudformation:UpdateStack` (and, where needed, `cloudformation:SetStackPolicy`) | iam:PassRole, cloudformation:UpdateStack | COVERED | `aws-cloudformation-passrole-updatestack` |
| `cloudformationupdatestack-and-where-needed-cloudformationsetstackpolicy` | `cloudformation:UpdateStack` (and, where needed, `cloudformation:SetStackPolicy`) | cloudformation:UpdateStack | COVERED | `aws-cloudformation-updatestack-attached-role` |
| `iampassrole-cloudformationcreatechangeset-cloudformationexecutechangeset-and-where-needed-cloudformationsetstackpolicy` | `iam:PassRole`, `cloudformation:CreateChangeSet`, `cloudformation:ExecuteChangeSet` (and, where needed, `cloudformation:SetStackPolicy`) | iam:PassRole, cloudformation:CreateChangeSet, cloudformation:ExecuteChangeSet | COVERED | `aws-cloudformation-passrole-changeset` |
| `cloudformationexecutechangeset-on-a-pre-staged-change-set` | `cloudformation:ExecuteChangeSet` on a pre-staged change set | cloudformation:ExecuteChangeSet | EXCLUDED | The source executes content it did not author; it only triggers an already-reviewed change. No attacker-controlled code under the role. |
| `cloudformationsignalresource--release-a-stack-waiting-on-a-success-signal` | `cloudformation:SignalResource` — Release a stack waiting on a success signal | cloudformation:SignalResource | EXCLUDED | Releases a gate for a fixed workload; no attacker-controlled execution under the role. |
| `cloudformationcreatechangeset-cloudformationexecutechangeset-and-where-needed-cloudformationsetstackpolicy` | `cloudformation:CreateChangeSet`, `cloudformation:ExecuteChangeSet` (and, where needed, `cloudformation:SetStackPolicy`) | cloudformation:CreateChangeSet, cloudformation:ExecuteChangeSet | COVERED | `aws-cloudformation-changeset-attached-role` |
| `iampassrole-cloudformationcreatestackset--cloudformationupdatestackset` | `iam:PassRole`, (`cloudformation:CreateStackSet` \| `cloudformation:UpdateStackSet`) | iam:PassRole, cloudformation:CreateStackSet, cloudformation:CreateStackInstances, cloudformation:UpdateStackSet | COVERED | `aws-cloudformation-passrole-stackset` |
| `cloudformationupdatestackset` | `cloudformation:UpdateStackSet` | cloudformation:UpdateStackSet | EXCLUDED | Excluded: UpdateStackSet changes an existing StackSet, but no collected StackSet-to-administration-role or execution-role join identifies the target; service trust alone overclaims the pivot. |
| `s3putobject-on-a-nested-stack-template--delayed-cloudformation-role-escalation` | `s3:PutObject` on a nested-stack template — delayed CloudFormation-role escalation | s3:PutObject | EXCLUDED | Excluded: The s3:PutObject source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ssmputparameter-on-a-cloudformation-supplied-parameter--delayed-policy-injection` | `ssm:PutParameter` on a CloudFormation-supplied parameter — delayed policy injection | ssm:PutParameter | EXCLUDED | Impact depends on how a template consumes a single value (template semantics not in the snapshot); delayed and value-only. Not generically evaluable.<br>Excluded: The ssm:PutParameter source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `cloudformationregistertype-iampassrole-and-an-extension-invocation-path` | `cloudformation:RegisterType`, `iam:PassRole`, and an extension invocation path | iam:PassRole, cloudformation:RegisterType, cloudformation:CreateResource, cloudformation:CreateStack, cloudformation:UpdateStack, cloudformation:SetTypeConfiguration | COVERED | `aws-cloudformation-registertype-passrole-extension` |
| `aws-cdk` | AWS CDK |  | EXCLUDED | CDK bootstrap roles are regular roles whose reachability is covered by sts:AssumeRole and CloudFormation PassRole entries. |
| `determining-the-role-names` | Determining the role names |  | EXCLUDED | Reconnaissance only. |
| `adding-malicious-code-to-the-project-source` | Adding malicious code to the project source |  | EXCLUDED | Source-repository write outside AWS IAM; not evaluable from the AWS snapshot. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloudformation-privesc/iam-passrole-cloudformation-createstack-and-cloudformation-describestacks.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iampassrole-cloudformationcreatestack-and-cloudformationdescribestacks` | iam:PassRole, cloudformation:CreateStack, and cloudformation:DescribeStacks |  | STRUCTURAL | Page title / references list |
| `cloudformation` | CloudFormation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloudfront-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloudfront-privesc` | AWS - CloudFront Privesc |  | STRUCTURAL | Page title / references list |
| `cloudfront` | CloudFront |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `cloudfrontupdatedistribution--cloudfrontgetdistributionconfig` | `cloudfront:UpdateDistribution` & `cloudfront:GetDistributionConfig` | cloudfront:UpdateDistribution, cloudfront:GetDistributionConfig | STRUCTURAL | Historical pointer to the relocated bounded operation in AWS post exploitation. |
| `cloudfrontcreatefunction-cloudfrontdescribefunction-cloudfrontpublishfunction-cloudfrontgetdistributionconfig--cloudfrontupdatedistribution` | `cloudfront:CreateFunction`, `cloudfront:DescribeFunction`, `cloudfront:PublishFunction`, `cloudfront:GetDistributionConfig` & `cloudfront:U | cloudfront:CreateFunction, cloudfront:DescribeFunction, cloudfront:PublishFunction, cloudfront:GetDistributionConfig, cloudfront:UpdateDistribution | STRUCTURAL | Historical pointer to the relocated bounded operation in AWS post exploitation. |
| `lambdacreatefunction-lambdapublishversion-iampassrole--cloudfrontupdatedistribution` | `lambda:CreateFunction`, `lambda:PublishVersion`, `iam:PassRole` & `cloudfront:UpdateDistribution` | lambda:CreateFunction, lambda:PublishVersion, lambda:GetFunction, lambda:EnableReplication, iam:PassRole, cloudfront:UpdateDistribution | COVERED | `aws-cloudfront-lambda-edge-passrole` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cloudwatch-omni-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloudwatch-omni-privesc` | AWS - CloudWatch Omni Privesc |  | STRUCTURAL | Page title / references list |
| `cloudwatch-omni` | CloudWatch Omni |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `cloudwatchgetspacecredentialsfororganization--obtain-member-account-space-credentials` | `cloudwatch:GetSpaceCredentialsForOrganization` — obtain member-account space credentials | cloudwatch:GetSpaceCredentialsForOrganization | EXCLUDED | Previously mapped to `aws-cloudwatch-omni-getspacecredentialsfororganization`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `cloudwatchcreateview-or-updateview--view-scoped-getrecords--expand-delegated-telemetry-access` | `cloudwatch:CreateView` or `UpdateView` + view-scoped `GetRecords` — expand delegated telemetry access | cloudwatch:CreateView | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codebuild-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codebuild-privesc` | AWS - Codebuild Privesc |  | STRUCTURAL | Page title / references list |
| `codebuild` | CodeBuild |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `codebuild-1` | codebuild |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `codebuildstartbuild--codebuildstartbuildbatch` | `codebuild:StartBuild` \| `codebuild:StartBuildBatch` | codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-startbuild-attached-role` |
| `codebuildretrybuild--re-execute-a-completed-build-under-its-stored-role` | `codebuild:RetryBuild` — Re-execute a completed build under its stored role | codebuild:RetryBuild | EXCLUDED | Replays the stored build configuration; the source controls nothing that runs under the role unless combined with source poisoning (modelled separately). |
| `codebuildstartcommandexecution--execute-in-a-running-sandbox` | `codebuild:StartCommandExecution` — Execute in a running sandbox | codebuild:StartCommandExecution | COVERED | `aws-codebuild-startcommandexecution`<br>`aws-codebuild-startsandbox-exec` |
| `codebuildstartsandboxconnection--open-an-interactive-shell-in-a-running-sandbox` | `codebuild:StartSandboxConnection` — Open an interactive shell in a running sandbox | codebuild:StartSandboxConnection | COVERED | `aws-codebuild-startsandboxconnection` |
| `startbuild-env-var-override` | StartBuild Env Var Override |  | EXCLUDED | Variant of the StartBuild override technique already modelled as aws-codebuild-startbuild-attached-role (same permission, same target: the project's stored service role); the examples are execution details. |
| `example-1-redirect-artifactupload-destination-to-exfiltrate-secrets` | Example 1: Redirect Artifact/Upload Destination to Exfiltrate Secrets | codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-startbuild-attached-role` — Example of the StartBuild override variant (same permission and target, the project's stored service role). |
| `example-2-python-startup-injection-via-pythonwarnings--browser` | Example 2: Python Startup Injection via `PYTHONWARNINGS` + `BROWSER` | codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-startbuild-attached-role` — Example of the StartBuild environment-variable override variant (code execution as the project's stored service role). |
| `iampassrole-codebuildcreateproject-codebuildstartbuild--codebuildstartbuildbatch` | `iam:PassRole`, `codebuild:CreateProject`, (`codebuild:StartBuild` \| `codebuild:StartBuildBatch`) | iam:PassRole, codebuild:CreateProject, codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-passrole-createproject` |
| `iampassrole-codebuildupdateproject-codebuildstartbuild--codebuildstartbuildbatch` | `iam:PassRole`, `codebuild:UpdateProject`, (`codebuild:StartBuild` \| `codebuild:StartBuildBatch`) | iam:PassRole, codebuild:UpdateProject, codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-passrole-updateproject` |
| `codebuildupdateproject-codebuildstartbuild--codebuildstartbuildbatch` | `codebuild:UpdateProject`, (`codebuild:StartBuild` \| `codebuild:StartBuildBatch`) | codebuild:UpdateProject, codebuild:StartBuild, codebuild:StartBuildBatch | COVERED | `aws-codebuild-updateproject-attached-role` |
| `ssm` | SSM |  | COVERED | `aws-codebuild-ssm-debug-session-role` — requires reviewed evidence that the debug session reaches the exact project service role. |
| `s3putobject-on-a-configured-s3-source-codebuildstartbuild-optional` | `s3:PutObject` on a configured S3 source (`codebuild:StartBuild` optional) | s3:PutObject | EXCLUDED | Excluded: The s3:PutObject source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `poison-a-secrets_manager-or-parameter_store-environment-value` | Poison a `SECRETS_MANAGER` or `PARAMETER_STORE` environment value |  | EXCLUDED | Value-only injection whose impact depends on the buildspec; not generically evaluable.<br>[excluded former aws-codebuild-env-parameter-store-poisoning]<br>Excluded: The writable secret is joined to a build, but no reviewed buildspec/consumer behavior proves its value executes code or yields role credentials; the effect can be configuration poisoning only. |
| `codebuildbatchgetprojects-codebuildbatchgetbuilds--read-build-environment-values` | `codebuild:BatchGetProjects`, `codebuild:BatchGetBuilds` — Read build environment values | codebuild:BatchGetProjects, codebuild:BatchGetBuilds | COVERED | Pure data read (plaintext env values). Historical EXCLUDED data read remains so without an exact usable IAM-user key; reviewed conditional credential variant `aws-codebuild-plaintext-env-credential`. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codecommit-pipeline-source-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codecommit-pipeline-source-privesc` | AWS - CodeCommit pipeline source Privesc |  | STRUCTURAL | Page title / references list |
| `codecommit` | CodeCommit |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `codecommitgitpush-on-a-codepipeline-source-repository` | `codecommit:GitPush` on a CodePipeline source repository | codecommit:GitPush | EXCLUDED | [excluded former aws-codecommit-gitpush-pipeline-source]<br>Excluded: The codecommit:GitPush source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codeconnections-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codeconnections-privesc` | AWS - CodeConnections Privesc |  | STRUCTURAL | Page title / references list |
| `codeconnections` | CodeConnections |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `codeconnectionscreatesyncconfiguration--codeconnectionsupdatesyncconfiguration--codeconnectionspassrepository--iampassrole` | `codeconnections:CreateSyncConfiguration` / `codeconnections:UpdateSyncConfiguration` + `codeconnections:PassRepository` + `iam:PassRole` | iam:PassRole, codeconnections:PassRepository, codeconnections:CreateSyncConfiguration, codeconnections:UpdateSyncConfiguration | EXCLUDED | Excluded: Git sync configuration plus PassRole does not prove the source can write the monitored repository branch/deployment file; external Git control is only prose. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codedeploy-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codedeploy-privesc` | AWS - CodeDeploy Privesc |  | STRUCTURAL | Page title / references list |
| `codedeploy` | CodeDeploy |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `codedeploycreatedeployment--dependent-actions` | `codedeploy:CreateDeployment` + dependent actions | codedeploy:CreateDeployment, codedeploy:GetDeploymentConfig, codedeploy:RegisterApplicationRevision | EXCLUDED | Excluded: CreateDeployment and RegisterApplicationRevision do not prove the source controls a revision that the target hosts download; artifact control is only a prose condition. |
| `required-conditions` | Required conditions | codedeploy:CreateDeployment, codedeploy:GetDeploymentConfig, codedeploy:RegisterApplicationRevision | EXCLUDED | Excluded: CreateDeployment and RegisterApplicationRevision do not prove the source controls a revision that the target hosts download; artifact control is only a prose condition. — Preconditions of the CreateDeployment technique, encoded as its controlled_revision and agent_running conditions. |
| `example-revision` | Example revision | codedeploy:CreateDeployment, codedeploy:GetDeploymentConfig, codedeploy:RegisterApplicationRevision | EXCLUDED | Excluded: CreateDeployment and RegisterApplicationRevision do not prove the source controls a revision that the target hosts download; artifact control is only a prose condition. — Exploitation example of the same technique. |
| `discovery-without-list-permissions` | Discovery without list permissions |  | STRUCTURAL | Enumeration guidance for the CreateDeployment technique. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codepipeline-job-credentials-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codepipeline-job-credentials-privesc` | AWS - CodePipeline job credentials Privesc |  | STRUCTURAL | Page title / references list |
| `codepipeline` | CodePipeline |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `codepipelinepollforjobs--custom-action-artifact-credentials` | `codepipeline:PollForJobs` — custom-action artifact credentials | codepipeline:PollForJobs | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `codepipelinegetjobdetails--known-job-artifact-credentials` | `codepipeline:GetJobDetails` — known-job artifact credentials | codepipeline:GetJobDetails | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codepipeline-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codepipeline-privesc` | AWS - Codepipeline Privesc |  | STRUCTURAL | Page title / references list |
| `codepipeline` | CodePipeline |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `codepipeline-1` | codepipeline |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole-codepipelinecreatepipeline-codebuildcreateproject-codepipelinestartpipelineexecution` | `iam:PassRole`, `codepipeline:CreatePipeline`, `codebuild:CreateProject`, `codepipeline:StartPipelineExecution` | iam:PassRole, codepipeline:CreatePipeline, codebuild:CreateProject, codepipeline:StartPipelineExecution | COVERED | `aws-codepipeline-passrole-createpipeline-codebuild`, `aws-codepipeline-passrole-createpipeline-codebuild-codecommit`, `aws-codepipeline-passrole-createpipeline-codebuild-ecr` |
| `codebuildupdateproject-codepipelineupdatepipeline-codepipelinestartpipelineexecution` | `codebuild:UpdateProject`, `codepipeline:UpdatePipeline`, `codepipeline:StartPipelineExecution` | codebuild:UpdateProject, codepipeline:UpdatePipeline, codepipeline:StartPipelineExecution | COVERED | `aws-codepipeline-updatepipeline-codebuild-updateproject` |
| `codepipelinestartpipelineexecution--inject-a-v2-pipeline-variable` | `codepipeline:StartPipelineExecution` — inject a V2 pipeline variable | codepipeline:StartPipelineExecution | EXCLUDED | Value-only injection whose impact depends on pipeline action semantics; not generically evaluable. |
| `codepipelineretrystageexecution--replay-a-failed-privileged-stage` | `codepipeline:RetryStageExecution` — Replay a failed privileged stage | codepipeline:RetryStageExecution | EXCLUDED | Replays a fixed workload; no attacker-controlled execution. |
| `codepipelineenablestagetransition--release-an-execution-waiting-at-a-disabled-transition` | `codepipeline:EnableStageTransition` — Release an execution waiting at a disabled transition | codepipeline:EnableStageTransition | EXCLUDED | Gate release for a fixed workload. |
| `codepipelineoverridestagecondition--bypass-an-active-stage-condition` | `codepipeline:OverrideStageCondition` — Bypass an active stage condition | codepipeline:OverrideStageCondition | EXCLUDED | Gate bypass for a fixed workload. |
| `codepipelinerollbackstage--replay-a-prior-successful-stage-revision` | `codepipeline:RollbackStage` — Replay a prior successful stage revision | codepipeline:RollbackStage | EXCLUDED | Replays a prior reviewed revision; no attacker-controlled execution. |
| `s3putobject-on-a-configured-s3-source-codepipelinestartpipelineexecution-optional` | `s3:PutObject` on a configured S3 source (`codepipeline:StartPipelineExecution` optional) | s3:PutObject | EXCLUDED | [excluded former aws-codepipeline-s3-source-poisoning]<br>Excluded: The s3:PutObject source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `codepipelineputapprovalresult--bypass-a-manual-gate` | `codepipeline:PutApprovalResult` — bypass a manual gate | codepipeline:PutApprovalResult | EXCLUDED | Approval bypass only; becomes an escalation only combined with source poisoning (modelled separately). |
| `codepipelineputjobsuccessresult--bypass-a-zero-output-custom-action-gate` | `codepipeline:PutJobSuccessResult` — bypass a zero-output custom-action gate | codepipeline:PutJobSuccessResult | EXCLUDED | Gate bypass for a fixed workload. |
| `codepipelinepollforjobs` | `codepipeline:PollForJobs` | codepipeline:PollForJobs | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codestar-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---codestar-privesc` | AWS - Codestar Privesc |  | STRUCTURAL | Page title / references list |
| `codestar` | CodeStar |  | EXCLUDED | AWS CodeStar discontinued (2024-07-31); introductory section. |
| `codestar-1` | Codestar |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole-codestarcreateproject` | `iam:PassRole`, `codestar:CreateProject` | iam:PassRole, codestar:CreateProject | EXCLUDED | AWS CodeStar was discontinued on 2024-07-31; the APIs are no longer available. |
| `codestarcreateproject-codestarassociateteammember` | `codestar:CreateProject`, `codestar:AssociateTeamMember` | codestar:CreateProject, codestar:AssociateTeamMember | EXCLUDED | AWS CodeStar discontinued (2024-07-31). |
| `codestarcreateprojectfromtemplate` | `codestar:CreateProjectFromTemplate` | codestar:CreateProjectFromTemplate | EXCLUDED | AWS CodeStar discontinued (2024-07-31). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codestar-privesc/codestar-createproject-codestar-associateteammember.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `codestarcreateproject-codestarassociateteammember` | codestar:CreateProject, codestar:AssociateTeamMember |  | STRUCTURAL | Page title / references list |
| `codestar` | CodeStar |  | STRUCTURAL | Introduction of a historical CodeStar page; AWS CodeStar was shut down in July 2024 (the technique heading is excluded as discontinued). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-codestar-privesc/iam-passrole-codestar-createproject.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iampassrole-codestarcreateproject` | iam:PassRole, codestar:CreateProject |  | STRUCTURAL | Page title / references list |
| `codestar` | CodeStar |  | STRUCTURAL | Introduction of a historical CodeStar page; AWS CodeStar project creation was discontinued on 2024-07-31 (the technique is excluded as discontinued). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cognito-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cognito-privesc` | AWS - Cognito Privesc |  | STRUCTURAL | Page title / references list |
| `cognito` | Cognito |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `gathering-credentials-from-identity-pool` | Gathering credentials from Identity Pool |  | EXCLUDED | Anonymous access to identity-pool roles is an Exposure finding (public), not a permission-based edge from a source principal. |
| `cognito-identitysetidentitypoolroles-iampassrole` | `cognito-identity:SetIdentityPoolRoles`, `iam:PassRole` | cognito-identity:SetIdentityPoolRoles, iam:PassRole | EXCLUDED | excluded: "Set the roles of an identity pool the source can obtain credentials from"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-identityupdateidentitypool` | `cognito-identity:UpdateIdentityPool` | cognito-identity:UpdateIdentityPool | EXCLUDED | excluded: "Add a provider the source controls to an identity pool, Enable the basic (classic) authentication flow on an identity pool"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-identitygetopenidtokenfordeveloperidentity--mint-credentials-for-the-pools-authenticated-role-with-no-account-at-all` | `cognito-identity:GetOpenIdTokenForDeveloperIdentity` — mint credentials for the pool's authenticated role with no account at all | cognito-identity:GetOpenIdTokenForDeveloperIdentity | EXCLUDED | excluded: "Mint a developer-authenticated identity token for an identity pool"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-identitysetprincipaltagattributemap--forge-the-session-tags-that-iam-conditions-trust` | `cognito-identity:SetPrincipalTagAttributeMap` — forge the session tags that IAM conditions trust | cognito-identity:SetPrincipalTagAttributeMap | EXCLUDED | excluded: "Remap identity-pool principal tags to attributes the source controls"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadminaddusertogroup` | `cognito-idp:AdminAddUserToGroup` | cognito-idp:AdminAddUserToGroup | EXCLUDED | excluded: "Add a user-pool user the source controls to a group with an IAM role"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpcreategroup--cognito-idpupdategroup-iampassrole` | (`cognito-idp:CreateGroup` \| `cognito-idp:UpdateGroup`), `iam:PassRole` | iam:PassRole, cognito-idp:CreateGroup, cognito-idp:UpdateGroup | EXCLUDED | excluded: "Create or update a user-pool group with a passed role"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadminconfirmsignup` | `cognito-idp:AdminConfirmSignUp` | cognito-idp:AdminConfirmSignUp | EXCLUDED | excluded: "Confirm a self-registered user-pool user"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadmincreateuser` | `cognito-idp:AdminCreateUser` | cognito-idp:AdminCreateUser | EXCLUDED | excluded: "Create a user in a user pool"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadminenableuser` | `cognito-idp:AdminEnableUser` | cognito-idp:AdminEnableUser | EXCLUDED | Requires already knowing the disabled user's credentials. |
| `cognito-idpadmininitiateauth-cognito-idpadminrespondtoauthchallenge` | `cognito-idp:AdminInitiateAuth`, **`cognito-idp:AdminRespondToAuthChallenge`** | cognito-idp:AdminInitiateAuth, cognito-idp:AdminRespondToAuthChallenge | EXCLUDED | Requires the user's password/secret (or a custom-auth flow weakness specific to the app); not derivable from permissions alone. |
| `cognito-idpadminsetuserpassword` | `cognito-idp:AdminSetUserPassword` | cognito-idp:AdminSetUserPassword | EXCLUDED | excluded: "Set the password of an existing user-pool user"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadduserpoolclientsecret--inject-an-m2m-application-credential` | `cognito-idp:AddUserPoolClientSecret` — inject an M2M application credential | cognito-idp:AddUserPoolClientSecret | EXCLUDED | Client-credentials (M2M) tokens grant OAuth scopes to resource servers, not identity-pool AWS roles (identity pools accept user tokens). Application-level impact only. |
| `cognito-idpadmindeletesoftwaretoken--cognito-idpadminsetusermfapreference--cognito-idpsetuserpoolmfaconfig--cognito-idpupdateuserpool` | `cognito-idp:AdminDeleteSoftwareToken` \| `cognito-idp:AdminSetUserMFAPreference` \| `cognito-idp:SetUserPoolMfaConfig` \| `cognito-idp:Upda | cognito-idp:AdminDeleteSoftwareToken, cognito-idp:AdminSetUserMFAPreference, cognito-idp:SetUserPoolMfaConfig, cognito-idp:UpdateUserPool | EXCLUDED | MFA weakening only; account takeover still needs the victim's password (or a separate reset primitive already modelled by the password entries). Supersedes the stale _excluded_a.yaml line for this heading. |
| `cognito-idpadminupdateuserattributes` | `cognito-idp:AdminUpdateUserAttributes` | cognito-idp:AdminUpdateUserAttributes | EXCLUDED | excluded: "Change a user-pool user's attributes to match an identity-pool role-mapping rule"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpcreateuserpoolclient--cognito-idpupdateuserpoolclient` | `cognito-idp:CreateUserPoolClient` \| `cognito-idp:UpdateUserPoolClient` | cognito-idp:CreateUserPoolClient, cognito-idp:UpdateUserPoolClient | EXCLUDED | Relaxes client settings (flows, scopes); still needs user credentials to obtain tokens. Application-level. |
| `cognito-idpcreateuserimportjob--cognito-idpstartuserimportjob` | `cognito-idp:CreateUserImportJob` \| `cognito-idp:StartUserImportJob` | cognito-idp:CreateUserImportJob, cognito-idp:StartUserImportJob, iam:PassRole | EXCLUDED | excluded: "Import users with known passwords via a user import job"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpcreateidentityprovider--cognito-idpupdateidentityprovider` | `cognito-idp:CreateIdentityProvider` \| `cognito-idp:UpdateIdentityProvider` | cognito-idp:CreateIdentityProvider, cognito-idp:UpdateIdentityProvider | EXCLUDED | excluded: "Add or change a federated identity provider of a user pool"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-idpadminlinkproviderforuser--graft-an-attacker-identity-onto-an-existing-privileged-user` | `cognito-idp:AdminLinkProviderForUser` — graft an attacker identity onto an existing privileged user | cognito-idp:AdminLinkProviderForUser | EXCLUDED | excluded: "Link a federated identity the source controls to an existing user-pool user"; no exact source-controlled usable token and role-slot relation is verified. |
| `cognito-sync-analysis` | cognito-sync:\* Analysis |  | STRUCTURAL | Service tooling notes; no separate principal or permission path. |
| `automatic-tools` | Automatic Tools |  | EXCLUDED | Tooling references only. |
| `usage` | Usage |  | STRUCTURAL | Tooling usage example (Pacu) under Automatic Tools; no technique. |
| `installation` | Installation |  | STRUCTURAL | Tooling installation (Cognito Scanner); no technique. |
| `usage-1` | Usage |  | STRUCTURAL | Tooling usage (Cognito Scanner); no technique. |
| `select-an-identity-pool-role-through-editable-claims` | Select an identity-pool role through editable claims |  | EXCLUDED | Needs no IAM permission: an end user edits its own token claims through user-pool self-service APIs. A role-mapping misconfiguration (Exposure check), not a permission-based edge from an IAM source principal. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-cognito-user-pools-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cognito-user-pools-privesc` | AWS - Cognito User Pools Privesc |  | STRUCTURAL | Page title / references list |
| `cognito` | Cognito |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `privilege-escalation--updating-attributes` | Privilege Escalation / Updating Attributes |  | STRUCTURAL | Parent heading of the custom-attribute and email/username variants, both excluded (end-user token self-service, application-level only, no IAM permission). |
| `custom-attribute-privesc` | Custom attribute privesc |  | EXCLUDED | Application-level privilege change for app users (token-authorized, no IAM permission); AWS-role impact only through claim-based role mapping, covered by the editable-claims exclusion. |
| `emailusername-modification-privesc` | Email/username modification privesc |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-config-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---config-privesc` | AWS - Config Privesc |  | STRUCTURAL | Page title / references list |
| `config` | Config |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `aws-config` | AWS Config |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `privilege-escalation-through-automatic-remediation` | Privilege escalation through automatic remediation | iam:PassRole, config:PutRemediationConfigurations, ssm:CreateDocument | COVERED | `aws-config-passrole-automatic-remediation` |
| `required-permissions` | Required permissions | iam:PassRole, config:PutRemediationConfigurations, ssm:CreateDocument | COVERED | `aws-config-passrole-automatic-remediation` — Permission list of the automatic-remediation technique. |
| `exploitation` | Exploitation | iam:PassRole, config:PutRemediationConfigurations, ssm:CreateDocument | COVERED | `aws-config-passrole-automatic-remediation` — Exploitation steps of the same technique. |
| `also-relevant-configputremediationconfigurations--iampassrole-classic-passrole` | Also relevant: `config:PutRemediationConfigurations` + `iam:PassRole` (classic PassRole) | iam:PassRole, config:PutRemediationConfigurations, ssm:CreateDocument | COVERED | `aws-config-passrole-automatic-remediation` — Same PassRole edge (PutRemediationConfigurations + iam:PassRole on an ssm.amazonaws.com-trusting role); the entry notes it. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-connect-cases-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---amazon-connect-cases-privesc` | AWS - Amazon Connect Cases Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-connect-cases` | Amazon Connect Cases |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `casestagresource--casesuntagresource-plus-tag-conditioned-cases-permissions` | `cases:TagResource` / `cases:UntagResource` plus tag-conditioned Cases permissions | cases:TagResource, cases:UntagResource | COVERED | `aws-cases-tagresource-domain-event-self-grant` — reviewed exact self permission gain; broader variants remain excluded. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-connect-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---amazon-connect-privesc` | AWS - Amazon Connect Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-connect` | Amazon Connect |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `impersonate-a-saml-connect-user-with-a-controllable-role-session-name` | Impersonate a SAML Connect user with a controllable role-session name |  | EXCLUDED | Excluded: GetFederationToken does not prove the source controls a SAML federation role session with the victim case-sensitive username or that victim holds Connect Admin. — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected. |
| `take-over-a-connect-managed-user-through-updateuseridentityinfo` | Take over a Connect-managed user through `UpdateUserIdentityInfo` |  | EXCLUDED | Excluded: UpdateUserIdentityInfo can change an arbitrary user email but no exact source-controlled mailbox/sign-in or Admin-profile victim mapping is proved. — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected. |
| `grant-admin-through-security-profile-mutation` | Grant Admin through security-profile mutation |  | EXCLUDED | excluded: "Grant Connect Admin through security-profile assignment or mutation"; The source can change a security profile or assignment, but no Connect user it controls and can sign into is joined to that change. |
| `invoke-a-privileged-flow-without-direct-lambda-or-lex-permission` | Invoke a privileged flow without direct Lambda or Lex permission |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-control-tower-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---control-tower-privesc` | AWS - Control Tower Privesc |  | STRUCTURAL | Page title / references list |
| `control-tower` | Control Tower |  | EXCLUDED | Service introduction describing the Control Tower orchestration surface; techniques are mapped under their own headings. |
| `account-factory--provision-an-account-you-control` | Account Factory → provision an account you control | servicecatalog:UpdateProvisionedProduct | EXCLUDED | Excluded: Product update does not prove the chosen SSO user or mailbox is source-controlled, nor which member-account admin is gained; both joins are prose conditions. |
| `account-factory-customization-afc--run-cloudformation-in-managed-accounts` | Account Factory Customization (AFC) → run CloudFormation in managed accounts |  | EXCLUDED | The blueprint (a Service Catalog product in a hub account) is applied to managed accounts only when Control Tower enrolls, creates or updates an account with it; the blueprint-to-account mapping and the account-update step are not inferable from collected IAM facts, and a generic servicecatalog:CreateProvisioningArtifact edge would duplicate aws-servicecatalog-createprovisioningartifact-provisionproduct. Needs a Control Tower blueprint inventory (see SCHEMA EXTENSIONS in the G1 report). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-customer-profiles-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---customer-profiles-privilege-escalation` | AWS - Customer Profiles Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `customer-profiles` | Customer Profiles |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `createintegrationworkflow--iampassrole` | `CreateIntegrationWorkflow` + `iam:PassRole` | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `createsegmentsnapshot--iampassrole` | `CreateSegmentSnapshot` + `iam:PassRole` | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `associatestreamforsegments--iampassrole` | `AssociateStreamForSegments` + `iam:PassRole` | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `confused-deputy-and-trust-policy-boundary` | Confused-deputy and trust-policy boundary |  | STRUCTURAL | Mitigation guidance (trust-policy source conditions) for the three excluded PassRole paths. |
| `non-paths-and-constraints` | Non-paths and constraints |  | STRUCTURAL | The page lists explicit non-paths (PutIntegration, CreateEventStream, GetUploadJobPath, profile data actions); no technique. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-datapipeline-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---datapipeline-privesc` | AWS - Datapipeline Privesc |  | STRUCTURAL | Page title / references list |
| `datapipeline` | DataPipeline |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `datapipeline-1` | datapipeline |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole-datapipelinecreatepipeline-datapipelineputpipelinedefinition-datapipelineactivatepipeline` | `iam:PassRole`, `datapipeline:CreatePipeline`, `datapipeline:PutPipelineDefinition`, `datapipeline:ActivatePipeline` | iam:PassRole, datapipeline:CreatePipeline, datapipeline:PutPipelineDefinition, datapipeline:ActivatePipeline | COVERED | `aws-datapipeline-passrole-create-activate` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-datasync-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---datasync-privesc` | AWS - DataSync Privesc |  | STRUCTURAL | Page title / references list |
| `aws-datasync` | AWS DataSync |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `datasync` | DataSync |  | STRUCTURAL | Service heading; the technique is the CreateLocationS3/CreateTask/StartTaskExecution subsection. |
| `datasynccreatelocations3-datasynccreatetask-datasyncstarttaskexecution-iampassrole` | `datasync:CreateLocationS3`, `datasync:CreateTask`, `datasync:StartTaskExecution`, `iam:PassRole` | datasync:CreateLocationS3, datasync:CreateTask, iam:PassRole | EXCLUDED | Previously mapped to `aws-datasync-passrole-createlocations3-createtask`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `datasyncupdatelocations3-datasyncstarttaskexecution-iampassrole--replace-a-stored-location-role` | `datasync:UpdateLocationS3`, `datasync:StartTaskExecution`, `iam:PassRole` — replace a stored location role | datasync:UpdateLocationS3, datasync:StartTaskExecution, iam:PassRole | EXCLUDED | Previously mapped to `aws-datasync-updatelocations3-starttaskexecution`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-datazone-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-datazone-privilege-escalation` | AWS DataZone Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `amazon-datazone` | Amazon DataZone |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `getenvironmentcredentials-as-a-custom-environment-role` | `GetEnvironmentCredentials` as a custom environment role | datazone:GetEnvironmentCredentials | EXCLUDED | Previously mapped to `aws-datazone-getenvironmentcredentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `associateenvironmentrole--iampassrole` | `AssociateEnvironmentRole` + `iam:PassRole` | iam:PassRole, datazone:AssociateEnvironmentRole, datazone:GetEnvironmentCredentials | EXCLUDED | Previously mapped to `aws-datazone-passrole-associateenvironmentrole`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `blueprint-configuration-role-substitution` | Blueprint configuration role substitution |  | EXCLUDED | The passed provisioning and manage-access roles run fixed built-in blueprint operations (CloudFormation provisioning, Glue/Lake Formation/Redshift grants); the caller does not control code run as the roles. Confused-deputy provisioning, not a direct role takeover. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-deadline-cloud-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---deadline-cloud-privesc` | AWS - Deadline Cloud Privesc |  | STRUCTURAL | Page title / references list |
| `deadline-cloud` | Deadline Cloud |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `fleet-role-read-credentials` | Fleet-role read credentials |  | EXCLUDED | Vends the read-scoped fleet role credentials used for monitoring; reduced read access, not the fleet role. |
| `queue-role-credential-vending` | Queue-role credential vending | deadline:AssumeQueueRoleForUser | EXCLUDED | Excluded: The queue membership and level needed to vend this exact queue role are not joined to the source; IAM permission plus role attachment alone is insufficient. |
| `deadlinecreatequeueupdatequeue--iampassrole--deadlineassumequeueroleforuser` | `deadline:CreateQueue`/`UpdateQueue` + `iam:PassRole` (+ `deadline:AssumeQueueRoleForUser`) | iam:PassRole, deadline:AssumeQueueRoleForUser, deadline:CreateQueue, deadline:UpdateQueue | COVERED | `aws-deadline-passrole-createqueue-updatequeue` |
| `deadlinecreatefleetupdatefleet--iampassrole--deadlinecreateworker--deadlineassumefleetroleforworker` | `deadline:CreateFleet`/`UpdateFleet` + `iam:PassRole` + `deadline:CreateWorker` + `deadline:AssumeFleetRoleForWorker` | iam:PassRole, deadline:CreateWorker, deadline:AssumeFleetRoleForWorker, deadline:CreateFleet, deadline:UpdateFleet | COVERED | `aws-deadline-passrole-fleet-createworker`<br>[excluded former aws-deadline-createworker-assumefleetroleforworker-existing-fleet] |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-device-farm-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---device-farm-privilege-escalation` | AWS - Device Farm Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `device-farm` | Device Farm |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `trojanize-an-existing-custom-test-specification` | Trojanize an existing custom test specification | devicefarm:UpdateUpload | EXCLUDED | Excluded: The devicefarm:UpdateUpload source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `devicefarmcreateprojectupdateprojectschedulerun--iampassrole` | `devicefarm:CreateProject`/`UpdateProject`/`ScheduleRun` + `iam:PassRole` | iam:PassRole, devicefarm:ScheduleRun, devicefarm:CreateUpload | COVERED | `aws-devicefarm-passrole-project-schedulerun`<br>`aws-devicefarm-schedulerun-existing-test-spec-passrole` — conditional verified exact-target authority. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-directory-services-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---directory-services-privesc` | AWS - Directory Services Privesc |  | STRUCTURAL | Page title / references list |
| `directory-services--workdocs` | Directory Services / WorkDocs |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `directory-services` | Directory Services |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `dsresetuserpassword` | `ds:ResetUserPassword` | ds:ResetUserPassword | EXCLUDED | [excluded former aws-ds-resetuserpassword]<br>Excluded: The directory-admin target is an account-level entity, not an exact resettable user; no evidence joins a specific user, credential usability, and admin rights. |
| `aws-management-console` | AWS Management Console |  | EXCLUDED | Descriptive section; the escalation is modelled as aws-ds-resetuserpassword. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-dlm-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---dlm-privesc` | AWS - DLM Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-data-lifecycle-manager` | Amazon Data Lifecycle Manager |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `data-lifecycle-manager-dlm` | Data Lifecycle Manager (DLM) |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `dlmcreatelifecyclepolicy-iampassrole--scheduled-commands-through-dlm-prepost-scripts` | `dlm:CreateLifecyclePolicy`, `iam:PassRole` — scheduled commands through DLM pre/post scripts | iam:PassRole, dlm:CreateLifecyclePolicy, dlm:UpdateLifecyclePolicy | EXCLUDED | Exact session or DLM policy to EC2 role join is not proven (`_excluded_unproven_ssm_dlm_target_final_reaudit_20261016.yaml`). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-documentdb-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---documentdb-privesc` | AWS - DocumentDB Privesc |  | STRUCTURAL | Page title / references list |
| `documentdb` | DocumentDB |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `post-exploitation-reset-an-elastic-cluster-administrator-password` | Post-exploitation: reset an Elastic cluster administrator password |  | EXCLUDED | Database administrator access only; Elastic cluster users are not AWS principals. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-dynamodb-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---dynamodb-privesc` | AWS - DynamoDB Privesc |  | STRUCTURAL | Page title / references list |
| `dynamodb` | DynamoDB |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `dynamodb-1` | dynamodb |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `dynamodbputresourcepolicy-and-optionally-dynamodbgetresourcepolicy` | `dynamodb:PutResourcePolicy`, and optionally `dynamodb:GetResourcePolicy` | dynamodb:PutResourcePolicy, dynamodb:GetResourcePolicy | EXCLUDED | Grants the source data access to tables; data access, not a new identity.<br>`aws-dynamodb-deleteresourcepolicy-guardrail` — conditional verified exact-target authority. |
| `write-behavior` | Write behavior |  | STRUCTURAL | Behaviour details of the excluded dynamodb:PutResourcePolicy technique (table data access, no new identity). |
| `post-exploitation` | Post Exploitation |  | EXCLUDED | Cross-reference only. |
| `todo-read-data-abusing-data-streams` | TODO: Read data abusing data Streams |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ebs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ebs-privesc` | AWS - EBS Privesc |  | STRUCTURAL | Page title / references list |
| `ebs` | EBS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `ebslistsnapshotblocks-ebsgetsnapshotblock-ec2describesnapshots` | `ebs:ListSnapshotBlocks`, `ebs:GetSnapshotBlock`, `ec2:DescribeSnapshots` | ebs:ListSnapshotBlocks, ebs:GetSnapshotBlock, ec2:DescribeSnapshots | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ec2createsnapshot` | **`ec2:CreateSnapshot`** | ec2:CreateSnapshot | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ec2-image-builder-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ec2-image-builder-privesc` | AWS - EC2 Image Builder Privesc |  | STRUCTURAL | Page title / references list |
| `ec2-image-builder` | EC2 Image Builder |  | EXCLUDED | Service introduction and enumeration link; techniques are mapped under their own headings. |
| `imagebuildercreatecomponent--imagebuilderstartimagepipelineexecution` | `imagebuilder:CreateComponent` + `imagebuilder:StartImagePipelineExecution` | imagebuilder:CreateComponent, imagebuilder:StartImagePipelineExecution | COVERED | `aws-imagebuilder-component-version-hijack` — pipeline from `imagebuilder_pipeline`; `consumer_input_writable_via` evaluated as conditional (recipe components not collected). |
| `required-conditions` | Required conditions | imagebuilder:CreateComponent, imagebuilder:StartImagePipelineExecution | COVERED | `aws-imagebuilder-component-version-hijack` — Preconditions of the component-version hijack (wildcard recipe reference, pipeline run), encoded as the unpinned_component condition. |
| `publish-a-higher-component-version` | Publish a higher component version | imagebuilder:CreateComponent, imagebuilder:StartImagePipelineExecution | COVERED | `aws-imagebuilder-component-version-hijack` — Exploitation step of the same technique. |
| `discovery-with-and-without-list-permissions` | Discovery with and without list permissions |  | STRUCTURAL | Enumeration guidance for the component-version hijack. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ec2-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ec2-privesc` | AWS - EC2 Privesc |  | STRUCTURAL | Page title / references list |
| `ec2` | EC2 |  | STRUCTURAL | Service introduction linking to the EC2 enumeration page. |
| `iampassrole-ec2runinstances` | `iam:PassRole`, `ec2:RunInstances` | iam:PassRole, ec2:RunInstances | COVERED | `aws-ec2-passrole-runinstances` |
| `privesc-to-ecs` | Privesc to ECS | iam:PassRole, ec2:RunInstances | EXCLUDED | Excluded: Joining a cluster with a new ECS container instance does not prove that a specific target-role task is scheduled onto that instance. |
| `iampassrole-iamaddroletoinstanceprofile` | **`iam:PassRole`,** **`iam:AddRoleToInstanceProfile`** | iam:PassRole, iam:AddRoleToInstanceProfile | EXCLUDED | Excluded: The caller can place a role in an instance profile, but the graph does not prove it controls and can execute on an instance using that profile; no usable role credential follows from the declared actions alone. |
| `iampassrole-with-ec2associateiaminstanceprofile-and-ec2disassociateiaminstanceprofile-or-ec2replaceiaminstanceprofileassociation` | `iam:PassRole` with (`ec2:AssociateIamInstanceProfile` and `ec2:DisassociateIamInstanceProfile`) or `ec2:ReplaceIamInstanceProfileAssociatio | iam:PassRole, ec2:AssociateIamInstanceProfile, ec2:DisassociateIamInstanceProfile, ec2:ReplaceIamInstanceProfileAssociation | COVERED | `aws-ec2-passrole-associate-instance-profile` |
| `ec2requestspotinstances-iampassrole` | `ec2:RequestSpotInstances`, `iam:PassRole` | iam:PassRole, ec2:RequestSpotInstances | COVERED | `aws-ec2-requestspotinstances-passrole` |
| `ec2modifyinstanceattribute` | `ec2:ModifyInstanceAttribute` | ec2:ModifyInstanceAttribute | STRUCTURAL | Parent heading; its two variants are mapped below (user data -> aws-ec2-modifyinstanceattribute-userdata, security groups -> excluded). |
| `replace-security-groups-on-a-running-instance` | Replace security groups on a running instance |  | EXCLUDED | Network change only. |
| `replace-user-data` | Replace user data | ec2:ModifyInstanceAttribute, ec2:StopInstances, ec2:StartInstances | COVERED | `aws-ec2-modifyinstanceattribute-userdata` |
| `ec2createlaunchtemplateversion-ec2createlaunchtemplate-ec2modifylaunchtemplate` | `ec2:CreateLaunchTemplateVersion`, `ec2:CreateLaunchTemplate`, `ec2:ModifyLaunchTemplate` | ec2:CreateLaunchTemplateVersion | COVERED | `aws-ec2-launchtemplate-version-asg` |
| `autoscalingcreatelaunchconfiguration--ec2createlaunchtemplate--iampassrole-autoscalingcreateautoscalinggroup--autoscalingupdateautoscalinggroup` | (`autoscaling:CreateLaunchConfiguration` \| `ec2:CreateLaunchTemplate`),  `iam:PassRole`, (`autoscaling:CreateAutoScalingGroup` \| `autoscal | iam:PassRole, autoscaling:CreateLaunchConfiguration, autoscaling:CreateAutoScalingGroup, autoscaling:UpdateAutoScalingGroup, ec2:CreateLaunchTemplate, ec2:RunInstances | COVERED | `aws-ec2-autoscaling-create-update-asg-passrole` |
| `launch-template-and-auto-scaling-constraints` | Launch-template and Auto Scaling constraints |  | EXCLUDED | Clarifying section (constraints); folded into ec2.yaml entries. |
| `autoscalingsetdesiredcapacity--activate-a-stored-launch-template-and-instance-role` | `autoscaling:SetDesiredCapacity` — activate a stored launch template and instance role | autoscaling:SetDesiredCapacity | EXCLUDED | Starts a fixed stored workload; the source controls nothing that runs under the role. |
| `ec2-instance-connectsendsshpublickey` | `ec2-instance-connect:SendSSHPublicKey` | ec2-instance-connect:SendSSHPublicKey | COVERED | `aws-ec2-instance-connect-sendsshpublickey` |
| `ec2-instance-connectsendserialconsolesshpublickey` | `ec2-instance-connect:SendSerialConsoleSSHPublicKey` | ec2-instance-connect:SendSerialConsoleSSHPublicKey | EXCLUDED | Serial console still requires a valid OS user password; not derivable from permissions (and serial console must be enabled account-wide). |
| `ec2enableserialconsoleaccess--unlock-the-account-level-gate-for-serial-console-access` | `ec2:EnableSerialConsoleAccess` — unlock the account-level gate for serial-console access | ec2:EnableSerialConsoleAccess | EXCLUDED | Only lifts the account-level gate; reaching an instance still requires serial-console key push and an OS account password, so the permission alone yields no new identity (consistent with the SendSerialConsoleSSHPublicKey exclusion). |
| `ec2describelaunchtemplateversions-ec2describelaunchtemplates-optional` | `ec2:DescribeLaunchTemplateVersions` (`ec2:DescribeLaunchTemplates` optional) | ec2:DescribeLaunchTemplateVersions, ec2:DescribeLaunchTemplates | EXCLUDED | Data read (secrets in user data).<br>`aws-ec2-launchtemplate-embedded-iam-key` — conditional verified exact-target authority. |
| `ec2modifyinstancemetadataoptions-imds-downgrade-to-enable-ssrf-credential-theft` | `ec2:ModifyInstanceMetadataOptions` (IMDS downgrade to enable SSRF credential theft) | ec2:ModifyInstanceMetadataOptions | EXCLUDED | Requires a separate SSRF vulnerability in the instance's application; not derivable from the snapshot. |
| `ec2modifyinstancemetadatadefaults--account-wide-imds-downgrade` | `ec2:ModifyInstanceMetadataDefaults` — account-wide IMDS downgrade | ec2:ModifyInstanceMetadataDefaults | EXCLUDED | Weakens IMDS defaults for future launches only; credential theft still needs a separate SSRF or code-execution foothold in a workload, so it is a defense-weakening misconfiguration rather than an edge (consistent with the ModifyInstanceMetadataOptions exclusion). |
| `ec2modifyimageattribute-ec2modifysnapshotattribute` | `ec2:ModifyImageAttribute`, `ec2:ModifySnapshotAttribute` | ec2:ModifyImageAttribute, ec2:ModifySnapshotAttribute | EXCLUDED | Data sharing/exfiltration; no identity gain. |
| `ec2getpassworddata` | `ec2:GetPasswordData` | ec2:GetPasswordData | EXCLUDED | Needs the key-pair private key; yields an OS login, whose instance-role reach depends on network access. Treated as data read. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ecr-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ecr-privesc` | AWS - ECR Privesc |  | STRUCTURAL | Page title / references list |
| `ecr` | ECR |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `ecrgetauthorizationtoken-ecrbatchgetimage-ecrgetdownloadurlforlayer` | `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` | ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer | EXCLUDED | Data read.<br>`aws-ecr-image-embedded-credential` — conditional verified exact-target authority. |
| `ecrgetauthorizationtoken-ecrbatchchecklayeravailability-ecrbatchgetimage-ecrcompletelayerupload-ecrinitiatelayerupload-ecrputimage-ecruploadlayerpart` | `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`, `ecr:CompleteLayerUpload`, `ecr:InitiateLayerUpload`, ` | ecr:PutImage, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:BatchGetImage | EXCLUDED | Excluded: The ecr:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecr-publicgetauthorizationtoken-stsgetservicebearertoken-ecr-publicbatchchecklayeravailability-ecr-publiccompletelayerupload-ecr-publicinitiatelayerupload-ecr-publicputimage-ecr-publicuploadlayerpart` | `ecr-public:GetAuthorizationToken`, `sts:GetServiceBearerToken`, `ecr-public:BatchCheckLayerAvailability`, `ecr-public:CompleteLayerUpload`, | ecr-public:GetAuthorizationToken, sts:GetServiceBearerToken, ecr-public:InitiateLayerUpload, ecr-public:UploadLayerPart, ecr-public:CompleteLayerUpload, ecr-public:BatchCheckLayerAvailability, ecr-public:PutImage | EXCLUDED | Excluded: The ecr-public:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecrsetrepositorypolicy--self-grant-private-image-access` | `ecr:SetRepositoryPolicy` — Self-grant private-image access | ecr:SetRepositoryPolicy, ecr:GetAuthorizationToken | EXCLUDED | Excluded: The ecr:SetRepositoryPolicy source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecr-publicsetrepositorypolicy` | `ecr-public:SetRepositoryPolicy` | ecr-public:SetRepositoryPolicy, ecr-public:GetAuthorizationToken, sts:GetServiceBearerToken | EXCLUDED | Excluded: The ecr-public:SetRepositoryPolicy source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecrputregistrypolicy` | `ecr:PutRegistryPolicy` | ecr:PutRegistryPolicy, ecr:GetAuthorizationToken | EXCLUDED | Excluded: The ecr:PutRegistryPolicy source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecrcreatepullthroughcacherule` | `ecr:CreatePullThroughCacheRule` | ecr:CreatePullThroughCacheRule | EXCLUDED | Excluded: The ecr:CreatePullThroughCacheRule source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `ecrputimagetagmutability` | `ecr:PutImageTagMutability` | ecr:PutImageTagMutability, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:PutImage | EXCLUDED | Excluded: The ecr:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `global-registry-hijack-via-root-pull-through-cache-rule` | Global registry hijack via ROOT Pull-Through Cache rule |  | EXCLUDED | Folded into aws-ecr-createpullthroughcacherule (condition root_prefix). |
| `ecrputaccountsetting-registry-policy-scope` | `ecr:PutAccountSetting` (registry policy scope) | ecr:PutAccountSetting | EXCLUDED | HackTricks documents the V2-to-V1 downgrade as no longer supported. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ecs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ecs-privesc` | AWS - ECS Privesc |  | STRUCTURAL | Page title / references list |
| `ecs` | ECS |  | STRUCTURAL | Service introduction linking to the ECS enumeration page. |
| `iampassrole-ecsregistertaskdefinition-ecsruntask` | `iam:PassRole`, `ecs:RegisterTaskDefinition`, `ecs:RunTask` | iam:PassRole, ecs:RegisterTaskDefinition, ecs:RunTask | COVERED | `aws-ecs-passrole-registertaskdefinition-runtask` |
| `iampassrole-ecsruntask` | `iam:PassRole`, `ecs:RunTask` | iam:PassRole, ecs:RunTask | COVERED | `aws-ecs-passrole-runtask-overrides` |
| `iampassrole-ecsregistertaskdefinition-ecsstarttask` | `iam:PassRole`, `ecs:RegisterTaskDefinition`, `ecs:StartTask` | iam:PassRole, ecs:RegisterTaskDefinition, ecs:StartTask | COVERED | `aws-ecs-passrole-registertaskdefinition-starttask` |
| `iampassrole-ecsregistertaskdefinition-ecsupdateserviceecscreateservice` | `iam:PassRole`, `ecs:RegisterTaskDefinition`, (`ecs:UpdateService\|ecs:CreateService)` | iam:PassRole, ecs:RegisterTaskDefinition, ecs:CreateService, ecs:UpdateService | COVERED | `aws-ecs-passrole-registertaskdefinition-service` |
| `ecsupdateservice--reactivate-a-dormant-service-with-its-stored-task-role` | `ecs:UpdateService` — Reactivate a dormant service with its stored task role | ecs:UpdateService | EXCLUDED | Starts a fixed stored workload; no attacker-controlled execution under the role. |
| `mutable-ecr-tag-consumed-by-an-ecs-service-deployment-digest-boundary` | Mutable ECR tag consumed by an ECS service: deployment digest boundary | ecr:PutImage, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:BatchGetImage | EXCLUDED | Excluded: The ecr:PutImage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. — Covered by aws-ecr-push-consumed-tag (digest boundary recorded there). |
| `runtime-command-overrides-with-iampassrole-and-ecsruntask` | Runtime command overrides with `iam:PassRole` and `ecs:RunTask` | iam:PassRole, ecs:RunTask | COVERED | `aws-ecs-passrole-runtask-overrides` — Duplicate of aws-ecs-passrole-runtask-overrides. |
| `ecsregistertaskdefinition-and-a-task-launching-action` | `ecs:RegisterTaskDefinition` and a task-launching action | ecs:RegisterTaskDefinition, ecs:RunTask, ecs:StartTask, ecs:CreateService, ecs:UpdateService | COVERED | `aws-ecs-registertaskdefinition-node-escape` |
| `ecsexecutecommand-ecsdescribetasks-and-optionally-a-task-launching-action` | `ecs:ExecuteCommand`, `ecs:DescribeTasks`, and optionally a task-launching action | ecs:ExecuteCommand, ecs:DescribeTasks | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `ssmstartsession` | `ssm:StartSession` | ssm:StartSession | EXCLUDED | Owned by ssm.yaml (part B). |
| `iampassrole-ec2runinstances` | `iam:PassRole`, `ec2:RunInstances` | iam:PassRole, ec2:RunInstances | EXCLUDED | Modelled as aws-ec2-runinstances-join-ecs-cluster. |
| `ecsregistercontainerinstance-ecsderegistercontainerinstance-ecsstarttask-iampassrole` | `ecs:RegisterContainerInstance`, `ecs:DeregisterContainerInstance`, `ecs:StartTask`, `iam:PassRole` | ecs:RegisterContainerInstance, ecs:StartTask, iam:PassRole | EXCLUDED | Source control of a connected ECS container host and target task placement are unverified; see archived aws-ecs-registercontainerinstance-starttask and aws-ecs-registercontainerinstance-scheduled-tasks. |
| `ecsregistertaskdefinition-ecscreatetaskset-ecsupdateserviceprimarytaskset-ecsdescribetasksets` | `ecs:RegisterTaskDefinition`, `ecs:CreateTaskSet`, `ecs:UpdateServicePrimaryTaskSet`, `ecs:DescribeTaskSets` | ecs:RegisterTaskDefinition, ecs:CreateTaskSet, ecs:UpdateServicePrimaryTaskSet, iam:PassRole | COVERED | `aws-ecs-taskset-primary` |
| `hijack-ecs-scheduling-via-malicious-capacity-provider-ec2-asg-takeover` | Hijack ECS Scheduling via Malicious Capacity Provider (EC2 ASG takeover) | ecs:CreateCapacityProvider, ecs:PutClusterCapacityProviders, ecs:UpdateService, autoscaling:CreateAutoScalingGroup, ec2:RunInstances, iam:PassRole | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `backdoor-compute-in-cluster-via-ecs-anywhere-external-registration` | Backdoor compute in-cluster via ECS Anywhere EXTERNAL registration |  | EXCLUDED | Requires iam:PassRole on task roles plus a task launch, already covered by aws-ecs-passrole-registertaskdefinition-starttask / aws-ecs-registercontainerinstance-starttask (plus ssm:CreateActivation). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ecs-privesc/aws-ecscape-privesc.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ecscape-ecs-task-role-privesc` | AWS - ECScape ECS Task Role Privesc |  | STRUCTURAL | Page title / references list |
| `ecs` | ECS |  | EXCLUDED | Background on the ECS agent credential channel; the technique is mapped by aws-ecs-ecscape-agent-impersonation. |
| `impersonate-the-ecs-agent-to-obtain-co-located-task-credentials` | Impersonate the ECS agent to obtain co-located task credentials | ecs:DiscoverPollEndpoint, ecs:Poll | COVERED | `aws-ecs-ecscape-agent-impersonation` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-efs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---efs-privesc` | AWS - EFS Privesc |  | STRUCTURAL | Page title / references list |
| `efs` | EFS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `elasticfilesystemdeletefilesystempolicyelasticfilesystemputfilesystempolicy` | `elasticfilesystem:DeleteFileSystemPolicy`\|`elasticfilesystem:PutFileSystemPolicy` | elasticfilesystem:DeleteFileSystemPolicy, elasticfilesystem:PutFileSystemPolicy | COVERED | `aws-efs-putfilesystempolicy-self-grant` — reviewed exact self permission gain; broader variants remain excluded. |
| `elasticfilesystemclientmount-and-client-action-combinations` | `elasticfilesystem:ClientMount` and client-action combinations | elasticfilesystem:ClientMount | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `elasticfilesystemcreateaccesspoint--elasticfilesystemclientmount` | `elasticfilesystem:CreateAccessPoint + elasticfilesystem:ClientMount` | elasticfilesystem:CreateAccessPoint, elasticfilesystem:ClientMount | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `elasticfilesystemcreatemounttarget` | `elasticfilesystem:CreateMountTarget` | elasticfilesystem:CreateMountTarget | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `elasticfilesystemmodifymounttargetsecuritygroups` | `elasticfilesystem:ModifyMountTargetSecurityGroups` | elasticfilesystem:ModifyMountTargetSecurityGroups | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-eks-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---eks-privesc` | AWS - EKS Privesc |  | STRUCTURAL | Page title / references list |
| `eks` | EKS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `ekscreateaccessentry-eksassociateaccesspolicy--iam-only-path-to-cluster-admin` | `eks:CreateAccessEntry`, `eks:AssociateAccessPolicy` — IAM-only path to cluster-admin | eks:CreateAccessEntry, eks:AssociateAccessPolicy | COVERED | `aws-eks-createaccessentry-associateaccesspolicy` |
| `ekscreateaccessentry-alone--join-an-existing-privileged-kubernetes-group` | `eks:CreateAccessEntry` alone — join an existing privileged Kubernetes group | eks:CreateAccessEntry | EXCLUDED | excluded: "Create an EKS access entry that places the source in an existing privileged Kubernetes group"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |
| `eksupdateaccessentry--escalate-an-access-entry-that-already-exists` | `eks:UpdateAccessEntry` — escalate an access entry that already exists | eks:UpdateAccessEntry | EXCLUDED | excluded: "Rewrite the Kubernetes groups of an existing EKS access entry"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |
| `ekscreatepodidentityassociation-iampassrole-iamgetrole--bind-an-aws-role-to-a-namespace-you-control` | `eks:CreatePodIdentityAssociation`, `iam:PassRole`, `iam:GetRole` — bind an AWS role to a namespace you control | eks:CreatePodIdentityAssociation, iam:PassRole, iam:GetRole | EXCLUDED | excluded: "Bind a passable role to a Kubernetes service account through EKS Pod Identity"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |
| `eksupdatepodidentityassociation-iampassrole--repoint-an-existing-association-role-swap-cross-account-chaining-tag-guardrail-bypass` | `eks:UpdatePodIdentityAssociation`, `iam:PassRole` — repoint an existing association (role swap, cross-account chaining, tag-guardrail bypas | eks:UpdatePodIdentityAssociation, iam:PassRole | EXCLUDED | excluded: "Repoint an existing EKS Pod Identity association to another passable role"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |
| `eksupdateclusterconfig--expose-the-api-server-to-the-internet` | `eks:UpdateClusterConfig` — expose the API server to the internet | eks:UpdateClusterConfig | EXCLUDED | Changes network exposure of the API endpoint (public access / CIDR allowlist) but grants no Kubernetes or AWS identity; reaching the API still needs an authorized principal. Network exposure is evaluated by the exposure checks, not as a privesc edge. |
| `iampassrole-ekscreatenodegroup--ekscreatefargateprofile--run-pods-on-capacity-you-control` | `iam:PassRole`, `eks:CreateNodegroup` / `eks:CreateFargateProfile` — run pods on capacity you control | eks:CreateNodegroup, iam:PassRole | EXCLUDED | excluded: "Create a managed node group with a passed node role"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-elastic-beanstalk-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---elastic-beanstalk-privesc` | AWS - Elastic Beanstalk Privesc |  | STRUCTURAL | Page title / references list |
| `elastic-beanstalk` | Elastic Beanstalk |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `elasticbeanstalkupdateenvironment` | `elasticbeanstalk:UpdateEnvironment` | elasticbeanstalk:UpdateEnvironment | EXCLUDED | Excluded: UpdateEnvironment alone does not prove the runtime interprets the chosen environment value as code or that source-controlled executable content is available to the instances. |
| `elasticbeanstalkrebuildenvironment-s3-write-permissions--many-others` | `elasticbeanstalk:RebuildEnvironment`, S3 write permissions & many others | elasticbeanstalk:RebuildEnvironment, s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `elasticbeanstalkcreateapplication-elasticbeanstalkcreateenvironment-elasticbeanstalkcreateapplicationversion-elasticbeanstalkupdateenvironment-iampassrole-and-more` | `elasticbeanstalk:CreateApplication`, `elasticbeanstalk:CreateEnvironment`, `elasticbeanstalk:CreateApplicationVersion`, `elasticbeanstalk:U | iam:PassRole, elasticbeanstalk:CreateApplication, elasticbeanstalk:CreateEnvironment, elasticbeanstalk:CreateApplicationVersion, elasticbeanstalk:UpdateEnvironment, s3:PutObject, cloudformation:CreateStack, ec2:RunInstances, autoscaling:CreateAutoScalingGroup | COVERED | `aws-elasticbeanstalk-passrole-create-environment` |
| `elasticbeanstalkcreateapplicationversion-elasticbeanstalkupdateenvironment-cloudformationgettemplate-cloudformationdescribestackresources-cloudformationdescribestackresource-autoscalingdescribeautoscalinggroups-autoscalingsuspendprocesses` | `elasticbeanstalk:CreateApplicationVersion`, `elasticbeanstalk:UpdateEnvironment`, `cloudformation:GetTemplate`, `cloudformation:DescribeSta | elasticbeanstalk:CreateApplicationVersion, elasticbeanstalk:UpdateEnvironment, cloudformation:GetTemplate, cloudformation:DescribeStackResources, cloudformation:DescribeStackResource, autoscaling:DescribeAutoScalingGroups, autoscaling:SuspendProcesses | EXCLUDED | Excluded: The elasticbeanstalk_environment resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `elasticbeanstalkdescribeenvironmentresources-elasticloadbalancingmodifyloadbalancerattributes-s3putbucketpolicy-s3listbucket-s3getobject-to-enable-alb-access-logs-exfiltration` | `elasticbeanstalk:DescribeEnvironmentResources`, `elasticloadbalancing:ModifyLoadBalancerAttributes`, `s3:PutBucketPolicy`, `s3:ListBucket`, | elasticbeanstalk:DescribeEnvironmentResources, elasticloadbalancing:ModifyLoadBalancerAttributes, s3:PutBucketPolicy, s3:ListBucket, s3:GetObject | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-elasticache-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---elasticache-privesc` | AWS - ElastiCache Privesc |  | STRUCTURAL | Page title / references list |
| `elasticache` | ElastiCache |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `privilege-escalation-take-over-and-widen-an-rbac-user-with-elasticachemodifyuser` | Privilege escalation: take over and widen an RBAC user with `elasticache:ModifyUser` | elasticache:ModifyUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-emr-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---emr-privesc` | AWS - EMR Privesc |  | STRUCTURAL | Page title / references list |
| `emr` | EMR |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole-elasticmapreducerunjobflow` | `iam:PassRole`, `elasticmapreduce:RunJobFlow` | iam:PassRole, elasticmapreduce:RunJobFlow | COVERED | `aws-emr-passrole-runjobflow` |
| `elasticmapreduceaddjobflowsteps--execute-as-an-existing-cluster-instance-profile` | `elasticmapreduce:AddJobFlowSteps` — execute as an existing cluster instance profile | elasticmapreduce:AddJobFlowSteps | EXCLUDED | Excluded: The emr_cluster resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `s3putobject-on-a-configured-bootstrap-or-step-script` | `s3:PutObject` on a configured bootstrap or step script | s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `elasticmapreducecreateeditor-iamlistroles-elasticmapreducelistclusters-iampassrole-elasticmapreducedescribeeditor-elasticmapreduceopeneditorinconsole` | `elasticmapreduce:CreateEditor`, `iam:ListRoles`, `elasticmapreduce:ListClusters`, `iam:PassRole`, `elasticmapreduce:DescribeEditor`, `elast | elasticmapreduce:CreateEditor, iam:ListRoles, elasticmapreduce:ListClusters, iam:PassRole, elasticmapreduce:DescribeEditor, elasticmapreduce:OpenEditorInConsole | EXCLUDED | Outdated: legacy EMR Notebooks editor API is not in the current service model; cannot be verified. |
| `legacy-elasticmapreduceopeneditorinconsole-boundary` | Legacy `elasticmapreduce:OpenEditorInConsole` boundary | elasticmapreduce:OpenEditorInConsole | EXCLUDED | Outdated legacy notebook path; the page itself documents it as a boundary/non-path. |
| `elasticmapreducegetclustersessioncredentials--vend-a-runtime-roles-credentials-without-iampassrole` | `elasticmapreduce:GetClusterSessionCredentials` — vend a runtime role's credentials without `iam:PassRole` | elasticmapreduce:GetClusterSessionCredentials | COVERED | `aws-emr-getclustersessioncredentials-runtime-role` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-emr-serverless-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---emr-serverless--emr-on-eks-privesc` | AWS - EMR Serverless & EMR on EKS Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-emr-serverless` | Amazon EMR Serverless |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `emr-serverless--emr-on-eks` | EMR Serverless / EMR on EKS |  | STRUCTURAL | Service overview; the job-run, managed-endpoint, session and application techniques are their own headings. |
| `emr-serverlessstartjobrun--emr-containersstartjobrun--iampassrole` | `emr-serverless:StartJobRun` / `emr-containers:StartJobRun` + `iam:PassRole` | iam:PassRole, emr-serverless:StartJobRun, emr-containers:StartJobRun | COVERED | `aws-emr-serverless-passrole-startjobrun`, `aws-emr-containers-passrole-startjobrun`, `aws-emr-containers-passrole-startjobrun-pod-identity` |
| `emr-containersgetmanagedendpointsessioncredentials--iampassrole--interactive-spark-session-as-the-execution-role` | `emr-containers:GetManagedEndpointSessionCredentials` (+ `iam:PassRole`) — interactive Spark session as the execution role | iam:PassRole, emr-containers:GetManagedEndpointSessionCredentials | COVERED | `aws-emr-containers-getmanagedendpointsessioncredentials` |
| `emr-serverlessgetsessionendpoint--take-over-an-existing-spark-connect-session` | `emr-serverless:GetSessionEndpoint` — take over an existing Spark Connect session | emr-serverless:GetSessionEndpoint | EXCLUDED | Excluded: The emr-serverless_session resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `emr-serverlessupdateapplication` | `emr-serverless:UpdateApplication` | emr-serverless:UpdateApplication | EXCLUDED | Excluded: The emr-serverless_application resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-entity-resolution-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---entity-resolution-privesc` | AWS - Entity Resolution Privesc |  | STRUCTURAL | Page title / references list |
| `entity-resolution` | Entity Resolution |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `pass-a-workflow-role-to-read-and-export-identity-data` | Pass a workflow role to read and export identity data |  | STRUCTURAL | Legacy anchor points to the bounded data or application operation on its post-exploitation page. |

| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-eventbridge-pipe-stored-role-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---eventbridge-pipes-privesc` | AWS - EventBridge Pipes Privesc |  | STRUCTURAL | Page title / references list |
| `eventbridge-pipes` | EventBridge Pipes |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `pipesstartpipe--execute-a-stopped-pipe-with-its-stored-role` | `pipes:StartPipe` — execute a stopped pipe with its stored role | pipes:StartPipe | EXCLUDED | Previously mapped to `aws-pipes-startpipe-stored-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-eventbridge-pipes-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---eventbridge-pipes-privesc` | AWS - EventBridge Pipes Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-eventbridge-pipes` | Amazon EventBridge Pipes |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `eventbridge-pipes` | EventBridge Pipes |  | STRUCTURAL | Service heading; the CreatePipe/UpdatePipe technique is mapped under its own heading. |
| `pipescreatepipe-or-updatepipe--iampassrole` | `pipes:CreatePipe` (or `UpdatePipe`) + `iam:PassRole` | iam:PassRole, pipes:CreatePipe, pipes:UpdatePipe | EXCLUDED | Previously mapped to `aws-pipes-passrole-createpipe-or-updatepipe`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-eventbridge-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---eventbridge-privesc` | AWS - EventBridge Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-eventbridge` | Amazon EventBridge |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `eventsputtargets--eventsputevents--invoke-a-resource-policy-authorized-lambda` | `events:PutTargets` + `events:PutEvents` — invoke a resource-policy-authorized Lambda | events:PutTargets, events:PutEvents | EXCLUDED | Invokes a fixed Lambda with attacker input; no control of code or role. |
| `eventsputpermission--self-grant-publishing-through-a-bus-policy` | `events:PutPermission` — self-grant publishing through a bus policy | events:PutPermission | EXCLUDED | Grants event-bus publishing; input injection only. |
| `eventsputrule--enable-a-disabled-rule-with-its-existing-target` | `events:PutRule` — enable a disabled rule with its existing target | events:PutRule | EXCLUDED | Runs an existing fixed target; no control of code or role. |
| `eventsstartreplay--replay-retained-events-into-unchanged-targets` | `events:StartReplay` — replay retained events into unchanged targets | events:StartReplay | EXCLUDED | Replays events into fixed targets; no control of code or role. |
| `eventsupdateapidestination--redirect-stored-connection-credentials` | `events:UpdateApiDestination` — redirect stored Connection credentials | events:UpdateApiDestination | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `eventscreatesubscriber--iampassrole--execute-supported-aws-apis-through-an-enhanced-bus-universal-target` | `events:CreateSubscriber` + `iam:PassRole` — execute supported AWS APIs through an enhanced-bus universal target | iam:PassRole, events:CreateSubscriber | COVERED | `aws-events-passrole-createsubscriber-universal-target` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-fis-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---fault-injection-service-privesc` | AWS - Fault Injection Service Privesc |  | STRUCTURAL | Page title / references list |
| `fault-injection-service` | Fault Injection Service |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `fis` | FIS |  | STRUCTURAL | Service heading; the UpdateExperimentTemplate + StartExperiment technique is mapped under its own heading. |
| `updateexperimenttemplate--startexperiment-through-the-stored-role` | `UpdateExperimentTemplate` + `StartExperiment` through the stored role | fis:UpdateExperimentTemplate, fis:StartExperiment | EXCLUDED | Previously mapped to `aws-fis-updateexperimenttemplate-startexperiment`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `iam-resource-scope-details` | IAM resource-scope details | fis:UpdateExperimentTemplate, fis:StartExperiment | EXCLUDED | Previously mapped to `aws-fis-updateexperimenttemplate-startexperiment`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `discovery-when-fis-reads-are-denied` | Discovery when FIS reads are denied |  | STRUCTURAL | Enumeration guidance for the FIS technique. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-gamelift-streams-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---gamelift-streams-privesc` | AWS - GameLift Streams Privesc |  | STRUCTURAL | Page title / references list |
| `gamelift-streams` | GameLift Streams |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `gameliftstreamscreatestreamsessionadminshell-on-a-session-with-a-role` | `gameliftstreams:CreateStreamSessionAdminShell` on a session with a role | gameliftstreams:CreateStreamSessionAdminShell | EXCLUDED | Excluded: The gameliftstreams_stream_session resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `gameliftstreamsstartstreamsession--iampassrole-with-attacker-controlled-application-code` | `gameliftstreams:StartStreamSession` + `iam:PassRole` with attacker-controlled application code | iam:PassRole, gameliftstreams:StartStreamSession, gameliftstreams:CreateStreamUrl | COVERED | `aws-gameliftstreams-passrole-startstreamsession` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-gamelift/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---gamelift` | AWS - Gamelift |  | STRUCTURAL | Page title / references list |
| `gamelift-servers` | GameLift Servers |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `gameliftrequestuploadcredentials` | `gamelift:RequestUploadCredentials` | gamelift:RequestUploadCredentials | EXCLUDED | Returns credentials scoped by GameLift to uploading a build to a service-owned S3 location; does not expose a customer principal's privileges. |
| `gameliftcreatefleet--iampassrole--run-code-on-fleet-ec2-as-a-passed-instance-role` | `gamelift:CreateFleet` + `iam:PassRole` — run code on fleet EC2 as a passed instance role | iam:PassRole, gamelift:CreateFleet | COVERED | `aws-gamelift-passrole-createfleet` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-glue-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---glue-privesc` | AWS - Glue Privesc |  | STRUCTURAL | Page title / references list |
| `glue` | Glue |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `create-an-interactive-session-with-a-privileged-role` | Create an interactive session with a privileged role | iam:PassRole, glue:CreateSession, glue:RunStatement | COVERED | `aws-glue-passrole-createsession` |
| `execute-code-in-an-existing-interactive-session` | Execute code in an existing interactive session | glue:RunStatement | COVERED | `aws-glue-runstatement-interactive-session` |
| `create-or-modify-and-run-a-glue-job` | Create or modify and run a Glue job | glue:StartJobRun, s3:PutObject, iam:PassRole, glue:CreateJob, glue:CreateTrigger, glue:UpdateJob | COVERED | `aws-glue-startjobrun-override-script`, [excluded former aws-glue-s3-putobject-job-script], `aws-glue-passrole-createjob-or-updatejob-run`, `aws-glue-updatejob-existing-role` |
| `create-a-legacy-development-endpoint-with-a-privileged-role` | Create a legacy development endpoint with a privileged role | iam:PassRole, glue:CreateDevEndpoint, glue:GetDevEndpoint, glue:GetDevEndpoints | COVERED | `aws-glue-passrole-createdevendpoint` |
| `replace-the-ssh-key-on-a-legacy-development-endpoint` | Replace the SSH key on a legacy development endpoint | glue:UpdateDevEndpoint | COVERED | `aws-glue-updatedevendpoint` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-healthomics-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---healthomics-privilege-escalation` | AWS - HealthOmics Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `healthomics` | HealthOmics |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `omicsstartrun--iampassrole` | `omics:StartRun` + `iam:PassRole` | iam:PassRole, omics:StartRun | EXCLUDED | Excluded: StartRun and PassRole do not prove the selected workflow executes source-controlled code; workflow control is only a prose condition. |
| `importexport-jobs--iampassrole` | Import/export jobs + `iam:PassRole` | iam:PassRole | EXCLUDED | Data-only confused deputy limited to genomic import/export; no credentials or code execution as the role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-iam-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---iam-privesc` | AWS - IAM Privesc |  | STRUCTURAL | Page title / references list |
| `iam` | IAM |  | STRUCTURAL | Service introduction linking to the IAM enumeration page. |
| `iamcreatepolicyversion` | **`iam:CreatePolicyVersion`** | iam:CreatePolicyVersion | COVERED | `aws-iam-createpolicyversion-self`, `aws-iam-createpolicyversion-assumable-role` |
| `iamsetdefaultpolicyversion` | **`iam:SetDefaultPolicyVersion`** | iam:SetDefaultPolicyVersion | COVERED | `aws-iam-setdefaultpolicyversion-self` |
| `iamcreateaccesskey-iamdeleteaccesskey` | **`iam:CreateAccessKey`, (`iam:DeleteAccessKey`)** | iam:CreateAccessKey | COVERED | `aws-iam-createaccesskey-other-user` |
| `iamcreateloginprofile--iamupdateloginprofile` | **`iam:CreateLoginProfile` \| `iam:UpdateLoginProfile`** | iam:CreateLoginProfile, iam:UpdateLoginProfile | COVERED | `aws-iam-createloginprofile-other-user`, `aws-iam-updateloginprofile-other-user` |
| `iamupdateaccesskey` | **`iam:UpdateAccessKey`** | iam:UpdateAccessKey | EXCLUDED | Only re-activates an existing key; using it requires already knowing the target's secret access key, so the permission alone does not yield a new identity. |
| `iamcreateservicespecificcredential--iamresetservicespecificcredential` | **`iam:CreateServiceSpecificCredential` \| `iam:ResetServiceSpecificCredential`** | iam:CreateServiceSpecificCredential, iam:ResetServiceSpecificCredential | COVERED | `aws-iam-createservicespecificcredential-other-user` |
| `iamattachuserpolicy--iamattachgrouppolicy` | **`iam:AttachUserPolicy` \|\| `iam:AttachGroupPolicy`** | iam:AttachUserPolicy, iam:AttachGroupPolicy | COVERED | `aws-iam-attachuserpolicy-self`, `aws-iam-attachgrouppolicy-self` |
| `iamattachrolepolicy-stsassumerole--iamcreaterole--iamputuserpolicy--iamputgrouppolicy--iamputrolepolicy` | **`iam:AttachRolePolicy`**, (`sts:AssumeRole` \| `iam:CreateRole`) \| **`iam:PutUserPolicy` \| `iam:PutGroupPolicy` \| `iam:PutRolePolicy`** | iam:PutUserPolicy, iam:PutGroupPolicy, iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreateRole | COVERED | `aws-iam-putuserpolicy-self`, `aws-iam-putgrouppolicy-self`, `aws-iam-attachrolepolicy-self`, `aws-iam-putrolepolicy-self`, `aws-iam-modify-assumable-role-policy`, `aws-iam-createrole-attach-assume` |
| `iamaddusertogroup` | **`iam:AddUserToGroup`** | iam:AddUserToGroup | COVERED | `aws-iam-addusertogroup` |
| `iamupdateassumerolepolicy` | **`iam:UpdateAssumeRolePolicy`** | iam:UpdateAssumeRolePolicy | COVERED | `aws-iam-updateassumerolepolicy` |
| `iampassrole--a-compute-service` | **`iam:PassRole`** (+ a compute service) | iam:PassRole | EXCLUDED | Generic overview; each service-specific PassRole technique is modelled per service with the correct trusted service principal. |
| `iamuploadsshpublickey--iamdeactivatemfadevice` | **`iam:UploadSSHPublicKey` \|\| `iam:DeactivateMFADevice`** | iam:UploadSSHPublicKey | COVERED | `aws-iam-uploadsshpublickey-other-user`<br>`aws-iam-deactivate-mfa-loginprofile-other-user` |
| `iamresyncmfadevice` | **`iam:ResyncMFADevice`** | iam:ResyncMFADevice | EXCLUDED | Requires possession of the target's MFA device and password; no new identity from the permission alone. |
| `iamupdatesamlprovider-iamlistsamlproviders-iamgetsamlprovider` | `iam:UpdateSAMLProvider`, `iam:ListSAMLProviders`, (`iam:GetSAMLProvider`) | iam:UpdateSAMLProvider | COVERED | `aws-iam-updatesamlprovider` |
| `iamupdateopenidconnectproviderthumbprint-iamlistopenidconnectproviders-iamgetopenidconnectprovider` | `iam:UpdateOpenIDConnectProviderThumbprint`, `iam:ListOpenIDConnectProviders`, (`iam:`**`GetOpenIDConnectProvider`**) | iam:UpdateOpenIDConnectProviderThumbprint, iam:ListOpenIDConnectProviders | EXCLUDED | AWS validates tokens of most major IdPs against its own trusted CA library and ignores thumbprints; exploitation also requires man-in-the-middle of the IdP JWKS endpoint. Not reliably derivable from a snapshot. |
| `iamputuserpermissionsboundary` | `iam:PutUserPermissionsBoundary` | iam:PutUserPermissionsBoundary, iam:DeleteUserPermissionsBoundary | EXCLUDED | Excluded: Deleting or replacing a boundary is a permission gain only if a restrictive boundary currently limits broader identity policies; that before/after effective permission is not evaluated. |
| `iamputrolepermissionsboundary` | `iam:PutRolePermissionsBoundary` | iam:PutRolePermissionsBoundary, iam:DeleteRolePermissionsBoundary | EXCLUDED | [excluded former aws-iam-putrolepermissionsboundary-self]<br>Excluded: The assumable role may have no restrictive boundary or admin-equivalent policy behind it; no exact before/after effective permission proof supports account-admin. |
| `iamcreatevirtualmfadevice-iamenablemfadevice-and-the-target-users-access-keys` | **`iam:CreateVirtualMFADevice`, `iam:EnableMFADevice`, and the target user's access keys** | iam:CreateVirtualMFADevice, iam:EnableMFADevice | COVERED | Requires the target user's access keys already; it only satisfies MFA conditions for an identity already held. Modelled as no new identity.<br>`aws-iam-enable-attacker-mfa-device-other-user` |
| `iamupdateuser--iamupdategroup--moving-the-target-into-a-path-you-already-control` | `iam:UpdateUser` \| `iam:UpdateGroup` — moving the target into a path you already control | iam:UpdateUser, iam:CreateAccessKey, iam:CreateLoginProfile, iam:UpdateLoginProfile, iam:UpdateGroup, iam:AddUserToGroup | EXCLUDED | [excluded former aws-iam-updateuser-path-move], [excluded former aws-iam-updategroup-path-move]<br>[excluded former aws-iam-updateuser-path-move-self-policy]<br>Excluded: No exact post-move group ARN is proven to satisfy both UpdateGroup and policy-edit authorization; the evaluator checks any group path. |
| `iamuploadsigningcertificate--plant-a-credential-on-another-user` | `iam:UploadSigningCertificate` — plant a credential on another user | iam:UploadSigningCertificate | EXCLUDED | IAM X.509 signing certificates authenticate only legacy SOAP API requests, which current AWS services no longer accept; they cannot sign SigV4 requests or obtain STS credentials, so the planted certificate yields no usable identity. Persistence/hygiene concern only. |
| `iamcreateopenidconnectprovider--iamcreatesamlprovider--bring-your-own-identity-provider` | `iam:CreateOpenIDConnectProvider` \| `iam:CreateSAMLProvider` — bring your own identity provider | iam:DeleteSAMLProvider, iam:CreateSAMLProvider, iam:CreateOpenIDConnectProvider | COVERED | `aws-iam-recreate-samlprovider`, `aws-iam-createsamlprovider-orphaned-trust`, [excluded former aws-iam-createoidcprovider-orphaned-trust] |
| `iamaddclientidtoopenidconnectprovider--widen-an-existing-federation-trust` | `iam:AddClientIDToOpenIDConnectProvider` — widen an existing federation trust | iam:AddClientIDToOpenIDConnectProvider, iam:DeleteOpenIDConnectProvider, iam:CreateOpenIDConnectProvider | EXCLUDED | Excluded: Adding an audience does not prove the source holds an issuer-signed token whose exact claims satisfy the target role trust. |
| `iam-delegation-requests--iamassociatedelegationrequest-iamacceptdelegationrequest-iamsenddelegationtoken` | IAM delegation requests — `iam:AssociateDelegationRequest`, `iam:AcceptDelegationRequest`, `iam:SendDelegationToken` | iam:AssociateDelegationRequest, iam:AcceptDelegationRequest, iam:SendDelegationToken | EXCLUDED | Accepting a delegation request exports the accepting identity's authority to an onboarded external partner; it does not escalate a principal in the snapshot, and sts:GetDelegatedAccessToken requires a provider-bound trade-in token from the approved workflow. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-invoicing-and-billing-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-invoicing-and-billing-privilege-escalation` | AWS Invoicing and Billing Privilege Escalation |  | STRUCTURAL | Page title. |
| `aws-invoicing-and-billing` | AWS Invoicing and Billing |  | STRUCTURAL | Service introduction linking to the Invoicing enumeration page. |
| `no-direct-iam-role-escalation-primitive` | No direct IAM role escalation primitive |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `turn-cost-view-administration-into-cross-account-disclosure` | Turn cost-view administration into cross-account disclosure |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `enable-previously-granted-legacy-billing-permissions` | Enable previously granted legacy Billing permissions |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `abuse-invoice-receiver-delegation` | Abuse invoice receiver delegation |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `the-billing-service-linked-role-is-not-a-general-escalation-target` | The Billing service-linked role is not a general escalation target |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `related-actions-that-amplify-business-impact-not-iam-authority` | Related actions that amplify business impact, not IAM authority |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-iot-core-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---iot-core-privesc` | AWS - IoT Core Privesc |  | STRUCTURAL | Page title / references list |
| `iot-core` | IoT Core |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `privilege-escalation-iotcreaterolealias--iampassrole--vend-any-iam-role-via-the-iot-credential-provider` | Privilege escalation: `iot:CreateRoleAlias` + `iam:PassRole` → vend any IAM role via the IoT credential provider | iot:CreateRoleAlias, iam:PassRole | EXCLUDED | Duplicate of aws-iot-privesc (catalog entry aws-iot-passrole-rolealias-certificate). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-iot-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---iot-privesc` | AWS - IoT Privesc |  | STRUCTURAL | Page title / references list |
| `iot-core` | IoT Core |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `aws-iot-core` | AWS IoT Core |  | STRUCTURAL | Service background on certificates and role aliases; the technique is the role-alias heading below (aws-iot-passrole-rolealias-certificate). |
| `iotcreaterolealias--updaterolealias--iampassrole--assume-an-arbitrary-role-via-a-device-certificate` | `iot:CreateRoleAlias` / `UpdateRoleAlias` + `iam:PassRole` → assume an arbitrary role via a device certificate | iam:PassRole, iot:CreateKeysAndCertificate, iot:AttachPolicy, iot:CreateRoleAlias, iot:UpdateRoleAlias | COVERED | `aws-iot-passrole-rolealias-certificate` |
| `iotcreateprovisioningtemplate--iampassrole--iotcreateprovisioningclaim--self-replenishing-fleet-of-attacker-certificates` | `iot:CreateProvisioningTemplate` + `iam:PassRole` + `iot:CreateProvisioningClaim` → self-replenishing fleet of attacker certificates | iot:CreateProvisioningTemplate, iam:PassRole, iot:CreateProvisioningClaim | COVERED | `aws-iot-provisioning-claim-existing-rolealias` — only when the issued certificate is verified to reach an exact existing role alias and role. |
| `iotregistercertificatewithoutca--register-an-attacker-generated-byo-certificate-as-a-device-identity` | `iot:RegisterCertificateWithoutCA` → register an attacker-generated (BYO) certificate as a device identity | iot:RegisterCertificateWithoutCA | COVERED | `aws-iot-byo-certificate-existing-rolealias` — only when the issued certificate is verified to reach an exact existing role alias and role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-iot-twinmaker-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---iot-twinmaker-privilege-escalation` | AWS - IoT TwinMaker Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `iot-twinmaker` | IoT TwinMaker |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `connector-invocation-without-direct-lambda-permission` | Connector invocation without direct Lambda permission |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `updateworkspace--iampassrole--connector-control` | `UpdateWorkspace` + `iam:PassRole` + connector control | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-iot-sitewise-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---iot-sitewise-privesc` | AWS - IoT SiteWise Privesc |  | STRUCTURAL | Page title. |
| `sitewise-monitor-portal-permission-grant` | SiteWise Monitor portal permission grant |  | STRUCTURAL | Section context; the grant is mapped under its own heading. |
| `references` | References |  | STRUCTURAL | Reference list. |
| `grant-yourself-access-to-a-legacy-sitewise-monitor-portal` | Grant yourself access to a legacy SiteWise Monitor portal | iotsitewise:CreateAccessPolicy | COVERED | `aws-sitewise-createaccesspolicy-portal-self-grant` — reviewed exact self permission gain; broader variants remain excluded. |

### aws-privilege-escalation/aws-ivs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ivs-privesc` | AWS - IVS Privesc |  | STRUCTURAL | Page title / references list |
| `ivs` | IVS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `ivscreatestreamkey-on-stream-key---publish-to-another-channel` | `ivs:CreateStreamKey` on `stream-key/*` - Publish to another channel | ivs:CreateStreamKey | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ivsgetstreamkey-or-ivsgetingestconfiguration---convert-a-read-into-publishing-access` | `ivs:GetStreamKey` or `ivs:GetIngestConfiguration` - Convert a read into publishing access | ivs:GetStreamKey, ivs:GetIngestConfiguration | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ivscreateparticipanttoken---mint-stage-publishsubscribe-access` | `ivs:CreateParticipantToken` - Mint stage publish/subscribe access | ivs:CreateParticipantToken | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ivsimportpublickey---sign-tokens-for-stages-account-wide` | `ivs:ImportPublicKey` - Sign tokens for stages account-wide | ivs:ImportPublicKey | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ivsimportplaybackkeypair---bypass-private-channel-playback-decisions` | `ivs:ImportPlaybackKeyPair` - Bypass private-channel playback decisions | ivs:ImportPlaybackKeyPair | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ivsstartcomposition---send-a-stage-to-an-unauthorized-channel` | `ivs:StartComposition` - Send a stage to an unauthorized channel | ivs:StartComposition | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-kinesis-data-streams-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-kinesis-data-streams-privilege-escalation` | AWS Kinesis Data Streams Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `kinesis-data-streams` | Kinesis Data Streams |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `createchannel--associatestreamswithchannel--iampassrole` | `CreateChannel` + `AssociateStreamsWithChannel` + `iam:PassRole` | iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-kms-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---kms-privesc` | AWS - KMS Privesc |  | STRUCTURAL | Page title / references list |
| `kms` | KMS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `kmslistkeyskmsputkeypolicy-kmslistkeypolicies-kmsgetkeypolicy` | `kms:ListKeys`,`kms:PutKeyPolicy`, (`kms:ListKeyPolicies`, `kms:GetKeyPolicy`) | kms:ListKeys, kms:PutKeyPolicy, kms:ListKeyPolicies, kms:GetKeyPolicy | EXCLUDED | Grants control/use of a KMS key (cryptographic/data access); no other principal's privileges obtained. |
| `kmscreategrant` | `kms:CreateGrant` | kms:CreateGrant | EXCLUDED | Grants use of a KMS key; data access only. |
| `kmscreatekey-kmsreplicatekey` | `kms:CreateKey`, `kms:ReplicateKey` | kms:CreateKey, kms:ReplicateKey | EXCLUDED | Replicates a multi-Region key with a new policy; key/data access only. |
| `kmsdecrypt` | `kms:Decrypt` | kms:Decrypt | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-lake-formation-grants-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---lake-formation-grants-privesc` | AWS - Lake Formation grants Privesc |  | STRUCTURAL | Page title / references list |
| `lake-formation` | Lake Formation |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `become-a-data-lake-administrator--lakeformationputdatalakesettings` | Become a data lake administrator — `lakeformation:PutDataLakeSettings` | lakeformation:PutDataLakeSettings | EXCLUDED | Grants Lake Formation data-governance administration (data access grants), not an IAM principal's privileges; data exposure belongs to exposure analysis. Covers the Impact and limits subsection. |
| `impact-and-limits` | Impact and limits |  | STRUCTURAL | Limits of the data-lake-administrator technique, which is excluded as Lake Formation data-governance access rather than an IAM principal's privileges. |
| `self-grant-data-access--lakeformationgrantpermissions--batchgrantpermissions` | Self-grant data access — `lakeformation:GrantPermissions` / `BatchGrantPermissions` | lakeformation:GrantPermissions | EXCLUDED | Data-only: self-grants catalog/table access; no IAM principal is obtained. |
| `register-a-location-under-a-privileged-role--lakeformationregisterresource--iampassrole` | Register a location under a privileged role — `lakeformation:RegisterResource` (+ `iam:PassRole`) | lakeformation:RegisterResource, iam:PassRole | EXCLUDED | Data-only confused deputy: the registered role is used to vend scoped S3 data credentials for Lake Formation grants; the caller runs no code as the role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-lambda-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---lambda-privesc` | AWS - Lambda Privesc |  | STRUCTURAL | Page title / references list |
| `lambda` | Lambda |  | EXCLUDED | Service introduction and enumeration link; techniques are mapped under their own headings. |
| `lambda-1` | lambda |  | STRUCTURAL | Section heading (CloudTrail event-name mapping); techniques are rows of their own. |
| `iampassrole-lambdacreatefunction-lambdainvokefunction` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction | COVERED | `aws-lambda-passrole-createfunction-invokefunction` |
| `iampassrole-lambdaupdatefunctionconfiguration-lambdainvokefunction--repoint-an-existing-functions-execution-role` | `iam:PassRole`, `lambda:UpdateFunctionConfiguration`, `lambda:InvokeFunction` — repoint an existing function's execution role | iam:PassRole, lambda:UpdateFunctionConfiguration, lambda:InvokeFunction | COVERED | `aws-lambda-passrole-updatefunctionconfiguration-role-swap` |
| `iampassrole-lambdacreatefunction-lambdaaddpermission` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:AddPermission` | iam:PassRole, lambda:CreateFunction, lambda:AddPermission | COVERED | `aws-lambda-passrole-createfunction-addpermission` |
| `iampassrole-lambdacreatefunction-lambdacreateeventsourcemapping` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:CreateEventSourceMapping` | iam:PassRole, lambda:CreateFunction, lambda:CreateEventSourceMapping, dynamodb:CreateTable, dynamodb:PutItem | COVERED | `aws-lambda-passrole-createfunction-createeventsourcemapping`, `aws-lambda-passrole-createfunction-dynamodb-stream-trigger` |
| `lambdaputresourcepolicy--lambdaaddpermission--lambdaremovepermission--grant-code-updates-through-a-function-policy` | `lambda:PutResourcePolicy` + `lambda:AddPermission` + `lambda:RemovePermission` — grant code updates through a function policy | lambda:PutResourcePolicy, lambda:AddPermission, lambda:RemovePermission | COVERED | `aws-lambda-putresourcepolicy-grant-updatefunctioncode` |
| `lambdaaddpermission` | `lambda:AddPermission` | lambda:AddPermission | EXCLUDED | Grants invoke on existing fixed code; no control of code or role.<br>`aws-s05-06-lambda-addpermission` — conditional verified exact-target authority. |
| `expose-a-pre-existing-authtypenone-function-url` | Expose a pre-existing `AuthType=NONE` Function URL |  | EXCLUDED | Exposure of fixed code; no control of code or role.<br>`aws-s05-07-expose-a-pre-existing-authtype-none-function-url` — conditional verified exact-target authority. |
| `lambdaaddlayerversionpermission` | `lambda:AddLayerVersionPermission` | lambda:AddLayerVersionPermission | EXCLUDED | Shares layer code (read); data access.<br>`aws-s05-08-lambda-addlayerversionpermission` — conditional verified exact-target authority. |
| `ecrputimage-on-a-mutable-lambda-image-tag-later-code-deployment-required` | `ecr:PutImage` on a mutable Lambda image tag (later code deployment required) | ecr:PutImage | EXCLUDED | Lambda pins the tag to a digest at deployment, so the write only executes after another principal later deploys the tag; this consumer-driven supply-chain path is modelled by the ECR writer entries in ecr.yaml. |
| `lambdaupdatefunctioncode` | `lambda:UpdateFunctionCode` | lambda:UpdateFunctionCode | COVERED | `aws-lambda-updatefunctioncode` |
| `lambdaupdatefunctionconfiguration` | `lambda:UpdateFunctionConfiguration` | lambda:UpdateFunctionConfiguration | EXCLUDED | Excluded: UpdateFunctionConfiguration alone does not prove a runtime-specific injection executes or that the source can publish/attach an executable wrapper layer; those requirements are unmodeled. |
| `rce-via-env-variables` | RCE via env variables | lambda:UpdateFunctionConfiguration | EXCLUDED | Excluded: UpdateFunctionConfiguration alone does not prove a runtime-specific injection executes or that the source can publish/attach an executable wrapper layer; those requirements are unmodeled. — Environment-variable variant of UpdateFunctionConfiguration (runtime_supports_env_injection condition). |
| `aws_lambda_exec_wrapper--runtime-agnostic-wrapper-any-language` | `AWS_LAMBDA_EXEC_WRAPPER` — runtime-agnostic wrapper (any language) | lambda:UpdateFunctionConfiguration | EXCLUDED | Excluded: UpdateFunctionConfiguration alone does not prove a runtime-specific injection executes or that the source can publish/attach an executable wrapper layer; those requirements are unmodeled. — AWS_LAMBDA_EXEC_WRAPPER plus layer variant of UpdateFunctionConfiguration, named in its runtime_supports_env_injection condition. |
| `rce-via-lambda-layers` | RCE via Lambda Layers | lambda:UpdateFunctionConfiguration | EXCLUDED | Excluded: UpdateFunctionConfiguration alone does not prove a runtime-specific injection executes or that the source can publish/attach an executable wrapper layer; those requirements are unmodeled. — Layer variant of UpdateFunctionConfiguration (blocked by enforced code signing). |
| `exploitation` | Exploitation | lambda:UpdateFunctionConfiguration | EXCLUDED | Excluded: UpdateFunctionConfiguration alone does not prove a runtime-specific injection executes or that the source can publish/attach an executable wrapper layer; those requirements are unmodeled. — Exploitation steps of the layer variant. |
| `iampassrole-lambdacreatefunction-lambdacreatefunctionurlconfig-lambdainvokefunctionurl` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:CreateFunctionUrlConfig`, `lambda:InvokeFunctionUrl` | iam:PassRole, lambda:CreateFunction, lambda:CreateFunctionUrlConfig, lambda:InvokeFunctionUrl | COVERED | `aws-lambda-passrole-createfunction-functionurl` |
| `lambda-mitm` | Lambda MitM |  | EXCLUDED | Requires prior code execution in the function; persistence/interception, not a new edge. |
| `lambdadeletefunctioncodesigningconfig-or-lambdaputfunctioncodesigningconfig--lambdaupdatefunctioncode--bypass-lambda-code-signing` | `lambda:DeleteFunctionCodeSigningConfig` or `lambda:PutFunctionCodeSigningConfig` + `lambda:UpdateFunctionCode` — Bypass Lambda Code Signing | lambda:UpdateFunctionCode, lambda:DeleteFunctionCodeSigningConfig, lambda:CreateCodeSigningConfig, lambda:PutFunctionCodeSigningConfig | COVERED | `aws-lambda-codesigning-bypass-updatefunctioncode` |
| `signerstartsigningjob--lambdaupdatefunctioncode--sign-attacker-code-with-an-already-trusted-publisher` | `signer:StartSigningJob` + `lambda:UpdateFunctionCode` — Sign attacker code with an already trusted publisher | signer:StartSigningJob, lambda:UpdateFunctionCode, lambda:GetCodeSigningConfig, s3:PutObject, s3:GetObject, s3:GetObjectVersion, s3:ListBucket | COVERED | `aws-lambda-signer-startsigningjob-updatefunctioncode` |
| `lambdaputprovisionedconcurrencyconfig--trigger-initialization-without-invocation` | `lambda:PutProvisionedConcurrencyConfig` — trigger initialization without invocation | lambda:PutProvisionedConcurrencyConfig | EXCLUDED | Triggers init of fixed code; no control of code or role. |
| `lambdacreatemicrovmshellauthtoken--shell-into-an-existing-lambda-microvm` | `lambda:CreateMicrovmShellAuthToken` — shell into an existing Lambda MicroVM | lambda:CreateMicrovmShellAuthToken | EXCLUDED | Excluded: The lambda_microvm resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `lambdagetfunction--download-a-function-deployment-package` | `lambda:GetFunction` — Download a function deployment package | lambda:GetFunction | EXCLUDED | Data read.<br>`aws-s05-10-lambda-getfunction-download-a-function-deployment-packa` — conditional verified exact-target authority. |
| `lambdagetfunctionconfiguration--read-environment-variables` | `lambda:GetFunctionConfiguration` — Read environment variables | lambda:GetFunctionConfiguration | EXCLUDED | Data read.<br>`aws-s05-11-lambda-getfunctionconfiguration-read-environment-variab` — conditional verified exact-target authority. |
| `lambdagetlayerversion--download-layer-code` | `lambda:GetLayerVersion` — Download layer code | lambda:GetLayerVersion | EXCLUDED | Data read.<br>`aws-s05-12-lambda-getlayerversion-download-layer-code` — conditional verified exact-target authority. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-lex-v2-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---amazon-lex-v2-privilege-escalation` | AWS - Amazon Lex V2 Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `amazon-lex-v2` | Amazon Lex V2 |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `lexcreatebotlexupdatebot--iampassrole` | `lex:CreateBot`/`lex:UpdateBot` + `iam:PassRole` | lex:CreateBot, lex:UpdateBot, iam:PassRole | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `existing-hook-as-a-confused-business-authority-boundary` | Existing hook as a confused business-authority boundary |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-lightsail-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---lightsail-privesc` | AWS - Lightsail Privesc |  | STRUCTURAL | Page title / references list |
| `lightsail` | Lightsail |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `lightsaildownloaddefaultkeypair` | `lightsail:DownloadDefaultKeyPair` | lightsail:DownloadDefaultKeyPair | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailgetinstanceaccessdetails` | `lightsail:GetInstanceAccessDetails` | lightsail:GetInstanceAccessDetails | EXCLUDED | Host access to Lightsail instances without a customer IAM identity. |
| `lightsailcreatebucketaccesskey` | `lightsail:CreateBucketAccessKey` | lightsail:CreateBucketAccessKey | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailgetrelationaldatabasemasteruserpassword` | `lightsail:GetRelationalDatabaseMasterUserPassword` | lightsail:GetRelationalDatabaseMasterUserPassword | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailupdaterelationaldatabase` | `lightsail:UpdateRelationalDatabase` | lightsail:UpdateRelationalDatabase | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailopeninstancepublicports` | `lightsail:OpenInstancePublicPorts` | lightsail:OpenInstancePublicPorts | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailputinstancepublicports` | `lightsail:PutInstancePublicPorts` | lightsail:PutInstancePublicPorts | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailsetresourceaccessforbucket` | `lightsail:SetResourceAccessForBucket` | lightsail:SetResourceAccessForBucket | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailupdatebucket` | `lightsail:UpdateBucket` | lightsail:UpdateBucket | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `lightsailupdatecontainerservice` | `lightsail:UpdateContainerService` | lightsail:UpdateContainerService | EXCLUDED | Container code/env change on Lightsail; no customer IAM role is attached to Lightsail containers. |
| `lightsailcreatedomainentry` | `lightsail:CreateDomainEntry` | lightsail:CreateDomainEntry | EXCLUDED | DNS manipulation; traffic interception, no new IAM identity. |
| `lightsailupdatedomainentry` | `lightsail:UpdateDomainEntry` | lightsail:UpdateDomainEntry | EXCLUDED | DNS manipulation; traffic interception, no new IAM identity. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-macie-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---macie-privesc` | AWS - Macie Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-macie` | Amazon Macie |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `macie` | Macie |  | STRUCTURAL | Service heading; the Reveal Sample subsection is handled on its own row. |
| `amazon-macie---bypass-reveal-sample-integrity-check` | Amazon Macie - Bypass `Reveal Sample` Integrity Check |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-mainframe-modernization-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---mainframe-modernization-privesc` | AWS - Mainframe Modernization Privesc |  | STRUCTURAL | Page title / references list |
| `mainframe-modernization` | Mainframe Modernization |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `m2startbatchjob---run-an-attacker-selected-ad-hoc-s3-job-in-an-application` | `m2:StartBatchJob` - Run an attacker-selected ad-hoc S3 job in an application | m2:StartBatchJob | EXCLUDED | Excluded: Starting an existing batch job does not prove that its program executes a source-controlled command or exposes the runtime role. |
| `m2createapplication--iampassrole---execute-a-workload-with-an-application-role` | `m2:CreateApplication` + `iam:PassRole` - Execute a workload with an application role | iam:PassRole, m2:CreateApplication, m2:CreateDeployment, m2:StartApplication | COVERED | `aws-m2-passrole-createapplication-deploy` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-managed-blockchain-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---managed-blockchain-privesc` | AWS - Managed Blockchain Privesc |  | STRUCTURAL | Page title / references list |
| `managed-blockchain` | Managed Blockchain |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `invite-an-attacker-account-into-a-hyperledger-fabric-network` | Invite an attacker account into a Hyperledger Fabric network |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-managed-flink-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---managed-service-for-apache-flink-privilege-escalation` | AWS - Managed Service for Apache Flink Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `managed-service-for-apache-flink` | Managed Service for Apache Flink |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `updateapplication--code-control--application-execution-role` | `UpdateApplication` + code control + application execution role | kinesisanalytics:UpdateApplication | EXCLUDED | Excluded: The kinesisanalytics_application resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `createapplication--iampassrole--malicious-code` | `CreateApplication` + `iam:PassRole` + malicious code | iam:PassRole, kinesisanalytics:CreateApplication, kinesisanalytics:StartApplication | COVERED | `aws-flink-passrole-createapplication` |
| `studio-presigned-url-to-zeppelin-execution` | Studio presigned URL to Zeppelin execution | kinesisanalytics:CreateApplicationPresignedUrl | EXCLUDED | Excluded: The kinesisanalytics_application resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches.<br> — conditional verified exact-target authority.; historical IDs excluded: aws-s05-28-studio-presigned-url-to-zeppelin-execution |
| `add-private-network-reach-without-ec2-permission` | Add private-network reach without EC2 permission |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-managed-grafana-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---managed-grafana-privesc` | AWS - Managed Grafana Privesc |  | STRUCTURAL | Page title / references list |
| `aws-managed-grafana` | AWS Managed Grafana |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `post-exploitation-mint-grafana-bearer-credentials` | Post-exploitation: mint Grafana bearer credentials |  | STRUCTURAL | Parent heading of the two Grafana token-vending techniques below. |
| `grafanacreateworkspaceapikey--arbitrary-role-legacy-api-key` | `grafana:CreateWorkspaceApiKey` — arbitrary-role legacy API key | grafana:CreateWorkspaceApiKey | COVERED | `aws-grafana-createworkspaceapikey-admin` — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected. |
| `createworkspaceserviceaccounttoken--existing-or-attacker-created-service-account` | `CreateWorkspaceServiceAccountToken` — existing or attacker-created service account |  | COVERED | `aws-grafana-serviceaccounttoken-admin` — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected.<br> — conditional verified exact-target authority.; historical IDs excluded: aws-s05-01-token-for-an-existing-admin-grafana-service-account |
| `privilege-escalation-pass-a-data-source-role` | Privilege escalation: pass a data-source role |  | STRUCTURAL | Parent heading of grafana:UpdateWorkspace + iam:PassRole (excluded, bounded delegation). |
| `grafanaupdateworkspace--iampassrole` | `grafana:UpdateWorkspace` + `iam:PassRole` | grafana:UpdateWorkspace, iam:PassRole | EXCLUDED | Not a privesc: bounded service delegation; the workspace role only mediates Grafana data-source and notification queries, and the page states it does not return IAM credentials. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-mediapackage-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---mediapackage-privesc` | AWS - Mediapackage Privesc |  | STRUCTURAL | Page title / references list |
| `mediapackage-v2` | MediaPackage v2 |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `mediapackagedescribechannel` | `mediapackage:DescribeChannel` | mediapackage:DescribeChannel | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `mediapackagelistchannels` | `mediapackage:ListChannels` | mediapackage:ListChannels | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `mediapackagerotatechannelcredentials` | `mediapackage:RotateChannelCredentials` | mediapackage:RotateChannelCredentials | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `mediapackagerotateingestendpointcredentials` | `mediapackage:RotateIngestEndpointCredentials` | mediapackage:RotateIngestEndpointCredentials | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `permissionless-discovery-fallbacks` | Permissionless discovery fallbacks |  | EXCLUDED | Enumeration notes; no technique. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-memorydb-user-reset-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---memorydb-acl-user-reset-privesc` | AWS - MemoryDB ACL user reset Privesc |  | STRUCTURAL | Page title / references list |
| `memorydb` | MemoryDB |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `post-exploitation-replace-an-acl-users-password-with-memorydbupdateuser` | Post-exploitation: replace an ACL user's password with `memorydb:UpdateUser` | memorydb:UpdateUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-migration-hub-orchestrator-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---migration-hub-orchestrator-privesc` | AWS - Migration Hub Orchestrator Privesc |  | STRUCTURAL | Page title / references list |
| `migration-hub-orchestrator` | Migration Hub Orchestrator |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `createworkflowstep--startworkflow---execute-an-s3-script-through-the-orchestrator-service-role` | `CreateWorkflowStep` + `StartWorkflow` - Execute an S3 script through the Orchestrator service role | migrationhub-orchestrator:CreateWorkflowStep, migrationhub-orchestrator:StartWorkflow, migrationhub-orchestrator:UpdateWorkflowStep, migrationhub-orchestrator:RetryWorkflowStep | COVERED | `aws-migrationhub-orchestrator-workflow-step` |
| `existing-step-variant` | Existing-step variant | migrationhub-orchestrator:CreateWorkflowStep, migrationhub-orchestrator:StartWorkflow, migrationhub-orchestrator:UpdateWorkflowStep, migrationhub-orchestrator:RetryWorkflowStep | COVERED | `aws-migrationhub-orchestrator-workflow-step` — The UpdateWorkflowStep + RetryWorkflowStep any_of branch of the same entry. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-migration-hub-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---migration-hub-privilege-escalation` | AWS - Migration Hub Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `application-discovery-service--migration-hub` | Application Discovery Service & Migration Hub |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `migration-hub-automation-custom-unit--passrole---execute-as-a-more-privileged-role` | Migration Hub Automation custom unit + PassRole - Execute as a more privileged role | iam:PassRole, mgh:CreateAutomationUnit, mgh:AssociateAutomationUnitRole, mgh:CreateAutomationRun | COVERED | `aws-mgh-passrole-automation-unit` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ml-dataaccess-passrole-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---passrole-to-mlanalytics-data-access-roles` | AWS - PassRole to ML/Analytics Data-Access Roles |  | STRUCTURAL | Page title / references list |
| `iam-identity-center--sso` | IAM, Identity Center & SSO |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `the-pattern` | The pattern |  | EXCLUDED | Data-access confused deputy (read/write S3 as the passed role); no credentials or code execution as the role. Code-executing services on the table are modelled (PCS, FinSpace) or have dedicated pages. |
| `affected-actions-non-exhaustive` | Affected actions (non-exhaustive) | iam:PassRole, pcs:CreateComputeNodeGroup, finspace:CreateKxCluster | COVERED | [excluded former aws-pcs-passrole-createcomputenodegroup], `aws-finspace-passrole-createkxcluster`<br>`aws-kafkaconnect-passrole-createconnector` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-mq-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---mq-privesc` | AWS - MQ Privesc |  | STRUCTURAL | Page title / references list |
| `mq` | MQ |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `mqcreateuser` | `mq:CreateUser` | mq:CreateUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `mqupdateuser` | `mq:UpdateUser` | mq:UpdateUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `mqupdateconfiguration-mqupdatebroker-mqcreateusermqupdateuser` | `mq:UpdateConfiguration`, `mq:UpdateBroker`, (`mq:CreateUser`\|`mq:UpdateUser`) | mq:UpdateConfiguration, mq:UpdateBroker, mq:CreateUser, mq:UpdateUser | EXCLUDED | ActiveMQ broker-level users and authorization map; broker administrator is not an AWS principal. |
| `mqupdateconfiguration-mqupdatebroker-mqupdatebrokeraccessconfiguration--trust-an-attacker-controlled-rabbitmq-idp` | `mq:UpdateConfiguration`, `mq:UpdateBroker`, `mq:UpdateBrokerAccessConfiguration` — trust an attacker-controlled RabbitMQ IdP | mq:UpdateConfiguration, mq:UpdateBroker, mq:UpdateBrokerAccessConfiguration | EXCLUDED | RabbitMQ broker administrator via an attacker IdP; broker-level access and persistence, not an AWS principal. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-msk-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---msk-privesc` | AWS - MSK Privesc |  | STRUCTURAL | Page title / references list |
| `msk` | MSK |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `kafkaupdatesecurity-to-expose-private-topics-without-credentials` | `kafka:UpdateSecurity` to expose private topics without credentials | kafka:UpdateSecurity | STRUCTURAL | Historical pointer to the relocated bounded operation in AWS post exploitation. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-odb-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---oracle-databaseaws-privilege-escalation` | AWS - Oracle Database@AWS Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `oracle-databaseaws` | Oracle Database@AWS |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `odbupdateautonomousdatabase--reset-the-oracle-admin-credential-and-weaken-connection-controls` | `odb:UpdateAutonomousDatabase` — reset the Oracle `ADMIN` credential and weaken connection controls | odb:UpdateAutonomousDatabase | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-opensearch-serverless-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---opensearch-serverless-privesc` | AWS - OpenSearch Serverless Privesc |  | STRUCTURAL | Page title / references list |
| `opensearch-service` | OpenSearch Service |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `opensearch-serverless-aoss` | OpenSearch Serverless (aoss) |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `aosscreateaccesspolicy` | `aoss:CreateAccessPolicy` | aoss:CreateAccessPolicy | EXCLUDED | Self-grant of collection data access through an additive data access policy; data access within the service, no other principal's privileges (Least Privilege finding). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-organizations-prinvesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---organizations-privesc` | AWS - Organizations Privesc |  | STRUCTURAL | Page title / references list |
| `organizations` | Organizations |  | EXCLUDED | Service introduction and enumeration link; techniques are mapped under their own headings. |
| `from-management-account-to-children-accounts` | From management Account to children accounts | sts:AssumeRole | COVERED | `aws-organizations-management-to-member-accounts` |
| `organizationscreateaccount--spawn-an-account-you-fully-own-inside-the-victim-org` | `organizations:CreateAccount` — spawn an account you fully own inside the victim org | organizations:CreateAccount, sts:AssumeRole | COVERED | `aws-organizations-createaccount-principalorgid-trust` |
| `organizationsregisterdelegatedadministrator--hand-a-services-org-wide-control-to-an-account-you-own` | `organizations:RegisterDelegatedAdministrator` — hand a service's org-wide control to an account you own | organizations:RegisterDelegatedAdministrator, organizations:EnableAWSServiceAccess | EXCLUDED | Previously mapped to `aws-organizations-registerdelegatedadministrator`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `dismantling-scp-guardrails--organizationsdetachpolicy-updatepolicy-disablepolicytype-moveaccount` | Dismantling SCP guardrails — `organizations:DetachPolicy`, `UpdatePolicy`, `DisablePolicyType`, `MoveAccount` | organizations:DetachPolicy | EXCLUDED | Previously mapped to `aws-v3-37-scp-guardrail-removal`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `organizationsputresourcepolicy--delegate-organizations-itself-to-a-member-account` | `organizations:PutResourcePolicy` — delegate Organizations itself to a member account | organizations:PutResourcePolicy | EXCLUDED | Previously mapped to `aws-v3-38-organizations-resource-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-payment-cryptography-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---payment-cryptography-privesc` | AWS - Payment Cryptography Privesc |  | STRUCTURAL | Page title / references list |
| `payment-cryptography` | Payment Cryptography |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `payment-cryptographyputresourcepolicy` | `payment-cryptography:PutResourcePolicy` | payment-cryptography:PutResourcePolicy | EXCLUDED | Self-grant of key usage through the key resource policy; bounded to that key's cryptographic operations, no other principal's privileges.<br>`aws-payment-cryptography-sameaccount-key-policy` — conditional verified exact-target authority. |
| `alias-policy-pivot-with-payment-cryptographyupdatealias` | Alias-policy pivot with `payment-cryptography:UpdateAlias` | payment-cryptography:UpdateAlias | EXCLUDED | Extends the source's own alias-scoped key permission to another key; key usage only, no other principal's privileges. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-pca-connector-ad-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---pca-connector-for-ad-privesc` | AWS - PCA Connector for AD Privesc |  | STRUCTURAL | Page title / references list |
| `private-ca-connector-for-active-directory` | Private CA Connector for Active Directory |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `pca-connector-for-ad` | PCA Connector for AD |  | STRUCTURAL | Service introduction (AD CS model); the template techniques are mapped under their own headings. |
| `pca-connector-adcreatetemplate--publish-a-malicious-certificate-template-esc1--esc9` | `pca-connector-ad:CreateTemplate` — publish a malicious certificate template (ESC1 / ESC9) | pca-connector-ad:CreateTemplate, pca-connector-ad:CreateTemplateGroupAccessControlEntry | EXCLUDED | Excluded: Template creation does not prove the source controls an enrollable AD identity or that certificate mapping authenticates as the exact directory admin. |
| `pca-connector-adupdatetemplate--weaken-an-existing-legitimate-template-in-place` | `pca-connector-ad:UpdateTemplate` — weaken an existing legitimate template in place | pca-connector-ad:UpdateTemplate | EXCLUDED | Excluded: Template update does not prove the source controls an enrollable AD identity or that certificate mapping authenticates as the exact directory admin. |
| `pca-connector-adcreatetemplategroupaccesscontrolentry--grant-enrollment-to-an-attacker-chosen-ad-group` | `pca-connector-ad:CreateTemplateGroupAccessControlEntry` — grant enrollment to an attacker-chosen AD group | pca-connector-ad:CreateTemplateGroupAccessControlEntry | EXCLUDED | Opens enrollment on an existing template only; on its own it grants no new identity, and it is the enrollment requirement of aws-pca-connector-ad-createtemplate-esc1 (CreateTemplate + CreateTemplateGroupAccessControlEntry).<br>`aws-s05-83-pca-connector-ad-createtemplategroupaccesscontrolentry` — conditional verified exact-target authority. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-proton-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---proton-privesc` | AWS - Proton Privesc |  | STRUCTURAL | Page title / references list |
| `proton` | Proton |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `protoncreateenvironment-iampassrole--template-control` | `proton:CreateEnvironment`, `iam:PassRole` (+ template control) | proton:CreateEnvironment, iam:PassRole | EXCLUDED | AWS Proton end of support was 2026-10-07 (no new customers since 2025-10-07); the APIs are no longer available, so no current path. |
| `protoncreatecomponent--arbitrary-iac-through-a-stored-component-role` | `proton:CreateComponent` — arbitrary IaC through a stored component role | proton:CreateComponent | EXCLUDED | AWS Proton end of support was 2026-10-07; the APIs are no longer available. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-q-business-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---q-business-privesc` | AWS - Q Business Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-q-business` | Amazon Q Business |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `plugin-configuration-hijack-and-action-execution` | Plugin configuration hijack and action execution |  | STRUCTURAL | Legacy anchor points to the bounded data or application operation on its post-exploitation page. |

| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-quicksight-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---quicksight-privesc` | AWS - QuickSight Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-quicksight` | Amazon QuickSight |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `quicksight` | QuickSight |  | STRUCTURAL | Service background on the QuickSight user directory; techniques are the two headings below. |
| `quicksightupdateuser--self-promote-to-admin` | `quicksight:UpdateUser` — self-promote to ADMIN | quicksight:UpdateUser | EXCLUDED | excluded: "Promote a controlled QuickSight user to ADMIN"; UpdateUser can promote any QuickSight user, but the source is not proved to control the promoted user or its sign-in. |
| `quicksightregisteruser--map-a-controlled-iam-identity-to-an-admin` | `quicksight:RegisterUser` — map a controlled IAM identity to an ADMIN | quicksight:RegisterUser | COVERED | `aws-quicksight-registeruser-admin` — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-rds-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---rds-privesc` | AWS - RDS Privesc |  | STRUCTURAL | Page title / references list |
| `relational-database-rds` | Relational Database (RDS) |  | EXCLUDED | Introductory section (links to enumeration); no technique. |
| `rds---relational-database-service` | RDS - Relational Database Service |  | STRUCTURAL | Section heading grouping the RDS techniques below. |
| `rdsmodifydbinstance` | `rds:ModifyDBInstance` | rds:ModifyDBInstance | EXCLUDED | Previously mapped to `aws-rds-modifydbinstance-master-password-associated-roles`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `rds-dbconnect` | rds-db:connect |  | EXCLUDED | Previously mapped to `aws-rds-dbconnect-iam-auth-associated-roles`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `abuse-rds-role-iam-permissions` | Abuse RDS Role IAM permissions | rds:ModifyDBInstance, iam:PassRole, rds:AddRoleToDBCluster, rds:AddRoleToDBInstance | EXCLUDED | Previously mapped to `aws-rds-modifydbinstance-master-password-associated-roles`, `aws-rds-addroletodbcluster-passrole`, `aws-rds-addroletodbinstance-passrole`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `postgresql-aurora` | Postgresql (Aurora) |  | EXCLUDED | Describes how SQL uses the attached role; the role edge is modelled by the RDS ModifyDBInstance and AddRoleTo* entries.<br>`aws-rds-dbconnect-aurora-role` — conditional verified exact-target authority. |
| `mysql-aurora` | Mysql (Aurora) |  | EXCLUDED | Describes how SQL uses the attached role; the role edge is modelled by the RDS ModifyDBInstance and AddRoleTo* entries. |
| `rdsaddroletodbcluster-iampassrole` | `rds:AddRoleToDBCluster`, `iam:PassRole` | iam:PassRole, rds:AddRoleToDBCluster | EXCLUDED | Previously mapped to `aws-rds-addroletodbcluster-passrole`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `rdscreatedbinstance` | `rds:CreateDBInstance` | rds:CreateDBInstance | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `rdscreatedbinstance-iampassrole-kms-key-use-permissions` | `rds:CreateDBInstance`, `iam:PassRole`, KMS key-use permissions | iam:PassRole, rds:CreateDBInstance, kms:CreateGrant, kms:DescribeKey | EXCLUDED | Excluded: Creating a database with a passed role does not prove source code execution or administrative access on its RDS Custom host. |
| `rdsaddroletodbinstance-iampassrole` | `rds:AddRoleToDBInstance`, `iam:PassRole` | iam:PassRole, rds:AddRoleToDBInstance | EXCLUDED | Previously mapped to `aws-rds-addroletodbinstance-passrole`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `rdscreatebluegreendeployment-rdsaddroletodbcluster-iampassrole-rdsswitchoverbluegreendeployment` | `rds:CreateBlueGreenDeployment`, `rds:AddRoleToDBCluster`, `iam:PassRole`, `rds:SwitchoverBlueGreenDeployment` | rds:CreateBlueGreenDeployment, rds:AddRoleToDBCluster, iam:PassRole, rds:SwitchoverBlueGreenDeployment | EXCLUDED | Reachable set is a subset of aws-rds-addroletodbcluster-passrole; the additional actions add nothing to the target set. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-redshift-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---redshift-privesc` | AWS - Redshift Privesc |  | STRUCTURAL | Page title / references list |
| `redshift` | Redshift | redshift:ModifyCluster | EXCLUDED | Previously mapped to `aws-redshift-modifycluster-master-password`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `redshiftgetclustercredentials` | `redshift:GetClusterCredentials` | redshift:GetClusterCredentials | EXCLUDED | Previously mapped to `aws-redshift-getclustercredentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `redshiftgetclustercredentialswithiam` | `redshift:GetClusterCredentialsWithIAM` | redshift:GetClusterCredentialsWithIAM | EXCLUDED | Previously mapped to `aws-redshift-getclustercredentialswithiam`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `redshift-serverlessgetcredentials` | `redshift-serverless:GetCredentials` | redshift-serverless:GetCredentials | EXCLUDED | Previously mapped to `aws-redshift-serverless-getcredentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `redshiftmodifyclusteriamroles-iampassrole--redshift-serverlessupdatenamespace-iampassrole---repoint-the-databases-aws-role` | `redshift:ModifyClusterIamRoles`, `iam:PassRole` \| `redshift-serverless:UpdateNamespace`, `iam:PassRole` - repoint the database's AWS role | iam:PassRole, redshift:ModifyClusterIamRoles, redshift-serverless:UpdateNamespace | EXCLUDED | Previously mapped to `aws-redshift-passrole-attach-warehouse-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `accessing-external-services` | Accessing External Services |  | EXCLUDED | Describes how SQL uses the attached roles; the role edge is modelled by the Redshift credential and role-attachment entries. Covers its subsections. |
| `lambdas` | Lambdas |  | STRUCTURAL | SQL usage of an attached role (external functions), subsection of the excluded Accessing External Services heading; the role edge is the Redshift credential and role-attachment entries. |
| `s3` | S3 |  | STRUCTURAL | SQL usage of an attached role (COPY/UNLOAD), subsection of Accessing External Services. |
| `dynamo` | Dynamo |  | STRUCTURAL | SQL usage of an attached role (COPY from DynamoDB), subsection of Accessing External Services. |
| `emr` | EMR |  | STRUCTURAL | Link-only subsection of Accessing External Services. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-region-switch-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---arc-region-switch-privesc` | AWS - ARC Region Switch Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-application-recovery-controller-region-switch` | Amazon Application Recovery Controller Region switch |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `arc-region-switch` | ARC Region Switch |  | STRUCTURAL | Service introduction (plan execution role model); techniques are mapped under their own headings. |
| `arc-region-switchcreateplan--updateplan--iampassrole--run-steps-as-the-execution-role` | `arc-region-switch:CreatePlan` / `UpdatePlan` (+ `iam:PassRole`) — run steps as the execution role | iam:PassRole, arc-region-switch:CreatePlan, arc-region-switch:UpdatePlan | EXCLUDED | Previously mapped to `aws-arc-region-switch-passrole-createplan`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `arc-region-switchstartplanexecution--force-a-region-switch-availability--traffic-hijack` | `arc-region-switch:StartPlanExecution` — force a Region switch (availability / traffic hijack) | arc-region-switch:StartPlanExecution | EXCLUDED | Runs an existing plan as written; disruption/traffic redirection only, the source does not choose the actions or the role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-resilience-hub-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---resilience-hub-privilege-escalation` | AWS - Resilience Hub Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `resilience-hub` | Resilience Hub |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `resiliencehubcreatetest-iampassrole-resiliencehubstarttestrun---execute-managed-fis-faults-as-a-passed-role` | `resiliencehub:CreateTest`, `iam:PassRole`, `resiliencehub:StartTestRun` - execute managed FIS faults as a passed role | resiliencehub:CreateTest, iam:PassRole, resiliencehub:StartTestRun | EXCLUDED | Runs AWS-managed fault-injection templates with fixed actions; disruptive impact only (no arbitrary FIS template or SSM command), out of scope as disruption. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-resource-explorer-view-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---resource-explorer-privesc` | AWS - Resource Explorer Privesc |  | STRUCTURAL | Page title / references list |
| `resource-explorer` | Resource Explorer |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `resource-explorer-2updateview--widen-existing-and-default-view-access` | `resource-explorer-2:UpdateView` — widen existing and default-view access | resource-explorer-2:UpdateView | EXCLUDED | Widens resource-metadata visibility of a view; reconnaissance only, no privileges gained. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-route53-domains-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---route-53-domains-privesc` | AWS - Route 53 Domains Privesc |  | STRUCTURAL | Page title / references list |
| `route53` | Route53 |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `route53domainsgetdomaindetail--read-domain-registration-contacts` | `route53domains:GetDomainDetail` — Read domain registration contacts | route53domains:GetDomainDetail | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `route53domainsretrievedomainauthcode--steal-a-domain-transfer-credential` | `route53domains:RetrieveDomainAuthCode` — Steal a domain-transfer credential | route53domains:RetrieveDomainAuthCode | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `route53domainstransferdomaintoanotherawsaccount--transfer-domain-registration-to-an-attacker-account` | `route53domains:TransferDomainToAnotherAwsAccount` — Transfer domain registration to an attacker account | route53domains:TransferDomainToAnotherAwsAccount | STRUCTURAL | Historical pointer to the relocated bounded operation in AWS post exploitation. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-s3-credential-brokers-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---s3-credential-brokers-privesc` | AWS - S3 credential brokers Privesc |  | STRUCTURAL | Page title / references list |
| `s3` | S3 |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `s3-express-and-s3-access-grants-credential-brokers` | S3 Express and S3 Access Grants credential brokers |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-s3-files-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---s3-files-privesc` | AWS - S3 Files Privesc |  | STRUCTURAL | Page title / references list |
| `s3-files` | S3 Files |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `s3filescreatefilesystem-iampassrole--mount-any-buckets-data-as-a-chosen-role` | `s3files:CreateFileSystem`, `iam:PassRole` — mount any bucket's data as a chosen role | s3files:CreateFileSystem, iam:PassRole | EXCLUDED | Previously mapped to `aws-s3files-passrole-createfilesystem`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-s3-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---s3-privesc` | AWS - S3 Privesc |  | STRUCTURAL | Page title / references list |
| `s3` | S3 |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `s3putbucketnotification-s3putobject-s3getobject` | `s3:PutBucketNotification`, `s3:PutObject`, `s3:GetObject` | s3:PutBucketNotification, s3:PutObject, s3:GetObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `s3putobject-s3getobject` | `s3:PutObject`, `s3:GetObject` <a href="#s3putobject-s3getobject" id="s3putobject-s3getobject"></a> | s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `s3putobject-s3getobject-optional-over-terraform-state-file` | `s3:PutObject`, `s3:GetObject` (optional) over terraform state file | s3:PutObject | EXCLUDED | Excluded: The terraform_state_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `s3putbucketpolicy--grant-your-principal-new-object-access` | `s3:PutBucketPolicy` — grant your principal new object access | s3:PutBucketPolicy | COVERED | `aws-s3-putbucketpolicy-self-grant` — exact reviewed source/bucket/prefix and observed new GetObject permission. |
| `s3-access-grants--vend-a-new-prefix-scoped-read-session` | S3 Access Grants — vend a new, prefix-scoped READ session | s3:CreateAccessGrantsLocation, iam:PassRole, s3:CreateAccessGrant, s3:GetDataAccess | COVERED | `aws-s3-accessgrants-self-grant` — exact reviewed source-grantee, role, prefix and newly usable scoped session. |
| `s3putbucketpolicy` | `s3:PutBucketPolicy` | s3:PutBucketPolicy | EXCLUDED | Grants bucket data access. Evaluator note: treat as implying s3:PutObject on that bucket for the artifact entries (s3/glue/emr/sagemaker/elasticbeanstalk). |
| `s3getbucketacl-s3putbucketacl` | `s3:GetBucketAcl`, `s3:PutBucketAcl` | s3:GetBucketAcl, s3:PutBucketAcl | EXCLUDED | Grants bucket data access (only when ACLs are enabled); same evaluator note as PutBucketPolicy. |
| `s3getobjectacl-s3putobjectacl` | `s3:GetObjectAcl`, `s3:PutObjectAcl` | s3:GetObjectAcl, s3:PutObjectAcl | EXCLUDED | Object data access only. |
| `s3getobjectversionacl-s3putobjectversionacl` | `s3:GetObjectVersionAcl`, `s3:PutObjectVersionAcl` | s3:GetObjectVersionAcl, s3:PutObjectVersionAcl | EXCLUDED | Object data access only. |
| `s3putbucketcors` | `s3:PutBucketCORS` | s3:PutBucketCORS | EXCLUDED | Browser cross-origin data access; no IAM principal. |
| `iampassrole-s3createaccessgrantslocation-s3createaccessgrant-s3getdataaccess` | `iam:PassRole`, `s3:CreateAccessGrantsLocation`, `s3:CreateAccessGrant`, `s3:GetDataAccess` | iam:PassRole, s3:CreateAccessGrantsLocation, s3:CreateAccessGrant, s3:GetDataAccess | EXCLUDED | Previously mapped to `aws-s3-accessgrants-passrole-location-getdataaccess`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `s3createjob-s3-batch-operations-iampassrole--mass-copyexposelock-a-whole-bucket-as-a-passed-role` | `s3:CreateJob` (S3 Batch Operations), `iam:PassRole` — mass copy/expose/lock a whole bucket as a passed role | s3:CreateJob, iam:PassRole | EXCLUDED | Previously mapped to `aws-s3-batchoperations-passrole-createjob`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-s3-tables-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---s3-tables-privesc` | AWS - S3 Tables Privesc |  | STRUCTURAL | Page title / references list |
| `s3-tables` | S3 Tables |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `self-grant-access-through-a-table-or-table-bucket-policy` | Self-grant access through a table or table-bucket policy |  | EXCLUDED | Self-grant through a table/table-bucket resource policy; data access within that resource, no other principal's privileges. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-s3-vectors-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---s3-vectors-privilege-escalation` | AWS - S3 Vectors Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `s3-vectors` | S3 Vectors |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `s3vectorsputvectorbucketpolicy---self-grant-vector-bucketindex-access` | `s3vectors:PutVectorBucketPolicy` - self-grant vector-bucket/index access | s3vectors:PutVectorBucketPolicy | EXCLUDED | Self-grant through a vector-bucket resource policy; data access within that bucket, no other principal's privileges. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-sagemaker-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---sagemaker-privesc` | AWS - Sagemaker Privesc |  | STRUCTURAL | Page title / references list |
| `sagemaker` | SageMaker |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole--sagemakercreatenotebookinstance-sagemakercreatepresignednotebookinstanceurl` | `iam:PassRole` , `sagemaker:CreateNotebookInstance`, `sagemaker:CreatePresignedNotebookInstanceUrl` | iam:PassRole, sagemaker:CreateNotebookInstance, sagemaker:CreatePresignedNotebookInstanceUrl | COVERED | `aws-sagemaker-passrole-createnotebookinstance` |
| `sagemakercreatepresignednotebookinstanceurl` | `sagemaker:CreatePresignedNotebookInstanceUrl` | sagemaker:CreatePresignedNotebookInstanceUrl | COVERED | `aws-sagemaker-createpresignednotebookinstanceurl` |
| `sagemakercreatepresigneddomainurl` | `sagemaker:CreatePresignedDomainUrl` | sagemaker:CreatePresignedDomainUrl | COVERED | `aws-sagemaker-createpresigneddomainurl` |
| `sagemakercreatepresignedmlflowtrackingserverurl-sagemaker-mlflowaccessui-sagemaker-mlflowsearchexperiments` | `sagemaker:CreatePresignedMlflowTrackingServerUrl`, `sagemaker-mlflow:AccessUI`, `sagemaker-mlflow:SearchExperiments` | sagemaker:CreatePresignedMlflowTrackingServerUrl, sagemaker-mlflow:AccessUI, sagemaker-mlflow:SearchExperiments | EXCLUDED | MLflow UI/artifact data access; no execution role obtained. |
| `s3putobject-on-configured-training-or-processing-code-job-creation-optional` | `s3:PutObject` on configured training or processing code (job creation optional) | s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `script-mode-training-source-bundle` | Script-mode training source bundle | s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. — Training source-bundle variant of the S3 job-code overwrite. |
| `processing-input-executed-by-the-container` | Processing input executed by the container | s3:PutObject | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. — Processing-input variant of the S3 job-code overwrite. |
| `ecrputimage-on-a-mutable-processing-image-later-job-required` | `ecr:PutImage` on a mutable Processing image (later job required) | ecr:PutImage, ecr:GetAuthorizationToken, ecr:InitiateLayerUpload, ecr:UploadLayerPart, ecr:CompleteLayerUpload, ecr:BatchCheckLayerAvailability, ecr:BatchGetImage | EXCLUDED | [excluded former aws-ecr-push-consumed-tag] — Mutable ECR tag consumed by a later Processing job; modelled generically by the ECR consumed-tag entry (consumer_input_writable_via ecr:PutImage).<br>Excluded: The ecr_repository artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `sagemakercreateprocessingjob-iampassrole` | `sagemaker:CreateProcessingJob`, `iam:PassRole` | iam:PassRole, sagemaker:CreateProcessingJob | COVERED | `aws-sagemaker-passrole-createprocessingjob` |
| `sagemakercreatetrainingjob-iampassrole` | `sagemaker:CreateTrainingJob`, `iam:PassRole` | iam:PassRole, sagemaker:CreateTrainingJob | COVERED | `aws-sagemaker-passrole-createtrainingjob` |
| `sagemakercreatehyperparametertuningjob-iampassrole` | `sagemaker:CreateHyperParameterTuningJob`, `iam:PassRole` | iam:PassRole, sagemaker:CreateHyperParameterTuningJob | COVERED | `aws-sagemaker-passrole-createhyperparametertuningjob` |
| `sagemakerupdateuserprofile-iampassrole-sagemakercreateapp-sagemakercreatepresigneddomainurl-sagemakerdeleteapp` | `sagemaker:UpdateUserProfile`, `iam:PassRole`, `sagemaker:CreateApp`, `sagemaker:CreatePresignedDomainUrl`, (`sagemaker:DeleteApp`) | iam:PassRole, sagemaker:UpdateUserProfile, sagemaker:CreateApp, sagemaker:CreatePresignedDomainUrl | COVERED | `aws-sagemaker-updateuserprofile-passrole-createapp` |
| `sagemakerupdatedomain-sagemakercreateuserprofile-sagemakercreateapp-iampassrole-sagemakercreatepresigneddomainurl-sagemakerdeleteapp` | `sagemaker:UpdateDomain`, `sagemaker:CreateUserProfile`, `sagemaker:CreateApp`, `iam:PassRole`, `sagemaker:CreatePresignedDomainUrl`, (`sage | iam:PassRole, sagemaker:UpdateDomain, sagemaker:CreateUserProfile, sagemaker:CreateApp, sagemaker:CreatePresignedDomainUrl | COVERED | `aws-sagemaker-updatedomain-createuserprofile-passrole`, `aws-sagemaker-createuserprofile-passrole-createapp` |
| `sagemakercreateapp-sagemakercreatepresigneddomainurl` | `sagemaker:CreateApp`, `sagemaker:CreatePresignedDomainUrl` | sagemaker:CreatePresignedDomainUrl | COVERED | `aws-sagemaker-createpresigneddomainurl` — Subsumed by aws-sagemaker-createpresigneddomainurl (same target set, fewer permissions). |
| `sagemakerstartpipelineexecution--inject-parameters-into-privileged-steps` | `sagemaker:StartPipelineExecution` — inject parameters into privileged steps | sagemaker:StartPipelineExecution | EXCLUDED | Runs fixed pipeline steps with attacker parameters; no control of code or role. |
| `sagemakerretrypipelineexecution--replay-failed-steps-and-stored-parameters` | `sagemaker:RetryPipelineExecution` — Replay failed steps and stored parameters | sagemaker:RetryPipelineExecution | EXCLUDED | Replays fixed steps; no control of code or role. |
| `sagemakerupdateclustersoftware--replace-hyperpod-nodes-with-a-custom-ami` | `sagemaker:UpdateClusterSoftware` — replace HyperPod nodes with a custom AMI | sagemaker:UpdateClusterSoftware | COVERED | `aws-sagemaker-updateclustersoftware-custom-ami` |
| `datazonecreateuserprofile-and-iamgetuser-for-project-assignment-without-an-existing-profile` | `datazone:CreateUserProfile` (and `iam:GetUser` for project assignment without an existing profile) | datazone:CreateUserProfile, iam:GetUser | EXCLUDED | A profile alone grants nothing; project membership (separate control) is needed to reach project roles. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-secrets-manager-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---secrets-manager-privesc` | AWS - Secrets Manager Privesc |  | STRUCTURAL | Page title / references list |
| `secrets-manager` | Secrets Manager |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `secretsmanagergetsecretvalue` | `secretsmanager:GetSecretValue` | secretsmanager:GetSecretValue | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `secretsmanagergetresourcepolicy-secretsmanagerputresourcepolicy-secretsmanagerlistsecrets` | `secretsmanager:GetResourcePolicy`, `secretsmanager:PutResourcePolicy`, (`secretsmanager:ListSecrets`) | secretsmanager:GetResourcePolicy, secretsmanager:PutResourcePolicy, secretsmanager:ListSecrets | COVERED | `aws-secretsmanager-putresourcepolicy-self-grant` — reviewed exact self permission gain; broader variants remain excluded. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-service-catalog-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---service-catalog-privesc` | AWS - Service Catalog Privesc |  | STRUCTURAL | Page title / references list |
| `service-catalog-and-appregistry` | Service Catalog and AppRegistry |  | EXCLUDED | Introductory section describing launch constraints; techniques are modelled in servicecatalog.yaml. |
| `servicecatalogcreateprovisioningartifact--servicecatalogprovisionproduct` | `servicecatalog:CreateProvisioningArtifact` + `servicecatalog:ProvisionProduct` | servicecatalog:CreateProvisioningArtifact, servicecatalog:ProvisionProduct | COVERED | `aws-servicecatalog-createprovisioningartifact-provisionproduct` |
| `required-conditions` | Required conditions | servicecatalog:CreateProvisioningArtifact, servicecatalog:ProvisionProduct | COVERED | `aws-servicecatalog-createprovisioningartifact-provisionproduct` — Preconditions of the launch-role technique, encoded as its conditions. |
| `example` | Example | servicecatalog:CreateProvisioningArtifact, servicecatalog:ProvisionProduct | COVERED | `aws-servicecatalog-createprovisioningartifact-provisionproduct` — Exploitation example of the same technique. |
| `discovery-without-list-permissions` | Discovery without list permissions |  | STRUCTURAL | Enumeration guidance for the launch-role technique. |
| `sensitive-cloudformation-outputs-with-servicecataloggetprovisionedproductoutputs` | Sensitive CloudFormation outputs with `servicecatalog:GetProvisionedProductOutputs` | servicecatalog:GetProvisionedProductOutputs | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `servicecatalogassociateprincipalwithportfolio--grant-a-principal-or-yourself-portfolio-access-to-reach-the-launch-role` | `servicecatalog:AssociatePrincipalWithPortfolio` — grant a principal (or yourself) portfolio access to reach the launch role | servicecatalog:AssociatePrincipalWithPortfolio, servicecatalog:CreateProvisioningArtifact, servicecatalog:ProvisionProduct | COVERED | `aws-servicecatalog-associateprincipal-createartifact-provision` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-snowball-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---snowball-edge-job-management-privilege-escalation` | AWS - Snowball Edge Job Management Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `snowball-edge-job-management` | Snowball Edge Job Management |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `snowballupdatejob--make-an-existing-snow-role-export-additional-s3-data-to-another-address` | `snowball:UpdateJob` — make an existing Snow role export additional S3 data to another address | snowball:UpdateJob | EXCLUDED | Previously mapped to `aws-snowball-updatejob-existing-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `snowballcreatejob--iampassrole--create-a-physical-s3-export-through-a-privileged-role` | `snowball:CreateJob` + `iam:PassRole` — create a physical S3 export through a privileged role | snowball:CreateJob, iam:PassRole | EXCLUDED | Previously mapped to `aws-snowball-passrole-createjob`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-sns-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---sns-privesc` | AWS - SNS Privesc |  | STRUCTURAL | Page title / references list |
| `sns` | SNS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `snssubscribe` | `sns:Subscribe` | sns:Subscribe | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `snsaddpermission` | `sns:AddPermission` | sns:AddPermission | EXCLUDED | Grants topic access; data/messaging access only. |
| `snssettopicattributes--grant-subscribe-access-to-a-controlled-iam-user` | `sns:SetTopicAttributes` — grant subscribe access to a controlled IAM user | sns:SetTopicAttributes | EXCLUDED | Resource-policy grant of sns:Subscribe on one topic to a controlled user: message read access only, like sns:AddPermission. |
| `invoke-a-lambda-by-abusing-wildcard-sns-permission-no-sourcearn` | Invoke a Lambda by abusing wildcard SNS permission (no `SourceArn`) |  | EXCLUDED | Invokes fixed Lambda code with attacker input; no control of code or role. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-sqs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---sqs-privesc` | AWS - SQS Privesc |  | STRUCTURAL | Page title / references list |
| `sqs` | SQS |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `sqsaddpermission` | `sqs:AddPermission` | sqs:AddPermission | EXCLUDED | Grants queue access; data access only. |
| `sqssetqueueattributes--grant-queue-access-to-a-controlled-iam-user` | `sqs:SetQueueAttributes` — grant queue access to a controlled IAM user | sqs:SetQueueAttributes | EXCLUDED | Resource-policy grant of queue access to a controlled user: message read access only, like sqs:AddPermission. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-ssm-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---ssm-privesc` | AWS - SSM Privesc |  | STRUCTURAL | Page title / references list |
| `systems-manager-ssm` | Systems Manager (SSM) |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `ssm` | SSM |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `ssmstartautomationexecution--execute-a-preauthorized-runbook-role` | `ssm:StartAutomationExecution` — execute a preauthorized runbook role | ssm:StartAutomationExecution, iam:PassRole, ssm:CreateDocument | COVERED | `aws-ssm-createdocument-startautomationexecution-passrole`<br>`aws-audit-use-existing-parameterized-automation-runbook-with-runtime-passrole` — conditional verified exact-target authority.; historical IDs excluded: aws-ssm-startautomationexecution-stored-role |
| `ssmcreateactivation-iampassrole--mint-a-hybrid-activation-that-hands-out-a-role` | `ssm:CreateActivation`, `iam:PassRole` — mint a hybrid activation that hands out a role | iam:PassRole, ssm:CreateActivation | COVERED | `aws-ssm-passrole-createactivation` |
| `ssmupdatemanagedinstancerole-iampassrole--re-point-an-existing-hybrid-instance-at-a-better-role` | `ssm:UpdateManagedInstanceRole`, `iam:PassRole` — re-point an existing hybrid instance at a better role | iam:PassRole, ssm:UpdateManagedInstanceRole | EXCLUDED | Excluded: The role swap changes a hybrid node configuration, but no source-controlled managed node or readable SSM agent credentials are joined. |
| `ssmupdateservicesetting-iampassrole--hijack-default-host-management-configuration` | `ssm:UpdateServiceSetting`, `iam:PassRole` — hijack Default Host Management Configuration | iam:PassRole, ssm:UpdateServiceSetting | EXCLUDED | Excluded: The account-wide role setting does not prove the source can execute on a DHMC-managed instance and obtain its SSM credentials. |
| `ssmstartassociationsonce--run-a-stored-association-on-its-fixed-targets` | `ssm:StartAssociationsOnce` — Run a stored association on its fixed targets | ssm:StartAssociationsOnce | EXCLUDED | Runs fixed associations on fixed targets; no control of code or role.<br>`aws-audit-start-stored-state-manager-association` — conditional verified exact-target authority. |
| `ssmsendcommand` | `ssm:SendCommand` | ssm:SendCommand | COVERED | `aws-ssm-sendcommand`<br>[excluded former aws-ssm-exec-hybrid-managed-node] |
| `ssmstartsession` | `ssm:StartSession` | ssm:StartSession | COVERED | `aws-ssm-startsession` |
| `privesc-to-ecs` | Privesc to ECS | ssm:StartSession | EXCLUDED | Excluded: The ecs_task resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `ssmstartaccessrequest--ssmgetaccesstoken--vend-jit-credentials-for-a-session-manager-shell` | `ssm:StartAccessRequest` + `ssm:GetAccessToken` — vend JIT credentials for a Session Manager shell | ssm:StartAccessRequest, ssm:GetAccessToken | COVERED | `aws-ssm-jit-startaccessrequest-getaccesstoken`<br> — conditional verified exact-target authority.; historical IDs excluded: aws-audit-jit-shell-to-hybrid-managed-instance |
| `ssmresumesession` | `ssm:ResumeSession` | ssm:ResumeSession | EXCLUDED | Exact session or DLM policy to EC2 role join is not proven (`_excluded_unproven_ssm_dlm_target_final_reaudit_20261016.yaml`). |
| `ssmdescribeparameters-ssmgetparameter--ssmgetparameters--ssmgetparametersbypath` | `ssm:DescribeParameters`, (`ssm:GetParameter` \| `ssm:GetParameters` \| `ssm:GetParametersByPath`) | ssm:DescribeParameters, ssm:GetParameter, ssm:GetParameters, ssm:GetParametersByPath | EXCLUDED | Data read. |
| `ssmgetparameterhistory--recover-current-and-previous-parameter-values` | `ssm:GetParameterHistory` — Recover current and previous parameter values | ssm:GetParameterHistory | EXCLUDED | Data read. |
| `ssmlistcommands` | `ssm:ListCommands` | ssm:ListCommands | EXCLUDED | Data read. |
| `ssmgetcommandinvocation-ssmlistcommandinvocations--ssmlistcommands` | `ssm:GetCommandInvocation`, (`ssm:ListCommandInvocations` \| `ssm:ListCommands`) | ssm:GetCommandInvocation, ssm:ListCommandInvocations, ssm:ListCommands | EXCLUDED | Data read. |
| `privileged-execution-through-a-state-manager-association` | Privileged execution through a State Manager association | ssm:CreateAssociation | COVERED | `aws-ssm-createassociation`<br> — conditional verified exact-target authority.; historical IDs excluded: aws-audit-create-association-targeting-hybrid-managed-node |
| `ssmupdatedocument-ssmupdatedocumentdefaultversion-ssmlistdocuments--ssmgetdocument` | `ssm:UpdateDocument`, `ssm:UpdateDocumentDefaultVersion`, (`ssm:ListDocuments` \| `ssm:GetDocument`) | ssm:UpdateDocument, ssm:UpdateDocumentDefaultVersion | EXCLUDED | Excluded: The ssm_document artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |
| `ssmregistertaskwithmaintenancewindow-ssmregistertargetwithmaintenancewindow-ssmdescribemaintenancewindows--ec2describeinstances` | `ssm:RegisterTaskWithMaintenanceWindow`, `ssm:RegisterTargetWithMaintenanceWindow`, (`ssm:DescribeMaintenanceWindows` \| `ec2:DescribeInstan | ssm:RegisterTaskWithMaintenanceWindow, ssm:RegisterTargetWithMaintenanceWindow | COVERED | `aws-ssm-maintenancewindow-register-task-target`<br>`aws-ssm-maintenancewindow-automation-task-passrole` |
| `codebuild` | Codebuild |  | EXCLUDED | Cross-reference to the CodeBuild page (other agent); no SSM permission combination here. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-sso-and-identitystore-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---sso--identitystore-privesc` | AWS - SSO & identitystore Privesc |  | STRUCTURAL | Page title / references list |
| `iam-identity-center--sso` | IAM, Identity Center & SSO |  | EXCLUDED | Page introduction and enumeration link; techniques are mapped under their own headings. |
| `aws-identity-center--aws-sso` | AWS Identity Center / AWS SSO |  | STRUCTURAL | Introduction on management/delegated-administrator ownership and PermissionSetsEnabled; captured as conditions of the sso entries. sso:UpdateInstance alone is not an escalation per the text.<br>`aws-audit-enable-permission-sets-then-create-admin-assignment` — conditional verified exact-target authority. |
| `sso-directoryupdatepassword` | `sso-directory:UpdatePassword` | sso-directory:UpdatePassword | EXCLUDED | Excluded: UpdatePassword may reset another Identity Center user, but the target entity is account-wide and does not bind an exact user, usable sign-in, MFA state, or gained assignment. |
| `identitystorecreategroupmembership` | `identitystore:CreateGroupMembership` | identitystore:CreateGroupMembership | EXCLUDED | excluded: "Add an Identity Center user controlled by the source to a group"; no reviewed source-to-controlled-subject and assignment join. |
| `ssoputinlinepolicytopermissionset-ssoprovisionpermissionset` | `sso:PutInlinePolicyToPermissionSet`, `sso:ProvisionPermissionSet` | sso:PutInlinePolicyToPermissionSet, sso:ProvisionPermissionSet | EXCLUDED | excluded: "Add an inline policy to a permission set and re-provision it"; no reviewed source-to-controlled-subject and assignment join. |
| `ssoattachmanagedpolicytopermissionset-ssoprovisionpermissionset` | `sso:AttachManagedPolicyToPermissionSet`, `sso:ProvisionPermissionSet` | sso:AttachManagedPolicyToPermissionSet, sso:ProvisionPermissionSet | EXCLUDED | excluded: "Attach an AWS-managed policy to a permission set and re-provision it"; no reviewed source-to-controlled-subject and assignment join. |
| `ssoattachcustomermanagedpolicyreferencetopermissionset-ssoprovisionpermissionset` | `sso:AttachCustomerManagedPolicyReferenceToPermissionSet`, `sso:ProvisionPermissionSet` | sso:AttachCustomerManagedPolicyReferenceToPermissionSet, sso:ProvisionPermissionSet | EXCLUDED | excluded: "Attach a customer-managed policy reference to a permission set and re-provision it"; no reviewed source-to-controlled-subject and assignment join. |
| `ssocreateaccountassignment` | `sso:CreateAccountAssignment` | sso:CreateAccountAssignment | EXCLUDED | excluded: "Assign a permission set to a controlled user in an account"; no reviewed source-to-controlled-subject and assignment join. |
| `ssogetrolecredentials` | `sso:GetRoleCredentials` | sso:GetRoleCredentials | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `ssodetachmanagedpolicyfrompermissionset` | `sso:DetachManagedPolicyFromPermissionSet` | sso:DetachManagedPolicyFromPermissionSet | EXCLUDED | Merged into aws-sso-remove-permission-set-restriction (any_of group). |
| `ssodetachcustomermanagedpolicyreferencefrompermissionset` | `sso:DetachCustomerManagedPolicyReferenceFromPermissionSet` | sso:DetachCustomerManagedPolicyReferenceFromPermissionSet | EXCLUDED | Merged into aws-sso-remove-permission-set-restriction (any_of group). |
| `ssodeleteinlinepolicyfrompermissionset` | `sso:DeleteInlinePolicyFromPermissionSet` | sso:DeleteInlinePolicyFromPermissionSet | EXCLUDED | Merged into aws-sso-remove-permission-set-restriction (any_of group). |
| `ssodeletepermissionsboundaryfrompermissionset` | `sso:DeletePermissionsBoundaryFromPermissionSet` | sso:ProvisionPermissionSet, sso:DetachManagedPolicyFromPermissionSet, sso:DetachCustomerManagedPolicyReferenceFromPermissionSet, sso:DeleteInlinePolicyFromPermissionSet, sso:DeletePermissionsBoundaryFromPermissionSet | EXCLUDED | excluded: "Remove a restricting policy or boundary from a permission set and re-provision it"; no reviewed source-to-controlled-subject and assignment join. |
| `ssocreatepermissionset--policy-attach--ssocreateaccountassignment--build-an-admin-path-from-scratch` | `sso:CreatePermissionSet` (+ policy attach + `sso:CreateAccountAssignment`) — build an admin path from scratch | sso:CreatePermissionSet, sso:CreateAccountAssignment, sso:ProvisionPermissionSet, sso:AttachManagedPolicyToPermissionSet, sso:PutInlinePolicyToPermissionSet | EXCLUDED | excluded: "Create an admin permission set and assign it to a controlled user in a member account"; no reviewed source-to-controlled-subject and assignment join. |
| `identitystorecreateuser--sso-directorycreateuser--group-membership--assignment` | `identitystore:CreateUser` / `sso-directory:CreateUser` (+ group membership / assignment) | identitystore:CreateUser, identitystore:CreateGroupMembership | EXCLUDED | [excluded former aws-identitystore-createuser-groupmembership]<br>Excluded: CreateUser and CreateAccountAssignment do not prove source control of a usable new-user credential or exact permission-set assignment scope. |
| `sso-admincreatetrustedtokenissuer--createapplication--putapplicationgrant--impersonate-any-user-via-a-rogue-trusted-token-issuer` | `sso-admin:CreateTrustedTokenIssuer` (+ `CreateApplication` / `PutApplicationGrant`) — impersonate any user via a rogue trusted token issuer | sso-admin:CreateTrustedTokenIssuer | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `account-accesscreateentitlement--assign-an-existing-iam-role-to-a-controlled-identity-center-user` | `account-access:CreateEntitlement` — assign an existing IAM role to a controlled Identity Center user | account-access:CreateEntitlement | EXCLUDED | excluded: "Assign an existing IAM role to a controlled Identity Center user through Account Access Manager"; no reviewed source-to-controlled-subject and assignment join. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-stepfunctions-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---step-functions-privesc` | AWS - Step Functions Privesc |  | STRUCTURAL | Page title / references list |
| `step-functions` | Step Functions |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `task-resources` | Task Resources |  | EXCLUDED | Informational list of service integrations; no technique on its own. |
| `statesteststate--iampassrole` | `states:TestState` & `iam:PassRole` | iam:PassRole, states:TestState | COVERED | `aws-stepfunctions-teststate-passrole` |
| `eventbridge-connection-credentials-without-statesrevealsecrets` | EventBridge Connection credentials without `states:RevealSecrets` | iam:PassRole, states:TestState | COVERED | `aws-stepfunctions-teststate-passrole` — HTTP Task variant of TestState + PassRole; the passed role's Connection credentials are sent to an attacker endpoint.<br> — conditional verified exact-target authority.; historical IDs excluded: aws-audit-exfiltrate-eventbridge-connection-credential-via-teststate-http-task |
| `statescreatestatemachine--iampassrole--statesstartexecution--statesstartsyncexecution` | `states:CreateStateMachine` & `iam:PassRole` & (`states:StartExecution` \| `states:StartSyncExecution`) | iam:PassRole, states:CreateStateMachine, states:StartExecution, states:StartSyncExecution | COVERED | `aws-stepfunctions-createstatemachine-passrole-start` |
| `statesupdatestatemachine--not-always-required-iampassrole` | `states:UpdateStateMachine` & (not always required) `iam:PassRole` | states:UpdateStateMachine, iam:PassRole | COVERED | [excluded former aws-stepfunctions-updatestatemachine-existing-role], `aws-stepfunctions-updatestatemachine-passrole` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-sts-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---sts-privesc` | AWS - STS Privesc |  | STRUCTURAL | Page title / references list |
| `sts` | STS |  | STRUCTURAL | Service introduction linking to the STS enumeration page. |
| `stsassumerole` | `sts:AssumeRole` | sts:AssumeRole | COVERED | `aws-sts-assumerole-trusted` |
| `stsassumerolewithsaml` | `sts:AssumeRoleWithSAML` | sts:AssumeRoleWithSAML | EXCLUDED | Requires a valid SAML assertion from the trusted IdP (possession of IdP credentials); no IAM permission grants it. Provider takeover is modelled as aws-iam-updatesamlprovider. |
| `stsassumerolewithwebidentity` | `sts:AssumeRoleWithWebIdentity` | sts:AssumeRoleWithWebIdentity | EXCLUDED | Requires a token from the trusted OIDC IdP (external identity possession); trust-policy misconfigurations on OIDC providers are an Exposure finding, not a principal-to-principal edge. |
| `stsassumeroot--privileged-root-sessions-into-any-member-account` | `sts:AssumeRoot` — privileged root sessions into any member account | sts:AssumeRoot | EXCLUDED | Excluded: AssumeRoot returns a short task-policy-scoped root session, not full account-admin authority; task policy and management/delegated-admin source scope are not modeled as bounded grants. |
| `enabling-the-feature-yourself-management-account` | Enabling the feature yourself (management account) | sts:AssumeRoot | EXCLUDED | Excluded: AssumeRoot returns a short task-policy-scoped root session, not full account-admin authority; task policy and management/delegated-admin source scope are not modeled as bounded grants. — Variant of the AssumeRoot section; the enable chain (organizations:EnableAWSServiceAccess, iam:EnableOrganizationsRootCredentialsManagement, iam:EnableOrganizationsRootSessions) is the root_sessions_enabled condition of the entry, which still needs sts:AssumeRoot.<br> — conditional verified exact-target authority.; historical IDs excluded: aws-audit-enable-centralized-root-sessions-then-call-assumeroot |
| `stsgetfederationtoken` | `sts:GetFederationToken` | sts:GetFederationToken | EXCLUDED | Federation tokens are the intersection of the caller's own permissions and the session policy; never more privileged than the source. Persistence only. |
| `stsgetwebidentitytoken--externalsaas-credential-minting` | `sts:GetWebIdentityToken` — external/SaaS credential minting | sts:GetWebIdentityToken | EXCLUDED | Mints outbound tokens of the caller's own identity for external relying parties; it cannot be exchanged into a different AWS principal, so no AWS privilege edge. |
| `federation-abuse` | Federation Abuse |  | EXCLUDED | Overview pointing to federation pages; requires external IdP control. |
| `iam-roles-anywhere-privesc` | IAM Roles Anywhere Privesc |  | EXCLUDED | Requires possession of a certificate issued by a trusted CA (external credential); the overly broad trust is an Exposure finding. CA replacement is modelled as aws-rolesanywhere-updatetrustanchor. |
| `rolesanywhereupdatetrustanchor--replace-the-trusted-ca-and-mint-role-sessions` | `rolesanywhere:UpdateTrustAnchor` — replace the trusted CA and mint role sessions | rolesanywhere:UpdateTrustAnchor | COVERED | `aws-rolesanywhere-updatetrustanchor` |
| `rolesanywhereupdateprofile--remove-the-session-policy-boundary` | `rolesanywhere:UpdateProfile` — remove the session-policy boundary | rolesanywhere:UpdateProfile | EXCLUDED | Excluded: The source is not proved to possess a usable private key and accepted certificate for the exact profile and role, nor that the removed session policy previously denied a permission; profile mutation alone grants no caller session. — profile ARN and membership from `rolesanywhere_profile`. |
| `rolesanywheredeleteattributemapping--putattributemapping--exploit-missing-certificate-tags` | `rolesanywhere:DeleteAttributeMapping` / `PutAttributeMapping` — exploit missing certificate tags | rolesanywhere:DeleteAttributeMapping, rolesanywhere:PutAttributeMapping | EXCLUDED | Excluded: The source is not proved to possess a usable private key/certificate or that the exact role trust has the described negative/IfExists condition; mapping mutation alone grants no credential. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-supply-chain-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---supply-chain-privesc` | AWS - Supply Chain Privesc |  | STRUCTURAL | Page title / references list |
| `supply-chain` | Supply Chain |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `scnassignadminpermissionstouser` | `scn:AssignAdminPermissionsToUser` | scn:AssignAdminPermissionsToUser | EXCLUDED | Excluded: AssignAdminPermissionsToUser names an Identity Center user, but source control and sign-in for that exact user are only prose conditions. — application-plane administrator (`aws_service_plane_admin`, schema v1.1); unresolved per-account placeholder until the service resources are collected. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-synthetics-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloudwatch-synthetics-privesc` | AWS - CloudWatch Synthetics Privesc |  | STRUCTURAL | Page title / references list |
| `amazon-cloudwatch-synthetics` | Amazon CloudWatch Synthetics |  | EXCLUDED | Service introduction heading linking to the enumeration page; no technique. |
| `synthetics` | Synthetics |  | STRUCTURAL | Section heading; techniques are rows of their own. |
| `syntheticsstartcanary--run-unchanged-canary-code-under-its-stored-role` | `synthetics:StartCanary` — Run unchanged canary code under its stored role | synthetics:StartCanary | EXCLUDED | Runs fixed canary code; no control of code or role.<br>`aws-audit-trigger-privileged-existing-canary` — conditional verified exact-target authority. |
| `dry-run-replacement-code--passrole` | Dry-run replacement code + PassRole | synthetics:StartCanaryDryRun, lambda:GetFunctionConfiguration, lambda:PublishLayerVersion, lambda:GetLayerVersion, lambda:UpdateFunctionConfiguration, lambda:PublishVersion, lambda:AddPermission, iam:PassRole | EXCLUDED | Excluded: The synthetics_canary resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |
| `discovery-without-aws-enumeration-permissions` | Discovery without AWS enumeration permissions |  | STRUCTURAL | Enumeration guidance for the dry-run replacement-code technique. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-timestream-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---timestream-privesc` | AWS - Timestream Privesc |  | STRUCTURAL | Page title / references list |
| `timestream` | Timestream |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `timestreamcreatescheduledquery--iampassrole--run-sql-and-downstream-writes-as-a-scheduled-query-role` | `timestream:CreateScheduledQuery` + `iam:PassRole` — run SQL and downstream writes as a scheduled-query role | timestream:CreateScheduledQuery, iam:PassRole | STRUCTURAL | Legacy anchor points to the bounded data or application operation on its post-exploitation page. |

| `timestreamexecutescheduledquery--trigger-an-already-stored-role-workflow` | `timestream:ExecuteScheduledQuery` — trigger an already stored role workflow | timestream:ExecuteScheduledQuery | STRUCTURAL | Legacy anchor points to the bounded data or application operation on its post-exploitation page. |

| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-transfer-family-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---transfer-family-privesc` | AWS - Transfer Family Privesc |  | STRUCTURAL | Page title / references list |
| `aws-transfer-family` | AWS Transfer Family |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `transferimportsshpublickey--impersonate-a-service-managed-user` | `transfer:ImportSshPublicKey` — impersonate a service-managed user | transfer:ImportSshPublicKey | EXCLUDED | Previously mapped to `aws-transfer-importsshpublickey`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `transferupdateconnector--redirect-an-sftp-connector-and-capture-its-stored-credential` | `transfer:UpdateConnector` — redirect an SFTP connector and capture its stored credential | transfer:UpdateConnector | EXCLUDED | Captures a third-party SFTP credential; not an IAM principal.<br>`aws-audit-redirect-connector-to-steal-partner-sftp-credential` — conditional verified exact-target authority. |
| `transferstartfiletransfer--send-role-readable-s3-data-through-a-stored-connector` | `transfer:StartFileTransfer` — send role-readable S3 data through a stored connector | transfer:StartFileTransfer | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `transfercreateuserupdateusercreateaccessupdateaccess--iampassrole--attach-a-chosen-role-to-an-sftp-identity` | `transfer:CreateUser`/`UpdateUser`/`CreateAccess`/`UpdateAccess` + `iam:PassRole` — attach a chosen role to an SFTP identity | iam:PassRole, transfer:CreateUser, transfer:UpdateUser, transfer:CreateAccess, transfer:UpdateAccess | EXCLUDED | Previously mapped to `aws-transfer-passrole-createuser-access`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `secretsmanagerputsecretvalue--poison-a-secrets-manager-backed-custom-idp-user` | `secretsmanager:PutSecretValue` — poison a Secrets Manager-backed custom IdP user | secretsmanager:PutSecretValue | EXCLUDED | Previously mapped to `aws-transfer-secret-backed-idp-record`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `transferupdateserver-lambdaupdatefunctioncode-or-api-gateway-response-writes--take-over-a-custom-identity-provider` | `transfer:UpdateServer`, `lambda:UpdateFunctionCode`, or API Gateway response writes — take over a custom identity provider | transfer:UpdateServer, lambda:UpdateFunctionCode, apigateway:PATCH, apigateway:POST | EXCLUDED | Previously mapped to `aws-transfer-custom-idp-takeover`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `managed-workflow-role-abuse--execute-storage-actions-on-upload` | Managed workflow role abuse — execute storage actions on upload | transfer:CreateWorkflow, transfer:UpdateServer, iam:PassRole | EXCLUDED | Previously mapped to `aws-transfer-workflow-passrole-updateserver`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `as2-partner-certificate-substitution--impersonate-a-trading-partner` | AS2 partner-certificate substitution — impersonate a trading partner | transfer:ImportCertificate, transfer:UpdateProfile | EXCLUDED | Previously mapped to `aws-v3-01-substitute-an-as2-partner-signing-certificate`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `host-keys-are-not-a-standalone-privilege-escalation` | Host keys are not a standalone privilege escalation |  | EXCLUDED | Server host-key injection; integrity/impersonation risk only with separate routing control, not privilege escalation (as the page states). |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-verified-permissions-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---verified-permissions-privilege-escalation` | AWS - Verified Permissions Privilege Escalation |  | STRUCTURAL | Page title / references list |
| `verified-permissions` | Verified Permissions |  | EXCLUDED | Service introduction / enumeration pointer heading; techniques are mapped under their own headings. |
| `create-or-modify-a-permissive-cedar-policy` | Create or modify a permissive Cedar policy |  | EXCLUDED | Application-level authorization change in a Cedar policy store; no AWS IAM privileges unless the application maps decisions to AWS operations (app-specific). |
| `redirect-token-trust-with-updateidentitysource` | Redirect token trust with `UpdateIdentitySource` |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `rebind-a-policy-store-alias-to-a-permissive-store` | Rebind a policy-store alias to a permissive store |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-wickr-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---wickr-privesc` | AWS - Wickr Privesc |  | STRUCTURAL | Page title / references list |
| `wickr` | Wickr |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `wickrcreatedataretentionbotchallenge--take-over-the-data-retention-bot` | `wickr:CreateDataRetentionBotChallenge` — take over the data-retention bot | wickr:CreateDataRetentionBotChallenge | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-workdocs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---workdocs-privesc` | AWS - WorkDocs Privesc |  | STRUCTURAL | Page title / references list |
| `directory-services--workdocs` | Directory Services / WorkDocs |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `workdocs` | WorkDocs |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `workdocscreateuser` | `workdocs:CreateUser` | workdocs:CreateUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `workdocs-activity-metadata-and-content-read-chain` | WorkDocs activity, metadata, and content-read chain |  | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `workdocsaddresourcepermissions` | `workdocs:AddResourcePermissions` | workdocs:AddResourcePermissions | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `workdocsupdateuser` | `workdocs:UpdateUser` | workdocs:UpdateUser | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/aws-workspaces-appstream-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---workspaces-applications-privesc` | AWS - WorkSpaces Applications Privesc |  | STRUCTURAL | Page title / references list |
| `workspaces` | WorkSpaces |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-privilege-escalation/aws-workspaces-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---workspaces-privesc` | AWS - WorkSpaces Privesc |  | STRUCTURAL | Page title / references list |
| `workspaces` | WorkSpaces |  | EXCLUDED | Service introduction pointing to the enumeration page; no technique. |
| `workspaces-instances` | WorkSpaces Instances |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `workspaces-instancescreateworkspaceinstance-iampassrole-ec2runinstances` | `workspaces-instances:CreateWorkspaceInstance`, `iam:PassRole`, `ec2:RunInstances` | workspaces-instances:CreateWorkspaceInstance, iam:PassRole, ec2:RunInstances | COVERED | `aws-workspaces-instances-passrole-createworkspaceinstance` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/eventbridgescheduler-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---eventbridge-scheduler-privesc` | AWS - EventBridge Scheduler Privesc |  | STRUCTURAL | Page title / references list |
| `eventbridge-scheduler` | EventBridge Scheduler |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `iampassrole-schedulercreateschedule--schedulerupdateschedule` | `iam:PassRole`, (`scheduler:CreateSchedule` \| `scheduler:UpdateSchedule`) | iam:PassRole, scheduler:CreateSchedule, scheduler:UpdateSchedule | COVERED | `aws-scheduler-passrole-createschedule-or-updateschedule` |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-privilege-escalation/route53-createhostedzone-route53-changeresourcerecordsets-acm-pca-issuecertificate-acm-pca-getcer/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---route53-privesc` | AWS - Route53 Privesc |  | STRUCTURAL | Page title / references list |
| `route53` | Route53 |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |
| `route53createhostedzone-route53changeresourcerecordsets-acm-pcaissuecertificate-acm-pcagetcertificate-ec2describevpcs` | `route53:CreateHostedZone`, `route53:ChangeResourceRecordSets`, `acm-pca:IssueCertificate`, `acm-pca:GetCertificate`, `ec2:DescribeVpcs` | route53:CreateHostedZone, route53:ChangeResourceRecordSets, acm-pca:IssueCertificate, acm-pca:GetCertificate, ec2:DescribeVpcs | STRUCTURAL | Legacy anchor points to the post-exploitation section; the bounded operation is excluded there. |
| `exploitation` | Exploitation <a href="#discovery" id="discovery"></a> |  | STRUCTURAL | Exploitation steps of the Route 53 + ACM PCA interception technique, excluded as traffic interception with no IAM principal obtained. |
| `references` | References |  | STRUCTURAL | Page title / references list |

### aws-services/aws-api-gateway-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-appstream-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-batch-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-bedrock-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-certificate-manager-acm-and-private-certificate-authority-pca.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Placeholder (TODO) heading with no content. |

### aws-services/aws-cloud-control-api-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `write-operations-and-privilege-escalation` | Write operations and privilege escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-cloudformation-and-codestar-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privesc-1` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-codebuild-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-codeconnections-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `post-exploitation-and-privilege-escalation` | Post exploitation and privilege escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-cognito-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-cognito-enum/cognito-identity-pools.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `identity-pool-role-escalation` | Identity-pool role escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-compute-optimizer-automation-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `execution-role-and-cross-account-boundary` | Execution role and cross-account boundary |  | NOT PRIVESC | Fixed service-linked role trusted only by aco-automation.amazonaws.com; no caller-selected role or PassRole path. |

### aws-services/aws-config-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-connect-cases-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `post-exploitation-and-privilege-escalation` | Post exploitation and privilege escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-connect-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation-post-exploitation-and-persistence` | Privilege escalation, post exploitation and persistence |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-control-tower-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-datapipeline-codepipeline-codebuild-and-codecommit.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privesc-1` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-datazone-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iampassrole-boundaries` | `iam:PassRole` boundaries | iam:PassRole | STRUCTURAL | PassRole boundary notes for the service; the role-bearing techniques are rows of the service privesc page. |

### aws-services/aws-directory-services-workdocs-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-dynamodb-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `instance-profiles` | Instance Profiles |  | STRUCTURAL | Background on instance profiles; techniques are on the EC2 privesc page. |
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privesc-1` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privesc-2` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `autoscalingdescribelaunchconfigurations--user-data-disclosure` | `autoscaling:DescribeLaunchConfigurations` — user-data disclosure | autoscaling:DescribeLaunchConfigurations | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained. |

| `local-enumeration` | Local Enumeration |  | EXCLUDED | Previously mapped to `aws-v3-33-read-aws-vpn-client-temporary-credentials-from-another`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-ecr-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-ecs-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-efs-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-eks-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-elastic-beanstalk-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-emr-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-gamelift-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-iam-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |
| `privilege-escalation-1` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

| `local-enumeration` | Local Enumeration |  | EXCLUDED | Previously mapped to `aws-v3-31-steal-a-different-user-s-cached-iam-identity-center-acc`, `aws-v3-32-reuse-another-user-s-cached-sts-role-credentials-or-sta`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-kms-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-lambda-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-lightsail-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-macie-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-memorydb-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-mq-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-msk-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-odb-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-payment-cryptography-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-redshift-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `provisioned-temporary-credentials` | Provisioned temporary credentials | redshift:GetClusterCredentials, redshift:GetClusterCredentialsWithIAM | EXCLUDED | Previously mapped to `aws-redshift-getclustercredentials`, `aws-redshift-getclustercredentialswithiam`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `serverless-temporary-credentials` | Serverless temporary credentials | redshift-serverless:GetCredentials | EXCLUDED | Previously mapped to `aws-redshift-serverless-getcredentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-relational-database-rds-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-route53-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-s3-athena-and-glacier-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-sagemaker-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-secrets-manager-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-snowball-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege escalation |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-sns-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-sqs-and-sns-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privilege-escalation` | Privilege Escalation |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-stepfunctions-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Service introduction / enumeration link; techniques are rows of their own |

### aws-services/aws-sts-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-services/aws-transfer-family-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `permission-and-iampassrole-boundaries` | Permission and `iam:PassRole` boundaries | iam:PassRole | STRUCTURAL | PassRole boundary notes for the service; the role-bearing techniques are rows of the service privesc page. |

### aws-services/eventbridgescheduler-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `schedulergetschedule--target-input-disclosure` | `scheduler:GetSchedule` — target-input disclosure | scheduler:GetSchedule | NOT PRIVESC | Data-only: the action exposes, copies or redirects data (or uses a stored/passed service role for a fixed data operation); no other principal's privileges are obtained.<br>`aws-scheduler-getschedule-static-credential` — conditional verified exact-target authority. |
| `pipesupdatepipe-revalidates-iampassrole` | `pipes:UpdatePipe` revalidates `iam:PassRole` | pipes:UpdatePipe, iam:PassRole | STRUCTURAL | PassRole boundary notes for the service; the role-bearing techniques are rows of the service privesc page. |
| `privesc` | Privesc |  | STRUCTURAL | Pointer to the service privesc page; techniques are rows of that page. |

### aws-unauthenticated-enum-access/aws-iam-and-sts-unauthenticated-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `privesc` | Privesc | sts:AssumeRole | COVERED | `aws-sts-assumerole-trusted` — Role trust allowing a wildcard/foreign principal, assumed with sts:AssumeRole. |


## Catalog mappings added for master 8d6a341c8a

### aws-cross-account-attacks/iam-trust-and-federation-attacks.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-cross-account-attacks/organizations-and-central-account-pivots.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

| `scp-and-rcp-gaps` | SCP and RCP gaps | organizations:LeaveOrganization | EXCLUDED | Previously mapped to `aws-v3-58-leaveorganization-scp-escape`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-ec2-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-persistence/aws-ec2-replace-root-volume-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `ec2` | EC2 |  | EXCLUDED | Excluded: CreateReplaceRootVolumeTask does not prove the source controls a compatible replacement AMI/snapshot containing executable payload; that separate artifact foothold is a prose condition. |

### aws-persistence/aws-mainframe-modernization-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-persistence/aws-sagemaker-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `set-lifecycle-configuration-on-sagemaker-studio` | Set Lifecycle Configuration on SageMaker Studio | sagemaker:UpdateDomain | COVERED | [excluded former aws-sagemaker-attach-studio-lifecycle-config-space], `aws-sagemaker-attach-studio-lifecycle-config-user-profile`; historical IDs excluded: aws-v3-46-sagemaker-domain-lifecycle |

### aws-persistence/aws-systems-manager-incident-manager-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-appsync-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `hijack-resolver-function-or-data-source-behavior` | Hijack resolver, function or data-source behavior |  | EXCLUDED | Previously mapped to `aws-appsync-updateresolver-existing-datasource-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-bedrock-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-codeartifact-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-codeconnections-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-ecs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-eks-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `abusing-access-entries` | Abusing Access Entries |  | COVERED | [excluded former aws-eks-associateaccesspolicy-existing-entry], `aws-eks-updateclusterconfig-enable-access-entries` |

### aws-post-exploitation/aws-gamelift-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-post-exploitation/aws-greengrass-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `greengrasscreatecomponentversion--greengrasscreatedeployment--run-code-on-edge-core-devices` | `greengrass:CreateComponentVersion` + `greengrass:CreateDeployment` — run code on edge core devices |  | EXCLUDED | Device code execution; the thing group to role alias to TES role join is not collected (`_excluded_greengrass_unjoined_tes_role_final_reaudit_20261016.yaml`). |

### aws-post-exploitation/aws-mwaa-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `exploitation` | Exploitation |  | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |

### aws-post-exploitation/aws-pcs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `pcsgetcluster-secretsmanagergetsecretvalue--steal-the-slurm-scheduler-authentication-key` | `pcs:GetCluster`, `secretsmanager:GetSecretValue` — Steal the Slurm scheduler authentication key |  | EXCLUDED | Previously mapped to `aws-pcs-getcluster-slurm-secret-node-roles`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-rds-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `out-of-band-sql-via-rds-data-api-by-enabling-http-endpoint--resetting-master-password` | Out-of-band SQL via RDS Data API by enabling HTTP endpoint + resetting master password |  | EXCLUDED | Previously mapped to `aws-rds-modifydbcluster-master-password-associated-roles`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `read-the-rds-managed-master-password-from-secrets-manager-rdsdescribedb--secretsmanagergetsecretvalue` | Read the RDS-managed master password from Secrets Manager (`rds:DescribeDB*` + `secretsmanager:GetSecretValue`) |  | EXCLUDED | Previously mapped to `aws-rds-managed-master-secret-associated-roles`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-sagemaker-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-services/aws-lambda-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

### aws-unauthenticated-enum-access/aws-codebuild-unauthenticated-access/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `buildspecyml` | buildspec.yml |  | EXCLUDED | Excluded: The codecommit:GitPush source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |

## NEEDS SCHEMA

Shared proposal used by every item below: a new AWS entity target kind `aws_service_plane_admin`, one node per application resource, meaning "administrator of the service's own application plane" (Amazon Connect instance, Managed Grafana workspace, QuickSight account, Supply Chain instance, Amplify Studio backend). It is not an IAM principal and must not be treated as AWS-admin-equivalent.

```yaml
# schema.py TARGET_KINDS
aws_service_plane_admin: (aws, entity)
# placeholders allowed for the kind
aws_service_plane_admin: {target.scope, target.account, target.resource_arn}
# {target.scope} / {target.resource_arn} = the application resource ARN (connect instance, grafana workspace, ...)
# selector keys: resource_permission_covers_target (existing), service_plane: <connect|grafana|quicksight|supplychain|amplifybackend>
# evaluator: one unresolved node per account and service_plane until the application resources are collected
```

IMPLEMENTED (shared kind): `aws_service_plane_admin` is an AWS entity target kind (outcome defaults to `application_admin`). `target.selector.service_plane` is MANDATORY and only valid with this kind: `amplifybackend | connect | grafana | quicksight | scn` (IAM prefix; write `scn`, not `supplychain`). Allowed placeholders: `{target.scope}` / `{target.account}` (the account), `{target.resource_arn}` / `{target.arn}` (the application resource). The application resources are not collected, so every holder gets one unresolved placeholder per account (`not_collected`), never a member; non-holders get nothing. Write requirement resources as `{target.resource_arn}` (or `{target.resource_arn}/agent/*`, `{target.resource_arn}/*`) rather than `{target.scope}`, so they stay correct once instances are collected. `resource_permission_covers_target` is optional (redundant with the requirement). Test: tests/test_peaso_privesc_schema_ext_aws.py.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-amplify-privesc/README.md#amplifygetapp-amplifybackendcreatetoken--mint-an-amplify-studio-login

SUPERSEDES the _excluded_a.yaml line ('Excluded pending verification'). The page documents an application-administration session (Amplify Studio, Cognito custom-auth as aws-amplify-admin) over a Gen 1 backend's data model, auth and configuration; this is an app-plane admin target, not an IAM principal, so it needs the shared aws_service_plane_admin entity kind.

```yaml
- id: aws-amplifybackend-createtoken-studio-admin
  provider: aws
  service: amplifybackend
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-amplify-privesc/README.md#amplifygetapp-amplifybackendcreatetoken--mint-an-amplify-studio-login
  requires:
    all_of:
      - action: amplify:GetApp
        resource: "{target.scope}"
      - action: amplifybackend:CreateToken
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin      # NEW kind; {target.scope} = Amplify app ARN with a Gen 1 backend
    selector:
      resource_permission_covers_target: amplifybackend:CreateToken
    scope: same_account
    aggregate_as: "Amplify Studio administrators in {account}"
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: amplifybackend` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-amplifybackend-createtoken-studio-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-amplify-privesc/README.md#amplifygetapp-amplifybackendgettoken--recover-a-live-studio-login

SUPERSEDES the _excluded_a.yaml line. Same app-plane admin target as CreateToken, recovering a live Studio login with amplifybackend:GetToken (needs a current session id).

```yaml
- id: aws-amplifybackend-gettoken-studio-admin
  provider: aws
  service: amplifybackend
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-amplify-privesc/README.md#amplifygetapp-amplifybackendgettoken--recover-a-live-studio-login
  requires:
    all_of:
      - action: amplify:GetApp
        resource: "{target.scope}"
      - action: amplifybackend:GetToken
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin
    selector:
      resource_permission_covers_target: amplifybackend:GetToken
    scope: same_account
    aggregate_as: "Amplify Studio administrators in {account}"
  conditions:
    - id: live_session
      description: A live, unexpired Studio login session id must be known.
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: amplifybackend` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-amplifybackend-gettoken-studio-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#impersonate-a-saml-connect-user-with-a-controllable-role-session-name

Becomes an arbitrary (e.g. Admin security profile) Amazon Connect user; an application-plane administrator, not an AWS principal. Needs the aws_service_plane_admin kind. Requires assuming the federation role with a chosen RoleSessionName plus that role's broad connect:GetFederationToken.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-connect-saml-session-name-impersonation
  provider: aws
  service: connect
  title: Impersonate a SAML Connect user by choosing the role-session name
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#impersonate-a-saml-connect-user-with-a-controllable-role-session-name
  source_revision: 171e422
  requires:
    all_of:
      - action: connect:GetFederationToken
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: connect
      resource_permission_covers_target: connect:GetFederationToken
    scope: same_account
    aggregate_as: "Amazon Connect administrators in {account}"
  confidence: conditional
  severity: high
  conditions:
    - id: saml_identity_and_session_name
      description: The instance uses SAML identity management and the source can assume the federation role with an arbitrary RoleSessionName matching the victim's Connect username.
```

IMPLEMENTED: write the YAML above with `service_plane: connect` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-connect-saml-session-name-impersonation`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#take-over-a-connect-managed-user-through-updateuseridentityinfo

Takes over a CONNECT_MANAGED Connect user (password reset to an attacker email); application-plane admin target. Needs aws_service_plane_admin.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-connect-updateuseridentityinfo-takeover
  provider: aws
  service: connect
  title: Take over a Connect-managed user by changing its email
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#take-over-a-connect-managed-user-through-updateuseridentityinfo
  source_revision: 171e422
  requires:
    all_of:
      - action: connect:UpdateUserIdentityInfo
        resource: "{target.scope}/agent/*"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: connect
      resource_permission_covers_target: connect:UpdateUserIdentityInfo
    scope: same_account
    aggregate_as: "Amazon Connect administrators in {account}"
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: connect` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-connect-updateuseridentityinfo-takeover`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#grant-admin-through-security-profile-mutation

Assigns the Admin security profile (UpdateUserSecurityProfiles) or widens an assigned profile (UpdateSecurityProfile); application-plane admin. Needs aws_service_plane_admin with any_of.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-connect-security-profile-admin
  provider: aws
  service: connect
  title: Grant Connect Admin through security-profile assignment or mutation
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-connect-privesc/README.md#grant-admin-through-security-profile-mutation
  source_revision: 171e422
  requires:
    all_of:
      - action: connect:UpdateUserSecurityProfiles
        resource: "{target.scope}/*"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: connect
      resource_permission_covers_target: connect:UpdateUserSecurityProfiles
    scope: same_account
    aggregate_as: "Amazon Connect administrators in {account}"
  confidence: conditional
  severity: high
  notes: any_of alternative connect:UpdateSecurityProfile on a profile already assigned to a user the source controls.
```

IMPLEMENTED: write the YAML above with `service_plane: connect` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-connect-security-profile-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-managed-grafana-privesc/README.md#grafanacreateworkspaceapikey--arbitrary-role-legacy-api-key

Mints a Grafana ADMIN bearer key; application-plane administrator of the workspace. Needs aws_service_plane_admin.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-grafana-createworkspaceapikey-admin
  provider: aws
  service: grafana
  title: Mint an ADMIN Grafana workspace API key
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-managed-grafana-privesc/README.md#grafanacreateworkspaceapikey--arbitrary-role-legacy-api-key
  source_revision: 171e422
  requires:
    all_of:
      - action: grafana:CreateWorkspaceApiKey
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: grafana
      resource_permission_covers_target: grafana:CreateWorkspaceApiKey
    scope: same_account
    aggregate_as: "Managed Grafana administrators in {account}"
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: grafana` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-grafana-createworkspaceapikey-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-managed-grafana-privesc/README.md#createworkspaceserviceaccounttoken--existing-or-attacker-created-service-account

Mints a token for an existing (or newly created ADMIN) Grafana service account; application-plane admin. Needs aws_service_plane_admin.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-grafana-serviceaccounttoken-admin
  provider: aws
  service: grafana
  title: Mint a Grafana service-account token (optionally for a new ADMIN account)
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-managed-grafana-privesc/README.md#createworkspaceserviceaccounttoken--existing-or-attacker-created-service-account
  source_revision: 171e422
  requires:
    all_of:
      - action: grafana:CreateWorkspaceServiceAccount
        resource: "{target.scope}"
      - action: grafana:CreateWorkspaceServiceAccountToken
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: grafana
      resource_permission_covers_target: grafana:CreateWorkspaceServiceAccountToken
    scope: same_account
    aggregate_as: "Managed Grafana administrators in {account}"
  confidence: conditional
  severity: high
  notes: Token vending alone (existing service account) reaches that account's Grafana role; ADMIN is guaranteed only with CreateWorkspaceServiceAccount.
```

IMPLEMENTED: write the YAML above with `service_plane: grafana` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-grafana-serviceaccounttoken-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-quicksight-privesc/README.md#quicksightupdateuser--self-promote-to-admin

Promotes a QuickSight user the source controls to ADMIN; application-plane admin. Needs aws_service_plane_admin.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-quicksight-updateuser-admin
  provider: aws
  service: quicksight
  title: Promote a controlled QuickSight user to ADMIN
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-quicksight-privesc/README.md#quicksightupdateuser--self-promote-to-admin
  source_revision: 171e422
  requires:
    all_of:
      - action: quicksight:UpdateUser
        resource: "arn:aws:quicksight:*:{target.account}:user/*"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: quicksight
      resource_permission_covers_target: quicksight:UpdateUser
    scope: same_account
    aggregate_as: "QuickSight administrators in {account}"
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: quicksight` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-quicksight-updateuser-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-quicksight-privesc/README.md#quicksightregisteruser--map-a-controlled-iam-identity-to-an-admin

Registers an IAM identity the source controls as a QuickSight ADMIN; application-plane admin. Needs aws_service_plane_admin.

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-quicksight-registeruser-admin
  provider: aws
  service: quicksight
  title: Register a controlled IAM identity as a QuickSight ADMIN
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-quicksight-privesc/README.md#quicksightregisteruser--map-a-controlled-iam-identity-to-an-admin
  source_revision: 171e422
  requires:
    all_of:
      - action: quicksight:RegisterUser
        resource: "arn:aws:quicksight:*:{target.account}:user/*"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: quicksight
      resource_permission_covers_target: quicksight:RegisterUser
    scope: same_account
    aggregate_as: "QuickSight administrators in {account}"
  confidence: conditional
  severity: high
```

IMPLEMENTED: write the YAML above with `service_plane: quicksight` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-quicksight-registeruser-admin`.

### src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-supply-chain-privesc/README.md#scnassignadminpermissionstouser

Makes a controlled IAM Identity Center user the Supply Chain application administrator; application-plane admin. Needs aws_service_plane_admin (plus a source-controls-Identity-Center-user condition).

```yaml
# Proposed entity kind aws_service_plane_admin (shared G-wide proposal): an application-plane
# administrator identity of a managed service; {target.scope} = the application/instance ARN.
- id: aws-supplychain-assignadmin
  provider: aws
  service: scn
  title: Assign Supply Chain application administrator to a controlled Identity Center user
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-supply-chain-privesc/README.md#scnassignadminpermissionstouser
  source_revision: 171e422
  requires:
    all_of:
      - action: scn:AssignAdminPermissionsToUser
        resource: "{target.scope}"
  target:
    kind: aws_service_plane_admin
    selector:
      service_plane: scn
      resource_permission_covers_target: scn:AssignAdminPermissionsToUser
    scope: same_account
    aggregate_as: "AWS Supply Chain administrators in {account}"
  confidence: conditional
  severity: high
  conditions:
    - id: controlled_identity_center_user
      description: The source controls a user in the instance's connected IAM Identity Center identity source.
```

IMPLEMENTED: write the YAML above with `service_plane: scn` under `target.selector` (mandatory) and `{target.resource_arn}` in place of `{target.scope}` in requirement resources; everything else as written. Edges are unresolved per-account placeholders until the application resources are collected.

STATUS: COVERED by `aws-supplychain-assignadmin`.

## Facts follow-ups (aws_facts_ext consumers, catalog round 2)

| Item | Entry | Change | Facts | Missing facts |
| --- | --- | --- | --- | --- |
| Roles Anywhere note | `aws-rolesanywhere-updateprofile-remove-session-policy` (sts.yaml) | Note corrected: profile ARN / membership come from `rolesanywhere_profile` (already evaluated in aws.py) | `rolesanywhere_profile` | profile ARN / membership unknown |
| Image Builder note + input | `aws-imagebuilder-component-version-hijack` | Note corrected; `consumer_input_writable_via: imagebuilder:*` now evaluated: roles of collected pipelines -> conditional (`imagebuilder_recipe_components_not_collected`), `{target.consumer_input_arn}` = `arn:aws:imagebuilder:<pipeline Region>:<account>:component/*` | `imagebuilder_pipeline` | unknown (`imagebuilder_pipelines_not_collected`) |
| Amplify Admin ARN | `aws-amplifybackend-createtoken-studio-admin`, `aws-amplifybackend-gettoken-studio-admin` | amplifybackend:CreateToken/GetToken now on the Amplify Admin token resource `arn:aws:amplifybackend:<Region>:<account>:/backend/<AppId>/challenge/*` (new placeholder `target.amplifybackend_token_arn`, derived from the collected app ARN); the redundant `resource_permission_covers_target` (which resolved to the app ARN) removed; amplify:GetApp stays on the app ARN | `amplify_app` + `BackendEnvironments` | unresolved per-account placeholder |
| Cognito UpdateIdentityPool | `aws-cognito-updateidentitypool` | `{target.attached_resource_arn}` resolved: `via_resource_type: cognito_identity_pool` (host = identity pool ARN of each pool whose `Roles.Roles` authenticated/unauthenticated names the role). RoleMappings roles deliberately excluded (they bind existing providers; a provider added through UpdateIdentityPool gets the default authenticated role) | `cognito_identity_pool` `Roles` | unknown (`cognito_identity_pool_roles_not_collected`) |

Fixture tests: `tests/test_peaso_privesc_facts_followups.py` (facts present -> edge; facts missing -> unresolved / needs-facts).
Not verified online: the amplifybackend token ARN format follows the Amplify Admin API path (`/backend/{appId}/challenge`) and the IAM Service Authorization Reference resource naming as known offline; re-check against the live reference when online.

### Facts follow-up 2 (recipe components, Amplify Admin backend resource)
- aws-imagebuilder-component-version-hijack: `aws_facts_ext` now reads `imagebuilder:GetImageRecipe` per distinct pipeline recipe and keeps only component ARNs (`RecipeComponents`). `{target.consumer_input_arn}` = `component/<name>/*` for account-owned version-wildcard components, so name-scoped CreateComponent grants match; pinned/AWS-owned-only recipes exclude the role; no recipe facts: Region `component/*`, conditional. Customer policy: +`imagebuilder:GetImageRecipe` (471 actions; 6102/6123/3294 chars). Tests: `tests/test_peaso_privesc_facts_followups.py` (exact name, wildcard/pinned, no recipe facts), `tests/test_peaso_collectors_aws_ext.py` (component ARNs only, denied status).
- aws-amplifybackend-createtoken/gettoken: the token ARN `/backend/<AppId>/challenge/*` was verified against the Service Authorization Reference JSON (servicereference.us-east-1.amazonaws.com/v1/amplifybackend); a second requirement on the backend resource `/backend/<AppId>/*` (`{target.amplifybackend_backend_arn}`) was added. Because the evaluator treats wildcard overlap as a match, a token-only grant still produces the (conditional) edge.

### aws-services/aws-workmail-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `exact-impersonation-to-mailbox-chain` | Exact impersonation-to-mailbox chain | workmail:AssumeImpersonationRole | EXCLUDED | Previously mapped to `aws-v3-57-workmail-impersonation-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-workspaces-web-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `add-or-replace-an-attacker-controlled-identity-provider` | Add or replace an attacker-controlled identity provider | workspaces-web:CreateIdentityProvider | EXCLUDED | Previously mapped to `aws-v3-18-attach-an-attacker-idp-to-a-workspaces-secure-browser-p`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-waf-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-waf-log-credential-harvesting-and-request-replay` | AWS WAF log credential harvesting and request replay | logs:FilterLogEvents | EXCLUDED | Previously mapped to `aws-v3-15-replay-a-victim-application-session-recovered-from-waf`, `aws-waf-sampled-request-session-replay`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-managed-blockchain-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `recover-an-accessor-bearer-token` | Recover an Accessor bearer token | managedblockchain:GetAccessor | EXCLUDED | Previously mapped to `aws-v3-26-reuse-an-amazon-managed-blockchain-accessor-billing-tok`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-lex-v2-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `abuse-an-existing-code-hook-through-runtime-access` | Abuse an existing code hook through runtime access | lex:RecognizeText | EXCLUDED | Previously mapped to `aws-v3-14-trigger-privileged-business-actions-through-a-lex-fulfi`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-lambda-post-exploitation/aws-lambda-privileged-event-consumer-injection.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `preconditions-and-discovery-without-list-permissions` | Preconditions and discovery without list permissions | sns:Publish | EXCLUDED | Previously mapped to `aws-v3-12-drive-a-privileged-lambda-consumer-through-a-writable-e`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-kinesis-video-streams-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `recover-turn-credentials-and-impersonate-webrtc-peers` | Recover TURN credentials and impersonate WebRTC peers | kinesisvideo:ConnectAsViewer | EXCLUDED | Previously mapped to `aws-v3-27-join-kinesis-video-signaling-as-a-master-or-viewer-peer`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-ivs-chat-room-token-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `mint-a-room-token-and-join-the-data-plane` | Mint a room token and join the data plane | ivschat:CreateChatToken | EXCLUDED | Previously mapped to `aws-v3-20-mint-an-ivs-chat-token-using-another-application-user-i`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-iot-wireless-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `recover-wireless-device-onboarding-and-session-secrets` | Recover wireless-device onboarding and session secrets | iotwireless:GetWirelessDevice | EXCLUDED | Previously mapped to `aws-v3-22-clone-a-wireless-device-with-recovered-lorawan-or-sidew`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-iot-sitewise-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|


### aws-post-exploitation/aws-invoicing-and-billing-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `steal-or-sabotage-a-procurement-portal-connection` | Steal or sabotage a procurement portal connection | invoicing:GetProcurementPortalPreference | EXCLUDED | Previously mapped to `aws-v3-24-recover-or-redirect-procurement-portal-authentication-m`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-iam-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `policy-and-permission-boundary-deletion` | Policy and Permission Boundary Deletion | iam:DeleteUserPolicy | EXCLUDED | Previously mapped to `aws-v3-65-remove-own-explicit-deny`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-gamelift-streams-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `reconnect-to-an-active-or-disconnected-session` | Reconnect to an active or disconnected session | gameliftstreams:CreateStreamSessionConnection | EXCLUDED | Previously mapped to `aws-v3-17-reconnect-to-another-user-s-live-gamelift-streams-appli`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-firewall-manager-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `organizationsdescribeorganization--fmsassociateadminaccount-fmsdisassociateadminaccount-fmsputadminaccount` | `organizations:DescribeOrganization` & (`fms:AssociateAdminAccount`, `fms:DisassociateAdminAccount`, `fms:PutAdminAccount`) | fms:AssociateAdminAccount | EXCLUDED | Previously mapped to `aws-v3-68-firewall-manager-admin-action`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-evs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `recover-evs-managed-vcf-and-esx-credentials` | Recover EVS-managed VCF and ESX credentials | evs:GetEnvironment, secretsmanager:GetSecretValue | EXCLUDED | Previously mapped to `aws-v3-66-evs-vmware-admin-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `recover-connector-credentials-for-an-existing-vcf-appliance` | Recover connector credentials for an existing VCF appliance | evs:GetEnvironment, secretsmanager:GetSecretValue | EXCLUDED | Previously mapped to `aws-v3-67-evs-connector-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-devops-agent-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `disable-and-re-enable-the-operator-app-with-an-attacker-idp` | Disable and re-enable the Operator App with an attacker IdP | aidevops:DisableOperatorApp, aidevops:EnableOperatorApp, iam:PassRole | EXCLUDED | Previously mapped to `aws-v3-64-devops-agent-operator-app-idp-swap`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-device-farm-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `take-over-a-running-remote-access-device` | Take over a running remote-access device | devicefarm:GetRemoteAccessSession | EXCLUDED | Previously mapped to `aws-v3-16-redeem-a-device-farm-session-endpoint-and-control-a-log`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-cognito-directory-secret-disclosure-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `iam-reads-that-expose-directory-data-and-idp-client-secrets` | IAM reads that expose directory data and IdP client secrets | cognito-idp:DescribeUserPoolClient | EXCLUDED | Previously mapped to `aws-v3-25-use-a-cognito-idp-client-secret-as-the-oauth-applicatio`, `aws-cognito-upstream-idp-client-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-audit-manager-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `delegate-a-control-set-to-another-role` | Delegate a control set to another role | auditmanager:BatchCreateDelegationByAssessment | EXCLUDED | Previously mapped to `aws-v3-21-delegate-audit-manager-control-set-authority-to-an-atta`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-workspaces-web-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `persist-a-hostile-extension-in-every-secure-browser-session` | Persist a hostile extension in every secure-browser session | workspaces-web:UpdateBrowserSettings | EXCLUDED | Previously mapped to `aws-v3-04-force-install-a-hostile-extension-in-workspaces-web-ses`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `persist-an-attacker-controlled-portal-identity-provider` | Persist an attacker-controlled portal identity provider | workspaces-web:CreateIdentityProvider | EXCLUDED | Previously mapped to `aws-v3-05-add-or-replace-a-workspaces-web-portal-saml-oidc-identi`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-timestream-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `timestream-for-influxdb-plant-a-native-api-token` | Timestream for InfluxDB: plant a native API token | secretsmanager:GetSecretValue | EXCLUDED | Previously mapped to `aws-v3-53-influxdb-admin-credentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-opensearch-access-policy-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `esupdatedomainconfig--domain-access-policy-takeover` | `es:UpdateDomainConfig` — Domain access-policy takeover | es:UpdateDomainConfig | EXCLUDED | Previously mapped to `aws-v3-55-opensearch-domain-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-odb-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `retain-oracle-admin-access-with-a-known-password` | Retain Oracle `ADMIN` access with a known password | odb:UpdateAutonomousDatabase | EXCLUDED | Previously mapped to `aws-v3-50-oracle-autonomous-database-admin`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-memorydb-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `memorydbcreateuser-memorydbcreateacl--memorydbupdateacl--plant-a-full-access-acl-user` | `memorydb:CreateUser`, `memorydb:CreateACL` \| `memorydb:UpdateACL` — plant a full-access ACL user | memorydb:CreateACL, memorydb:CreateUser | EXCLUDED | Previously mapped to `aws-v3-43-memorydb-full-access-acl-user`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `memorydbupdateuser--hijack-or-widen-an-existing-acl-user` | `memorydb:UpdateUser` — hijack or widen an existing ACL user | memorydb:UpdateUser | EXCLUDED | Previously mapped to `aws-v3-44-memorydb-attached-user-takeover`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-marketplace-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws-marketplaceputresourcepolicy--cross-account-seller-entity-control` | `aws-marketplace:PutResourcePolicy` — cross-account seller-entity control | aws-marketplace:PutResourcePolicy | EXCLUDED | Previously mapped to `aws-v3-56-marketplace-seller-entity-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-lightsail-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `download-instance-ssh-keys--db-passwords` | Download Instance SSH keys & DB passwords | lightsail:GetRelationalDatabaseMasterUserPassword | EXCLUDED | Previously mapped to `aws-v3-54-lightsail-db-master-password`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-healthlake-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `take-over-smart-on-fhir-authorization` | Take over SMART-on-FHIR authorization | healthlake:UpdateFHIRDatastore | EXCLUDED | Previously mapped to `aws-v3-49-healthlake-smart-authorizer`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-firewall-manager-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `retaining-the-fms-administrator-role` | Retaining the FMS administrator role | fms:PutAdminAccount | EXCLUDED | Previously mapped to `aws-v3-51-firewall-manager-delegate`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-elasticache-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `elasticachemodifyuser--hijack-or-widen-an-existing-rbac-user` | `elasticache:ModifyUser` — hijack or widen an existing RBAC user | elasticache:ModifyUser | EXCLUDED | Previously mapped to `aws-v3-41-elasticache-attached-rbac-user-takeover`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `elasticachecreateuser-elasticachecreateusergroup--elasticachemodifyusergroup--plant-a-full-access-rbac-user` | `elasticache:CreateUser`, `elasticache:CreateUserGroup` \| `elasticache:ModifyUserGroup` — plant a full-access RBAC user | elasticache:CreateUser, elasticache:CreateUserGroup | EXCLUDED | Previously mapped to `aws-v3-42-elasticache-full-access-user-group`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-connect-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `create-a-durable-connect-administrator` | Create a durable Connect administrator | connect:CreateUser | EXCLUDED | Previously mapped to `aws-v3-47-connect-createuser`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-chime-sdk-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `add-an-attacker-controlled-messaging-identity` | Add an attacker-controlled messaging identity | chime:CreateAppInstanceAdmin | EXCLUDED | Previously mapped to `aws-v3-45-chime-sdk-admin-persistence`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-appintegrations-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `appintegrations` | AppIntegrations | app-integrations:UpdateApplication | EXCLUDED | Previously mapped to `aws-v3-03-replace-a-trusted-connect-workspace-application-with-at`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-persistence/aws-acm-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `register-an-attacker-controlled-acme-certificate-account` | Register an attacker-controlled ACME certificate account | acm:GetAcmeExternalAccountBindingCredentials | EXCLUDED | Previously mapped to `aws-v3-02-register-an-acme-account-with-a-binding-to-issue-certif`, `aws-pa-persist-s01-01`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-unauthenticated-enum-access/aws-lex-v2-unauthenticated-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `public-web-clients-backed-by-unauthenticated-cognito-identities` | Public web clients backed by unauthenticated Cognito identities |  | EXCLUDED | Previously mapped to `aws-v3-63-cognito-guest-to-lex`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-unauthenticated-enum-access/aws-dynamodb-unauthenticated-access/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cognito-guest-identities-for-dynamodb` | Cognito guest identities for DynamoDB |  | EXCLUDED | Previously mapped to `aws-v3-62-cognito-guest-to-dynamodb`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-unauthenticated-enum-access/aws-cognito-user-pool-unauthenticated-access/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `multi-region-replicas-split-password-lockout-counters` | Multi-Region replicas split password-lockout counters |  | EXCLUDED | Previously mapped to `aws-v3-06-use-independent-cognito-replica-lockout-counters-to-gue`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `registration` | Registration |  | EXCLUDED | Previously mapped to `aws-v3-61-public-signup-cognito-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `guest-identity-credentials` | Guest identity credentials |  | EXCLUDED | Previously mapped to `aws-v3-59-anonymous-cognito-guest-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |
| `enhanced-and-basic-authentication-flows` | Enhanced and basic authentication flows |  | EXCLUDED | Previously mapped to `aws-v3-60-cognito-classic-flow`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-services/aws-resource-groups-tagging-api-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `bulk-tagging-and-tag-sync-boundaries` | Bulk-tagging and tag-sync boundaries | tag:TagResources | EXCLUDED | Previously mapped to `aws-v3-34-change-an-authorization-tag-to-satisfy-a-tag-conditione`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-services/aws-devops-agent-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `inventory-private-connectivity` | Inventory private connectivity |  | EXCLUDED | Previously mapped to `aws-v3-35-use-a-compromised-devops-agent-integration-endpoint-as`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-supply-chain-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redirect-an-erp-connection-to-expose-credentials-used-by-the-instance-role` | Redirect an ERP connection to expose credentials used by the instance role |  | EXCLUDED | Previously mapped to `aws-v3-23-redirect-a-supply-chain-erp-connector-to-capture-a-dele`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-migration-hub-strategy-recommendations-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `harvest-credentials-from-a-compromised-collector-host` | Harvest credentials from a compromised collector host |  | EXCLUDED | Previously mapped to `aws-v3-11-harvest-the-strategy-recommendations-collector-aws-keys`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


## Additive v4 reviewed mappings

These entries were added after the historical heading sweep. Catalog binding: `4913b6d88ced9972f72ccdd708d21641725a6fb5`. Each row retains its entry's authored source revision in the proof manifest.

### aws-persistence/aws-cloudformation-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cdk-bootstrap-stack` | Change CDKToolkit TrustedAccounts to attacker account and deploy role trust | cloudformation:UpdateStack | EXCLUDED | Excluded: CloudFormation stack update can alter a bootstrap trust list, but the source is not proved to control the admitted external-account principal or receive role credentials; the generic challenge fact has no typed source-to-target contract. — conditional exact-target evidence; source revision `unspecified`. |

### aws-persistence/aws-ecs-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `periodic-ecs-task-through-eventbridge` | Schedule attacker-controlled ECS code under a task role | events:PutRule, events:PutTargets, iam:PassRole | EXCLUDED | Excluded: PutRule/PutTargets and PassRole can schedule a task, but the source is not proved to control code in the selected task definition or obtain its task-role credentials; the generic challenge fact has no typed execution/target contract. — conditional exact-target evidence; source revision `0b36331`. |

### aws-persistence/aws-iam-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `common-iam-persistence` | Create a privileged IAM user and obtain its access key | iam:AttachUserPolicy, iam:CreateAccessKey, iam:CreateUser, iam:PutUserPolicy | COVERED | `aws-iam-createuser-policy-accesskey` — conditional exact-target evidence; source revision `0b36331`. |

### aws-persistence/aws-lambda-persistence/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cronevent-actuator` | Run a newly created Lambda with a passable role through EventBridge | events:PutRule, events:PutTargets, iam:PassRole, lambda:AddPermission, lambda:CreateFunction | COVERED | `aws-lambda-passrole-createfunction-eventbridge-trigger` — conditional exact-target evidence; source revision `0b36331`. |

### aws-services/aws-lambda-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `enumeration` | Recover a distinct identity credential from GetFunctionConfiguration environment | lambda:GetFunctionConfiguration | COVERED | `aws-lambda-getconfig-secret-identity` — conditional exact-target evidence; source revision `0b36331`.<br> — conditional verified exact-target authority.<br> — conditional verified exact-target authority.<br> — conditional verified exact-target authority.; historical IDs excluded: aws-lambda-getfunction-package-secret-identity, aws-lambda-listfunctions-secret-identity, aws-lambda-listversions-secret-identity |

### aws-services/aws-lightsail-enum.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `metadata` | Read an actual AWS role credential from Lightsail IMDS |  | EXCLUDED | Previously mapped to `aws-lightsail-imds-verified-role`; these entries are excluded by the strict principal-to-principal or permission-gain review. |


### aws-post-exploitation/aws-lakeformation-post-exploitation/README.md
| `register-an-s3-location-under-a-privileged-role` | aws-audit-lf-register-an-s3-location-under-a-privileged-384933ea | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit-lf-register-an-s3-location-under-a-privileged-384933ea`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-appconfig-post-exploitation/README.md
| `appconfig-data--read-the-deployed-configuration` | aws-audit2-appconfig-2 | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit2-appconfig-2`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-chime-sdk-enum.md
| `media-pipelines` | aws-chime-rtmp-publisher-key-read | Verified native evidence | EXCLUDED | Previously mapped to `aws-chime-rtmp-publisher-key-read`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-codeconnections-post-exploitation/README.md
| `complete-or-replace-a-connection-installation` | aws-codeconnections-installation-consumer | Verified native evidence | EXCLUDED | Previously mapped to `aws-codeconnections-installation-consumer`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-control-tower-post-exploitation/README.md
| `enable--disable-controls` | aws-controltower-preventive-scp-disable | Verified native evidence | EXCLUDED | Previously mapped to `aws-controltower-preventive-scp-disable`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-payment-cryptography-enum.md
| `resource-and-authorization-model` | aws-payment-cryptography-crossaccount-key-policy | Verified native evidence | EXCLUDED | Previously mapped to `aws-payment-cryptography-crossaccount-key-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-partner-central-selling-persistence/README.md
| `add-an-external-engagement-member-for-permanent-snapshot-access` | aws-peaso-add-an-external-engagement-member-for-permanent-snapshot-access | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-add-an-external-engagement-member-for-permanent-snapshot-access`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-managed-prometheus-persistence/README.md
| `backdoor-a-workspace-with-its-resource-policy` | aws-peaso-backdoor-a-workspace-with-its-resource-policy | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-backdoor-a-workspace-with-its-resource-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-msk-policy-persistence/README.md
| `cross-account-cluster-access-with-kafkaputclusterpolicy` | aws-peaso-cross-account-cluster-access-with-kafkaputclusterpolicy | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-cross-account-cluster-access-with-kafkaputclusterpolicy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-q-business-persistence/README.md
| `cross-account-data-accessor-persistence` | aws-peaso-cross-account-data-accessor-persistence | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-cross-account-data-accessor-persistence`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-mediaconnect-persistence/README.md
| `grant-a-cross-account-flow-entitlement` | aws-peaso-grant-a-cross-account-flow-entitlement | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-grant-a-cross-account-flow-entitlement`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-mediapackage-v2-policy-persistence/README.md
| `grant-external-ingest--mediapackagev2putchannelpolicy` | aws-peaso-grant-external-ingest-mediapackagev2putchannelpolicy | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-grant-external-ingest-mediapackagev2putchannelpolicy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-payment-cryptography-persistence/README.md
| `persist-cross-account-key-access-with-a-resource-policy` | aws-peaso-persist-cross-account-key-access-with-a-resource-policy | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-persist-cross-account-key-access-with-a-resource-policy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-mediapackage-v2-policy-persistence/README.md
| `publish-a-private-origin-endpoint--mediapackagev2putoriginendpointpolicy` | aws-peaso-publish-a-private-origin-endpoint-mediapackagev2putoriginendpointpolicy | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-publish-a-private-origin-endpoint-mediapackagev2putoriginendpointpolicy`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-network-manager-persistence/README.md
| `share-a-core-network-with-an-external-account-through-aws-ram` | aws-peaso-share-a-core-network-with-an-external-account-through-aws-ram | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-share-a-core-network-with-an-external-account-through-aws-ram`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-q-business-enum.md
| `data-accessors-and-resource-policies` | aws-qbusiness-crossaccount-data-accessor | Verified native evidence | EXCLUDED | Previously mapped to `aws-qbusiness-crossaccount-data-accessor`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-transfer-family-post-exploitation/README.md
| `connector-remote-directory-move-and-delete-capability-pivot` | aws-s05-connector-remote-directory-move-and-delete-capability-pivot | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-connector-remote-directory-move-and-delete-capability-pivot`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-verified-permissions-post-exploitation/README.md
| `delete-or-corrupt-the-authorization-store` | aws-s05-delete-or-corrupt-the-authorization-store | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-delete-or-corrupt-the-authorization-store`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-vpc-lattice-post-exploitation/README.md
| `vpc-latticecreateservicenetworkvpcassociation--obtain-network-reachability-into-a-service-network` | aws-s05-vpc-latticecreateservicenetworkvpcassociation-obtain-network-reachabil | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-vpc-latticecreateservicenetworkvpcassociation-obtain-network-reachabil`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-waf-post-exploitation/README.md
| `wafv2tagresource-wafv2untagresource` | aws-s05-wafv2tagresource-wafv2untagresource | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-wafv2tagresource-wafv2untagresource`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-verified-permissions-enum.md
| `enumerate-stores-and-aliases` | aws-verifiedpermissions-alias-rebind | Verified native evidence | EXCLUDED | Previously mapped to `aws-verifiedpermissions-alias-rebind`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-verified-permissions-enum.md
| `exact-iam-boundaries` | aws-verifiedpermissions-policy-app-admin | Verified native evidence | EXCLUDED | Previously mapped to `aws-verifiedpermissions-policy-app-admin`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-gamelift-streams-enum.md
| `enumerate-bearer-stream-urls` | aws-audit-gameliftstreams-bearer-url | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit-gameliftstreams-bearer-url`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-ivs-post-exploitation/README.md
| `recover-publishing-and-playback-capabilities` | aws-audit-ivs-recover-publishing-and-playback-capabilit-7128f3c7 | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit-ivs-recover-publishing-and-playback-capabilit-7128f3c7`, `aws-audit-ivs-recover-publishing-and-playback-capabilit-997dd8c9`, `aws-audit-ivs-recover-publishing-and-playback-capabilit-fd578249`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-appsync-post-exploitation/README.md
| `read-environment-secrets-and-export-the-schema` | aws-audit2-appsync-2 | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit2-appsync-2`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-athena-query-disclosure-post-exploitation/README.md
| `query-history-and-result-disclosure` | aws-audit2-athena-query-disclosure-1 | Verified native evidence | EXCLUDED | Previously mapped to `aws-audit2-athena-query-disclosure-1`, `aws-audit2-athena-query-disclosure-2`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-chime-sdk-enum.md
| `meetings` | aws-chime-attendee-jointoken-read | Verified native evidence | EXCLUDED | Previously mapped to `aws-chime-attendee-jointoken-read`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-codebuild-enum.md
| `enumeration` | aws-codebuild-read-plaintext-aws-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-codebuild-read-plaintext-aws-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-cognito-enum/cognito-user-pools.md
| `directory-and-client-secret-disclosure` | aws-cognito-describeidentityprovider-upstream-client-secret | Verified native evidence | EXCLUDED | Previously mapped to `aws-cognito-describeidentityprovider-upstream-client-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md
| `collect-contact-metadata-attributes-references-and-files` | aws-connect-contact-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-contact-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md
| `read-or-monitor-live-conversations` | aws-connect-conversation-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-conversation-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-connect-enum.md
| `authorization-and-unauthenticated-boundary` | aws-connect-createparticipant-bearer | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-createparticipant-bearer`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md
| `recover-flow-source-and-integration-targets` | aws-connect-flow-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-flow-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md
| `intercept-and-alter-an-active-chat-with-a-custom-message-processor` | aws-connect-processor-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-processor-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md
| `stream-an-active-chat-to-a-cross-account-sns-topic` | aws-connect-stream-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-connect-stream-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-datazone-persistence/README.md
| `add-an-attacker-profile-as-a-project-owner` | aws-datazone-createprojectmembership-owner | Verified native evidence | EXCLUDED | Previously mapped to `aws-datazone-createprojectmembership-owner`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/eventbridgescheduler-enum.md
| `eventbridge-rule-targets` | aws-events-listtargets-static-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-events-listtargets-static-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-healthomics-enum.md
| `cloudtrail-and-stealth` | aws-healthomics-cloudtrail-workflow-zip-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-healthomics-cloudtrail-workflow-zip-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-keyspaces-enum.md
| `enumerate-and-read-cdc-streams` | aws-keyspaces-cdc-credential-record | Verified native evidence | EXCLUDED | Previously mapped to `aws-keyspaces-cdc-credential-record`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-keyspaces-enum.md
| `connect-to-cql-with-sigv4` | aws-keyspaces-select-credential-row | Verified native evidence | EXCLUDED | Previously mapped to `aws-keyspaces-select-credential-row`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-lambda-enum.md
| `lambda-durable-executions` | aws-lambda-durablehistory-secret-identity | Verified native evidence | EXCLUDED | Previously mapped to `aws-lambda-durablehistory-secret-identity`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-lex-v2-enum.md
| `runtime-sessions-and-stored-utterances` | aws-lex-getsession-other-application-session | Verified native evidence | EXCLUDED | Previously mapped to `aws-lex-getsession-other-application-session`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-managed-blockchain-persistence/README.md
| `establish-an-attacker-owned-consortium-member` | aws-peaso-establish-an-attacker-owned-consortium-member | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-establish-an-attacker-owned-consortium-member`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-persistence/aws-managed-blockchain-persistence/README.md
| `mint-an-accessor-bearer-credential` | aws-peaso-mint-an-accessor-bearer-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-peaso-mint-an-accessor-bearer-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-workmail-post-exploitation/README.md
| `abusing-workmail-to-bypass-ses-sandbox` | aws-s05-abusing-workmail-to-bypass-ses-sandbox | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-abusing-workmail-to-bypass-ses-sandbox`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-workspaces-web-post-exploitation/README.md
| `disable-inline-redaction` | aws-s05-disable-inline-redaction | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-disable-inline-redaction`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-vpn-post-exploitation/README.md
| `ec2getvpnconnectiondevicesampleconfiguration--disclose-site-to-site-vpn-pre-shared-keys` | aws-s05-ec2getvpnconnectiondevicesampleconfiguration-disclose-site-to-site-vpn | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-ec2getvpnconnectiondevicesampleconfiguration-disclose-site-to-site-vpn`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-timestream-post-exploitation/README.md
| `liveanalytics-export-query-results-to-s3-with-timestreamunload` | aws-s05-liveanalytics-export-query-results-to-s3-with-timestreamunload | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-liveanalytics-export-query-results-to-s3-with-timestreamunload`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-timestream-post-exploitation/README.md
| `liveanalytics-query-a-table-with-timestreamselect` | aws-s05-liveanalytics-query-a-table-with-timestreamselect | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-liveanalytics-query-a-table-with-timestreamselect`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-transfer-family-post-exploitation/README.md
| `logsfilterlogevents--logsgetlogevents--recover-custom-idp-passwords-from-logs` | aws-s05-logsfilterlogevents-logsgetlogevents-recover-custom-idp-passwords-from | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-logsfilterlogevents-logsgetlogevents-recover-custom-idp-passwords-from`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-systems-manager-for-sap-post-exploitation/README.md
| `recover-configured-sap-hana-administrator-credentials` | aws-s05-recover-configured-sap-hana-administrator-credentials | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-recover-configured-sap-hana-administrator-credentials`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-workspaces-thin-client-post-exploitation/README.md
| `thinclientupdateenvironment---redirect-devices-to-another-desktop-provider-or-idp-endpoint` | aws-s05-thinclientupdateenvironment-redirect-devices-to-another-desktop-provid | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-thinclientupdateenvironment-redirect-devices-to-another-desktop-provid`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-wickr-post-exploitation/README.md
| `wickrgetoidcinfo--disclose-the-sso-client-secret` | aws-s05-wickrgetoidcinfo-disclose-the-sso-client-secret | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-wickrgetoidcinfo-disclose-the-sso-client-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-wickr-post-exploitation/README.md
| `wickrgetopentdfconfig--disclose-the-opentdf-client-secret` | aws-s05-wickrgetopentdfconfig-disclose-the-opentdf-client-secret | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-wickrgetopentdfconfig-disclose-the-opentdf-client-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-wickr-post-exploitation/README.md
| `wickrlistusers--recover-an-invited-users-enrollment-code` | aws-s05-wickrlistusers-recover-an-invited-users-enrollment-code | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-wickrlistusers-recover-an-invited-users-enrollment-code`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-workspaces-post-exploitation/README.md
| `workspacesmodifysamlproperties--modifycertificatebasedauthproperties--weaken-desktop-authentication` | aws-s05-workspacesmodifysamlproperties-modifycertificatebasedauthproperties-we | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-workspacesmodifysamlproperties-modifycertificatebasedauthproperties-we`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-post-exploitation/aws-workspaces-post-exploitation/README.md
| `workspacesupdateworkspaceimagepermission--share-a-custom-image-with-an-attacker-account` | aws-s05-workspacesupdateworkspaceimagepermission-share-a-custom-image-with-an | Verified native evidence | EXCLUDED | Previously mapped to `aws-s05-workspacesupdateworkspaceimagepermission-share-a-custom-image-with-an`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-systems-manager-for-sap-enum.md
| `applications-components-and-databases` | aws-ssm-sap-hana-admin-secret | Verified native evidence | EXCLUDED | Previously mapped to `aws-ssm-sap-hana-admin-secret`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-transfer-family-enum.md
| `main-resource-relationships` | aws-transfer-connector-remote-credential | Verified native evidence | EXCLUDED | Previously mapped to `aws-transfer-connector-remote-credential`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-services/aws-verified-permissions-enum.md
| `identity-source-and-cross-account-boundaries` | aws-verifiedpermissions-identity-source-impersonation | Verified native evidence | EXCLUDED | Previously mapped to `aws-verifiedpermissions-identity-source-impersonation`; these entries are excluded by the strict principal-to-principal or permission-gain review. |

### aws-privilege-escalation/aws-codeartifact-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `publish-a-newer-compatible-package-version` | Publish a newer compatible package version |  | EXCLUDED | Excluded: The codeartifact_package artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |


### aws-privilege-escalation/aws-mwaa-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `airflow-serverlesscreateworkflow--iampassrole--run-attacker-code-as-the-execution-role` | `airflow-serverless:CreateWorkflow` + `iam:PassRole` → run attacker code as the execution role |  | COVERED | `aws-mwaa-serverless-passrole-createworkflow` |
| `classic-mwaa-airflowcreateweblogintoken--airflowcreateclitoken--code-execution-as-the-environment-execution-role` | Classic MWAA: `airflow:CreateWebLoginToken` / `airflow:CreateCliToken` → code execution as the environment execution role |  | EXCLUDED | Resource-to-role attachment is not collected; exact target cannot be proven (`_excluded_uncollected_service_join_final_reaudit_20261016.yaml`). |
| `repoint-the-execution-role-airflowupdateenvironment--iampassrole` | Repoint the execution role: `airflow:UpdateEnvironment` + `iam:PassRole` |  | COVERED | `aws-mwaa-passrole-updateenvironment` |
| `write-a-dag-file-into-an-mwaa-environments-dag-bucket-and-run-code-as-its-execution-role` | Write a DAG file into an MWAA environment's DAG bucket and run code as its execution role |  | EXCLUDED | Excluded: The s3_object artifact is not joined to an exact consuming resource and role: the AWS evaluator does not implement via_artifact_type or resolve target.artifact_arn. Writing the artifact alone cannot establish a principal-to-principal path. |

### aws-privilege-escalation/aws-cloudformation-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `change-cdktoolkit-trustedaccounts-to-attacker-account-and-deploy-role-trust` | change cdktoolkit trustedaccounts to attacker account and deploy role trust |  | EXCLUDED | Excluded: CloudFormation stack update can alter a bootstrap trust list, but the source is not proved to control the admitted external-account principal or receive role credentials; the generic challenge fact has no typed source-to-target contract. |
| `cloudformation-stacksets` | cloudformation stacksets |  | COVERED | `aws-cloudformation-service-managed-stackset-org-members` |

### aws-privilege-escalation/aws-codecommit-pipeline-source-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `push-a-codecommit-source-revision-executed-by-a-codebuild-project` | push a codecommit source revision executed by a codebuild project |  | EXCLUDED | Excluded: The codecommit:GitPush source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |

### aws-privilege-escalation/aws-codeconnections-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `redirect-a-repository-link` | redirect a repository link |  | EXCLUDED | Excluded: Repository link update does not join an existing sync configuration to the target role or prove control of the replacement Git installation and branch. |

### aws-privilege-escalation/aws-ec2-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `replace-the-root-volume-of-an-existing-role-bearing-ec2-instance` | replace the root volume of an existing role bearing ec2 instance |  | EXCLUDED | Excluded: CreateReplaceRootVolumeTask does not prove the source controls a compatible replacement AMI/snapshot containing executable payload; that separate artifact foothold is a prose condition. |
| `spot-fleet-request` | spot fleet request |  | COVERED | `aws-ec2-passrole-requestspotfleet` |

### aws-privilege-escalation/aws-ecs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `periodic-ecs-task-through-eventbridge` | periodic ecs task through eventbridge |  | EXCLUDED | Excluded: PutRule/PutTargets and PassRole can schedule a task, but the source is not proved to control code in the selected task definition or obtain its task-role credentials; the generic challenge fact has no typed execution/target contract. |
| `steer-replacement-service-tasks-to-an-attacker-controlled-container-instance` | steer replacement service tasks to an attacker controlled container instance |  | EXCLUDED | Excluded: Draining nodes does not prove replacement service tasks run on a source-controlled connected host or expose their credentials. |

### aws-privilege-escalation/aws-eks-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `associate-a-cluster-admin-access-policy-with-an-existing-eks-access-entry-the-source-controls` | associate a cluster admin access policy with an existing eks access entry the source controls |  | COVERED | `aws-eks-associateaccesspolicy-existing-entry`, `aws-eks-updateclusterconfig-enable-access-entries` |
| `eksassociateidentityproviderconfig-with-a-matching-privileged-rbac-group` | eksassociateidentityproviderconfig with a matching privileged rbac group |  | EXCLUDED | excluded: "Associate an attacker-controlled OIDC identity provider with an EKS cluster that binds a privileged RBAC group"; exact source-controlled identity or Kubernetes execution/RBAC join is unproved. |

### aws-privilege-escalation/aws-gamelift/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `managed-compute-shell-with-gameliftgetcomputeaccess` | managed compute shell with gameliftgetcomputeaccess |  | EXCLUDED | Excluded: The gamelift_fleet resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |

### aws-privilege-escalation/aws-iam-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `common-iam-persistence` | common iam persistence |  | COVERED | `aws-iam-createuser-policy-accesskey` |
| `iam-roles-anywhere-trust-anchor-backdoor-rolesanywherecreatetrustanchor--createprofile` | iam roles anywhere trust anchor backdoor rolesanywherecreatetrustanchor  createprofile |  | COVERED | `aws-rolesanywhere-createtrustanchor-createprofile-passrole` |
| `path-name-and-arn-conditions` | path name and arn conditions |  | EXCLUDED | Excluded: The selector checks trust against the existing source, not the newly created role; no typed new-role ARN to external trust-pattern join proves the target accepts it. |

### aws-privilege-escalation/aws-lambda-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cronevent-actuator` | cronevent actuator |  | COVERED | `aws-lambda-passrole-createfunction-eventbridge-trigger` |
| `enumeration` | enumeration |  | COVERED | `aws-lambda-getconfig-secret-identity` |
| `lambda-microvms` | lambda microvms |  | COVERED | `aws-lambda-microvm-passrole-runmicrovm-shell` |

### aws-privilege-escalation/aws-mainframe-modernization-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `m2updateapplication---store-a-malicious-application-version-for-later-deployment` | m2updateapplication   store a malicious application version for later deployment |  | EXCLUDED | Excluded: The m2_application resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |

### aws-privilege-escalation/aws-managed-grafana-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `grafanaupdatepermissions--iam-identity-center-administrator` | grafanaupdatepermissions  iam identity center administrator |  | EXCLUDED | excluded: "Grant a controlled Identity Center identity Grafana administrator access"; UpdatePermissions can grant ADMIN to an Identity Center identity, but the source is not proved to control a credentialed member of that user/group. |
| `grafanaupdateworkspaceauthentication--attacker-controlled-saml-idp` | grafanaupdateworkspaceauthentication  attacker controlled saml idp |  | COVERED | `aws-grafana-updateworkspaceauthentication-saml-admin` |

### aws-privilege-escalation/aws-sagemaker-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `sagemaker-model-registry-supply-chain-injection-via-createmodelpackageapproved` | sagemaker model registry supply chain injection via createmodelpackageapproved |  | EXCLUDED | Excluded: The sagemaker:CreateModelPackage source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `sagemakerupdatenotebookinstancelifecycleconfig--stored-code-execution-as-the-notebook-role` | sagemakerupdatenotebookinstancelifecycleconfig  stored code execution as the notebook role |  | EXCLUDED | Excluded: The sagemaker:UpdateNotebookInstanceLifecycleConfig source operation is not joined to an exact consumed input and target role: the AWS evaluator implements consumer_input_writable_via and target.consumer_input_arn only for Image Builder. This entry cannot prove the later consumer execution or authority gain. |
| `set-lifecycle-configuration-on-notebook-instances` | set lifecycle configuration on notebook instances |  | COVERED | `aws-sagemaker-attach-notebook-lifecycle-config` |
| `set-lifecycle-configuration-on-sagemaker-studio` | set lifecycle configuration on sagemaker studio |  | COVERED | [excluded former aws-sagemaker-attach-studio-lifecycle-config-space], `aws-sagemaker-attach-studio-lifecycle-config-user-profile` |

### aws-privilege-escalation/aws-ssm-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `hijack-response-plan-actions-chat-channel-and-contacts` | hijack response plan actions chat channel and contacts |  | COVERED | `aws-ssm-incidents-response-plan-automation-passrole` |

## PR #473 HEAD heading reconciliation

The rows below cover headings added or renamed after the historical ledger baseline.

### aws-privilege-escalation/aws-appsync-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Callable field, data-source role and source authorization are not joined. |
| `hijack-resolver-function-or-data-source-behavior` | hijack resolver function or data source behavior |  | EXCLUDED | Resolver mutation does not prove a caller-accessible field and exact stored data-source role; application data effects alone are not privilege escalation. |

### aws-privilege-escalation/aws-bedrock-agentcore-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Excluded: The bedrock-agentcore_harness resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |

### aws-privilege-escalation/aws-cloudformation-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Control of the admitted external-account principal and exact bootstrap-role access are not verified. |

### aws-privilege-escalation/aws-codeartifact-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Writable package→exact consumer role and execution are not collected. |
| `aws---codeartifact-privilege-escalation` | aws   codeartifact privilege escalation |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |

### aws-privilege-escalation/aws-codecommit-pipeline-source-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Writable revision, triggered build and project execution role are not joined. |

### aws-privilege-escalation/aws-codeconnections-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Git installation/branch control and sync configuration→role are not joined. |

### aws-privilege-escalation/aws-ec2-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Controlled replacement image and execution on the role-bearing instance are unverified. |

### aws-privilege-escalation/aws-ecs-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Source-controlled ECS host and replacement task placement are not verified. |

### aws-privilege-escalation/aws-eks-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | The configured OIDC claims are not joined to a privileged Kubernetes RBAC binding. |

### aws-privilege-escalation/aws-gamelift/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Excluded: The gamelift_fleet resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |


### aws-privilege-escalation/aws-iam-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | The newly created role and external trust claim/pattern are not joined. |

### aws-privilege-escalation/aws-lambda-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | COVERED | `aws-lambda-microvm-passrole-runmicrovm-shell` |
| `lambda-core-network-connectors` | lambda core network connectors |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |

### aws-privilege-escalation/aws-mainframe-modernization-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | EXCLUDED | Excluded: The m2_application resource-to-role attachment is not loaded by the AWS evaluator (absent from HOST_KIND); service trust or a guessed resource cannot identify the exact role that the source operation reaches. |

### aws-privilege-escalation/aws-managed-grafana-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | COVERED | `aws-grafana-updateworkspaceauthentication-saml-admin` |

### aws-privilege-escalation/aws-mwaa-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | COVERED | `aws-mwaa-serverless-passrole-createworkflow` |
| `aws---mwaa-privilege-escalation` | aws   mwaa privilege escalation |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |

### aws-privilege-escalation/aws-sagemaker-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `codeeditor` | codeeditor |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `critical-info` | critical info |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `example-aws-cli-commands` | example aws cli commands |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `impact` | impact |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `jupyterlab` | jupyterlab |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `jupyterserver` | jupyterserver |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `kernelgateway` | kernelgateway |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `requirements` | requirements |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `steps` | steps |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |
| `studio-domain-level-all-users` | studio domain level all users |  | EXCLUDED | Domain default lifecycle settings are not joined to a specific user/space execution role and a subsequent app start. |
| `studio-space-level-individual-or-shared-spaces` | studio space level individual or shared spaces |  | EXCLUDED | Studio space→execution role is not collected; the archived space entry matched any SageMaker-trusting role. |
| `types-of-studio-application-lifecycle-configurations` | types of studio application lifecycle configurations |  | STRUCTURAL | Section title, explanatory subheading, or API example; no separate proven gain. |

### aws-privilege-escalation/aws-ssm-privesc/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-privilege-escalation-paths` | additional privilege escalation paths |  | COVERED | `aws-ssm-incidents-response-plan-automation-passrole` |


### aws-post-exploitation/aws-entity-resolution-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

| `delegated-workflow-data-export` | Delegated workflow data export |  | STRUCTURAL | Groups the bounded workflow data export below. |

| `pass-a-workflow-role-to-read-and-export-identity-data` | Pass a workflow role to read and export identity data |  | NOT PRIVESC | Bounded data deputy: the passed entityresolution.amazonaws.com role only reads Glue/S3 inputs and writes S3 output for the workflow; no code execution or role credentials (page-level exclusion in _excluded_refresh_g7.yaml). |



### aws-post-exploitation/aws-q-business-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

| `application-integration-abuse` | Application integration abuse |  | STRUCTURAL | Groups the connected SaaS plugin behavior below. |

| `plugin-configuration-hijack-and-action-execution` | Plugin configuration hijack and action execution |  | NOT PRIVESC | App-plane only: repointing a plugin yields authenticated actions in connected SaaS systems; no AWS principal is obtained. |



### aws-post-exploitation/aws-timestream-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|

| `delegated-scheduled-query-data-operations` | Delegated scheduled-query data operations |  | STRUCTURAL | Groups bounded scheduled-query operations below. |

| `scheduled-query-references` | Scheduled query references |  | STRUCTURAL | Reference list for the moved scheduled-query operations. |

| `timestreamcreatescheduledquery--iampassrole--run-sql-and-downstream-writes-as-a-scheduled-query-role` | `timestream:CreateScheduledQuery` + `iam:PassRole` — run SQL and downstream writes as a scheduled-query role | timestream:CreateScheduledQuery, iam:PassRole | NOT PRIVESC | Bounded data deputy: the passed role only runs the fixed Timestream SQL and writes to Timestream/SNS/S3 error reports; the page states it does not vend credentials or allow actions outside the scheduled-query workflow.<br>`aws-audit-create-scheduled-query-to-exfiltrate-role-readable-secrets` — conditional verified exact-target authority. |

| `timestreamexecutescheduledquery--trigger-an-already-stored-role-workflow` | `timestream:ExecuteScheduledQuery` — trigger an already stored role workflow | timestream:ExecuteScheduledQuery | NOT PRIVESC | Bounded data deputy: re-runs a stored fixed query as its role; SQL, role and destinations cannot be changed.<br>`aws-audit-trigger-stored-query-that-delivers-restricted-secrets` — conditional verified exact-target authority. |



### aws-post-exploitation/aws-api-gateway-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `apigatewayget` | `apigateway:GET` | apigateway:GET | EXCLUDED | Pure data read (API keys). |
| `moved-apigateway-references` | Moved apigateway references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-athena-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `athenaupdatepreparedstatement--poison-a-query-executed-by-another-principal` | `athena:UpdatePreparedStatement` — Poison a query executed by another principal | athena:UpdatePreparedStatement | EXCLUDED | Data-level confused deputy: the replaced SQL runs with a later caller's data access; no IAM role or principal is obtained. |
| `athenaupdatenamedquery--poison-saved-sql-consumed-by-another-principal` | `athena:UpdateNamedQuery` — Poison saved SQL consumed by another principal | athena:UpdateNamedQuery | EXCLUDED | Data-level confused deputy: saved SQL is executed by another principal with its own data access; no IAM role or principal is obtained. |
| `moved-athena-stored-query-references` | Moved athena-stored-query references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-cloud-control-handler-role-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---cloud-control-handler-role-post-exploitation` | AWS - Cloud Control Handler Role Post Exploitation |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `data-and-application-operations` | Data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `getresource--listresources--iampassrole--read-through-a-resource-handler-role` | `GetResource` / `ListResources` + `iam:PassRole` — read through a resource-handler role | iam:PassRole | EXCLUDED | Read-only: the passed handler role only reads resource configuration (IAM trust, policies, endpoints) back to the caller; configuration disclosure, no write or code execution as the role. Least Privilege / Exposure. |
| `moved-cloud-control-handler-role-references` | Moved cloud-control-handler-role references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `references` | References |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-cloudwatch-omni-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `cloudwatchcreateview-or-updateview--view-scoped-getrecords--expand-delegated-telemetry-access` | `cloudwatch:CreateView` or `UpdateView` + view-scoped `GetRecords` — expand delegated telemetry access | cloudwatch:CreateView | EXCLUDED | Telemetry data access through a view (no IAM access to source workloads); data read, not principal escalation. |
| `moved-cloudwatch-omni-references` | Moved cloudwatch-omni references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-codepipeline-data-access-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `codepipelinepollforjobs` | `codepipeline:PollForJobs` | codepipeline:PollForJobs | EXCLUDED | Steals custom-action job artifacts/credentials scoped to the pipeline artifact bucket; data access, not a role identity. |
| `codepipelinepollforjobs--custom-action-artifact-credentials` | `codepipeline:PollForJobs` — custom-action artifact credentials | codepipeline:PollForJobs | EXCLUDED | Returns short-lived artifact credentials scoped to the pipeline artifact store for a custom action; data access, not another principal's identity (same reasoning as the codepipeline-privesc PollForJobs exclusion).<br>`aws-codepipeline-pollforjobs-artifact-session` — conditional verified exact-target authority. |
| `codepipelinegetjobdetails--known-job-artifact-credentials` | `codepipeline:GetJobDetails` — known-job artifact credentials | codepipeline:GetJobDetails | EXCLUDED | Narrower route to the same job artifact credentials as PollForJobs; data access, not a role identity.<br>`aws-codepipeline-getjobdetails-artifact-session` — conditional verified exact-target authority. |
| `moved-codepipeline-references` | Moved codepipeline references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `moved-codepipeline-job-credentials-references` | Moved codepipeline-job-credentials references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-connect-cases-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `moved-connect-cases-references` | Moved connect-cases references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-connect-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `invoke-a-privileged-flow-without-direct-lambda-or-lex-permission` | Invoke a privileged flow without direct Lambda or Lex permission |  | EXCLUDED | App-plane only: the flow invokes its Lambda/Lex integrations under their own roles and returns only what the flow logic exposes; the page states it does not grant arbitrary use of the Lambda role. |
| `moved-connect-references` | Moved connect references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-customer-profiles-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `createsegmentsnapshot--iampassrole` | `CreateSegmentSnapshot` + `iam:PassRole` | iam:PassRole | EXCLUDED | Not a privesc: bounded data delivery; the passed role only writes the segment export to the chosen S3 destination (data exfiltration, not principal escalation). |
| `associatestreamforsegments--iampassrole` | `AssociateStreamForSegments` + `iam:PassRole` | iam:PassRole | EXCLUDED | Not a privesc: bounded data delivery; the passed role only puts segment-membership records into the chosen Kinesis stream. |
| `moved-customer-profiles-references` | Moved customer-profiles references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-dynamodb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `todo-read-data-abusing-data-streams` | TODO: Read data abusing data Streams |  | EXCLUDED | Data read; unfinished section. |
| `moved-dynamodb-references` | Moved dynamodb references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `ebslistsnapshotblocks-ebsgetsnapshotblock-ec2describesnapshots` | `ebs:ListSnapshotBlocks`, `ebs:GetSnapshotBlock`, `ec2:DescribeSnapshots` | ebs:ListSnapshotBlocks, ebs:GetSnapshotBlock, ec2:DescribeSnapshots | EXCLUDED | Data read (credentials found on disks are not derivable from the snapshot). |
| `ec2createsnapshot` | **`ec2:CreateSnapshot`** | ec2:CreateSnapshot | EXCLUDED | Data access to volumes; no new identity. |
| `moved-ebs-references` | Moved ebs references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-efs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `elasticfilesystemclientmount-and-client-action-combinations` | `elasticfilesystem:ClientMount` and client-action combinations | elasticfilesystem:ClientMount | EXCLUDED | File-system data access only; any code-planting effect on hosts that execute from EFS is an unmodelled artifact chain without a stable consumer mapping. |
| `elasticfilesystemcreateaccesspoint--elasticfilesystemclientmount` | `elasticfilesystem:CreateAccessPoint + elasticfilesystem:ClientMount` | elasticfilesystem:CreateAccessPoint, elasticfilesystem:ClientMount | EXCLUDED | Bypasses POSIX restrictions on file data; data access only. |
| `elasticfilesystemcreatemounttarget` | `elasticfilesystem:CreateMountTarget` | elasticfilesystem:CreateMountTarget | EXCLUDED | Network pivot to reach the file system; no new identity. |
| `elasticfilesystemmodifymounttargetsecuritygroups` | `elasticfilesystem:ModifyMountTargetSecurityGroups` | elasticfilesystem:ModifyMountTargetSecurityGroups | EXCLUDED | Network pivot to reach the file system; no new identity. |
| `moved-efs-references` | Moved efs references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-elastic-beanstalk-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `elasticbeanstalkdescribeenvironmentresources-elasticloadbalancingmodifyloadbalancerattributes-s3putbucketpolicy-s3listbucket-s3getobject-to-enable-alb-access-logs-exfiltration` | `elasticbeanstalk:DescribeEnvironmentResources`, `elasticloadbalancing:ModifyLoadBalancerAttributes`, `s3:PutBucketPolicy`, `s3:ListBucket`, | elasticbeanstalk:DescribeEnvironmentResources, elasticloadbalancing:ModifyLoadBalancerAttributes, s3:PutBucketPolicy, s3:ListBucket, s3:GetObject | EXCLUDED | Exfiltration of request metadata; data only. |
| `moved-elastic-beanstalk-references` | Moved elastic-beanstalk references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-elasticache-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `privilege-escalation-take-over-and-widen-an-rbac-user-with-elasticachemodifyuser` | Privilege escalation: take over and widen an RBAC user with `elasticache:ModifyUser` | elasticache:ModifyUser | EXCLUDED | Cache data-plane (Valkey/Redis RBAC user) takeover; the cache user is not an AWS principal and no IAM privileges are obtained. |
| `moved-elasticache-references` | Moved elasticache references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-eventbridge-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `eventsupdateapidestination--redirect-stored-connection-credentials` | `events:UpdateApiDestination` — redirect stored Connection credentials | events:UpdateApiDestination | EXCLUDED | Exfiltrates third-party API credentials from a connection; not an IAM principal. |
| `moved-eventbridge-references` | Moved eventbridge references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-invoicing-and-billing-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `no-direct-iam-role-escalation-primitive` | No direct IAM role escalation primitive |  | EXCLUDED | Not a privesc: the page states the Invoicing and Billing APIs take no execution role, need no iam:PassRole and return no AWS credentials; their effects are financial-data disclosure and billing changes. |
| `moved-invoicing-and-billing-references` | Moved invoicing-and-billing references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-iot-twinmaker-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `connector-invocation-without-direct-lambda-permission` | Connector invocation without direct Lambda permission |  | EXCLUDED | App-plane only: TwinMaker invokes the nominated Lambda connector, which runs with its own execution role and exposes only what its code returns; the page states no generic role credentials are obtained. |
| `moved-iot-twinmaker-references` | Moved iot-twinmaker references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-ivs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `ivscreatestreamkey-on-stream-key---publish-to-another-channel` | `ivs:CreateStreamKey` on `stream-key/*` - Publish to another channel | ivs:CreateStreamKey | EXCLUDED | App-plane only: a stream key is a media-plane publishing credential for a channel, not an AWS principal. |
| `ivsgetstreamkey-or-ivsgetingestconfiguration---convert-a-read-into-publishing-access` | `ivs:GetStreamKey` or `ivs:GetIngestConfiguration` - Convert a read into publishing access | ivs:GetStreamKey, ivs:GetIngestConfiguration | EXCLUDED | App-plane only: disclosure of a media-plane publishing credential, not an AWS principal. |
| `ivscreateparticipanttoken---mint-stage-publishsubscribe-access` | `ivs:CreateParticipantToken` - Mint stage publish/subscribe access | ivs:CreateParticipantToken | EXCLUDED | App-plane only: stage participant tokens grant media publish/subscribe, not an AWS principal. |
| `ivsimportpublickey---sign-tokens-for-stages-account-wide` | `ivs:ImportPublicKey` - Sign tokens for stages account-wide | ivs:ImportPublicKey | EXCLUDED | App-plane only: lets the caller sign stage participant tokens offline; media-plane access, not an AWS principal. |
| `ivsimportplaybackkeypair---bypass-private-channel-playback-decisions` | `ivs:ImportPlaybackKeyPair` - Bypass private-channel playback decisions | ivs:ImportPlaybackKeyPair | EXCLUDED | App-plane only: private-channel playback authorization tokens, not an AWS principal. |
| `ivsstartcomposition---send-a-stage-to-an-unauthorized-channel` | `ivs:StartComposition` - Send a stage to an unauthorized channel | ivs:StartComposition | EXCLUDED | App-plane only: routes stage media to a channel; content injection, not an AWS principal. |
| `moved-ivs-references` | Moved ivs references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-kinesis-data-streams-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `createchannel--associatestreamswithchannel--iampassrole` | `CreateChannel` + `AssociateStreamsWithChannel` + `iam:PassRole` | iam:PassRole | EXCLUDED | Bounded data delivery: the passed role only copies future records of an on-demand stream to an S3 bucket or streaming table; data exfiltration, not principal escalation. kinesis:CreateChannel is not yet in aws_permissions_cat.yaml. |
| `moved-kinesis-data-streams-references` | Moved kinesis-data-streams references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-kms-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `kmsdecrypt` | `kms:Decrypt` | kms:Decrypt | EXCLUDED | Data read only. |
| `moved-kms-references` | Moved kms references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-lex-v2-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `existing-hook-as-a-confused-business-authority-boundary` | Existing hook as a confused business-authority boundary |  | EXCLUDED | App-plane only: reaches the business logic of an existing fulfillment Lambda, which keeps its own execution role; the page states it does not grant generic control of that role. |
| `moved-lex-v2-references` | Moved lex-v2 references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-lightsail-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `lightsaildownloaddefaultkeypair` | `lightsail:DownloadDefaultKeyPair` | lightsail:DownloadDefaultKeyPair | EXCLUDED | SSH access to Lightsail instances; Lightsail instances have no customer IAM instance profile, so no IAM principal is obtained (host/data access). |
| `lightsailcreatebucketaccesskey` | `lightsail:CreateBucketAccessKey` | lightsail:CreateBucketAccessKey | EXCLUDED | Creates keys scoped to a Lightsail bucket (service-managed identity); data access only. |
| `lightsailgetrelationaldatabasemasteruserpassword` | `lightsail:GetRelationalDatabaseMasterUserPassword` | lightsail:GetRelationalDatabaseMasterUserPassword | EXCLUDED | Database credential read; data access. |
| `lightsailupdaterelationaldatabase` | `lightsail:UpdateRelationalDatabase` | lightsail:UpdateRelationalDatabase | EXCLUDED | Database password reset/exposure; data access. |
| `lightsailopeninstancepublicports` | `lightsail:OpenInstancePublicPorts` | lightsail:OpenInstancePublicPorts | EXCLUDED | Network exposure; no new identity. |
| `lightsailputinstancepublicports` | `lightsail:PutInstancePublicPorts` | lightsail:PutInstancePublicPorts | EXCLUDED | Network exposure; no new identity. |
| `lightsailsetresourceaccessforbucket` | `lightsail:SetResourceAccessForBucket` | lightsail:SetResourceAccessForBucket | EXCLUDED | Bucket data access for an instance; no IAM principal. |
| `lightsailupdatebucket` | `lightsail:UpdateBucket` | lightsail:UpdateBucket | EXCLUDED | Bucket access/exposure change; data access. |
| `moved-lightsail-references` | Moved lightsail references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-macie-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `amazon-macie---bypass-reveal-sample-integrity-check` | Amazon Macie - Bypass `Reveal Sample` Integrity Check |  | EXCLUDED | Data disclosure only. |
| `moved-macie-references` | Moved macie references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-managed-blockchain-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `invite-an-attacker-account-into-a-hyperledger-fabric-network` | Invite an attacker account into a Hyperledger Fabric network |  | EXCLUDED | App-plane only: yields an attacker-owned Fabric consortium member, not an AWS principal in either account (the page states it is not elevation to AWS administrator). |
| `moved-managed-blockchain-references` | Moved managed-blockchain references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-managed-flink-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `add-private-network-reach-without-ec2-permission` | Add private-network reach without EC2 permission |  | EXCLUDED | Network exposure only; no code execution or principal change by itself. |
| `moved-managed-flink-references` | Moved managed-flink references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-mediapackage-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---mediapackage-post-exploitation` | AWS - Mediapackage Post Exploitation |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `data-and-application-operations` | Data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `mediapackagelistchannels` | `mediapackage:ListChannels` | mediapackage:ListChannels | EXCLUDED | Read only. |
| `mediapackagerotatechannelcredentials` | `mediapackage:RotateChannelCredentials` | mediapackage:RotateChannelCredentials | EXCLUDED | Rotates ingest credentials; media-plane access/DoS, no IAM principal. |
| `mediapackagerotateingestendpointcredentials` | `mediapackage:RotateIngestEndpointCredentials` | mediapackage:RotateIngestEndpointCredentials | EXCLUDED | Rotates ingest credentials; media-plane access/DoS, no IAM principal. |
| `moved-mediapackage-references` | Moved mediapackage references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `references` | References |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-memorydb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `post-exploitation-replace-an-acl-users-password-with-memorydbupdateuser` | Post-exploitation: replace an ACL user's password with `memorydb:UpdateUser` | memorydb:UpdateUser | EXCLUDED | Database ACL user password reset; data-plane access only, the MemoryDB user is not an AWS principal. |
| `moved-memorydb-user-reset-references` | Moved memorydb-user-reset references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-mq-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---mq-post-exploitation` | AWS - Mq Post Exploitation |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `data-and-application-operations` | Data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `mqcreateuser` | `mq:CreateUser` | mq:CreateUser | EXCLUDED | Creates broker users; message data access, no IAM principal. |
| `mqupdateuser` | `mq:UpdateUser` | mq:UpdateUser | EXCLUDED | Broker user change; message data access, no IAM principal. |
| `moved-mq-references` | Moved mq references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `references` | References |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-odb-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `odbupdateautonomousdatabase--reset-the-oracle-admin-credential-and-weaken-connection-controls` | `odb:UpdateAutonomousDatabase` — reset the Oracle `ADMIN` credential and weaken connection controls | odb:UpdateAutonomousDatabase | EXCLUDED | Oracle ADMIN database credential reset; database-level access, no AWS account permissions obtained. |
| `moved-odb-references` | Moved odb references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-rds-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `rdscreatedbinstance` | `rds:CreateDBInstance` | rds:CreateDBInstance | EXCLUDED | Does not provide database credentials; no new identity without an existing DB login. |
| `moved-rds-references` | Moved rds references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-route53-domains-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---route53-domains-post-exploitation` | AWS - Route53 Domains Post Exploitation |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `data-and-application-operations` | Data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `route53domainsgetdomaindetail--read-domain-registration-contacts` | `route53domains:GetDomainDetail` — Read domain registration contacts | route53domains:GetDomainDetail | EXCLUDED | Read only. |
| `moved-route53-domains-references` | Moved route53-domains references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `references` | References |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-s3-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `s3-express-and-s3-access-grants-credential-brokers` | S3 Express and S3 Access Grants credential brokers |  | EXCLUDED | Credential vending for data access the source is already granted (bucket session or existing grant); data access only, no escalation beyond existing grants. The location-creation variant is aws-s3-accessgrants-passrole-location-getdataaccess. |
| `moved-s3-credential-brokers-references` | Moved s3-credential-brokers references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-secrets-manager-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `secretsmanagergetsecretvalue` | `secretsmanager:GetSecretValue` | secretsmanager:GetSecretValue | EXCLUDED | Data read; any IAM keys stored in secrets are not modelable from the control plane. |
| `moved-secrets-manager-references` | Moved secrets-manager references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-service-catalog-appregistry-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `sensitive-cloudformation-outputs-with-servicecataloggetprovisionedproductoutputs` | Sensitive CloudFormation outputs with `servicecatalog:GetProvisionedProductOutputs` | servicecatalog:GetProvisionedProductOutputs | EXCLUDED | Data read. |
| `moved-service-catalog-references` | Moved service-catalog references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-sns-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `snssubscribe` | `sns:Subscribe` | sns:Subscribe | EXCLUDED | Message data access. |
| `moved-sns-references` | Moved sns references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-sso-and-identitystore-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `ssogetrolecredentials` | `sso:GetRoleCredentials` | sso:GetRoleCredentials | EXCLUDED | Requires an Identity Center access token of a user already assigned the permission set; no new identity beyond what the user already has. |
| `sso-admincreatetrustedtokenissuer--createapplication--putapplicationgrant--impersonate-any-user-via-a-rogue-trusted-token-issuer` | `sso-admin:CreateTrustedTokenIssuer` (+ `CreateApplication` / `PutApplicationGrant`) — impersonate any user via a rogue trusted token issuer | sso-admin:CreateTrustedTokenIssuer | EXCLUDED | A rogue trusted token issuer impersonates users only towards trusted-identity-propagation applications (data-plane access in services such as Redshift, Q, S3 Access Grants); it yields no permission set session or IAM role. |
| `moved-sso-and-identitystore-references` | Moved sso-and-identitystore references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-transfer-family-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `transferstartfiletransfer--send-role-readable-s3-data-through-a-stored-connector` | `transfer:StartFileTransfer` — send role-readable S3 data through a stored connector | transfer:StartFileTransfer | EXCLUDED | Data exfiltration through a fixed connector role (the role only reads/sends files the caller selects); data access. |
| `moved-transfer-family-references` | Moved transfer-family references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-wickr-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `wickrcreatedataretentionbotchallenge--take-over-the-data-retention-bot` | `wickr:CreateDataRetentionBotChallenge` — take over the data-retention bot | wickr:CreateDataRetentionBotChallenge | EXCLUDED | App-plane only: the challenge authenticates a data-retention bot that receives message copies; messaging data access, not an AWS principal or an application administrator.<br>`aws-audit-reset-wickr-retention-bot-challenge-and-operate-bot` — conditional verified exact-target authority. |
| `moved-wickr-references` | Moved wickr references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-workdocs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `aws---workdocs-post-exploitation` | AWS - Workdocs Post Exploitation |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `data-and-application-operations` | Data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `workdocs-activity-metadata-and-content-read-chain` | WorkDocs activity, metadata, and content-read chain |  | EXCLUDED | Data read. |
| `workdocsaddresourcepermissions` | `workdocs:AddResourcePermissions` | workdocs:AddResourcePermissions | EXCLUDED | Document access; data only. |
| `moved-workdocs-references` | Moved workdocs references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `references` | References |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-api-gateway-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `apigatewayupdaterestapipolicy--apigatewaypatch` | `apigateway:UpdateRestApiPolicy` / `apigateway:PATCH` | apigateway:UpdateRestApiPolicy, apigateway:PATCH | EXCLUDED | Opens API invocation (resource policy); application access, not an IAM principal. |

### aws-post-exploitation/aws-aurora-dsql-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `dsqldbconnectadmin--database-administrator-access` | `dsql:DbConnectAdmin` — database administrator access | dsql:DbConnectAdmin | EXCLUDED | Database-plane administrator access only; no IAM principal is obtained. |
| `moved-aurora-dsql-references` | Moved aurora-dsql references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-cognito-user-pools-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `emailusername-modification-privesc` | Email/username modification privesc |  | EXCLUDED | Application-level impersonation when the app trusts unverified claims; no IAM permission and no AWS principal reached. |
| `moved-cognito-user-pools-references` | Moved cognito-user-pools references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-customer-profiles-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `createintegrationworkflow--iampassrole` | `CreateIntegrationWorkflow` + `iam:PassRole` | iam:PassRole | EXCLUDED | Not a privesc: bounded service delegation; Customer Profiles uses the passed role only to create AppFlow-backed integration resources, with no credentials or arbitrary actions under the role. |

### aws-post-exploitation/aws-invoicing-and-billing-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `turn-cost-view-administration-into-cross-account-disclosure` | Turn cost-view administration into cross-account disclosure |  | EXCLUDED | Not a privesc: cross-account disclosure of cost-and-usage data; the recipient gains no role or IAM authority and must accept a RAM invitation. |
| `enable-previously-granted-legacy-billing-permissions` | Enable previously granted legacy Billing permissions |  | EXCLUDED | Not a privesc: activates Billing permissions that identities already hold in IAM (invoice, credit, payment and preference access); it grants no new policy and no IAM or role authority.<br>`aws-billing-enable-dormant-iam-console-access` — conditional verified exact-target authority. |
| `abuse-invoice-receiver-delegation` | Abuse invoice receiver delegation |  | EXCLUDED | Not a privesc: lets an eligible member account download the unit's invoice documents; it grants no access to other AWS APIs or payer-account resources. |
| `the-billing-service-linked-role-is-not-a-general-escalation-target` | The Billing service-linked role is not a general escalation target |  | EXCLUDED | Not a privesc: the service-linked role only allows billing:GetBillingViewData, is trusted only by billing.amazonaws.com and cannot be edited or attached to other identities. |
| `related-actions-that-amplify-business-impact-not-iam-authority` | Related actions that amplify business impact, not IAM authority |  | EXCLUDED | Not a privesc: the page lists these as financial or governance impact (billing-view sharing, invoice URLs, a procurement-integration secret, credit allocation), not IAM authority. |

### aws-post-exploitation/aws-iot-twinmaker-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `updateworkspace--iampassrole--connector-control` | `UpdateWorkspace` + `iam:PassRole` + connector control | iam:PassRole | EXCLUDED | Not a privesc: bounded service delegation; the workspace role is used only for connector invocation and supported data sources, and the page states changing it does not expose its credentials. |

### aws-post-exploitation/aws-lex-v2-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `lexcreatebotlexupdatebot--iampassrole` | `lex:CreateBot`/`lex:UpdateBot` + `iam:PassRole` | lex:CreateBot, lex:UpdateBot, iam:PassRole | EXCLUDED | Not a privesc: bounded service delegation; the bot role is used by Lex only for configured features (Lambda hooks, Kendra queries, logs), and the page states passing it does not return credentials. |

### aws-post-exploitation/aws-mediapackage-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `mediapackagedescribechannel` | `mediapackage:DescribeChannel` | mediapackage:DescribeChannel | EXCLUDED | Reads ingest credentials of a media channel; data/third-party credential, not an IAM principal. |

### aws-post-exploitation/aws-route53-dns-takeover-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `route53createhostedzone-route53changeresourcerecordsets-acm-pcaissuecertificate-acm-pcagetcertificate-ec2describevpcs` | `route53:CreateHostedZone`, `route53:ChangeResourceRecordSets`, `acm-pca:IssueCertificate`, `acm-pca:GetCertificate`, `ec2:DescribeVpcs` | route53:CreateHostedZone, route53:ChangeResourceRecordSets, acm-pca:IssueCertificate, acm-pca:GetCertificate, ec2:DescribeVpcs | EXCLUDED | Traffic interception (MitM) of in-VPC clients; no IAM principal is obtained directly. |
| `moved-route53-createhostedzone-route53-changeresourcerecordsets-acm-pca-issuecertificate-acm-pca-getcer-references` | Moved route53-createhostedzone-route53-changeresourcerecordsets-acm-pca-issuecertificate-acm-pca-getcer references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-route53-domains-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `route53domainsretrievedomainauthcode--steal-a-domain-transfer-credential` | `route53domains:RetrieveDomainAuthCode` — Steal a domain-transfer credential | route53domains:RetrieveDomainAuthCode | EXCLUDED | Domain transfer credential theft; external asset takeover, no IAM principal. |

### aws-post-exploitation/aws-verified-permissions-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `additional-data-and-application-operations` | Additional data and application operations |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |
| `redirect-token-trust-with-updateidentitysource` | Redirect token trust with `UpdateIdentitySource` |  | EXCLUDED | Application-level principal impersonation in the policy store; no AWS principal reached. |
| `rebind-a-policy-store-alias-to-a-permissive-store` | Rebind a policy-store alias to a permissive store |  | EXCLUDED | Application-level authorization redirection; no AWS principal reached. |
| `moved-verified-permissions-references` | Moved verified-permissions references |  | STRUCTURAL | Page title, grouping, or source references for a relocated bounded operation. |

### aws-post-exploitation/aws-workdocs-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `workdocscreateuser` | `workdocs:CreateUser` | workdocs:CreateUser | EXCLUDED | Application-level user in WorkDocs; no IAM principal. |
| `workdocsupdateuser` | `workdocs:UpdateUser` | workdocs:UpdateUser | EXCLUDED | Application-level role change inside WorkDocs; no IAM principal.<br>`aws-audit-promote-controlled-workdocs-user-to-administrator` — conditional verified exact-target authority. |

### aws-post-exploitation/aws-amplify-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `amplifygetartifacturl--download-end-to-end-test-artifacts` | `amplify:GetArtifactUrl` — Download end-to-end test artifacts | amplify:GetArtifactUrl | EXCLUDED | Pure data read.<br>`aws-amplify-artifact-credential` — conditional verified exact-target authority. |

### aws-post-exploitation/aws-cloudfront-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `cloudfrontupdatedistribution--cloudfrontgetdistributionconfig` | `cloudfront:UpdateDistribution` & `cloudfront:GetDistributionConfig` | cloudfront:UpdateDistribution, cloudfront:GetDistributionConfig | EXCLUDED | Traffic/content hijack of end users; no IAM identity gained. |
| `cloudfrontcreatefunction-cloudfrontdescribefunction-cloudfrontpublishfunction-cloudfrontgetdistributionconfig--cloudfrontupdatedistribution` | `cloudfront:CreateFunction`, `cloudfront:DescribeFunction`, `cloudfront:PublishFunction`, `cloudfront:GetDistributionConfig` & `cloudfront:U | cloudfront:CreateFunction, cloudfront:DescribeFunction, cloudfront:PublishFunction, cloudfront:GetDistributionConfig, cloudfront:UpdateDistribution | EXCLUDED | CloudFront Functions have no IAM role; impact is on end-user traffic only. |

### aws-post-exploitation/aws-msk-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `kafkaupdatesecurity-to-expose-private-topics-without-credentials` | `kafka:UpdateSecurity` to expose private topics without credentials | kafka:UpdateSecurity | EXCLUDED | Enables unauthenticated access to topics; data exposure, no IAM principal.<br>`aws-s05-04-read-public-msk-sasl-scram-secret` — conditional verified exact-target authority. |

### aws-post-exploitation/aws-route53-domains-post-exploitation/README.md

| Anchor | Heading | Permissions | Status | Catalog ids / reason |
|---|---|---|---|---|
| `route53domainstransferdomaintoanotherawsaccount--transfer-domain-registration-to-an-attacker-account` | `route53domains:TransferDomainToAnotherAwsAccount` — Transfer domain registration to an attacker account | route53domains:TransferDomainToAnotherAwsAccount | EXCLUDED | Domain registration hijack to another account; asset takeover, not another principal's privileges. |

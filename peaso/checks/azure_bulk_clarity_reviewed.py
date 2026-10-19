"""64 source-reviewed signed Azure predicates with concise bounded guidance.

Legacy identifiers remain stable. Configuration is not runtime proof.
"""
from copy import deepcopy
import hashlib
import json

VERSION = "azure-bulk-clarity-v1"
ROWS = json.loads(r'''
{
  "azure.cis.agentless_discovery_kubernetes_component_status": {
    "description_base_sha256": "b733a93feeb3acfcc0e6cf42ec1bdfdb041291de4f37758d52784d4a74e60146",
    "description_fields": {
      "description": "Joins each AKS cluster to its effective Defender pricing plans and agentless-discovery extension setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Plan and extension settings do not prove discovery activity or inventory completeness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Microsoft.Security/pricings LIST/GET at subscription and effective resource scope: Containers and CloudPosture properties.pricingTier, properties.extensions[].name/isEnabled/operationStatus; account for pricing inheritance or overrides.",
          "Complete inventories: aks_cluster, defender_pricing"
        ],
        "kind": "defender_pricing",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the required Defender plan and Kubernetes agentless-discovery component for affected clusters."
      ],
      "summary": "Enable the required Defender plan and Kubernetes agentless-discovery component for affected clusters."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "defender_pricing",
      "module": "peaso.checks._bulk_pending_compliance_new_sw28",
      "predicate_qualname": "agentless_discovery_kubernetes",
      "predicate_source_sha256": "d153fbb612e7a2cd6cf79235faa10c39c5de880c5eef3d90edaa495a94a919a3",
      "source_qualname": "agentless_discovery_kubernetes"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An AKS cluster has no qualifying enabled agentless-discovery component."
  },
  "azure.cis.auto_provision_vulnerability_assessment_machines": {
    "description_base_sha256": "2e314a50bb716b6fa354b173399d12354354bdb67a8c17c4c35ec432f4c0402a",
    "description_fields": {
      "description": "Checks Defender VM pricing, the MdeTvm assessment setting and complete Arc auto-provisioning evidence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Provisioning configuration does not establish completed scans, current findings or remediation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM GET Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting 2023-05-01: kind AzureServersSetting, properties.selectedProvider MdeTvm; GET Microsoft.Security/pricings/VirtualMachines 2024-01-01: pricingTier; paged Microsoft.HybridCompute/machines inventory and independently documented Arc vulnerability-assessment auto-provisioning/integration evidence for applicable hybrid machines.",
          "Complete inventories: security_pricing"
        ],
        "kind": "server_vulnerability_assessment_setting",
        "target": "scope"
      },
      "references": [
        {
          "title": "Defender for Cloud configuration",
          "url": "https://learn.microsoft.com/azure/defender-for-cloud/enable-enhanced-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the supported vulnerability assessment integration and correct affected Arc provisioning gaps."
      ],
      "summary": "Enable the supported vulnerability assessment integration and correct affected Arc provisioning gaps."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "machine_vulnerability_assessment"
        }
      },
      "delegates": {},
      "kind": "server_vulnerability_assessment_setting",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "machine_vulnerability_assessment",
      "predicate_source_sha256": "af4baf81d3a76e1f3dd44a73f1050651d43ad07776a223ac9559a7f303030b10",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A required vulnerability assessment integration or Arc auto-provisioning setting is disabled."
  },
  "azure.cis.guest_users_reviewed_monthly_basis": {
    "description_base_sha256": "4094b5419e607cd2beee90787a6a961ac8d145271ef9c31112c8b0ff6de6b80c",
    "description_fields": {
      "description": "Checks bound guest access-review scope, schedules, completed instances and decisions for the monthly profile."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "The native no-owner path uses a conservative 28-day witness; unsupported or incomplete reviews remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Graph v1.0 /users?$select=id,accountEnabled,userType; accessReviews/definitions, per-definition instances and per-instance decisions; resolve review scope and transitive group membership.",
          "Complete inventories: access_review_subject, access_review_definition, access_review_instance, access_review_decision"
        ],
        "kind": "access_review_definition",
        "target": "scope"
      },
      "references": [
        {
          "title": "Microsoft Graph identity governance",
          "url": "https://learn.microsoft.com/graph/api/resources/accessreviewsv2-root"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure regular guest access reviews and complete overdue decisions for applicable guests."
      ],
      "summary": "Configure regular guest access reviews and complete overdue decisions for applicable guests."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "azure.cis.guest_users_reviewed_monthly_basis"
      },
      "delegates": {
        "_reviews": "a317a5ba0777647e0a0e6661dce82075c77a1bec06967d08470b48e1198126e2",
        "native_guest_reviews": "bfb1ca148818fd4a534b9fd095cc38ddd78c9f739b671584aca3f651755bc0e1"
      },
      "kind": "access_review_definition",
      "module": "peaso.checks._bulk_pending_compliance_new_sw25",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "f0d49b11d5bd6038ffa670e4108dae55274021289d54675ab2203277d2909443",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An applicable guest lacks the required timely completed review."
  },
  "azure.cis.guest_users_reviewed_regular_basis": {
    "description_base_sha256": "4e8f01a90895f3d741b4e63ae5eba2c28637a840e6a5c07c9b83e694b3e6ae86",
    "description_fields": {
      "description": "Checks guest access-review schedules and completed decisions; the native no-owner profile uses a 28-day witness."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "A sufficient native review witness can pass; its absence does not prove every unsupported review design is noncompliant."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Graph v1.0 paged /users?$select=id,userType,accountEnabled; /identityGovernance/accessReviews/definitions, each definition/instances, and each instance/decisions. Resolve scope.query against guest IDs and follow every @odata.nextLink.",
          "Complete inventories: access_review_subject, access_review_definition, access_review_instance, access_review_decision"
        ],
        "kind": "access_review_definition",
        "target": "scope"
      },
      "references": [
        {
          "title": "Microsoft Graph identity governance",
          "url": "https://learn.microsoft.com/graph/api/resources/accessreviewsv2-root"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure regular guest access reviews and complete required guest decisions."
      ],
      "summary": "Configure regular guest access reviews and complete required guest decisions."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "azure.cis.guest_users_reviewed_regular_basis"
      },
      "delegates": {
        "_reviews": "a317a5ba0777647e0a0e6661dce82075c77a1bec06967d08470b48e1198126e2",
        "native_guest_reviews": "bfb1ca148818fd4a534b9fd095cc38ddd78c9f739b671584aca3f651755bc0e1"
      },
      "kind": "access_review_definition",
      "module": "peaso.checks._bulk_pending_compliance_new_sw25",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "f0d49b11d5bd6038ffa670e4108dae55274021289d54675ab2203277d2909443",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An applicable guest lacks the required completed review."
  },
  "azure.cis.latest_os_patches_vms_applied": {
    "description_base_sha256": "eb3512d4f5b046045a49b04cf5c5d0b42541e4c19c4cb3b1dfd2ac03b557d803",
    "description_fields": {
      "description": "Checks a successful patch assessment no older than seven days for available critical or security patches."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Pending installation, reboot or stale assessment remains UNKNOWN; a clean assessment is not a full vulnerability scan."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged VM inventory and per-VM Microsoft.Compute/virtualMachines/instanceView GET 2023-09-01: patchStatus.availablePatchSummary.status,lastModifiedTime,criticalAndSecurityPatchCount; patch installation/reboot state when available.",
          "Complete inventories: vm"
        ],
        "kind": "virtual_machine",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Install the listed critical and security patches with suitable maintenance and reboot planning."
      ],
      "summary": "Install the listed critical and security patches with suitable maintenance and reboot planning."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure.cis.latest_os_patches_vms_applied",
        "evaluator": {
          "callable": "_vm_patches"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "virtual_machine",
      "module": "peaso.checks._bulk_pending_compliance_new_sw27",
      "predicate_qualname": "_vm_patches",
      "predicate_source_sha256": "0a2d58a1453b4151e255378f9cdf2d96a7c68b0cc9ba9707690d64a51fe29332",
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The VM assessment reports available critical or security patches."
  },
  "azure.cis.multifactor_auth_status_non_privileged_users": {
    "description_base_sha256": "a9baeb7572f7effe4042a131e0d63ec8bcc9e00e54ea75c305236832ce061f38",
    "description_fields": {
      "description": "Checks enabled non-privileged users for usable MFA registration and per-user requirements or a fully resolved equivalent path."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. Disabled per-user MFA requires separately approved equivalence evidence."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Graph users, directory role assignments/definitions and group transitiveMembers identify enabled non-privileged users. GET Graph beta /users/{id}/authentication/requirements supplies perUserMfaState enum disabled/enabled/enforced. Also collect registration details, Conditional Access policies and named locations if evaluating equivalent effective MFA enforcement; resolve every condition and exclusion.",
          "Complete inventories: directory_user, azure_sw18_evidence"
        ],
        "kind": "directory_user",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Register a usable MFA method and require MFA on the user\u2019s applicable sign-in paths."
      ],
      "summary": "Register a usable MFA method and require MFA on the user\u2019s applicable sign-in paths."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "directory_user",
      "module": "peaso.checks._bulk_pending_compliance_new_sw18",
      "predicate_qualname": "non_privileged_mfa",
      "predicate_source_sha256": "9d07ae19ffbee2675c313db3668b646617d36ff16784e1e865ff9a3632a010e5",
      "source_qualname": "non_privileged_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The non-privileged user lacks usable required MFA or has an unprotected sign-in path."
  },
  "azure.cis.multifactor_auth_status_privileged_users": {
    "description_base_sha256": "040a0c85538f622df76cc5b1f7150efc3aec6e904e2b6e008f614500b21518f2",
    "description_fields": {
      "description": "Checks enabled users\u2019 resolved MFA contexts, applying the legacy per-user requirement to privileged users or Azure resource writers."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. This profile separately evaluates its legacy per-user requirement."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Graph v1.0 paged /users, /identity/conditionalAccess/policies, /reports/authenticationMethods/userRegistrationDetails; paged directory and Azure RBAC role assignments, role definitions, PIM active schedules, transitive group membership; /policies/identitySecurityDefaultsEnforcementPolicy. Resolve named locations, authentication strengths, device filters and sign-in conditions. For CIS 1.1.2 exact legacy status, Graph beta GET /users/{id}/authentication/requirements returns perUserMfaState string; this beta API must be explicitly supported or that status is UNKNOWN.",
          "Complete inventories: directory_user, conditional_access_policy"
        ],
        "kind": "directory_user",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require suitable MFA for the privileged identity and resolve unprotected or excluded paths."
      ],
      "summary": "Require suitable MFA for the privileged identity and resolve unprotected or excluded paths."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure.cis.multifactor_auth_status_privileged_users"
      },
      "delegates": {
        "_mfa": "5d218c2440d8d0906c7dd02e9d005519eb23362e28caeb24f691f26fb10c8a5c"
      },
      "kind": "directory_user",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The user has an unprotected MFA context or fails the applicable per-user requirement."
  },
  "azure.cis.multifactor_authentication_policy_exists_administrative_groups": {
    "description_base_sha256": "60305a1e4660aa482afc2f365987ba99634bad67b3b7dbce6452c016a201e797",
    "description_fields": {
      "description": "Evaluates tenant-bound administrative principals against supported Conditional Access or Security Defaults MFA selectors."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. Unsupported selectors remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Graph v1.0 paged Conditional Access policies, users, role assignments and definitions, PIM activation, transitive groups, named locations and authentication strengths; security defaults policy; policy input designated administrative roles/groups and applicable sign-in contexts.",
          "Complete inventories: conditional_access_policy, directory_user, conditional_access_principal, conditional_access_partition, named_location, authentication_strength, directory_security_defaults, security_defaults_context_proof"
        ],
        "kind": "conditional_access_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Apply an enforcing MFA policy to the affected administrative scope and remove unintended exclusions."
      ],
      "summary": "Apply an enforcing MFA policy to the affected administrative scope and remove unintended exclusions."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "conditional_access_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw13",
      "predicate_qualname": "administrative_mfa",
      "predicate_source_sha256": "f52020994aaeb00418d232879347fd40262f3a0a7f15f5c1df25ce89d231e879",
      "source_qualname": "administrative_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The administrative scope lacks qualifying enforced MFA coverage."
  },
  "azure.cis.multifactor_authentication_policy_exists_users": {
    "description_base_sha256": "ece2b4fc5f9a1b8c5cbaee25d1f7f5686246b6db9994f5648189fd80cbf23f69",
    "description_fields": {
      "description": "Evaluates enabled users against supported tenant-bound Conditional Access or Security Defaults MFA coverage."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Graph v1.0 paged /users, /groups and membership, /directoryRoles or role assignments, and /identity/conditionalAccess/policies. Inspect policy state; all user, app, client, location, platform, device, risk and authentication-flow conditions and exclusions; grantControls.operator, builtInControls and authenticationStrength.",
          "Complete inventories: conditional_access_policy, directory_user, conditional_access_principal, conditional_access_partition, named_location, authentication_strength, directory_security_defaults, security_defaults_context_proof"
        ],
        "kind": "conditional_access_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require MFA for the affected enabled users and remove unintended coverage gaps."
      ],
      "summary": "Require MFA for the affected enabled users and remove unintended coverage gaps."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "conditional_access_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw13",
      "predicate_qualname": "users_mfa",
      "predicate_source_sha256": "c9b4e0c453adbb0146815de8834d85714e2cb1506dcad7ffd9b993e1b1a6d13a",
      "source_qualname": "users_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Enabled users lack qualifying enforced MFA coverage."
  },
  "azure.cis.multifactor_authentication_risky_sign_ins": {
    "description_base_sha256": "ab0e8e8830e913c811934515a06b202e06ce16ee2741ff5a9388e60ea7f4a9d2",
    "description_fields": {
      "description": "Evaluates supported medium- and high-risk sign-in contexts against enforced MFA policies and risk entitlement."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. Missing risk entitlement or unsupported conditions remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Microsoft Graph /identity/conditionalAccess/policies: state,conditions.signInRiskLevels,conditions.users,conditions.applications,grantControls; /users id,accountEnabled",
          "Complete inventories: conditional_access_policy, directory_user, conditional_access_principal, conditional_access_partition, named_location, authentication_strength, directory_security_defaults, security_defaults_context_proof"
        ],
        "kind": "conditional_access_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require MFA on the applicable risky sign-in paths and review exclusions."
      ],
      "summary": "Require MFA on the applicable risky sign-in paths and review exclusions."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "conditional_access_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw13",
      "predicate_qualname": "risky_mfa",
      "predicate_source_sha256": "dfb6b0e572a42486b6f2486d0142c7eca96fed25664cbd5b37625fae6ca507a8",
      "source_qualname": "risky_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Risky sign-in contexts lack qualifying enforced MFA coverage."
  },
  "azure.cis.private_endpoint_should_mariadb_servers": {
    "description_base_sha256": "0fcc2b241606a37e3af0e46c10c40032457eaf5f573bc5f6dd7d73a008739d8c",
    "description_fields": {
      "description": "Checks MariaDB servers for approved bound private endpoints and disabled or resolved restricted public ingress."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. An approved connection alone does not prove exclusive private connectivity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged MariaDB servers LIST and each server privateEndpointConnections child LIST 2018-06-01; properties.privateLinkServiceConnectionState.status string=Approved and properties.privateEndpoint.id; server properties.publicNetworkAccess where exposed, otherwise firewall/network reachability evidence; exact target server ARM ID.",
          "Complete inventories: mariadb_server"
        ],
        "kind": "mariadb_server",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the intended private endpoint and restrict unnecessary public database access."
      ],
      "summary": "Configure the intended private endpoint and restrict unnecessary public database access."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure.cis.private_endpoint_should_mariadb_servers"
      },
      "delegates": {},
      "kind": "mariadb_server",
      "module": "peaso.checks._bulk_pending_compliance_new_sw32",
      "predicate_qualname": "_mariadb",
      "predicate_source_sha256": "a1d35f8bf91d34be575810c9ae2f2c0d9f21d87a91cb9769913a7af90b11b207",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A MariaDB server lacks qualifying private connectivity or permits unrestricted public ingress."
  },
  "azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed": {
    "description_base_sha256": "d180c3d420d579ed7d29427a8df692b415212a2e0049fc5662096c364b8a681b",
    "description_fields": {
      "description": "Checks complete Arc cluster extensions for Microsoft.AzureDefender.Kubernetes with provisioningState=Succeeded."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Successful provisioning does not prove current telemetry or security coverage."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged ARM connectedClusters LIST and Microsoft.KubernetesConfiguration/extensions LIST per cluster 2023-05-01: properties.extensionType, properties.provisioningState.",
          "Complete inventories: arc_kubernetes_cluster"
        ],
        "kind": "arc_kubernetes_cluster",
        "target": "scope"
      },
      "references": [
        {
          "title": "Defender for Cloud configuration",
          "url": "https://learn.microsoft.com/azure/defender-for-cloud/enable-enhanced-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Install or repair the Defender extension on affected Arc clusters."
      ],
      "summary": "Install or repair the Defender extension on affected Arc clusters."
    },
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_arc"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "arc_kubernetes_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw22",
      "predicate_qualname": "_arc",
      "predicate_source_sha256": "a8aacb509f3121eb774dbf12d0ed5e3ee6846e038cd85c32fa9ebda7ef9da31b",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An Arc cluster has no successfully provisioned Defender extension."
  },
  "azure.gap.automation_account_encrypted_with_cmk": {
    "description_base_sha256": "725f43da81dcb986c47b30a148c594b5d67009f3d6b89dd05b766b46c89fb48d",
    "description_fields": {
      "description": "Checks Automation\u2019s key source, selected assigned identity and current bound Key Vault access."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Customer-managed key requirements do not mean platform-managed encryption is plaintext; key rotation and recovery are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM GET Microsoft.Automation/automationAccounts: properties.encryption.keySource, keyVaultProperties.keyName/keyvaultUri, properties.encryption.identity (Identity object), top-level identity.principalId/userAssignedIdentities; resolve selected principal and effective Key Vault key access.",
          "Complete inventories: automation_account"
        ],
        "kind": "automation_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required customer-managed key and repair its selected identity\u2019s access."
      ],
      "summary": "Configure the required customer-managed key and repair its selected identity\u2019s access."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "automation_account",
      "module": "peaso.checks._bulk_pending_compliance_new_sw03",
      "predicate_qualname": "automation_cmk",
      "predicate_source_sha256": "52fcb74518e7107f1bf6da5557680124383695772443f3bbd1ae8cf2169bdcd5",
      "source_qualname": "automation_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Automation account lacks the required usable customer-managed key configuration."
  },
  "azure.gap.machine_learning_workspace_private_link_used": {
    "description_base_sha256": "2a1dc8e35ad1ed8b6957f1da21894e9d858e33a9325577c0aa6446d5463554eb",
    "description_fields": {
      "description": "Checks each ML workspace\u2019s complete private-endpoint connections for an approved valid endpoint reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. This checks Private Link presence, not exclusive private ingress."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Existing azure.py ml_workspace.items[] GET 2024-04-01 may include privateEndpointConnections, but require new paged /privateEndpointConnections LIST per workspace ?api-version=2024-04-01; properties.privateLinkServiceConnectionState.status enum Approved/Pending/Rejected/Disconnected, properties.privateEndpoint.id.",
          "Complete inventories: ml_workspace"
        ],
        "kind": "ml_workspace",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the intended approved private endpoint if private connectivity is required."
      ],
      "summary": "Configure the intended approved private endpoint if private connectivity is required."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "ml_workspace",
      "module": "peaso.checks._bulk_pending_compliance_new_sw03",
      "predicate_qualname": "ml_private_link",
      "predicate_source_sha256": "c019678da9d28ad43d9342ee414a3d727688ce0e72cfede24c1ab66ce997184b",
      "source_qualname": "ml_private_link"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An ML workspace has no qualifying approved private endpoint."
  },
  "azure.gap.monitor_log_cluster_encrypted_with_cmk": {
    "description_base_sha256": "f40922b87988a57dd0db2a304766e392fc7ae5c8cca9c306b7996e2004f4b930",
    "description_fields": {
      "description": "Checks the Log Analytics cluster key reference, assigned identity and matching key-access result."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Customer-managed key requirements do not mean platform-managed encryption is plaintext; key rotation and recovery are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "New paged Microsoft.OperationalInsights/clusters List plus GET 2023-09-01: properties.keyVaultProperties.keyVaultUri/keyName/keyVersion; identity.type, identity.principalId or identity.userAssignedIdentities[*].principalId; Key Vault access check.",
          "Complete inventories: log_analytics_cluster"
        ],
        "kind": "log_analytics_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required customer-managed key and resolve its managed identity access."
      ],
      "summary": "Configure the required customer-managed key and resolve its managed identity access."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure.gap.monitor_log_cluster_encrypted_with_cmk",
        "evaluator": {
          "callable": "_cluster_cmk"
        },
        "target": "resource"
      },
      "delegates": {},
      "kind": "log_analytics_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw27",
      "predicate_qualname": "_cluster_cmk",
      "predicate_source_sha256": "0e7f9471b95562ff927a927130eb834ad4681ef50848bfa5c78ca011bcd24f3d",
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Log Analytics cluster lacks a required key or identity, or key access is denied."
  },
  "azure.gap.monitor_log_profile_enabled_for_all_categories": {
    "description_base_sha256": "eb0d52488e05b37f1968a1c7fe72ad266bdb11271217d0c562abf7f13dacd310",
    "description_fields": {
      "description": "Combines log-profile categories with declared destinations and requires Write, Delete and Action."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM Microsoft.Insights/logProfiles List 2016-03-01: value[].properties.categories,locations,storageAccountId,serviceBusRuleId,retentionPolicy; subscription inventory",
          "Complete inventories: subscription, monitor_log_profile"
        ],
        "kind": "subscription",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Route the missing activity-log categories to the intended destination."
      ],
      "summary": "Route the missing activity-log categories to the intended destination."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "subscription",
      "module": "peaso.checks._bulk_pending_compliance_new_sw15",
      "predicate_qualname": "profile_categories",
      "predicate_source_sha256": "f9a5dcc0cacf13a50c14857e5f667736f800daade6c25a34ca63128f8b0ed158",
      "source_qualname": "profile_categories"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log profiles do not export all three required categories."
  },
  "azure.gap.postgresql_server_infrastructure_encryption_enabled": {
    "description_base_sha256": "66704435618d69f8a385ed5aaae4ba934c0bf4bdff73c042d542f9a58e233c2f",
    "description_fields": {
      "description": "Checks separately inventoried legacy PostgreSQL single servers for infrastructureEncryption=Enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "The signed legacy identifier also names flexible servers; this evaluator deliberately assesses legacy single-server evidence only."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM GET Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01: properties.infrastructureEncryption; applies to legacy single servers, not flexibleServers.",
          "Complete inventories: postgresql_single_server"
        ],
        "kind": "postgresql_flexible_server",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use infrastructure encryption where supported and required for the applicable legacy service."
      ],
      "summary": "Use infrastructure encryption where supported and required for the applicable legacy service."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "azure.gap.postgresql_server_infrastructure_encryption_enabled"
      },
      "delegates": {},
      "kind": "postgresql_flexible_server",
      "module": "peaso.checks._bulk_pending_compliance_new_sw14",
      "predicate_qualname": "infrastructure_encryption",
      "predicate_source_sha256": "1b3839cc085ae48d4cd69e9edd881dfc3c3baee249c221c3f3ca8c252117fdb4",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A legacy PostgreSQL single server disables infrastructure encryption."
  },
  "azure.gap.sql_database_long_term_geo_redundant_backup_enabled": {
    "description_base_sha256": "f1959326a6a2b2814a0b7b869881218948b8dc1105c48d4f5544b6333e890291",
    "description_fields": {
      "description": "Joins user databases to nonzero long-term retention policies and observed Geo or GeoZone backup copies."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration. Missing copy evidence stays unresolved rather than proving geo redundancy."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Complete Azure SQL Database inventory and per-database backupLongTermRetentionPolicies; additionally list actual longTermRetentionBackups by database through the Azure SQL REST API and inspect each retained copy properties.backupStorageRedundancy. Current database backup redundancy is future-backup configuration only.",
          "Complete inventories: sql_database, sql_database_ltr_policy, sql_ltr_backup"
        ],
        "kind": "sql_database",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure appropriate long-term retention and geo-redundant copies if cross-region recovery is required."
      ],
      "summary": "Configure appropriate long-term retention and geo-redundant copies if cross-region recovery is required."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "sql_database",
      "module": "peaso.checks._bulk_pending_compliance_new_sw31",
      "predicate_qualname": "sql_geo_ltr",
      "predicate_source_sha256": "49e924a63126fce5e9f4bfaa5ced9bc35f0321cc51e2c7eecc775841c577b732",
      "source_qualname": "sql_geo_ltr"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A database lacks the required long-term retention or has only local or zone backup redundancy."
  },
  "azure.gap.stream_analytics_job_encrypted_with_cmk": {
    "description_base_sha256": "ffa6e736f984cced31c7ea50066b28f4047cc1393cea30a8b33d2fda332e98d2",
    "description_fields": {
      "description": "Checks required external job storage for a customer-managed key and usable selected identity access."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Customer-managed key requirements do not mean platform-managed encryption is plaintext; key rotation and recovery are separate. Internal service data is outside this external-storage predicate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Existing azure.py stream_analytics_job.items[] GET 2020-03-01, properties.jobStorageAccount.accountName/container/authenticationMode; existing storage_account.items[] GET 2023-05-01, properties.encryption.keySource enum Microsoft.Storage/Microsoft.Keyvault, keyVaultProperties.keyName,keyVaultUri; match account by subscription/resource group or a unique ARM ID resolution.",
          "Complete inventories: stream_analytics_job"
        ],
        "kind": "stream_analytics_job",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable external job storage and its customer-managed key if that storage is required."
      ],
      "summary": "Configure suitable external job storage and its customer-managed key if that storage is required."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "stream_analytics_job",
      "module": "peaso.checks._bulk_pending_compliance_new_sw03",
      "predicate_qualname": "stream_analytics_storage_cmk",
      "predicate_source_sha256": "bdb7c1f52f985a1894b7a2c69d97d5cca7b7bea8dd17e2a8691acff684b1803d",
      "source_qualname": "stream_analytics_storage_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Required external job storage is absent, platform-keyed or has an unusable configured customer key."
  },
  "azure.other.access_analysis_coverage": {
    "description_base_sha256": "e80d42d6d846e885d099d1280ba4c6e48dbd506bd352fc5d78e8e876b061c0c1",
    "description_fields": {
      "description": "Checks CloudPosture pricing and bound external-public-access and unused-access capability states."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Enabled capabilities do not establish analysis correctness or complete current findings."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Microsoft.Security/pricings/CloudPosture GET 2024-01-01 properties.pricingTier and extensions[].name/isEnabled, plus documented Defender CSPM external/public exposure and unused-access assessment capabilities and per-subscription assessment/coverage inventory.",
          "Complete inventories: security_pricing"
        ],
        "kind": "defender_setting",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the required posture analysis capabilities and resolve assessment provisioning gaps."
      ],
      "summary": "Enable the required posture analysis capabilities and resolve assessment provisioning gaps."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure.other.access_analysis_coverage",
        "evaluator": {
          "callable": "_access_coverage"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "defender_setting",
      "module": "peaso.checks._bulk_pending_compliance_new_sw27",
      "predicate_qualname": "_access_coverage",
      "predicate_source_sha256": "0291230e7b09e28ef2f174f8b809076f4c6b9c1b3839be41ea731934b4f2aaa5",
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "CloudPosture or a required access-analysis capability is disabled."
  },
  "azure.other.audit_storage_access_logging": {
    "description_base_sha256": "3dec1557b27cecb7a229adeaefdd1204125ff00e70bbd60f044aa60c049776f8",
    "description_fields": {
      "description": "Checks classified audit-storage read, write and delete logging configuration and separately verified secure delivery."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This historical control needs explicit audit-account classification; configuration alone cannot prove actual secure delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Azure Monitor diagnostic settings LIST at each blob service, with properties.logs[].category/categoryGroup, enabled and setting-level destination IDs; destination/account identity. Separate data-plane blob-read, blob-write and blob-delete audit log evidence and a policy-approved independent secure logging sink are required to assess bucket-style server access logging.",
          "Complete inventories: storage_account, audit_storage_access_evidence"
        ],
        "kind": "storage_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Storage security",
          "url": "https://learn.microsoft.com/azure/storage/common/storage-security-guide"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Route the required storage access categories to a suitable separate destination and verify delivery."
      ],
      "summary": "Route the required storage access categories to a suitable separate destination and verify delivery."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "storage_account",
      "module": "peaso.checks._bulk_pending_compliance_new_sw23",
      "predicate_qualname": "audit_access",
      "predicate_source_sha256": "3f309d8d2bbbfac8e5768cb0a3421e717d373801235b92860eac198f40a388f2",
      "source_qualname": "audit_access"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Required audit-storage access logging is absent or targets the same account."
  },
  "azure.other.backup_immutability_30": {
    "description_base_sha256": "ce3c86a9cc790fac64f6803d618e73cfe47fa0e085ca02b0b5bab6e9e145113d",
    "description_fields": {
      "description": "Checks protected vault items for Locked immutability and assigned policy retention floors of at least 30 days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Recovery Services vaults GET 2024-04-01: properties.securitySettings.immutabilitySettings.state; paged backupProtectedItems LIST and backupPolicies LIST per vault; item.policyId and workload-specific retentionPolicy fields.",
          "Complete inventories: recovery_vault, backup_protected_item, backup_policy"
        ],
        "kind": "recovery_vault",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose suitable retention, then lock immutability only after reviewing the irreversible protection commitment."
      ],
      "summary": "Choose suitable retention, then lock immutability only after reviewing the irreversible protection commitment."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "recovery_vault",
      "module": "peaso.checks._bulk_pending_compliance_new_sw13",
      "predicate_qualname": "immutable_backups",
      "predicate_source_sha256": "8cf5d2a1d83751aeac2a1a289a9c94d9b5100b823813e7d70db8d52526d11252",
      "source_qualname": "immutable_backups"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The backup vault is not immutability-locked or a policy retains points for fewer than 30 days."
  },
  "azure_aks_cluster_10_2_1_1_17_885658f": {
    "description_base_sha256": "e2a328d14915dd9f2a9be9fcbb7c609f90f06686acd9acfb7fc0570ce9e1bf99",
    "description_fields": {
      "description": "Checks supported AKS log categories against enabled diagnostic exports with resolved usable destination references."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM GET Microsoft.ContainerService/managedClusters; GET {clusterId}/providers/Microsoft.Insights/diagnosticSettingsCategories and /diagnosticSettings: properties.logs[].category/categoryGroup/enabled and destination IDs.",
          "Complete inventories: aks_cluster"
        ],
        "kind": "aks_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "AKS security context",
          "url": "https://learn.microsoft.com/azure/aks/concepts-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the missing AKS log categories at an appropriate destination."
      ],
      "summary": "Enable the missing AKS log categories at an appropriate destination."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "aks_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "diagnostics",
      "predicate_source_sha256": "7e1eedec3994e5028ceb7c1940cf661f6c13c2d3e1f73f56f839b0025918bca7",
      "source_qualname": "diagnostics"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An AKS diagnostic log category lacks a qualifying enabled export."
  },
  "azure_aks_cluster_1_4_5_2_3ac7b3c": {
    "description_base_sha256": "511de0583fbdf4fc54d38af0ca20116cf61923958c43ecfab3f9a3e8acb6c2de",
    "description_fields": {
      "description": "Checks full Pod hostPID declarations and separately resolved ACI host-process sharing evidence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "PodSpec declarations do not prove runtime isolation; unresolved ACI sharing stays UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Kubernetes core/v1 Pods LIST across every AKS namespace: items[].spec.hostPID (optional boolean, default false). Also enumerate policy-scoped ACI container groups; ARM 2023-05-01 has no equivalent hostPID setting, so obtain deployment/runtime evidence or mark ACI UNKNOWN.",
          "Complete inventories: pod, container_group"
        ],
        "kind": "container_group_and_aks_pod",
        "target": "scope"
      },
      "references": [
        {
          "title": "AKS security context",
          "url": "https://learn.microsoft.com/azure/aks/concepts-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable unnecessary host PID sharing and verify the workload\u2019s required process access."
      ],
      "summary": "Disable unnecessary host PID sharing and verify the workload\u2019s required process access."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "container_group_and_aks_pod",
      "module": "peaso.checks._bulk_pending_compliance_new_sw26",
      "predicate_qualname": "host_pid",
      "predicate_source_sha256": "07d4d8cadd9f5d97f1e28ba68cf8b669f3841bb4c98f78d00b12a7f733847ebf",
      "source_qualname": "host_pid"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A Pod or container group declares host PID sharing."
  },
  "azure_aks_cluster_7_2_1_6_93c4fab": {
    "description_base_sha256": "de73ea2e7252875b254d6497cfa93ddd1d841bda70a5bab2c34d184553dc57de",
    "description_fields": {
      "description": "Checks present AKS Pod containers for securityContext.privileged=true."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Only collected current Pods are assessed; templates and runtime confinement are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "New paged Kubernetes core/v1 Pods list across all namespaces of every AKS cluster; spec.containers[],initContainers[],ephemeralContainers[].securityContext.privileged boolean (omitted defaults false). Include RBAC/watch completeness and cluster association.",
          "Complete inventories: aks_cluster"
        ],
        "kind": "aks_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "AKS security context",
          "url": "https://learn.microsoft.com/azure/aks/concepts-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary privileged mode and retain only capabilities the container needs."
      ],
      "summary": "Remove unnecessary privileged mode and retain only capabilities the container needs."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "aks_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "privileged",
      "predicate_source_sha256": "ef7b992d7276bf5ba86ff0e337b9cb92f1fc938187ac89796a1fa2979f603719",
      "source_qualname": "privileged"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "An observed Pod declares a privileged container."
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb": {
    "description_base_sha256": "c434b371964db0ac7a380b61bfe0f785fa12ff62d2c1421943c43150910f00b0",
    "description_fields": {
      "description": "Checks Pod and workload-template containers for readOnlyRootFilesystem=true."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This legacy identifier names RBAC but evaluates filesystem declarations; no running filesystem is inspected."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Kubernetes apps/v1 Deployments, StatefulSets, DaemonSets; batch/v1 Jobs, CronJobs; core/v1 Pods: spec/template.spec.containers[], initContainers[] and Pod-only ephemeralContainers[] securityContext.readOnlyRootFilesystem.",
          "Complete inventories: aks_pod, aks_deployment, aks_statefulset, aks_daemonset, aks_job, aks_cronjob"
        ],
        "kind": "aks_pod",
        "target": "scope"
      },
      "references": [
        {
          "title": "AKS security context",
          "url": "https://learn.microsoft.com/azure/aks/concepts-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use read-only root filesystems and provide writable volumes only where the application needs them."
      ],
      "summary": "Use read-only root filesystems and provide writable volumes only where the application needs them."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "read_only_root_filesystems"
        }
      },
      "delegates": {},
      "kind": "aks_pod",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "read_only_root_filesystems",
      "predicate_source_sha256": "5e5d7153207dd342c3b8ef0056751093df1dd8ec20a05b965bc090bc994a57a9",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A container does not declare a read-only root filesystem."
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524": {
    "description_base_sha256": "89b0230bba25a2554403f54075beece455a3fb94cc1e33b976ec53d9d0fb944d",
    "description_fields": {
      "description": "Checks Linux Pod container user IDs with Pod-level inheritance and rejects omitted or zero UIDs."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This legacy identifier names RBAC but evaluates declared UIDs; Windows or unresolved OS context stays UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Existing aks_cluster inventory; add paged Kubernetes /api/v1/pods list across all namespaces using resourceVersion/continue. Kubernetes Pod v1 schema: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.32/#pod-v1-core. Kubernetes core/v1 list_namespaced_pod (all namespaces): items[].spec.containers[].securityContext.runAsUser,pod.securityContext.runAsUser.",
          "Complete inventories: aks_cluster"
        ],
        "kind": "aks_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "AKS security context",
          "url": "https://learn.microsoft.com/azure/aks/concepts-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable nonzero container user IDs and verify application compatibility."
      ],
      "summary": "Configure suitable nonzero container user IDs and verify application compatibility."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "aks_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "nonroot",
      "predicate_source_sha256": "145cd00154f8a701c093147ffa74fd90b8198bb44d5718906c0af28f1ae4bb22",
      "source_qualname": "nonroot"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Linux container declares UID zero or has no declared user ID."
  },
  "azure_api_management_10_3_1_3_8a50dc0": {
    "description_base_sha256": "41cd7099ca512483a285114a20f5a40b681c9f95000771a99bc08f98bfbeb81a",
    "description_fields": {
      "description": "Checks REST API diagnostics and logger references; native configuration proves missing routes, while logger usability needs separate evidence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery. Native metadata alone cannot certify logger credential usability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged APIM APIs LIST and per-API diagnostics LIST 2024-05-01; service loggers LIST. Join diagnostic.properties.loggerId (full ARM ID) to logger.id, require logger.properties.loggerType=applicationInsights; inspect diagnostic.properties.sampling.percentage and alwaysLog.",
          "Complete inventories: api_management, apim_diagnostic_evidence"
        ],
        "kind": "api_management",
        "target": "resource"
      },
      "references": [
        {
          "title": "API Management diagnostics",
          "url": "https://learn.microsoft.com/azure/api-management/api-management-howto-use-azure-monitor"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure required API tracing and a valid logger reference, then independently verify usable logging."
      ],
      "summary": "Configure required API tracing and a valid logger reference, then independently verify usable logging."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "api_management",
      "module": "peaso.checks._bulk_pending_compliance_new_sw23",
      "predicate_qualname": "api_application_insights",
      "predicate_source_sha256": "e6433e3cb07c16fb3f72d6eeb206cc0b15e4f8788530c287416cedc699039318",
      "source_qualname": "api_application_insights"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A REST API lacks a qualifying tracing diagnostic or usable logger route."
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2": {
    "description_base_sha256": "2e57b4322e86e95a65764dca95456118ccc77c914130952dcf06ca16591f4d93",
    "description_fields": {
      "description": "Joins public frontends to exact DDoS protection and applicable effective WAF policies."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Complete configuration bindings do not prove traffic mitigation or WAF efficacy."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Application Gateway, Front Door, Load Balancer and Public IP inventories; Public IP GET ddosSettings.protectionMode and plan; protected VNet association where inherited; effective App Gateway/Front Door WAF policy linkage, state and mode. Resolve WAF policy state defaults from the documented schema.",
          "Complete inventories: application_gateway, load_balancer, public_ip, frontdoor, frontdoor_profile, public_edge_binding"
        ],
        "kind": "application_gateway_frontdoor_load_balancer_public_ip",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Add the required DDoS or WAF protection to the affected public frontend or route."
      ],
      "summary": "Add the required DDoS or WAF protection to the affected public frontend or route."
    },
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_network"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "application_gateway_frontdoor_load_balancer_public_ip",
      "module": "peaso.checks._bulk_pending_compliance_new_sw22",
      "predicate_qualname": "_network",
      "predicate_source_sha256": "237723d0f6042e9bc1fbecd0ea96d918be0e6a9bac3b5314f511ccf65a78fa25",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A public resource lacks the required DDoS or WAF protection."
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361": {
    "description_base_sha256": "c5485c53fbdb4dc08b970b986fd1cb824d71e85257fb68a9ac8c1eed2fb0c59a",
    "description_fields": {
      "description": "Checks supported gateway or load-balancer access or operational categories for exports to collected destinations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery. One supported enabled category satisfies this profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Collector peaso/collectors/azure.py: application_gateway and load_balancer are collected; diagnostic_setting GET {resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview is collected per resource. New GET diagnosticSettingsCategories at the same resource to determine supported category names; page settings and categories, require approved destination IDs and logs[].enabled=true.",
          "Complete inventories: application_gateway, load_balancer, diagnostic_setting, diagnostic_category, log_analytics_workspace, storage_account"
        ],
        "kind": "application_gateway_and_load_balancer",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable appropriate access or operational logging and verify the intended destination."
      ],
      "summary": "Enable appropriate access or operational logging and verify the intended destination."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gateway_and_balancer_logs"
        }
      },
      "delegates": {},
      "kind": "application_gateway_and_load_balancer",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "gateway_and_balancer_logs",
      "predicate_source_sha256": "a4927de5baf9dcd0574ec2970095c00ae0cd67511787c1ef8f7cc08e03a4b84e",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A gateway or load balancer has no qualifying access or operational log export."
  },
  "azure_cdn_profile_10_3_4_1_4e40487": {
    "description_base_sha256": "d19f22987af844a36a8d1e217c1f0133a67e8bc8330672d33d153d58b90ea2d2",
    "description_fields": {
      "description": "Checks applicable Front Door Blob origins for managed-identity authentication, required HTTPS prerequisites and reader-role evidence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Origin authentication declarations do not prove every origin request is authorized; unsupported product modes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Front Door and CDN profile, endpoint, route, origin-group and origin GET/LIST at supported API versions; origin-group properties.authentication, identity scope, profile identity and storage Blob RBAC; verify whether each origin is a Blob Storage container.",
          "Complete inventories: cdn_profile"
        ],
        "kind": "cdn_profile",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the intended managed identity and Blob read access, with HTTPS forwarding and probes."
      ],
      "summary": "Configure the intended managed identity and Blob read access, with HTTPS forwarding and probes."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "cdn_profile",
      "module": "peaso.checks._bulk_pending_compliance_new_sw26",
      "predicate_qualname": "frontdoor_blob_identity",
      "predicate_source_sha256": "5a8421fff68d9a1432bc6e1a89bc91bbf95de1c6f7df861de58f26b2edef8da1",
      "source_qualname": "frontdoor_blob_identity"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Blob origin lacks the required managed-identity authentication or HTTPS prerequisites."
  },
  "azure_cdn_profile_1_2_8_5_ed953a0": {
    "description_base_sha256": "3e8d7b615b47724e54045c03266b95435477f88a720559584bbec1dfe7cbc5a1",
    "description_fields": {
      "description": "Checks applicable CDN or Front Door custom domains for activated customer-provided certificate configuration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Managed certificates may be appropriate; certificate source preference does not establish a TLS weakness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "New paged CDN profiles/endpoints/customDomains lists 2024-02-01; properties.customHttpsProvisioningState enum Enabled/Disabled/Enabling/Disabling/Failed and customHttpsParameters.certificateSource enum Cdn/AzureKeyVault; read AzureKeyVaultCertificateSourceParameters keyVaultCertificateSourceParameters if present.",
          "Complete inventories: cdn_profile"
        ],
        "kind": "cdn_profile",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a customer-provided certificate only if required and verify activation before removing the current certificate."
      ],
      "summary": "Use a customer-provided certificate only if required and verify activation before removing the current certificate."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "cdn_profile",
      "module": "peaso.checks._bulk_pending_compliance_new_sw26",
      "predicate_qualname": "cdn_customer_cert",
      "predicate_source_sha256": "85f3ebc493b1c3d4ee6498e8bdcf79e40f414ba10f51efcad8a2112f1a42b974",
      "source_qualname": "cdn_customer_cert"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A custom domain does not meet the customer-provided certificate profile."
  },
  "azure_cosmos_account_10_2_1_1_13_5c115b0": {
    "description_base_sha256": "3bb2ce539cde6261e67c4caee3e922d797407f61ccf756ec270ea3aef2102f61",
    "description_fields": {
      "description": "Checks supported MongoDB request-log categories for Cosmos Mongo accounts or vCore clusters and declared diagnostic destinations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Microsoft.DocumentDB/databaseAccounts LIST/GET 2024-05-15 and Microsoft.DocumentDB/mongoClusters LIST/GET; account capabilities identify Mongo API when present, while vCore Mongo clusters are separate resources. List diagnostic settings at each exact resource ID with 2021-05-01-preview; read properties.logs[].category/enabled and setting-level workspaceId/storageAccountId/eventHubAuthorizationRuleId/eventHubName. Supported account categories include MongoRequests and DataPlaneRequests; mongoClusters category is vCoreMongoRequests.",
          "Complete inventories: cosmos_account, mongo_cluster"
        ],
        "kind": "cosmos_account",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the applicable MongoDB request-log export to the intended destination."
      ],
      "summary": "Enable the applicable MongoDB request-log export to the intended destination."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_cosmos_account_10_2_1_1_13_5c115b0"
      },
      "delegates": {},
      "kind": "cosmos_account",
      "module": "peaso.checks._bulk_pending_compliance_new_sw32",
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "7e85ccc198d71d97648a6e9a710afa2f3160519640c287eda3b89642f470b277",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An applicable MongoDB service lacks a qualifying request-log export."
  },
  "azure_devops_project_1_2_8_6_fb0e5a8": {
    "description_base_sha256": "cbfbcadfec1721ad6fc704084d83a2387f832edfea885276950f15854f92bd98",
    "description_fields": {
      "description": "Checks source-bound repository clone URL variants for embedded user information using the native Git URL policy."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "SSH user@host syntax is not automatically a secret; native policy distinguishes service-specific URL forms. No credential value is displayed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Azure DevOps 7.1 complete projects LIST and per-project Git repositories LIST with includeHidden=true and includeAllUrls=true; inspect repository.remoteUrl and every validRemoteUrls[] clone URL.",
          "Complete inventories: devops_project"
        ],
        "kind": "devops_project",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Repos repository security",
          "url": "https://learn.microsoft.com/azure/devops/repos/git/secure-git-experience"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary embedded credentials from configured clone URLs and rotate any actual exposed credentials."
      ],
      "summary": "Remove unnecessary embedded credentials from configured clone URLs and rotate any actual exposed credentials."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_devops_project_1_2_8_6_fb0e5a8"
      },
      "delegates": {},
      "kind": "devops_project",
      "module": "peaso.checks._bulk_pending_compliance_new_sw32",
      "predicate_qualname": "_urls",
      "predicate_source_sha256": "8c2a5558206c41d0e5720e62169b017b01d52eecbbca3d216206731143727e4b",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A repository URL contains disallowed embedded user information or credentials."
  },
  "azure_devops_project_6_5_5_2_2908a87": {
    "description_base_sha256": "38b8212d16c2a0b577d45da86ad16b9db2067bd0909fa928451a41019115f001",
    "description_fields": {
      "description": "Counts resolved deployment jobs per pipeline stage against the first-stage and supplied later-stage limits."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This historical control requires a custom later-stage limit; job count alone is not a security defect."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Azure DevOps Pipelines GET 7.1 and referenced YAML/templates at immutable repository revisions; paged pipeline inventory; optional deploymentLimit policy for later stages.",
          "Complete inventories: devops_project"
        ],
        "kind": "devops_project",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Repos repository security",
          "url": "https://learn.microsoft.com/azure/devops/repos/git/secure-git-experience"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Split deployment jobs only where the organization\u2019s stage-separation requirement calls for it."
      ],
      "summary": "Split deployment jobs only where the organization\u2019s stage-separation requirement calls for it."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_devops_project_6_5_5_2_2908a87"
      },
      "delegates": {},
      "kind": "devops_project",
      "module": "peaso.checks._bulk_pending_compliance_new_sw32",
      "predicate_qualname": "_pipelines",
      "predicate_source_sha256": "4045d44cda8ab92bf32ff0336243977e2e38ed2a15ddf3b2a641e885220daf3c",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A resolved stage exceeds its supplied deployment-job count limit."
  },
  "azure_directory_user_10_6_3_21_d013932": {
    "description_base_sha256": "c486aa74f02470b420cc3f8b3fecaee4f1b1688a6fd1a3ce63c55d34745815e2",
    "description_fields": {
      "description": "Joins every directory user to its complete transitive group-membership list and flags empty lists."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This profile includes disabled users; group absence alone does not establish excessive permissions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Graph v1.0 paged /users?$select=id,accountEnabled and each /users/{id}/transitiveMemberOf/microsoft.graph.group?$select=id; follow @odata.nextLink for both lists.",
          "Complete inventories: directory_user, directory_user_group_membership"
        ],
        "kind": "directory_user_and_group",
        "target": "scope"
      },
      "references": [
        {
          "title": "Microsoft Graph identity governance",
          "url": "https://learn.microsoft.com/graph/api/resources/accessreviewsv2-root"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review whether the user intentionally has no groups; add required group-based access only if needed."
      ],
      "summary": "Review whether the user intentionally has no groups; add required group-based access only if needed."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "user_group_membership"
        }
      },
      "delegates": {},
      "kind": "directory_user_and_group",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "user_group_membership",
      "predicate_source_sha256": "83924aeb9b7d9e99c5cb3507d2e080826f4a280a669ae0deb61c0f02e31f106f",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A directory user has no collected transitive group membership."
  },
  "azure_directory_user_7_2_1_19_28e2aa7": {
    "description_base_sha256": "34cdf6eddbf96ce1d650261ab7cb21e7dff2df0eb949a8fbe73f6eae660e8567",
    "description_fields": {
      "description": "Checks resolved directory, active or eligible PIM, and Azure RBAC assignments directly granted to the user."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "A direct assignment is a management preference, not proof of excessive permissions; group-mediated grants are excluded."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Graph /users, directory roleAssignments, active and eligible PIM role assignment instances/schedules; complete paged ARM roleAssignments across tenant root/management groups, subscriptions, resource groups and child resource scopes; compare principalId to user.id and resolve principal type.",
          "Complete inventories: directory_user"
        ],
        "kind": "directory_user",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Graph identity governance",
          "url": "https://learn.microsoft.com/graph/api/resources/accessreviewsv2-root"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use appropriate group-based assignments where the access-management profile requires them."
      ],
      "summary": "Use appropriate group-based assignments where the access-management profile requires them."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_directory_user_7_2_1_19_28e2aa7"
      },
      "delegates": {
        "_direct": "28b382880ce43f87fa4519f9f5b35d75c8d31c0e68eeebce8266107a5d8bfe7c"
      },
      "kind": "directory_user",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user has a direct directory, PIM or Azure RBAC role assignment."
  },
  "azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9": {
    "description_base_sha256": "a5b50e90cdcec0c315bb7d7fe272d18b82b740dd33d6027b4b4c519e40f64b3b",
    "description_fields": {
      "description": "Checks enabled users\u2019 resolved required sign-in contexts for enforced MFA, accounting for grant alternatives and exclusions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. The signed profile\u2019s user selection is broader than its legacy identifier suggests."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Graph v1.0 /users?$select=id,accountEnabled; /identity/conditionalAccess/policies; /policies/identitySecurityDefaultsEnforcementPolicy; transitive group membership and authentication-method registration; sign-in contexts required by policy.",
          "Complete inventories: directory_user, conditional_access_policy"
        ],
        "kind": "directory_user",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require MFA on the affected sign-in paths and correct unintended policy exclusions."
      ],
      "summary": "Require MFA on the affected sign-in paths and correct unintended policy exclusions."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9"
      },
      "delegates": {
        "_mfa": "5d218c2440d8d0906c7dd02e9d005519eb23362e28caeb24f691f26fb10c8a5c"
      },
      "kind": "directory_user",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A required sign-in context lacks enforced MFA."
  },
  "azure_directory_user_entra_privileged_user_has_mfa_6f6d584": {
    "description_base_sha256": "902ed52a08915cf9133cccc3a9b7cb38363ad105bea9ea125e16da39d5cc90aa",
    "description_fields": {
      "description": "Checks effective Global Administrators\u2019 Azure-console contexts for enforced MFA or a resolved Security Defaults requirement."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Registration alone does not prove MFA enforcement; exclusions, alternative grants and unresolved sign-in contexts remain separate. This predicate specifically selects Global Administrators."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Microsoft Graph /roleManagement/directory/roleAssignments, /users, /identity/conditionalAccess/policies, /policies/identitySecurityDefaultsEnforcementPolicy: principalId,roleDefinitionId,accountEnabled,state,conditions,grantControls,isEnabled",
          "Complete inventories: directory_user, conditional_access_policy"
        ],
        "kind": "directory_user",
        "target": "resource"
      },
      "references": [
        {
          "title": "Microsoft Entra MFA",
          "url": "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require suitable MFA for administrator console access and resolve excluded paths."
      ],
      "summary": "Require suitable MFA for administrator console access and resolve excluded paths."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_directory_user_entra_privileged_user_has_mfa_6f6d584"
      },
      "delegates": {
        "_mfa": "5d218c2440d8d0906c7dd02e9d005519eb23362e28caeb24f691f26fb10c8a5c"
      },
      "kind": "directory_user",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A Global Administrator console context lacks enforced MFA."
  },
  "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf": {
    "description_base_sha256": "ef864fa7e5f79c25a798bb0ceeeac5fa3d9bf15f0a09bc3d5b2548f6405eed1d",
    "description_fields": {
      "description": "Checks MySQL or PostgreSQL flexible-server Entra authentication and complete bound administrator lists."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Administrator metadata does not prove successful database login or least privilege."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged MySQL Flexible Server and PostgreSQL Flexible Server inventory and per-server administrators child LIST; PostgreSQL properties.authConfig.activeDirectoryAuth, MySQL properties.authConfig.activeDirectoryAuth or documented equivalent, with valid administrator principal identity.",
          "Complete inventories: mysql_flexible_server, postgresql_flexible_server"
        ],
        "kind": "mysql_and_postgresql_flexible_server",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable supported Entra authentication and configure the required administrator identity."
      ],
      "summary": "Enable supported Entra authentication and configure the required administrator identity."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf",
        "evaluator": {
          "callable": "_database_admins"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "mysql_and_postgresql_flexible_server",
      "module": "peaso.checks._bulk_pending_compliance_new_sw27",
      "predicate_qualname": "_database_admins",
      "predicate_source_sha256": "f64627ce6b6283dc36c2a7721a74a0da486824985c5cba38d58b1ad6e05171f9",
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A flexible server disables Entra authentication or has no configured administrator."
  },
  "azure_disk_10_3_3_12_174f526": {
    "description_base_sha256": "8f9c97c3c0fe4286cdf2cd032e0113b3dca4f941592488af7ab2d790861ee2b8",
    "description_fields": {
      "description": "Joins each disk to a unique active backup instance and its vault."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged ARM Microsoft.Compute/disks LIST 2023-10-02 and every Microsoft.DataProtection/backupVaults/backupInstances LIST 2024-04-01 across in-scope subscriptions; exact normalized disk ARM ID to properties.dataSourceInfo.resourceID and properties.policyInfo.policyId; properties.currentProtectionState enum.",
          "Complete inventories: disk, backup_vault, backup_instance"
        ],
        "kind": "disk_and_backup_instance",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required disk backup protection and repair stopped or missing protection."
      ],
      "summary": "Configure the required disk backup protection and repair stopped or missing protection."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "disk_and_backup_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw16",
      "predicate_qualname": "disk_backup",
      "predicate_source_sha256": "1359827bf2b42c927ab72fa88233c0039f01a2c464868f5f6b8fd35bad2dc8cf",
      "source_qualname": "disk_backup"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A disk lacks a qualifying active backup instance."
  },
  "azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d": {
    "description_base_sha256": "da2a0f2a6bacdc5fbb7378bb0dfd27dded52886353a3e85b74c2fca9ce58f66d",
    "description_fields": {
      "description": "Checks complete SQL-family firewall rules for full IPv4 ranges and the separately governed zero-address service rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. The zero-address exception uses a custom optional-policy path and is not equivalent to all Internet IPv4."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Existing azure.py sql_server and mysql/postgresql flexible server items, sql_firewall_rule child for SQL only; new paged firewallRules list per MySQL/PostgreSQL server using each provider API; properties.startIpAddress/endIpAddress IPv4 strings.",
          "Complete inventories: sql_server, mysql_flexible_server, postgresql_flexible_server"
        ],
        "kind": "mysql_postgresql_sql_firewall_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict unnecessary database firewall ranges and review broad Azure-service exceptions."
      ],
      "summary": "Restrict unnecessary database firewall ranges and review broad Azure-service exceptions."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "mysql_postgresql_sql_firewall_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw15",
      "predicate_qualname": "database_firewalls",
      "predicate_source_sha256": "34c17cf2bfab2a7c1951588f02a9b4a4b85e882cd023234b10c58f362cace366",
      "source_qualname": "database_firewalls"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A database firewall rule admits the full IPv4 range or a disallowed Azure-service exception."
  },
  "azure_frontdoor_1_2_5_4_ccc7b8f": {
    "description_base_sha256": "3d05b124ee46c4bef1938f2c9bb0fc351afb2441465bb2eaab0d8a44dc7e4864",
    "description_fields": {
      "description": "Checks applicable classic CDN or Front Door custom domains for activated Key Vault-backed SNI certificate configuration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Standard or Premium Front Door lacks equivalent classic SNI semantics; managed certificates may be appropriate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Enumerate classic Front Door frontend endpoints from Microsoft.Network/frontDoors GET (2019-05-01 schema) and classic CDN profile/endpoint/customDomain lists with paging. Front Door: properties.frontendEndpoints[].properties.customHttpsProvisioningState, customHttpsConfiguration.certificateSource and protocolType. CDN: each custom domain properties.customHttpsProvisioningState, customHttpsParameters.certificateSource and protocolType. Do not infer SNI from certificate type.",
          "Complete inventories: frontdoor_and_cdn_endpoint"
        ],
        "kind": "frontdoor_and_cdn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required certificate source and supported SNI mode only if this profile applies."
      ],
      "summary": "Configure the required certificate source and supported SNI mode only if this profile applies."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_frontdoor_1_2_5_4_ccc7b8f"
      },
      "delegates": {
        "_domain_checks": "8ee85fce160b775e4c70edfa60c469d9dc8c83d571d47cd2625a5ec912bdd194"
      },
      "kind": "frontdoor_and_cdn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A custom domain does not meet the Key Vault-backed SNI certificate profile."
  },
  "azure_frontdoor_1_2_8_4_90159db": {
    "description_base_sha256": "c8ee36c5b26842dd258e748102df03111963d2d4f70052cc43d44c9189bd5c05",
    "description_fields": {
      "description": "Joins enabled Front Door routes and domains to enabled WAF association patterns."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "An enabled association does not establish Prevention mode, rule strength or observed blocking; ambiguous wildcard coverage stays UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "New paged Microsoft.Cdn/profiles/securityPolicies, customDomains, afdEndpoints/routes List 2024-02-01 and WAF policy GET 2023-09-01. Security policy properties.parameters.type, wafPolicy.id, associations[].domains[].id, patternsToMatch; WAF properties.policySettings.enabledState enum Enabled/Disabled.",
          "Complete inventories: afd_profile, afd_security_policy, afd_route, afd_domain, frontdoor_waf_policy"
        ],
        "kind": "afd_security_policy",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Associate the required enabled WAF policy with affected domains and route paths."
      ],
      "summary": "Associate the required enabled WAF policy with affected domains and route paths."
    },
    "reviewed_binding": {
      "closure": {
        "fn": {
          "callable": "frontdoor_waf_coverage"
        }
      },
      "delegates": {},
      "kind": "afd_security_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw21",
      "predicate_qualname": "frontdoor_waf_coverage",
      "predicate_source_sha256": "b51cfc1a6636e003371f3c9d6e183c578a7cf9624d70608aa4e500a3445a31f7",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "An enabled Front Door domain or route path lacks an enabled WAF association."
  },
  "azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9": {
    "description_base_sha256": "6ada3b57888d20cca773e90a9d16de412b9c62bc04cb30e055f53391de826801",
    "description_fields": {
      "description": "Checks enabled effective route paths accepting HTTP for HTTPS-only redirection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared effective paths are assessed; no endpoint request or redirect chain is tested."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Classic Front Door GET 2021-06-01 routingRules; paged Microsoft.Cdn profiles, endpoints/customDomains and afdEndpoints/routes GET 2024-02-01; inspect classic acceptedProtocols/routeConfiguration, AFD supportedProtocols/httpsRedirect, and CDN endpoint/custom-domain HTTPS/protocol or rules-engine redirect configuration for each SKU.",
          "Complete inventories: frontdoor_and_cdn_endpoint"
        ],
        "kind": "frontdoor_and_cdn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Redirect HTTP requests to HTTPS where encrypted client access is required."
      ],
      "summary": "Redirect HTTP requests to HTTPS where encrypted client access is required."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9"
      },
      "delegates": {
        "_route_checks": "31b7fc182059f49fc6f99679589164c8c7bf170d2192191560601f033111f2d5"
      },
      "kind": "frontdoor_and_cdn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An enabled route accepts HTTP without an HTTPS-only redirect."
  },
  "azure_frontdoor_app_minimum_tls_version_12_0512053": {
    "description_base_sha256": "6cfc02b212e2c81f55eecd64bcb4b273ad180ebef078f5150382582f3c3bafa5",
    "description_fields": {
      "description": "Checks applicable activated HTTPS domains\u2019 declared minimum TLS version, resolving known Front Door presets."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Disabled HTTPS domains are not applicable; deployment or unknown preset states remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Collect both resource families with complete pagination: classic Microsoft.Network/frontDoors frontendEndpoints[].properties.customHttpsConfiguration.minimumTlsVersion; CDN Microsoft.Cdn/profiles/endpoints/customDomains GET properties.customHttpsParameters.minimumTlsVersion (enum None/TLS10/TLS12); AFD Standard/Premium Microsoft.Cdn/profiles/customDomains GET properties.tlsSettings.cipherSuiteSetType and minimumTlsVersion (TLS10/TLS12/TLS13 for Customized). Resolve HTTPS enablement, custom domain deployment, and the effective minimum for AFD preset cipher suites separately.",
          "Complete inventories: frontdoor_and_cdn_endpoint"
        ],
        "kind": "frontdoor_and_cdn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require TLS 1.2 or later after checking client compatibility."
      ],
      "summary": "Require TLS 1.2 or later after checking client compatibility."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_frontdoor_app_minimum_tls_version_12_0512053"
      },
      "delegates": {
        "_domain_checks": "8ee85fce160b775e4c70edfa60c469d9dc8c83d571d47cd2625a5ec912bdd194"
      },
      "kind": "frontdoor_and_cdn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An HTTPS domain permits a minimum TLS version below 1.2."
  },
  "azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a": {
    "description_base_sha256": "43ff10b8f2201c3afb5c0c40cc95f5a852227dfda318fe1ca55db19949ded1eb",
    "description_fields": {
      "description": "Checks discovered access-log categories for an enabled diagnostic export to a workspace or storage destination."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery. This legacy identifier mentions destination privacy; the evaluator does not assess destination privacy."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ARM Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview at Microsoft.Network/frontDoors and Microsoft.Cdn/profiles IDs: properties.logs[].category/categoryGroup, enabled and setting-level properties.workspaceId/storageAccountId. Discover supported categories for each resource with diagnosticSettingsCategories LIST; expand allLogs groups.",
          "Complete inventories: frontdoor_and_cdn_endpoint"
        ],
        "kind": "frontdoor_and_cdn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the required access-log category at the intended destination."
      ],
      "summary": "Enable the required access-log category at the intended destination."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a"
      },
      "delegates": {
        "_access_logs": "958bd0bf51cccf4e9d661fd944c944dfff926f49eef0b4d59add8bf409550e0a"
      },
      "kind": "frontdoor_and_cdn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The frontend lacks a qualifying enabled access-log export."
  },
  "azure_frontdoor_network_http_internet_access_restricted_7004685": {
    "description_base_sha256": "a5be00812666de9ee6491d3b3af972ff5c3bf95ae7fbf3607fae0785fa3d6daf",
    "description_fields": {
      "description": "Checks enabled custom-origin route paths for HTTP forwarding or protocol matching that can send HTTP."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Origin ports alone do not establish protocol; unresolved CDN origin evidence stays UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged classic Front Door routing rules and AFD routes with effective rule-set forwarding overrides; enumerate Microsoft.Cdn classic profiles/endpoints/origins for scope. Classic CDN endpoint GET exposes isHttpAllowed/isHttpsAllowed and origin ports but does not expose a universal origin-protocol policy; require provider-specific configuration or traffic evidence before judging its origin protocol. Resolve each enabled route/endpoint with a custom origin and all effective origin-request paths.",
          "Complete inventories: frontdoor_and_cdn_endpoint"
        ],
        "kind": "frontdoor_and_cdn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Front Door security",
          "url": "https://learn.microsoft.com/azure/frontdoor/front-door-security"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use HTTPS-only origin forwarding after verifying the origin supports it."
      ],
      "summary": "Use HTTPS-only origin forwarding after verifying the origin supports it."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "azure_frontdoor_network_http_internet_access_restricted_7004685"
      },
      "delegates": {
        "_route_checks": "31b7fc182059f49fc6f99679589164c8c7bf170d2192191560601f033111f2d5"
      },
      "kind": "frontdoor_and_cdn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw19",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "47297ac90b8fd9ada5e1d7ad41189bb82a41b92e668d150d945e417ba37671e0",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An enabled custom-origin route can forward traffic over HTTP."
  },
  "azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b": {
    "description_base_sha256": "2383450991e2d847c73582b06b45d9d33527241b49c0b47eba1be256e9d1b520",
    "description_fields": {
      "description": "Checks resources for at least one supported log category exported to a resolved workspace destination."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivered logs, retention coverage or successful notification delivery. One qualifying category satisfies this existence profile; it does not require every supported category."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged resource inventory and Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview at each resource: setting.properties.logs[].category/categoryGroup and enabled; setting.properties.workspaceId full ARM ID; category support LIST and approved workspace IDs.",
          "Complete inventories: resource_diagnostic_setting"
        ],
        "kind": "resource_diagnostic_setting",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable appropriate resource logs at the intended Log Analytics workspace."
      ],
      "summary": "Enable appropriate resource logs at the intended Log Analytics workspace."
    },
    "reviewed_binding": {
      "closure": {
        "fn": {
          "callable": "resource_logs_to_workspace"
        }
      },
      "delegates": {},
      "kind": "resource_diagnostic_setting",
      "module": "peaso.checks._bulk_pending_compliance_new_sw21",
      "predicate_qualname": "resource_logs_to_workspace",
      "predicate_source_sha256": "1b8b396b093a4a0827d2e507d9ff8f3ff57233419e65ad812c77093216c5a2cb",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A resource has no qualifying log export to a workspace."
  },
  "azure_pci_10_2_1_1_16": {
    "description_base_sha256": "71f2e3b6beef2d717d7201857bdac8b5c0738f130f2e75d53db32238be80325a",
    "description_fields": {
      "description": "Checks active container groups for a resolved workspace and fresh collected logs from at least one container."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "One freshly verified container satisfies this profile; it does not certify logging for every container."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Container Instance group inventory and per-group GET 2023-05-01: properties.diagnostics.logAnalytics.workspaceId/logType plus properties.containers[]; container logging enablement from supported runtime configuration or fresh per-container log/ingestion evidence.",
          "Complete inventories: container_group"
        ],
        "kind": "container_group",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the intended workspace logging and verify current container records arrive."
      ],
      "summary": "Configure the intended workspace logging and verify current container records arrive."
    },
    "reviewed_binding": {
      "closure": {
        "fn": {
          "callable": "container_instance_logging"
        }
      },
      "delegates": {},
      "kind": "container_group",
      "module": "peaso.checks._bulk_pending_compliance_new_sw21",
      "predicate_qualname": "container_instance_logging",
      "predicate_source_sha256": "cf91e8010b515fa9f3748ffec724bdc38f745a7ac2a0e5c11af1b5f790e0a69c",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active group has no workspace or all containers explicitly disable logging."
  },
  "azure_pci_10_2_1_1_8": {
    "description_base_sha256": "c20dc9010516794f3bcd00290573e1361cc4c65f264207502cf6a7974183f730",
    "description_fields": {
      "description": "Checks applicable alert-action states for nonempty configured action-group routing."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Default operation requires no owner-provided group ID; configured routing does not prove receiver availability or delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged ARM activityLogAlerts LIST 2020-10-01, metricAlerts LIST 2018-03-01, and scheduledQueryRules LIST 2021-08-01 for policy-scoped Azure Monitor alerts; inspect each alert type's action-group IDs, enabled state and scope. GET actionGroups 2023-01-01 when destination existence is required. Optional policy actionGroupId may narrow matching but is not universally required.",
          "Complete inventories: activity_log_alert, metric_alert, scheduled_query_rule"
        ],
        "kind": "activity_log_alert",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach the intended action groups to alert actions that lack a route."
      ],
      "summary": "Attach the intended action groups to alert actions that lack a route."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "azure_pci_10_2_1_1_8"
      },
      "delegates": {
        "_routing": "532642b4b58a58cbacc2f5b1c130fcf33d249fae685426248faa04db50e4ee13"
      },
      "kind": "activity_log_alert",
      "module": "peaso.checks._bulk_pending_compliance_new_sw25",
      "predicate_qualname": "_register.<locals>.evaluate",
      "predicate_source_sha256": "f0d49b11d5bd6038ffa670e4108dae55274021289d54675ab2203277d2909443",
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An applicable alert-action state has no required action-group route."
  },
  "azure_pci_1_3_1_33": {
    "description_base_sha256": "120776d7c974d7f58d0938e974877f95cb0c985deaa9e9e1b5cd3d733edff6ff",
    "description_fields": {
      "description": "Joins dedicated Synapse SQL pools\u2019 approved private endpoints to the workspace and sql group."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. Private endpoint presence does not disable public access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Complete Synapse workspace and dedicated SQL-pool inventory; Synapse privateEndpointConnections LIST for connection status and privateEndpoint.id; Microsoft.Network/privateEndpoints GET for properties.privateLinkServiceConnections[].properties.groupIds and privateLinkServiceId. Join by exact endpoint ID and workspace ARM ID; follow all pages.",
          "Complete inventories: synapse_workspace"
        ],
        "kind": "synapse_workspace",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the intended approved SQL private endpoint if private connectivity is required."
      ],
      "summary": "Configure the intended approved SQL private endpoint if private connectivity is required."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "synapse_workspace",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "private_sql",
      "predicate_source_sha256": "6cee45b578932bab87fc4876f00b7e1b4067761d6177a679c3711dc1726de12a",
      "source_qualname": "private_sql"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dedicated SQL workspace lacks a qualifying approved SQL private endpoint."
  },
  "azure_recovery_vault_10_3_3_1_1f42f66": {
    "description_base_sha256": "447142bfc995f82de085b4f8df7cfa6b2051319b84989c9fd0e0a8c48a91f36c",
    "description_fields": {
      "description": "Checks applicable online user databases for positive short-term point-in-time backup retention."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Microsoft.Sql/servers/databases LIST 2023-08-01: id, properties.status; child /backupShortTermRetentionPolicies/default GET 2023-08-01: properties.retentionDays. The retention policy is a child, not in database GET.",
          "Complete inventories: sql_database, sql_backup_short_term_policy"
        ],
        "kind": "sql_database",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure an appropriate positive short-term retention policy for databases needing recovery."
      ],
      "summary": "Configure an appropriate positive short-term retention policy for databases needing recovery."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "sql_database",
      "module": "peaso.checks._bulk_pending_compliance_new_sw31",
      "predicate_qualname": "sql_pitr",
      "predicate_source_sha256": "581ba6ba417810600c81dd5ec826e1b55044cccd045556f13472697e256d057c",
      "source_qualname": "sql_pitr"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An online user database lacks positive short-term backup retention."
  },
  "azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9": {
    "description_base_sha256": "966fe7aff467fb921bb61353c9854b00cf7ad60e6d0b5b57132d4b9960cd2d8d",
    "description_fields": {
      "description": "Joins database parent servers and managed instances to ActiveDirectory administrators with valid identity IDs."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Administrator metadata does not prove successful authentication or least privilege."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged SQL servers, databases and managed instances; GET SQL server /administrators and managed instance /administrators child lists, api-version=2023-08-01, using properties.administratorType=ActiveDirectory and properties.sid UUID; resolve each database to its parent server. Optional Entra-only authentication child GET is a stricter separate signal.",
          "Complete inventories: sql_database, sql_server, mssql_managed_instance, sql_managed_instance_administrator"
        ],
        "kind": "sql_server_and_managed_instance",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable Entra administrator for the affected database server or managed instance."
      ],
      "summary": "Configure a suitable Entra administrator for the affected database server or managed instance."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sql_entra_administrator"
        }
      },
      "delegates": {},
      "kind": "sql_server_and_managed_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "sql_entra_administrator",
      "predicate_source_sha256": "94ad6e0bcaa0bc6c58a2eef9b1423fe956a2e6500e8eded5b16f583d5cdeb0a4",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A SQL server or managed instance has no qualifying Entra administrator."
  },
  "azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a": {
    "description_base_sha256": "8e10d4c4f02da2e89bdc4c666f24dd10fcdb322ac664ea8d2d7dc6f4846f869b",
    "description_fields": {
      "description": "Checks enabled database public networking, bypass evidence and firewall intervals for globally routable clients."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. SQL\u2019s zero-address Azure-service rule differs from an all-IPv4 range."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged SQL Server, MySQL Flexible Server and PostgreSQL Flexible Server GET/LIST plus each server firewall-rules LIST, using the matching resource API version. Read SQL properties.publicNetworkAccess and flexible-server properties.network.publicNetworkAccess, every firewall rule startIpAddress/endIpAddress, SQL Allow Azure services special rule, and any applicable public trusted-service bypass. PublicNetworkAccess=Enabled alone is not proof of reachable ingress.",
          "Complete inventories: mysql_postgresql_sql_server"
        ],
        "kind": "mysql_postgresql_sql_server",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure SQL security",
          "url": "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict unnecessary public database client ranges and review service-bypass rules."
      ],
      "summary": "Restrict unnecessary public database client ranges and review service-bypass rules."
    },
    "reviewed_binding": {
      "closure": {
        "fn": {
          "callable": "database_public_ingress"
        }
      },
      "delegates": {},
      "kind": "mysql_postgresql_sql_server",
      "module": "peaso.checks._bulk_pending_compliance_new_sw21",
      "predicate_qualname": "database_public_ingress",
      "predicate_source_sha256": "fd327be34a9a9bb9efdd2c5d144de83e8fb955a32d48c534f830f2ec983de24d",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A database server declares access for an external public client."
  },
  "azure_storage_account_10_3_3_24_61d5e36": {
    "description_base_sha256": "38103128179ee005bf37473ae1b841f3e0e93158aa3815414b77d74a4d976377",
    "description_fields": {
      "description": "Joins every collected Blob container to active backup protection and explicit or fully resolved automatic selection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration. Unresolved automatic selection cannot prove a protected container."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Existing storage_account.blobContainers; new paged Microsoft.DataProtection backupVaults and backupInstances LIST 2024-04-01. Match properties.dataSourceInfo.resourceID to storage-account ARM ID, inspect policyInfo.policyId, currentProtectionState and policyInfo.policyParameters.backupDatasourceParametersList[].containersList; independently resolve any provider-supported automatic-selection policy from its documented API before using it as evidence.",
          "Complete inventories: storage_account, backup_vault, backup_instance"
        ],
        "kind": "storage_account_and_backup_instance",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Include the required containers in active backup protection and repair stopped protection."
      ],
      "summary": "Include the required containers in active backup protection and repair stopped protection."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "storage_account_and_backup_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw16",
      "predicate_qualname": "blob_backup",
      "predicate_source_sha256": "d7e098a957c9e289d8e12402df5623a78f3005efab77b4c76e135c883365797c",
      "source_qualname": "blob_backup"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Blob container is not selected by qualifying active backup protection."
  },
  "azure_storage_account_10_3_4_7_02943e9": {
    "description_base_sha256": "45b335cc84842df5e06ec74ef7aef60bacbfc86ea6c045378f71a7375ccf5cd3",
    "description_fields": {
      "description": "Checks each container\u2019s effective default retention policy and whether new writes inherit positive retention."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Versioning alone does not prove new-write retention inheritance; locking and existing-object protection are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Microsoft.Storage/storageAccounts/blobServices/default/containers LIST 2023-05-01, each container GET and immutabilityPolicies/default GET, plus storage-account GET 2023-05-01: container properties.immutableStorageWithVersioning.enabled, properties.immutabilityPolicy, account properties.immutabilityPolicy. Resolve effective container-level or inherited account/container default version-level retention policy and its period/state.",
          "Complete inventories: storage_account, storage_immutability_evidence"
        ],
        "kind": "storage_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Storage security",
          "url": "https://learn.microsoft.com/azure/storage/common/storage-security-guide"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable default immutability retention where required, after reviewing write compatibility."
      ],
      "summary": "Configure suitable default immutability retention where required, after reviewing write compatibility."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "storage_account",
      "module": "peaso.checks._bulk_pending_compliance_new_sw23",
      "predicate_qualname": "default_immutability",
      "predicate_source_sha256": "decfb8acc630520deb963941f88d1a34b55c4cf006602bbe96a616c5fc046a23",
      "source_qualname": "default_immutability"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A container\u2019s new writes lack effective positive default retention."
  },
  "azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3": {
    "description_base_sha256": "3cc458082565f6d53d11564a3f0a9c27fd4a63a385fe53f6caeab4107a2cf1ee",
    "description_fields": {
      "description": "Resolves Blob encryption scopes and historical Blob metadata to current account or scope key sources."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Customer-managed key requirements do not mean platform-managed encryption is plaintext; key rotation and recovery are separate. This legacy identifier names Defender, but evaluates encryption-key sources and write-scope restrictions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Blob container LIST/GET and storage account GET 2023-05-01; container properties.defaultEncryptionScope and denyEncryptionScopeOverride; account properties.encryption.keySource/keyVaultProperties; account encryptionScopes child LIST/GET with source and keyVaultProperties; resolve effective scope for each container and any permitted per-blob override.",
          "Complete inventories: storage_account, storage_blob_key_evidence"
        ],
        "kind": "storage_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Storage security",
          "url": "https://learn.microsoft.com/azure/storage/common/storage-security-guide"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use customer-managed keys if required and review existing Blob encryption scopes before changing defaults."
      ],
      "summary": "Use customer-managed keys if required and review existing Blob encryption scopes before changing defaults."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "storage_account",
      "module": "peaso.checks._bulk_pending_compliance_new_sw23",
      "predicate_qualname": "blob_keyvault_keys",
      "predicate_source_sha256": "d6901445bef0e6c109f365c13ebd95905a633e6d2dea80d2a9c49356435245b3",
      "source_qualname": "blob_keyvault_keys"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Blob or mandatory write scope uses platform-managed encryption."
  },
  "azure_storage_file_share_10_3_3_15_f2d7075": {
    "description_base_sha256": "31c5c4e10ccb41b9d4cd88a4345f3d9fce5c7645fa7a48031ad8d708f0a3f28a",
    "description_fields": {
      "description": "Joins Azure Files shares to complete all-vault backup items and checks Protected state with a policy."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Microsoft.Storage/storageAccounts/fileServices/default/shares LIST api-version=2023-05-01 for every scoped storage account; paged Microsoft.RecoveryServices/vaults/backupProtectedItems LIST api-version=2024-04-01 across all accessible scoped vaults. Join protectedItem.properties.sourceResourceId to the parent account ID, friendlyName to share name, and protectedItemType=AzureFileShareProtectedItem; read policyId and protectionState.",
          "Complete inventories: storage_file_share_and_backup_item, backup_protected_item"
        ],
        "kind": "storage_file_share_and_backup_item",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure required share backup protection and repair stopped protection."
      ],
      "summary": "Configure required share backup protection and repair stopped protection."
    },
    "reviewed_binding": {
      "closure": {
        "fn": {
          "callable": "azure_files_backup"
        }
      },
      "delegates": {},
      "kind": "storage_file_share_and_backup_item",
      "module": "peaso.checks._bulk_pending_compliance_new_sw21",
      "predicate_qualname": "azure_files_backup",
      "predicate_source_sha256": "725cbf3ff5ac7608e9412ec66ba1b0448eaa5deb58a98d088a5becd158a0256a",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An Azure Files share lacks qualifying active backup protection."
  },
  "azure_storage_file_share_10_3_3_18_d67ab34": {
    "description_base_sha256": "12232d6aa5300c163647002f7ec462a2a0bfa3ac2215ea9a704ed8a127dec6ad",
    "description_fields": {
      "description": "Joins Azure Files protection and NetApp backup declarations to their required policies and vaults."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Protection and policy declarations are not proof of a successful backup or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged ARM storageAccounts/fileServices/shares LIST and every Recovery Services vault backupProtectedItems LIST 2024-04-01: properties.sourceResourceId (storage account ID), friendlyName (share name), protectedItemType, protectionState, policyId; NetApp volumes GET/LIST 2026-01-01: properties.dataProtection.backup.backupPolicyId/backupVaultId/policyEnforced. Resolve backup policy and vault existence.",
          "Complete inventories: storage_file_share, netapp_volume, backup_protected_item, backup_policy, recovery_vault, netapp_backup_policy, netapp_backup_vault"
        ],
        "kind": "storage_file_share_and_netapp_volume",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Backup protection",
          "url": "https://learn.microsoft.com/azure/backup/backup-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure required backup protection for the affected share or volume and verify its policy association."
      ],
      "summary": "Configure required backup protection for the affected share or volume and verify its policy association."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "files_and_netapp_backup"
        }
      },
      "delegates": {},
      "kind": "storage_file_share_and_netapp_volume",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "files_and_netapp_backup",
      "predicate_source_sha256": "95c849eb0a5631a8ccd2ad1ef0eb3cb15671b07e600faf1f0a40c31889367e20",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An Azure Files share or NetApp volume lacks qualifying backup protection."
  },
  "azure_synapse_workspace_1_2_8_29_fcdc827": {
    "description_base_sha256": "0f3691e6757aaf11495c2e8b0bf5d3d33c506a104454cbbf3a6069d2c58815e0",
    "description_fields": {
      "description": "Checks workspaces with dedicated Synapse SQL pools for publicNetworkAccess=Enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Synapse workspace and dedicated sqlPools inventory at api-version=2021-06-01; workspace properties.publicNetworkAccess enum Enabled/Disabled. SQL pool resources do not supply an independent publicNetworkAccess field in this API version.",
          "Complete inventories: synapse_workspace"
        ],
        "kind": "synapse_workspace",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable public access if database clients can use the intended private connectivity."
      ],
      "summary": "Disable public access if database clients can use the intended private connectivity."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "synapse_workspace",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "public_sql",
      "predicate_source_sha256": "945c0cb0ba1c6020ae01f3177c059b033f121790d5ecbeb6e00ab4f1357ca63a",
      "source_qualname": "public_sql"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The dedicated SQL workspace enables public network access."
  },
  "azure_vault_3_7_1_2_532ecd2": {
    "description_base_sha256": "892aea990a07b4159bb48fbf3834c74d97484980ed67e4b8502eb8def86babc0",
    "description_fields": {
      "description": "Parses the current issued X.509 certificate and checks RSA modulus size below 2048 bits."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "EC certificates are not applicable; a future issuance policy does not establish the current certificate\u2019s key size."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged Key Vault data-plane GET /certificates and GET /certificates/{name} current issued version, with X.509 certificate bytes or backing public key used to measure actual RSA modulus. Optional GET /certificates/{name}/policy?api-version=7.4 supplies future-issuance context only.",
          "Complete inventories: key_vault_certificate"
        ],
        "kind": "key_vault_certificate",
        "target": "scope"
      },
      "references": [
        {
          "title": "Key Vault certificate resource",
          "url": "https://learn.microsoft.com/rest/api/keyvault/certificates/get-certificate/get-certificate"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace undersized RSA certificates with suitable supported keys and roll them out safely."
      ],
      "summary": "Replace undersized RSA certificates with suitable supported keys and roll them out safely."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "issued_rsa_size"
        }
      },
      "delegates": {},
      "kind": "key_vault_certificate",
      "module": "peaso.checks._bulk_pending_compliance_new_sw20",
      "predicate_qualname": "issued_rsa_size",
      "predicate_source_sha256": "4f4975e56abf7b5c8347f2d8578b8a3a4c4f8ed5c7fd25bb25c057600144477b",
      "source_qualname": "signed.<locals>.decorate.<locals>.dispatch"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The current issued RSA certificate has a modulus smaller than 2048 bits."
  },
  "azure_vm_1_4_5_1_d40be43": {
    "description_base_sha256": "3f4b4eae7705cfebe4d276e219ddf4b5f5d924b7d3895e54ad75138499367105",
    "description_fields": {
      "description": "Joins VM network interfaces and VM scale-set templates to declared public-IP references."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Declared network configuration does not establish endpoint reachability or effective authorization. Template declarations do not establish the current state of every scale-set instance."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Paged ARM virtualMachines GET/LIST 2024-07-01 (networkProfile.networkInterfaces[].id); networkInterfaces GET 2023-09-01 (ipConfigurations[].properties.publicIPAddress.id); virtualMachineScaleSets GET/LIST 2024-07-01 (virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].properties.ipConfigurations[].properties.publicIPAddressConfiguration). VMSS instance NICs provide a separate drift signal.",
          "Complete inventories: vm, nic, vm_scale_set"
        ],
        "kind": "vm_and_vm_scale_set",
        "target": "scope"
      },
      "references": [
        {
          "title": "Azure Monitor diagnostics",
          "url": "https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-IP attachments or templates while preserving required connectivity."
      ],
      "summary": "Remove unnecessary public-IP attachments or templates while preserving required connectivity."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "vm_and_vm_scale_set",
      "module": "peaso.checks._bulk_pending_compliance_new_sw15",
      "predicate_qualname": "compute_public_ips",
      "predicate_source_sha256": "719b134b37b6734a320d4b747930d6b31ae56a3d0ff11f922f34b9e0810ec68a",
      "source_qualname": "compute_public_ips"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A VM interface or scale-set template declares public-IP configuration."
  },
  "azure_vm_8_2_1_1_712e1ad": {
    "description_base_sha256": "963fac05ebfcb6c043172b7843eb564e80f2a8ec37b534b3f0147d1276123488",
    "description_fields": {
      "description": "Checks running Linux VMs\u2019 full ARM bootstrap SSH publicKeys list and flags configured keys."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "This corrected historical source profile prefers no bootstrap keys; key presence is not a vulnerability or a guest-runtime observation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Complete paged Microsoft.Compute/virtualMachines GET and instanceView: properties.storageProfile.osDisk.osType, properties.osProfile.linuxConfiguration.ssh.publicKeys[] and PowerState status.",
          "Complete scoped vm inventory and explicit ssh.publicKeys array"
        ],
        "kind": "vm",
        "target": "resource"
      },
      "references": [
        {
          "title": "Azure VM SSH keys",
          "url": "https://learn.microsoft.com/azure/virtual-machines/linux/ssh-from-windows"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review the configured bootstrap public keys under this legacy profile; preserve a working administrative access method."
      ],
      "summary": "Review the configured bootstrap public keys under this legacy profile; preserve a working administrative access method."
    },
    "reviewed_binding": {
      "closure": {},
      "delegates": {},
      "kind": "vm",
      "module": "peaso.checks._bulk_pending_compliance_new_sw18",
      "predicate_qualname": "contradictory_ssh_key_rule",
      "predicate_source_sha256": "c51bec80698d8829d83eb6252822cca9184863ba4729b57b6b91d262f98ff2f2",
      "source_qualname": "contradictory_ssh_key_rule"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The running Linux VM declares a bootstrap SSH public key."
  }
}
''')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    if _digest(original) != row[kind + "_base_sha256"] or (not isinstance(original, dict) and not (kind == "remediation" and original is None)):
        raise ValueError("Reviewed Azure bulk clarity base changed: " + check_id + " (" + kind + ")")
    updated = deepcopy(original) if original is not None else {}
    updated.update(deepcopy(row[kind + "_fields"]))
    return updated


def description(check_id, original):
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    return _apply(check_id, original, "remediation")


REVIEWED_RISKS = {cid: (row["reviewed_source_severity"], row["reviewed_severity"]) for cid, row in ROWS.items()}


def severity_review(check_id, source_severity):
    review = REVIEWED_RISKS.get(check_id)
    if review is None:
        return None
    if review[0] != source_severity:
        raise ValueError("Reviewed Azure bulk source severity changed: " + check_id)
    return review[1]


# template() has a separate provenance-preserving return for this corrected
# historical source. Pin that public dictionary independently of the raw pack.
SSH_DYNAMIC_BASE_SHA256 = "cc9d283117d886060b2dfe6b0bc84f705d549e6470bd5dbb70de7c4648f2eca7"


def dynamic_remediation(check_id, original):
    if check_id != "azure_vm_8_2_1_1_712e1ad":
        return deepcopy(original)
    if not isinstance(original, dict) or _digest(original) != SSH_DYNAMIC_BASE_SHA256:
        raise ValueError("Reviewed Azure bulk dynamic remediation base changed: " + check_id)
    result = deepcopy(original)
    fields = ROWS[check_id]["remediation_fields"]
    for key in ("summary", "steps", "caveats"):
        result[key] = deepcopy(fields[key])
    return result

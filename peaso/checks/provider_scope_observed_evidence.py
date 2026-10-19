"""Check-bound scope observations and precise incomplete-certificate limitations.

Only recorded, typed applicability facts are interpreted. Unsupported or
unreadable historical shapes retain their existing uncertainty and raw details.
"""
import json

REVIEWED_SCOPES=json.loads(r'''
[
  {
    "check_id": "azure.claude.disk_unattached_cmk",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "disk_state": "Attached",
      "applies_to": "unattached"
    },
    "summary": "The disk is attached; this check evaluates unattached disks.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.disk_unattached_customer_key",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "disk_state": "Attached",
      "applies_to": "unattached"
    },
    "summary": "The disk is attached; this check evaluates unattached disks.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.disk_attached_cmk",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "disk_state": "Unattached",
      "applies_to": "attached"
    },
    "summary": "The disk is unattached; this check evaluates attached disks.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.disk_attached_customer_key",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "disk_state": "Unattached",
      "applies_to": "attached"
    },
    "summary": "The disk is unattached; this check evaluates attached disks.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.disk_attached_double_encryption",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "disk_state": "Unattached",
      "applies_to": "attached"
    },
    "summary": "The disk is unattached; this check evaluates attached disks.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_guest_configuration_extension_linux",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows",
      "applies_to": "Linux"
    },
    "summary": "The VM runs Windows; this check evaluates Linux VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_guest_configuration_extension_windows",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_antimalware_auto_upgrade",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_dependency_agent_linux",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows",
      "applies_to": "Linux"
    },
    "summary": "The VM runs Windows; this check evaluates Linux VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_dependency_agent_windows",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_linux_no_passwordless_accounts",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows",
      "applies_to": "Linux"
    },
    "summary": "The VM runs Windows; this check evaluates Linux VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_linux_remote_requires_password",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows",
      "applies_to": "Linux"
    },
    "summary": "The VM runs Windows; this check evaluates Linux VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_max_password_age",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_min_password_age",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_min_password_length",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_password_complexity",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_no_reversible_password_encryption",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_password_history",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_linux_security_baseline",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows",
      "applies_to": "Linux"
    },
    "summary": "The VM runs Windows; this check evaluates Linux VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_security_baseline",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_exploit_guard",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_secure_protocol_tls13",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_automatic_updates",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Linux",
      "applies_to": "Windows"
    },
    "summary": "The VM runs Linux; this check evaluates Windows VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vm_windows_secure_boot",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "image_offer": "sql2019-ubuntu"
    },
    "summary": "The image offer is sql2019-ubuntu; this Secure Boot check evaluates Windows image offers.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.vmss_linux_ssh_keys",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "os_type": "Windows"
    },
    "summary": "The scale set runs Windows; this check evaluates Linux SSH authentication.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.acr_geo_replication",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "sku": "Standard"
    },
    "summary": "The registry uses the Standard tier; this geo-replication check evaluates Premium registries.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure.claude.databricks_diagnostic_log_delivery",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "sku": "standard"
    },
    "summary": "The Databricks workspace uses the standard tier; this category check evaluates Premium workspaces.",
    "case": "not_applicable"
  },
  {
    "check_id": "gcp.claude.instance.suspended_without_disks",
    "provider": "gcp",
    "status": "NOT_APPLICABLE",
    "witness": {
      "status": "RUNNING"
    },
    "summary": "The VM is running; this disk-attachment check evaluates suspended or suspending VMs.",
    "case": "not_applicable"
  },
  {
    "check_id": "gcp.claude.backend_service.external_iap",
    "provider": "gcp",
    "status": "NOT_APPLICABLE",
    "witness": {
      "load_balancing_scheme": "INTERNAL_MANAGED"
    },
    "summary": "The backend uses internal managed load balancing; this IAP check evaluates external backends.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure_vault_3_7_1_2_532ecd2",
    "provider": "azure",
    "status": "NOT_APPLICABLE",
    "witness": {
      "evaluated_count": 0,
      "outcomes": []
    },
    "summary": "No certificate records were evaluated in the scoped inventory.",
    "case": "not_applicable"
  },
  {
    "check_id": "azure_vault_3_7_1_2_532ecd2",
    "provider": "azure",
    "status": "UNKNOWN",
    "witness": {
      "evaluated_count": 1,
      "outcomes": [
        {
          "status": "UNKNOWN",
          "reason": "missing fact: parent_id"
        }
      ]
    },
    "summary": "The certificate assessment is incomplete: its parent resource identifier is missing.",
    "case": "unknown"
  }
]
''')


def _same(actual,expected):
    if type(actual)is not type(expected):return False
    if isinstance(expected,dict):return all(k in actual and _same(actual[k],v)for k,v in expected.items())
    if isinstance(expected,list):return len(actual)==len(expected)and all(_same(a,b)for a,b in zip(actual,expected))
    return actual==expected


def provider_scope(finding):
    if not isinstance(finding,dict):return None
    e=finding.get('evidence')
    if not isinstance(e,dict):return None
    for row in REVIEWED_SCOPES:
        if (finding.get('provider')==row['provider']and finding.get('check_id')==row['check_id']
                and finding.get('status')==row['status']and _same(e,row['witness'])):
            return row['summary']
    return None

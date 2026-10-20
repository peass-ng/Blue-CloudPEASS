"""Check-specific Azure evidence copy, independent of evaluator semantics.

The exact-ID review map is shared with the UI. It describes why each reviewed
setting matters and what the available evidence cannot establish. No title,
category, or keyword heuristics select an explanation at runtime.
"""
from __future__ import annotations

import json
from pathlib import Path

ROWS = json.loads(Path(__file__).with_suffix('.json').read_text())
_BULK_FAILURE_SHAPES = json.loads(Path(__file__).with_name('azure_bulk_evidence_shapes.json').read_text())

# Labels describe the actual field rather than the desired outcome in the title.
_SCALAR_LABELS = {
    'azure.storage.no_shared_key': 'Storage Shared Key authorization',
    'azure.storage.default_oauth': 'Default Microsoft Entra authorization',
    'azure.storage.no_public_network': 'Storage public network access',
    'azure.vault.soft_delete': 'Key Vault soft delete',
    'azure.vault.purge_protection': 'Key Vault purge protection',
    'azure.vault.rbac': 'Key Vault Azure RBAC authorization',
    'azure.vault.no_public_network': 'Key Vault public network access',
    'azure.vault.default_deny': 'The Key Vault network default',
    'azure.aks.rbac': 'Kubernetes RBAC',
    'azure.aks.no_local_accounts': 'Local AKS accounts',
    'azure.aks.private_cluster': 'The private AKS API endpoint',
    'azure.aks.azure_rbac': 'Azure RBAC for Kubernetes authorization',
    'azure.sql.minimum_tls': 'The SQL minimum TLS version',
    'azure.sql.no_public_network': 'SQL public network access',
    'azure.sql.auditing': 'SQL auditing',
    'azure.sql.threat_detection': 'SQL threat detection',
    'azure.storage.default_deny': 'The storage network default',
    'azure.storage.cross_tenant_replication': 'Cross-tenant object replication',
    'azure.storage.infrastructure_encryption': 'Additional storage infrastructure encryption',
    'azure.vm.encryption_at_host': 'VM encryption at host',
    'azure.disk.entra_export_auth': 'The disk export authentication mode',
    'azure.network.load_balancer_standard': 'The load-balancer SKU',
    'azure.network.public_ip_standard': 'The public-IP SKU',
    'azure.network.nic_no_ip_forwarding': 'NIC IP forwarding',
    'azure.network.ddos_configured': 'Virtual-network DDoS protection',
    'azure.aks.defender_monitoring': 'AKS Defender monitoring',
    'azure.app.https_only': 'The App Service HTTPS requirement',
    'azure.app.http2': 'App Service HTTP/2',
    'azure.app.request_logging': 'App Service HTTP request logging',
    'azure.app.remote_debugging_off': 'App Service remote debugging',
    'azure.port.databricks_workspace_no_public_ip_enabled': 'Databricks no-public-IP mode',
    'azure.port.databricks_workspace_public_network_access_disabled': 'Databricks public network access',
}


def reviewed_explanation(check_id: str, observation: str, status: str = '') -> str | None:
    """Explain an already verified observation once, retaining its actual values."""
    row = ROWS.get(check_id)
    if row is None or not isinstance(observation, str) or not observation.strip():
        return None
    observation = observation.strip()
    if row['purpose'] in observation:
        return observation
    suffix = row['purpose'] + ' ' + row['limit']
    return observation + ('' if observation.endswith(('.', '!', '?')) else '.') + ' ' + suffix


def _scalar_observation(check_id, evidence):
    from .facts import FIELD_SPECS
    spec = FIELD_SPECS.get(check_id)
    label = _SCALAR_LABELS.get(check_id)
    if not spec or not label or evidence.get('field') != spec['path']:
        return None
    value = evidence.get('configured')
    if type(value) is not spec['expected'] or value not in (spec['good'], spec['bad']):
        return None
    if isinstance(value, bool):
        enabled = not value if check_id == 'azure.aks.no_local_accounts' else value
        return f'{label} is {"enabled" if enabled else "disabled"}.'
    if check_id == 'azure.disk.entra_export_auth':
        return ('Disk exports require Microsoft Entra authentication.' if value == 'AzureActiveDirectory'
                else 'Disk exports do not require Microsoft Entra authentication.')
    return f'{label} is {value}.'


def _observation(finding):
    """Reuse exact native evidence interpreters before adding explanatory copy."""
    from .azure_native_evidence_observations import evidence_summary as native
    observed = native(finding)
    if observed:
        return observed
    from .provider_scope_observed_evidence import provider_scope
    from .azure_bulk_observed_evidence import evidence_summary as bulk_pass
    from .azure_bulk_finding_summary import evidence_summary as bulk_fail
    from .azure_native_evidence_observations import _matches
    # The legacy bulk failure helper has an unguarded static-text fallback.
    # Its text is safe only after the exact reviewed native witness matches.
    bulk_failure = None
    if finding['status'] == 'FAIL' and any(_matches(finding['evidence'], shape)
            for shape in _BULK_FAILURE_SHAPES.get(finding['check_id'], ())):
        bulk_failure = bulk_fail(finding)
        if finding['check_id'] == 'azure_vault_3_7_1_2_532ecd2':
            outcomes = finding['evidence'].get('outcomes', [])
            if not any(isinstance(item, dict) and item.get('status') == 'FAIL'
                       and type(item.get('measured_rsa_modulus_bits')) is int
                       and 0 < item['measured_rsa_modulus_bits'] < 2048 for item in outcomes):
                bulk_failure = None
    observation = provider_scope(finding) or bulk_pass(finding) or bulk_failure
    if observation:
        return observation
    check_id = finding['check_id']
    evidence = finding['evidence']
    scalar = _scalar_observation(check_id, evidence)
    if scalar:
        return scalar
    if check_id == 'azure.storage.https_only' and type(evidence.get('supports_https_traffic_only')) is bool:
        return 'The storage account '+('requires' if evidence['supports_https_traffic_only'] else 'does not require')+' secure HTTPS transfer.'
    if check_id == 'azure.storage.no_blob_public_access' and type(evidence.get('allow_blob_public_access')) is bool:
        return 'The storage account '+('permits' if evidence['allow_blob_public_access'] else 'disables')+' anonymous Blob access as an account capability.'
    if check_id == 'azure.storage.minimum_tls' and evidence.get('minimum_tls_version') in {'TLS1_0', 'TLS1_1', 'TLS1_2', 'TLS1_3'}:
        return 'The storage minimum TLS version is '+evidence['minimum_tls_version'].replace('TLS', '').replace('_', '.')+'.'
    if check_id == 'azure.iam.review_owner_assignment':
        role = evidence.get('role_definition_id')
        if isinstance(role, str) and role:
            return ('The declared assignment grants the Owner role.' if role.rsplit('/',1)[-1].lower() == '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
                    else 'The declared assignment grants a role other than Owner.')
    return None


def evidence_summary(finding):
    """Return concise observations only for evidence shapes understood here.

    The UI retains its separately typed per-check interpreters for other native
    evidence shapes and uses the same exact-ID purpose and limit records.
    """
    if not isinstance(finding, dict) or finding.get('provider') != 'azure':
        return None
    check_id = finding.get('check_id')
    if not isinstance(check_id, str) or check_id not in ROWS or not isinstance(finding.get('evidence'), dict):
        return None
    if finding.get('status') not in {'PASS', 'FAIL'}:
        return None
    observation = _observation(finding)
    return reviewed_explanation(check_id, observation, finding['status']) if observation else None

"""Reviewed concise copy for twelve exact GCP scalar predicates.

Newly reviewed entries contain text only; no pending command is promoted.
"""
from copy import deepcopy
import hashlib
import json

VERSION = "gcp-scalar-clarity-20261019"
ROWS = {'gcp.compute.integrity_monitoring': {'description_base_sha256': '81860628e058fafc72af75e1a505b9eb51e66a5736cacf8cdca1f44d1fee1deb',
                                      'description_fields': {'description': 'Checks whether the VM declares '
                                                                            'Shielded VM integrity '
                                                                            'monitoring enabled.'},
                                      'remediation_base_sha256': '3959197c3351a6e0798bfa7d19d2b71169cc9ac52a25d4088701bdfe86363422',
                                      'remediation_fields': {'steps': ['Enable integrity monitoring in the '
                                                                       'VM’s Shielded VM settings.'],
                                                             'summary': 'Enable integrity monitoring in the '
                                                                        'VM’s Shielded VM settings.'}},
 'gcp.compute.secure_boot': {'description_base_sha256': 'e938474139e5d4922d86557485c87a96aaa82578344ea80d7d96f39e2955d952',
                             'description_fields': {'description': 'Checks whether the VM declares Secure '
                                                                   'Boot enabled.'},
                             'remediation_base_sha256': 'c067578648ccd0d95d3ed084f7b497e290b2ca915048f3cd15fbbe7e80e6df6a',
                             'remediation_fields': {'steps': ['Enable Secure Boot after checking that the VM '
                                                              'kernel and drivers are signed and supported.'],
                                                    'summary': 'Enable Secure Boot after checking that the '
                                                               'VM kernel and drivers are signed and '
                                                               'supported.'}},
 'gcp.compute.shielded_vtpm': {'description_base_sha256': '3afa475257ea2dcc376acf95d93de24cfd3c5294dded3359813e12f887ccd367',
                               'description_fields': {'description': 'Checks whether the VM declares its '
                                                                     'virtual TPM enabled.'},
                               'remediation_base_sha256': 'f393112f4aab65a3a0fa94a44a31a83a6b1004875adab1245fe57f970c70357a',
                               'remediation_fields': {'steps': ['Enable vTPM in the VM’s Shielded VM '
                                                                'settings.'],
                                                      'summary': 'Enable vTPM in the VM’s Shielded VM '
                                                                 'settings.'}},
 'gcp.gke.secrets_encryption': {'description_base_sha256': '7ec6d4813b0de5767e2966a378e6caad6f78a8001393673556e491b0fee5d7ac',
                                'description_fields': {'description': 'Compares the GKE cluster’s '
                                                                      'application-layer encryption state '
                                                                      'with ENCRYPTED; this is separate from '
                                                                      'Google’s default storage encryption.'},
                                'remediation_base_sha256': 'e15d94a5879f1895c8c42dfe44a3e2deec939cdd72026269072072ddf2323208',
                                'remediation_fields': {'caveats': ['Only the recorded setting is evaluated; '
                                                                   'supported configuration and runtime '
                                                                   'behavior must be checked separately.'],
                                                       'cli': [],
                                                       'references': [{'title': 'GKE application-layer '
                                                                                'Secrets encryption',
                                                                       'url': 'https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets'}],
                                                       'review_status': 'approved',
                                                       'steps': ['Enable application-layer Secrets '
                                                                 'encryption with a Cloud KMS key and grant '
                                                                 'the GKE service agent access to that key.'],
                                                       'summary': 'Enable application-layer Secrets '
                                                                  'encryption with a Cloud KMS key and grant '
                                                                  'the GKE service agent access to that '
                                                                  'key.'}},
 'gcp.network.custom_subnets': {'description_base_sha256': '164fa92132607e032134e4888e8bc120c847b1622bb00683338274a76a9b73d6',
                                'description_fields': {'description': 'Checks whether the VPC uses custom '
                                                                      'subnet mode instead of automatically '
                                                                      'creating regional subnets.'},
                                'remediation_base_sha256': 'dab407e3a3d41c8764ab0c65d80f05d8b8ef77fd6a1bd724e0a5b6c7eacbdc6a',
                                'remediation_fields': {'steps': ['Review the existing subnets and routes, '
                                                                 'then convert this VPC to custom mode; '
                                                                 'conversion cannot be reversed.'],
                                                       'summary': 'Review the existing subnets and routes, '
                                                                  'then convert this VPC to custom mode; '
                                                                  'conversion cannot be reversed.'}},
 'gcp.reviewed.compute.automatic_restart': {'description_base_sha256': '48ee64f4f16bb4026ae771f0c70a90e4dd9a564969fe079419a7ef63befc9c5f',
                                            'description_fields': {'description': 'Checks whether automatic '
                                                                                  'restart after a host '
                                                                                  'failure is enabled; it '
                                                                                  'does not test '
                                                                                  'availability.'},
                                            'remediation_base_sha256': 'e59484abf16059b58f11893194e13080455bf9888990e1abab8cc02b3dc44cb6',
                                            'remediation_fields': {'steps': ['Enable automatic restart if '
                                                                             'this VM should restart after a '
                                                                             'host failure.'],
                                                                   'summary': 'Enable automatic restart if '
                                                                              'this VM should restart after '
                                                                              'a host failure.'}},
 'gcp.reviewed.compute.confidential_computing': {'description_base_sha256': '13e1ec1aa1934595567681772dc3bcdd2bbcce379c47ad505c6832c06b7040e1',
                                                 'description_fields': {'description': 'Checks whether the '
                                                                                       'VM declares '
                                                                                       'Confidential '
                                                                                       'Computing enabled; '
                                                                                       'it does not attest '
                                                                                       'the running VM.'},
                                                 'remediation_base_sha256': '4c58d71ce7ebe3dd7ac2bc76699f26d052c0c3a08099972d1a8ba1c12ca193d4',
                                                 'remediation_fields': {'caveats': ['Only the recorded '
                                                                                    'setting is evaluated; '
                                                                                    'supported configuration '
                                                                                    'and runtime behavior '
                                                                                    'must be checked '
                                                                                    'separately.'],
                                                                        'cli': [],
                                                                        'references': [{'title': 'Create a '
                                                                                                 'Confidential '
                                                                                                 'VM',
                                                                                        'url': 'https://cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance'}],
                                                                        'review_status': 'approved',
                                                                        'steps': ['Use a supported '
                                                                                  'Confidential VM '
                                                                                  'configuration if this '
                                                                                  'workload requires '
                                                                                  'confidential computing.'],
                                                                        'summary': 'Use a supported '
                                                                                   'Confidential VM '
                                                                                   'configuration if this '
                                                                                   'workload requires '
                                                                                   'confidential '
                                                                                   'computing.'}},
 'gcp.reviewed.compute.deletion_protection': {'description_base_sha256': 'b777f5c9929e688097f800510771451cef9d5a4c7b71eb04dc213598dbb9b8e8',
                                              'description_fields': {'description': 'Checks whether the VM '
                                                                                    'declares deletion '
                                                                                    'protection enabled.'},
                                              'remediation_base_sha256': '10a6d33fef418a217d0f42b4a536746c2cb854d4e8dc9b60943f2c7f58208df5',
                                              'remediation_fields': {'steps': ['Enable deletion protection '
                                                                               'for VMs that should be '
                                                                               'protected from accidental '
                                                                               'deletion.'],
                                                                     'summary': 'Enable deletion protection '
                                                                                'for VMs that should be '
                                                                                'protected from accidental '
                                                                                'deletion.'}},
 'gcp.reviewed.compute.maintenance_migrate': {'description_base_sha256': 'fafe69dd5400256780a8c4a7545ff14a912dcb72972b317f8c2cced1caffe38e',
                                              'description_fields': {'description': 'Checks whether the VM’s '
                                                                                    'host maintenance policy '
                                                                                    'is MIGRATE; hardware '
                                                                                    'and workload support '
                                                                                    'are not evaluated.'},
                                              'remediation_base_sha256': '510321dfd31eb7077444e36203d4a6cba32806b1a715fa4a1b437fe5e5a1439a',
                                              'remediation_fields': {'caveats': ['Only the recorded setting '
                                                                                 'is evaluated; supported '
                                                                                 'configuration and runtime '
                                                                                 'behavior must be checked '
                                                                                 'separately.'],
                                                                     'cli': [],
                                                                     'references': [{'title': 'VM host '
                                                                                              'maintenance '
                                                                                              'policy',
                                                                                     'url': 'https://cloud.google.com/compute/docs/instances/setting-vm-host-options'}],
                                                                     'review_status': 'approved',
                                                                     'steps': ['Use MIGRATE for VMs that '
                                                                               'support live migration; '
                                                                               'retain TERMINATE where the '
                                                                               'VM type requires it.'],
                                                                     'summary': 'Use MIGRATE for VMs that '
                                                                                'support live migration; '
                                                                                'retain TERMINATE where the '
                                                                                'VM type requires it.'}},
 'gcp.reviewed.loadbalancer.backend_logging': {'description_base_sha256': '076c3ed45038a1e317cc2760f740980042d59db74e1dd69d61e157f49af3942f',
                                               'description_fields': {'description': 'Checks whether logging '
                                                                                     'is enabled on the load '
                                                                                     'balancer backend '
                                                                                     'service; it does not '
                                                                                     'verify log delivery or '
                                                                                     'completeness.'},
                                               'remediation_base_sha256': '3f58f7ad18cf566d9aad35fa2ef8e7445562c2abbab5432f582439ca5dc9cbf4',
                                               'remediation_fields': {'caveats': ['Only the recorded setting '
                                                                                  'is evaluated; supported '
                                                                                  'configuration and runtime '
                                                                                  'behavior must be checked '
                                                                                  'separately.'],
                                                                      'cli': [],
                                                                      'references': [{'title': 'Load '
                                                                                               'balancer '
                                                                                               'logging',
                                                                                      'url': 'https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring'}],
                                                                      'review_status': 'approved',
                                                                      'steps': ['Enable logging on this '
                                                                                'backend service and choose '
                                                                                'a sample rate suited to the '
                                                                                'traffic you need to '
                                                                                'record.'],
                                                                      'summary': 'Enable logging on this '
                                                                                 'backend service and choose '
                                                                                 'a sample rate suited to '
                                                                                 'the traffic you need to '
                                                                                 'record.'}},
 'gcp.sql.backups': {'description_base_sha256': '8434c7d01c64b7251f693312f7df2937ceeb2b5a3044c1f0eb56ae17b66f8408',
                     'description_fields': {'description': 'Checks whether automated backups are enabled for '
                                                           'the Cloud SQL instance; it does not test '
                                                           'restoration or point-in-time recovery.'},
                     'remediation_base_sha256': 'c4b4c03406eca6a603f2df34d9a65fa331fda23ec4090941f4b9e0bdc84e5a23',
                     'remediation_fields': {'steps': ['Enable automated backups for this Cloud SQL '
                                                      'instance.'],
                                            'summary': 'Enable automated backups for this Cloud SQL '
                                                       'instance.'}},
 'gcp.sql.no_public_ip': {'description_base_sha256': 'b9a500fe5d342c690dae6b2d0a0efce4bbdbd9e94bc087830d26c54cf6b7e018',
                          'description_fields': {'description': 'Checks whether public IPv4 is disabled on '
                                                                'the Cloud SQL instance; it does not test '
                                                                'database access.'},
                          'remediation_base_sha256': 'dd4fb1ee6a49748c8337551b020a63a331431f9587f6b1de0c3cbd15e3257d21',
                          'remediation_fields': {'steps': ['Move intended clients to private connectivity '
                                                           'before disabling public IPv4.'],
                                                 'summary': 'Move intended clients to private connectivity '
                                                            'before disabling public IPv4.'}}}
def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    digest = hashlib.sha256(json.dumps(original, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode()).hexdigest()
    if not isinstance(original, dict) or digest != row[kind + "_base_sha256"]:
        raise ValueError("GCP scalar clarity base changed: " + check_id)
    current = deepcopy(original)
    current.update(deepcopy(row[kind + "_fields"]))
    return current


def description(check_id, original):
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    return _apply(check_id, original, "remediation")


REVIEWED_RISKS = {
    "gcp.compute.shielded_vtpm": ("medium", "medium"),
    "gcp.compute.integrity_monitoring": ("medium", "medium"),
    "gcp.compute.secure_boot": ("medium", "medium"),
    "gcp.sql.backups": ("medium", "medium"),
    "gcp.sql.no_public_ip": ("medium", "medium"),
    "gcp.gke.secrets_encryption": ("medium", "low"),
    "gcp.network.custom_subnets": ("medium", "low"),
    "gcp.reviewed.compute.deletion_protection": ("medium", "low"),
    "gcp.reviewed.compute.automatic_restart": ("medium", "low"),
    "gcp.reviewed.compute.maintenance_migrate": ("medium", "info"),
    "gcp.reviewed.compute.confidential_computing": ("medium", "low"),
    "gcp.reviewed.loadbalancer.backend_logging": ("medium", "medium"),
}

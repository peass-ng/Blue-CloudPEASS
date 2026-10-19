"""Assertions for signed source contracts plus the separately reviewed UI layer."""
from copy import deepcopy
from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for,description_for
from peaso.remediation import template


def assert_approved_presentation(check_id, original):
    """Keep source bindings/commands while permitting short reviewed prose."""
    saved=deepcopy(original)
    current=template(check_id)
    assert original==saved
    assert current and current['review_status']=='approved'
    from peaso.checks.native_only import exclusions
    if check_id in exclusions() and current==original:
        # Archived operator-review controls are retained byte-for-byte for old
        # reports, and are outside the active automated presentation redesign.
        assert current==original
        return current
    assert current['summary'] and 1<=len(current['steps'])<=2
    assert len(current['summary'].split())<=40
    assert all(0<len(step.split())<=40 for step in current['steps'])
    assert current['references'] and current['caveats']
    assert {key:value for key,value in current.items() if key not in {'summary','steps','caveats'}}=={
        key:value for key,value in original.items() if key not in {'summary','steps','caveats'}}
    assert_description_preserves_contract(check_id)
    return current


def assert_description_preserves_contract(check_id):
    original=_base_description_for(check_id)
    current=description_for(check_id)
    changed_fields={'description'}
    # Three separately reviewed interval corrections deliberately replace the
    # old exact-endpoint criterion; no other criterion differences are allowed.
    lightsail_ports={
        'aws.cb.lightsail.ssh_rdp_http_world_closed': ('22, 80 or 3389', '0.0.0.0/0 or ::/0'),
        'aws.cb.lightsail.ssh_restricted': ('22', '0.0.0.0/0'),
        'aws.cb.lightsail.rdp_restricted': ('3389', '0.0.0.0/0'),
    }
    if check_id in lightsail_ports:
        ports,sources=lightsail_ports[check_id]
        assert current['pass_when']==f'No valid TCP interval containing {ports} permits {sources}.'
        assert current['fail_when']==f'A valid TCP interval containing {ports} permits {sources}.'
        from peaso.checks.aws_compute_storage_clarity_reviewed import ROWS
        row=ROWS[check_id]
        assert row['reviewed_binding']['helper_contract']['source_sha256']=='b4199ed341491f07ba38a732d25096ab6ce8d3dc848a55a25fda49a4efbbfeff'
        assert row['criterion_correction']=='Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required.'
        changed_fields.update({'pass_when','fail_when'})
    azure_corrections = {
        'azure.claude.network_watcher_flow_logs_retention_90': {
            'pass_when': 'PASS when flow logs exist and each is enabled with retention zero (unlimited) or at least 90 days.',
            'fail_when': 'FAIL when no flow logs exist, a log is disabled, or a positive retention is below 90 days. Negative, missing or malformed durations are UNKNOWN.',
        },
        'azure.claude.sql_database_long_term_retention': {
            'pass_when': 'PASS when all three reported durations are recognized ISO durations and at least one is positive.',
            'fail_when': 'FAIL when all three recognized durations are zero; malformed or missing durations are UNKNOWN.',
            'not_applicable_when': 'NOT_APPLICABLE when the parent database is master.',
        },
        'azure.claude.storage_key_expiration_policy_max_90': {
            'pass_when': 'PASS when the reported integer expiration period is 1–90 days.',
            'fail_when': 'FAIL when the policy is absent, zero, or greater than 90 days; missing or malformed required evidence and negative days are UNKNOWN.',
        },
    }
    if check_id in azure_corrections:
        expected = azure_corrections[check_id]
        assert {key: current[key] for key in expected} == expected
        from peaso.checks.azure_finding_clarity_reviewed import ROWS
        assert {key: value for key, value in ROWS[check_id]['description_fields'].items()
                if key != 'description'} == expected
        changed_fields.update(expected)
    assert {key:value for key,value in current.items() if key not in changed_fields}=={
        key:value for key,value in original.items() if key not in changed_fields}
    assert 0<len(current['description'].split())<=45
    return current


def assert_reviewed_text_only_admission(check_id, *, require_binding=True):
    check=next(c for c in CHECKS if c.id==check_id)
    current=template(check_id)
    assert current and current['review_status']=='approved'
    assert current['cli']==[] and not current.get('iac')
    assert 1<=len(current['steps'])<=2 and len(current['summary'].split())<=40
    assert current['references'] and current['caveats']
    assert all(ref['url'].startswith('https://') for ref in current['references'])
    if require_binding:
        assert current['field_binding']['kind']==check.kind
        assert current['field_binding']['target']==check.target
    assert_description_preserves_contract(check_id)
    return current

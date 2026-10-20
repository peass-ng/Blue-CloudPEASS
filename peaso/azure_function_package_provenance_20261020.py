"""Preserve actual package assertion provenance on existing one-secret DTOs."""
from copy import deepcopy

CHECK = 'azure.review.function.selected_package_source_secret_indicators'
FIELDS = ('context_provenance', 'snapshot_trust', 'cloud_authenticity', 'credential_validation',
          'coverage', 'runtime_bytes', 'continuous_immutability', 'complete')


def retain_package_source_assertions(before, after):
    """Copy only supplied source evidence for this fingerprint and occurrence.

    Never create detector receipts, merge engine pairs, change a FAIL decision,
    or label metadata from the same JSON as an independent native context.
    """
    for final in after:
        if (final.get('provider') != 'azure' or final.get('status') != 'FAIL'
                or CHECK not in final.get('linked_check_ids', [])):
            continue
        fingerprint = final.get('secret_fingerprint')
        leaks = final.get('evidence', {}).get('secret_leaks', [])
        if len(leaks) != 1 or leaks[0].get('fingerprint') != fingerprint:
            continue
        rows = []
        for source in before:
            evidence = source.get('evidence', {})
            resource = source.get('native_resource_id') or source.get('resource_id')
            if (source.get('provider') != 'azure' or source.get('check_id') != CHECK
                    or source.get('status') != 'FAIL'
                    or evidence.get('context_provenance') not in ('native_owner_retained_context', 'supplied_snapshot_assertions')
                    or evidence.get('cloud_authenticity') != 'not_established'
                    or not any(leak.get('fingerprint') == fingerprint for leak in evidence.get('secret_leaks', []))
                    or not any(loc.get('scope') == source.get('scope') and loc.get('resource_id') == resource
                        for loc in leaks[0].get('locations', []))):
                continue
            parts = []
            for part in evidence.get('parts', []):
                matched = [deepcopy(leak) for leak in part.get('leaks', [])
                           if leak.get('fingerprint') == fingerprint]
                if matched:
                    retained = deepcopy(part)
                    retained['leaks'] = matched
                    parts.append(retained)
            # These are the original validated parts, never synthesized from a
            # final leak's detectors or a different archive member's engines.
            rows.append(dict({key: deepcopy(evidence[key]) for key in FIELDS if key in evidence},
                             check_id=CHECK, scope=source['scope'], resource_id=resource, parts=parts))
        if rows:
            final['evidence']['package_source_assertions'] = rows
    return after

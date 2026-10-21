"""Provider-neutral inactivity decisions; adapters must establish evidence authority.

This module never fetches credentials or treats inventory absence as activity
coverage. Provider adapters supply an explicit observation window only after
validating the native response's principal, scope and collection provenance.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re


class UsageEvidenceError(ValueError):
    """Activity cannot support an inactivity conclusion."""


def instant(value):
    if not isinstance(value, str) or not value.strip():
        raise UsageEvidenceError('timestamp is missing')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise UsageEvidenceError('timestamp is malformed') from exc
    if parsed.tzinfo is None:
        raise UsageEvidenceError('timestamp has no timezone')
    return parsed.astimezone(timezone.utc)


def inactivity(*, created_at, observed_at, last_successful_use=None,
               observation_start=None, complete_usage=False, threshold_days=90,
               enabled=True):
    """Return native-style status/evidence from a verified identity observation.

    complete_usage means that the source establishes the most recent successful
    use (or its absence) throughout the supplied interval. A complete object LIST
    or a single log page must never be used as that assertion. Recent positive
    use is sufficient to reject inactivity even if the rest of history is partial.
    """
    base = {'threshold_days': threshold_days}
    try:
        if type(threshold_days) is not int or not 1 <= threshold_days <= 3660:
            raise UsageEvidenceError('invalid inactivity threshold')
        if type(enabled) is not bool or type(complete_usage) is not bool:
            raise UsageEvidenceError('invalid activity state')
        now = instant(observed_at)
        created = instant(created_at)
        if created > now:
            raise UsageEvidenceError('creation time is after the observation')
        last = instant(last_successful_use) if last_successful_use is not None else None
        if last is not None and (last < created or last > now):
            raise UsageEvidenceError('successful use is outside the object lifetime')
        start = instant(observation_start) if observation_start is not None else None
        if start is not None and start > now:
            raise UsageEvidenceError('activity observation starts after it ends')
        if last is not None and start is not None and last < start:
            # Some APIs retain a historical last-use field beyond the current
            # log window. Retain it as a date but do not claim complete coverage.
            base['historical_last_use_precedes_window'] = True
        base.update(created_at=created.isoformat(), observed_at=now.isoformat(),
                    last_successful_use=last.isoformat() if last else None,
                    observation_start=start.isoformat() if start else None,
                    usage_coverage_complete=complete_usage)
        if not enabled:
            return 'NOT_APPLICABLE', {**base, 'reason': 'identity or credential is disabled'}
        cutoff = now - timedelta(days=threshold_days)
        if last is not None and last >= cutoff:
            return 'PASS', {**base, 'days_since_last_successful_use': (now-last).days,
                            'reason': 'successful use is within the inactivity threshold'}
        if created >= cutoff:
            return 'PASS', {**base, 'object_age_days': (now-created).days,
                            'reason': 'object is newer than the inactivity threshold'}
        if not complete_usage or start is None or start > cutoff:
            raise UsageEvidenceError('complete successful-use evidence does not cover the inactivity threshold')
        # At the exact threshold boundary, the interval is not MORE than N days.
        if start == cutoff and last is None:
            return 'UNKNOWN', {**base, 'reason': 'no successful use observed for exactly the threshold; older inactivity is unproven'}
        if last is not None:
            base['days_since_last_successful_use'] = (now-last).days
        else:
            base['no_successful_use_observed_days'] = (now-max(start, created)).days
        return 'FAIL', {**base, 'reason': 'no successful use within a complete inactivity observation interval'}
    except (UsageEvidenceError, OverflowError) as exc:
        return 'UNKNOWN', {**base, 'reason': str(exc)}


def legacy_token_usage(item, *, observed_at, service_account=None, threshold_days=90):
    """Read metadata-only Kubernetes legacy-token evidence; never token data.

    Kubernetes' last-used label is a UTC DATE, not an exact authentication time.
    Use the end of that day to avoid labeling a token stale up to a day early.
    No label means UNKNOWN: manual tokens and newer token mechanisms are not
    comprehensively tracked by the legacy-token controller.
    """
    try:
        if not isinstance(item, dict) or item.get('collection_status', 'collected') not in ('collected', 'empty'):
            raise UsageEvidenceError('Secret metadata is unavailable')
        if item.get('type') != 'kubernetes.io/service-account-token':
            if isinstance(item.get('type'), str) and item['type']:
                return 'NOT_APPLICABLE', {'reason': 'Secret is not a legacy ServiceAccount token'}
            raise UsageEvidenceError('Secret type metadata is unavailable')
        metadata = item.get('metadata')
        if not isinstance(metadata, dict):
            raise UsageEvidenceError('Secret metadata is unavailable')
        for field in ('name', 'namespace', 'uid'):
            if not isinstance(metadata.get(field), str) or not metadata[field]:
                raise UsageEvidenceError('Secret identity metadata is incomplete')
        annotations = metadata.get('annotations', {})
        if not isinstance(annotations, dict) or not isinstance(annotations.get('kubernetes.io/service-account.name'), str) or not annotations['kubernetes.io/service-account.name']:
            raise UsageEvidenceError('ServiceAccount token association is unavailable')
        # Only auto-generated legacy tokens participate in the documented
        # tracking/cleanup mechanism. A stale label on a manual token cannot
        # stand in for this bidirectional ServiceAccount association.
        if not isinstance(service_account, dict):
            raise UsageEvidenceError('ServiceAccount metadata is unavailable')
        sa_meta = service_account.get('metadata')
        if (not isinstance(sa_meta, dict) or sa_meta.get('namespace') != metadata['namespace']
                or sa_meta.get('name') != annotations['kubernetes.io/service-account.name']
                or not isinstance(sa_meta.get('uid'), str) or not sa_meta['uid']
                or annotations.get('kubernetes.io/service-account.uid') != sa_meta['uid']):
            raise UsageEvidenceError('Secret and ServiceAccount identity association is unresolved')
        references = service_account.get('secrets')
        if (not isinstance(references, list) or any(not isinstance(ref, dict) for ref in references)
                or not any(ref.get('name') == metadata['name'] for ref in references)):
            raise UsageEvidenceError('automatic legacy token reference is unavailable')
        labels = metadata.get('labels', {})
        if not isinstance(labels, dict):
            raise UsageEvidenceError('Secret labels are malformed')
        used = labels.get('kubernetes.io/legacy-token-last-used')
        if not isinstance(used, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', used):
            raise UsageEvidenceError('legacy token last-used date is unavailable')
        start_day = instant(used + 'T00:00:00Z')
        now = instant(observed_at)
        if start_day > now:
            raise UsageEvidenceError('legacy token last-used date is in the future')
        end_day = min(start_day + timedelta(days=1) - timedelta(microseconds=1), now)
        # A valid native last-used label is the source's latest recorded date,
        # unlike a bounded audit-log query. It proves the recorded last use but
        # does not apply to tokens without that label.
        status, evidence = inactivity(created_at=metadata.get('creationTimestamp'),
            observed_at=observed_at, last_successful_use=end_day.isoformat(),
            observation_start=metadata.get('creationTimestamp'), complete_usage=True,
            threshold_days=threshold_days)
        evidence.update(resource_name=metadata['namespace']+'/'+metadata['name'],
                        resource_uid=metadata['uid'], service_account=annotations['kubernetes.io/service-account.name'],
                        last_used_date=used, timestamp_precision='UTC calendar day')
        return status, evidence
    except (UsageEvidenceError, OverflowError) as exc:
        return 'UNKNOWN', {'reason': str(exc)}

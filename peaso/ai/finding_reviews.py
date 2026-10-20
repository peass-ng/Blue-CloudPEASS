"""Apply validated AI rechecks to finding views without changing native evidence."""
from .contracts import Review

_UNAVAILABLE = 'AI review was unavailable, timed out, or returned an invalid result; the original failure could not be verified.'


def review_index(result):
    """Bind reviews by category and exact finding ID; ignore invalid/duplicate rows."""
    index, seen = {}, set()
    if not isinstance(result, dict) or not isinstance(result.get('reviews'), dict):
        return index
    for category in ('hardening', 'exposure'):
        rows = result['reviews'].get(category, [])
        if not isinstance(rows, list):
            continue
        for raw in rows:
            try:
                row = Review.model_validate(raw).model_dump()
            except ValueError:
                continue
            key = (category, row['finding_id'])
            if key in seen:
                index.pop(key, None)
                continue
            seen.add(key)
            if row['verdict'] == 'UNKNOWN' and row['reason'] == _UNAVAILABLE:
                continue
            index[key] = row
    return index


def apply_review(finding, reviews, meta=None):
    category = finding.get('category', ((meta or {}).get(finding.get('check_id')) or {}).get('category'))
    review = reviews.get((category, finding.get('id')))
    # Review agents are assigned native FAILs only. Never override another
    # native result or let a review for another category affect this finding.
    if not review or finding.get('scanner_status', finding.get('status')) != 'FAIL':
        return finding
    result = dict(finding, scanner_status='FAIL', status=review['verdict'],
                  ai_review={'verdict': review['verdict'], 'reason': review['reason']})
    if review['reason']:
        result['evidence_summary'] = review['reason']
    return result


def apply_report_reviews(report):
    """Publish effective findings/counts while retaining native scanner results."""
    from collections import Counter
    reviews = review_index(report.get('ai'))
    if not reviews:
        return report
    findings = [apply_review(row, reviews, report.get('check_meta')) for row in report.get('findings', [])]
    stats = dict(report.get('stats', {}))
    if 'scanner_by_status' not in stats:
        stats['scanner_by_status'] = stats.get('by_status', {})
    counts = Counter(row['status'] for row in findings)
    for row in report.get('finding_aggregates', []):
        counts[row['status']] += row['count']
    stats['by_status'] = dict(counts)
    stats['by_severity'] = dict(Counter(row.get('severity', (report.get('check_meta', {}).get(row.get('check_id')) or {}).get('severity', 'info'))
                                      for row in findings if row.get('status') == 'FAIL'))
    return dict(report, findings=findings, stats=stats)

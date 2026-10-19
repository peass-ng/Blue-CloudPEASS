"""Source-bound observed AWS compute/storage configuration, without runtime claims."""
from .aws_compute_storage_clarity_reviewed import ROWS


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='aws' or finding.get('status')!='FAIL':
        return None
    row=ROWS.get(finding.get('check_id'))
    if row is None or not isinstance(finding.get('evidence'),dict):
        return None
    return row['observed_fail']

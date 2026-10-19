#!/usr/bin/env python3
"""Export reviewed prose for the UI without shipping evaluator/review metadata."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / 'frontend/src/reviewedEvidenceCopy.json'
PUBLIC_FIELDS = ('purpose', 'limit', 'missing_observation', 'manual_observation', 'not_applicable_observation')


def current_copy():
    return {
        provider: {
            cid: {key: row[key] for key in PUBLIC_FIELDS if key in row
                  and not (key == 'missing_observation' and row[key].startswith('The saved result omits the deciding evidence for'))}
            for cid, row in json.loads((ROOT / 'peaso/checks' / f'{provider}_evidence_explanations.json').read_text()).items()
        }
        for provider in ('aws', 'gcp', 'azure', 'k8s')
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    encoded = json.dumps(current_copy(), ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'
    if args.check:
        if not DESTINATION.is_file() or DESTINATION.read_text() != encoded:
            raise SystemExit('Reviewed browser copy is stale; run scripts/sync_evidence_explanation_copy.py')
    else:
        DESTINATION.write_text(encoded)

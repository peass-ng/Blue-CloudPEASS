"""Captured offline native cases for the three reviewed provider controls."""
import hashlib
import json
from pathlib import Path

SHA256 = 'c1f459d1b83a5a2895f49c06067e5f2357d3a6634bd4102d2c0b1f757ff3c1f9'
IDS = frozenset({
    'azure.review.acr.selected_image_high_critical_vulnerabilities',
    'gcp.review.artifact_image.selected_image_vulnerabilities',
    'k8s.review.selected_text_content.secret_indicators',
})


def native_case(check_id):
    raw = Path(__file__).with_suffix('.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError('Provider native reproduction cases changed')
    cases = json.loads(raw)
    if set(cases) != IDS or check_id not in IDS:
        raise RuntimeError('Provider native reproduction IDs changed')
    return cases[check_id]

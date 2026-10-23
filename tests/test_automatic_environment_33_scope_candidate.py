"""Registered 33-workload and denied-scope witness in the admitted merge copy."""
from pathlib import Path
import runpy


def test_registered_automatic_environment_33_scope_and_denied_sibling():
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / 'scripts/verify_automatic_batch_consumer_candidate.py'))

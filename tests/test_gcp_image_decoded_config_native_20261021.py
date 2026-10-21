"""Exact pure GCP image helper with the real offline detector pipeline."""
import ast
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAND = ROOT
from peaso.secret_scanning import scan_content

TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SOURCE = CAND / 'peaso/collectors/gcp_image_stream_inspection_20261021.py'


def helper():
    from peaso.collectors.gcp_image_stream_inspection_20261021 import decoded_config_strings
    return decoded_config_strings


def escaped_config():
    config = {'os': 'linux', 'config': {'Env': ['APP_TOKEN=' + TOKEN],
              'Cmd': ['echo', TOKEN], 'Labels': {'owned.example/credential': TOKEN}},
              'history': [{'created_by': 'export APP_TOKEN=' + TOKEN}]}
    raw = json.dumps(config, separators=(',', ':')).encode()
    encoded = ''.join('\\u%04x' % ord(char) for char in TOKEN).encode()
    raw = raw.replace(TOKEN.encode(), encoded)
    assert TOKEN.encode() not in raw
    return raw, json.loads(raw)


def test_decoded_env_cmd_labels_history_reach_both_real_detectors():
    raw, decoded = escaped_config()
    joined = helper()(decoded, lambda: None, 2 * 1024 * 1024)
    assert joined.count(TOKEN.encode()) == 4
    raw_outcome = scan_content(raw, 'image-config.json', timeout=15)
    decoded_outcome = scan_content(joined, 'image-config-decoded.txt', timeout=15)
    assert raw_outcome['complete'] and decoded_outcome['complete']
    assert all('kingfisher' not in {d['engine'] for d in leak['detectors']}
               for leak in raw_outcome['leaks'])
    assert {'kingfisher', 'trufflehog'} <= {d['engine'] for leak in decoded_outcome['leaks']
                                            for d in leak['detectors']}
    assert TOKEN not in json.dumps(decoded_outcome)
    tree = ast.parse(SOURCE.read_text())
    leaf = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_inspect_leaf')
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'decoded_config_strings'
               for n in ast.walk(leaf))
    inspect = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'inspect_image')
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == '_inspect_leaf'
               for n in ast.walk(inspect))
    assert 'image-config-decoded.txt' in SOURCE.read_text()


def test_bounded_decoding_and_cancellation():
    visit = helper()
    with pytest.raises(ValueError, match='byte bound'):
        visit({'Env': [TOKEN]}, lambda: None, 8)
    with pytest.raises(ValueError, match='node bound'):
        visit(['x'] * 20001, lambda: None, 100000)
    def cancel(): raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError, match='cancelled'):
        visit({'Env': [TOKEN]}, cancel, 100000)

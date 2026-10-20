"""Pinned historical HTTP execution alongside the installed native successors."""
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
from types import FunctionType, ModuleType

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = 'peaso/checks/gcp_function_secret_paired_predecessors_20261020.json.gz'
ARCHIVE_SHA256 = 'aa4d52a469ec2ef9525488aa1b9dfb2b67be07d69179e9e5772d7f90f36892e2'
TEST_ARCHIVE = 'tests/fixtures/gcp-wave2-test-predecessors-20261020.json.gz'
TEST_SHA256 = 'e3c788b34181b863831d35a3cf71efb5d6b1a378331667bd3f7f0d4bce7c8e53'


def historical_bytes(path, expected):
    raw = (ROOT / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() == expected:
        return raw
    packed = (ROOT / ARCHIVE).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == ARCHIVE_SHA256
    archive = json.loads(gzip.decompress(packed))['files']
    if path in archive:
        raw = bytes.fromhex(archive[path]['hex'])
        assert hashlib.sha256(raw).hexdigest() == archive[path]['sha256'] == expected
        return raw
    packed = (ROOT / TEST_ARCHIVE).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == TEST_SHA256
    raw = json.loads(gzip.decompress(packed))[path].encode()
    assert hashlib.sha256(raw).hexdigest() == expected
    return raw


@lru_cache(maxsize=1)
def historical_gcp():
    path = 'peaso/collectors/gcp.py'
    source = historical_bytes(path, '852aa00e59ca4cf540233b38865ea789eb8e16439bd4ac217ed5705bdd72475c')
    module = ModuleType('peaso.collectors._gcp_wave2_pinned_predecessor')
    module.__package__ = 'peaso.collectors'
    module.__file__ = str(ROOT / path)
    exec(compile(source, module.__file__, 'exec'), vars(module))
    return module


def collect_historical_native(*args, **kwargs):
    # The original harness and detectors execute unchanged. Only its explicit
    # gcp module argument uses the hash-pinned transport epoch it reviewed.
    from tests.gcp_function_partial_positive_native_20261020 import collect_native
    globals_ = dict(collect_native.__globals__, gcp=historical_gcp())
    run = FunctionType(collect_native.__code__, globals_, collect_native.__name__, collect_native.__defaults__)
    run.__kwdefaults__ = collect_native.__kwdefaults__
    return run(*args, **kwargs)

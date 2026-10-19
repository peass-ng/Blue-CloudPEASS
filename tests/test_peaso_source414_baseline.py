"""Historical catalog reconstruction is immutable and independent of current UI metadata."""
import hashlib
from pathlib import Path
import pytest
from tests import release_successor_history as history
from scripts.peaso_deploy import REPRODUCTION_INPUT_PATTERNS


def release():
 return {'files':{history.SOURCE414_NATIVE_MEMBER:history.SOURCE414_NATIVE_SHA256}}


def test_historical_reconstruction_never_reads_current_materialized_catalog(monkeypatch):
 original=Path.read_bytes
 def guarded(path):
  if path.resolve()==(history.ROOT/history.SOURCE414_NATIVE_MEMBER).resolve():
   pytest.fail('Historical reconstruction read mutable current native catalog')
  return original(path)
 monkeypatch.setattr(Path,'read_bytes',guarded)
 raw=history._source414_native_catalog(release())
 assert hashlib.sha256(raw).hexdigest()==history.SOURCE414_NATIVE_SHA256
 assert history.SOURCE414_NATIVE_BASELINE in REPRODUCTION_INPUT_PATTERNS


def test_historical_baseline_archive_tampering_rejected_before_decompression(monkeypatch):
 original=Path.read_bytes
 def altered(path):
  value=original(path)
  return value+b'unreviewed' if path.name==Path(history.SOURCE414_NATIVE_BASELINE).name else value
 monkeypatch.setattr(Path,'read_bytes',altered)
 with pytest.raises(ValueError,match='baseline archive digest differs'):
  history._source414_native_catalog(release())


def test_historical_release_binding_still_rejects_repinning_to_current():
 with pytest.raises(ValueError,match='release binding differs'):
  history._source414_native_catalog({'files':{history.SOURCE414_NATIVE_MEMBER:history.SOURCE414_NATIVE_BASE_SHA256}})

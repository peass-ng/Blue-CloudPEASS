"""IAM evidence enrichment cannot alter the authenticated historical release."""
import hashlib
from pathlib import Path
import pytest
from tests import release_successor_history as history

MEMBER='peaso/checks/claude_aws_a_iam.py'
MANIFEST='tests/fixtures/post_dfaf_integration/historical-release-manifests.json'


def test_exact_evidence_successor_recovers_original_baseline_bytes():
 current=(history.ROOT/MEMBER).read_bytes()
 original=history._source414_reviewed_baseline(MEMBER,current,history._IAM_HISTORICAL_BASELINE_SHA256)
 assert hashlib.sha256(current).hexdigest()==history._IAM_EVIDENCE_SUCCESSOR_SHA256
 assert hashlib.sha256(original).hexdigest()==history._IAM_HISTORICAL_BASELINE_SHA256
 assert len(history._IAM_EVIDENCE_ONLY_REVERSE_HUNKS)==4


def test_no_zip_iam_reconstruction_is_hermetic_and_release_bound(tmp_path,monkeypatch):
 for member in (MEMBER,MANIFEST):
  target=tmp_path/member;target.parent.mkdir(parents=True,exist_ok=True)
  target.write_bytes((history.ROOT/member).read_bytes())
 monkeypatch.setattr(history,'ROOT',tmp_path)
 archive=tmp_path/history.PUBLISHED_SPRINT_ARCHIVE.name
 assert not archive.exists()
 release=history.historical_release(archive)
 raw=history.historical_bytes(archive,MEMBER)
 assert hashlib.sha256(raw).hexdigest()==release['files'][MEMBER]

@pytest.mark.parametrize('change',['unknown_bytes','different_member','wrong_baseline'])
def test_unreviewed_successor_member_or_baseline_rejected(change):
 raw=(history.ROOT/MEMBER).read_bytes();member=MEMBER;expected=history._IAM_HISTORICAL_BASELINE_SHA256
 if change=='unknown_bytes':raw+=b'\n# unreviewed change\n'
 elif change=='different_member':member='peaso/checks/claude_aws_b_iam.py'
 else:expected='0'*64
 with pytest.raises(ValueError,match='baseline digest differs'):
  history._source414_reviewed_baseline(member,raw,expected)

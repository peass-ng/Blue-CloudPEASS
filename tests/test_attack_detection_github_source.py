"""The public rule archive is immutable, bounded, and parsed without extraction."""
from __future__ import annotations

import hashlib
import io
import tarfile
from urllib.request import Request

import pytest

from peaso.attack_detection import github_source as source


COMMIT = "a" * 40
ROOT = f"rules-{COMMIT}"
TEXT = "title: reviewed example\n"


def archive(*entries: tuple[str, bytes, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(content) if kind == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


def pack(*extra):
    return archive((ROOT, b"", tarfile.DIRTYPE),
                   (f"{ROOT}/README.md", b"Public reviewed rules\n", tarfile.REGTYPE),
                   (f"{ROOT}/rules", b"", tarfile.DIRTYPE),
                   (f"{ROOT}/rules/sample.yml", TEXT.encode(), tarfile.REGTYPE), *extra)


def digest(raw=TEXT.encode()):
    return hashlib.sha256(b"sample.yml\0" + raw + b"\0").hexdigest()


class Reply(io.BytesIO):
    status = 200

    def __init__(self, raw):
        super().__init__(raw)
        self.read_limits = []

    def read(self, size=-1):
        self.read_limits.append(size)
        return super().read(size)


class Network:
    def __init__(self, raw):
        self.raw = raw
        self.requests = []
        self.replies = []

    def open(self, request: Request, timeout):
        assert timeout == 15
        assert request.full_url == f"https://codeload.github.com/acme/rules/tar.gz/{COMMIT}"
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") is None
        self.requests.append(request)
        response = Reply(self.raw)
        self.replies.append(response)
        return response


def mock_network(monkeypatch, raw):
    network = Network(raw)
    monkeypatch.setattr(source, "build_opener", lambda *handlers: network)
    return network


def fetch(expected=None):
    return source.fetch_rules("acme/rules", COMMIT, expected)


def test_single_public_archive_read_and_content_digest(monkeypatch):
    network = mock_network(monkeypatch, pack())
    assert fetch(digest()) == {"sample.yml": TEXT}
    assert len(network.requests) == 1
    assert network.replies[0].closed
    assert network.replies[0].read_limits == [source.MAX_ARCHIVE_BYTES + 1]


@pytest.mark.parametrize("repo,commit,expected,code", [
    ("https://github.com/acme/rules", COMMIT, None, "invalid_repo"),
    ("acme/rules/other", COMMIT, None, "invalid_repo"),
    ("acme/../rules", COMMIT, None, "invalid_repo"),
    ("acme/rules", "main", None, "invalid_commit_sha"),
    ("acme/rules", COMMIT, "wrong", "invalid_pack_hash"),
])
def test_bad_parameters_never_make_a_request(monkeypatch, repo, commit, expected, code):
    monkeypatch.setattr(source, "build_opener", lambda *args: pytest.fail("network called"))
    with pytest.raises(source.RuleSourceError, match=code):
        source.fetch_rules(repo, commit, expected)


@pytest.mark.parametrize("name,kind", [
    (f"{ROOT}/rules/nested/sample.yml", tarfile.REGTYPE),
    (f"{ROOT}/rules/../sample.yml", tarfile.REGTYPE),
    (f"{ROOT}/other.yml", tarfile.REGTYPE),
    (f"{ROOT}/rules/other.yaml", tarfile.REGTYPE),
    (f"{ROOT}/rules/link.yml", tarfile.SYMTYPE),
])
def test_rejects_unreviewed_paths_and_links(monkeypatch, name, kind):
    mock_network(monkeypatch, pack((name, b"", kind)))
    with pytest.raises(source.RuleSourceError, match="invalid_rule_archive_path"):
        fetch()


def test_rejects_duplicate_and_wrong_root(monkeypatch):
    mock_network(monkeypatch, pack((f"{ROOT}/rules/sample.yml", TEXT.encode(), tarfile.REGTYPE)))
    with pytest.raises(source.RuleSourceError, match="duplicate_rule"):
        fetch()
    mock_network(monkeypatch, archive(("other/rules/sample.yml", TEXT.encode(), tarfile.REGTYPE)))
    with pytest.raises(source.RuleSourceError, match="invalid_rule_archive_path"):
        fetch()


def test_rejects_oversized_archive_rule_and_bad_digest(monkeypatch):
    network = mock_network(monkeypatch, b"x" * (source.MAX_ARCHIVE_BYTES + 1))
    with pytest.raises(source.RuleSourceError, match="rule_archive_too_large"):
        fetch()
    assert network.replies[0].read_limits == [source.MAX_ARCHIVE_BYTES + 1]
    mock_network(monkeypatch, pack((f"{ROOT}/rules/huge.yml", b"x" * (source.MAX_MEMBER_BYTES + 1), tarfile.REGTYPE)))
    with pytest.raises(source.RuleSourceError, match="rule_too_large"):
        fetch()
    mock_network(monkeypatch, pack())
    with pytest.raises(source.RuleSourceError, match="rule_pack_hash_mismatch"):
        fetch("0" * 64)


def test_rejects_invalid_gzip_and_redirect(monkeypatch):
    mock_network(monkeypatch, b"not a gzip archive")
    with pytest.raises(source.RuleSourceError, match="invalid_rule_archive"):
        fetch()
    handler = source._NoRedirect()
    with pytest.raises(source.RuleSourceError, match="redirect_rejected"):
        handler.redirect_request(None, None, 302, "moved", {}, "https://evil.example/")

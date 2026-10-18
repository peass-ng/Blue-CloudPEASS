"""Pinned private GitHub rule reads with mocked network responses."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from urllib.request import Request

import pytest

from peaso.attack_detection import github_source as source


COMMIT = "a" * 40
TREE = "b" * 40
TEXT = "title: reviewed example\n"


def blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def fixture(*, paths=("rules/sample.yml",), content=TEXT):
    raw = content.encode()
    sha = blob_sha(raw)
    entries = [{"path": path, "mode": "100644", "type": "blob", "size": len(raw), "sha": sha}
               for path in paths]
    return {
        f"/commits/{COMMIT}": {"sha": COMMIT, "tree": {"sha": TREE}},
        f"/trees/{TREE}": {"sha": TREE, "truncated": False, "tree": entries},
        f"/blobs/{sha}": {"sha": sha, "size": len(raw), "encoding": "base64",
                           "content": base64.b64encode(raw).decode()},
    }


class Reply(io.BytesIO):
    status = 200

    def __init__(self, data):
        super().__init__(data)
        self.read_limits = []

    def read(self, size=-1):
        self.read_limits.append(size)
        return super().read(size)


class Network:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.replies = []

    def open(self, request: Request, timeout):
        assert timeout == 15
        assert request.full_url.startswith("https://api.github.com/repos/acme/rules/git/")
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer secret"
        self.calls.append(request.full_url)
        path = request.full_url.split("/git", 1)[1].split("?", 1)[0]
        value = self.responses[path]
        reply = Reply(value if isinstance(value, bytes) else json.dumps(value).encode())
        self.replies.append(reply)
        return reply


def mock_network(monkeypatch, responses):
    network = Network(responses)
    monkeypatch.setattr(source, "build_opener", lambda *handlers: network)
    return network


def fetch():
    return source.fetch_rules("acme/rules", COMMIT, "secret")


def test_fetches_pinned_tree_and_verifies_blob(monkeypatch):
    responses = fixture()
    responses[f"/trees/{TREE}"]["tree"].insert(0, {"path": "README.md", "type": "blob", "mode": "100644"})
    network = mock_network(monkeypatch, responses)
    assert fetch() == {"sample.yml": TEXT}
    assert len(network.calls) == 3
    assert all(reply.closed for reply in network.replies)
    assert network.replies[1].read_limits == [source.MAX_TREE_BYTES + 1]
    assert network.replies[2].read_limits == [source.MAX_BLOB_RESPONSE_BYTES + 1]


@pytest.mark.parametrize("repo,commit,token,code", [
    ("https://github.com/acme/rules", COMMIT, "secret", "invalid_repo"),
    ("acme/rules/other", COMMIT, "secret", "invalid_repo"),
    ("acme/../rules", COMMIT, "secret", "invalid_repo"),
    ("acme/rules", "main", "secret", "invalid_commit_sha"),
    ("acme/rules", COMMIT, "", "invalid_token"),
    ("acme/rules", COMMIT, "secret\nother", "invalid_token"),
])
def test_rejects_untrusted_parameters_before_network(monkeypatch, repo, commit, token, code):
    monkeypatch.setattr(source, "build_opener", lambda *args: pytest.fail("network called"))
    with pytest.raises(source.RuleSourceError, match=code):
        source.fetch_rules(repo, commit, token)


def test_rejects_truncated_tree(monkeypatch):
    responses = fixture()
    responses[f"/trees/{TREE}"]["truncated"] = True
    network = mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="invalid_or_truncated_tree"):
        fetch()
    assert len(network.calls) == 2


@pytest.mark.parametrize("path", ["sample.yml", "other/sample.yaml", "rules/nested/sample.yml",
                                        "rules/sample.yaml", "rules/../sample.yml", "rules/README.md"])
def test_rejects_rule_paths_outside_exact_rule_directory(monkeypatch, path):
    network = mock_network(monkeypatch, fixture(paths=(path,)))
    with pytest.raises(source.RuleSourceError, match="invalid_rule_path"):
        fetch()
    assert len(network.calls) == 2


def test_rejects_duplicate_basename_and_symlink(monkeypatch):
    responses = fixture(paths=("rules/sample.yml", "rules/sample.yml"))
    mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="duplicate_rule"):
        fetch()
    responses = fixture()
    responses[f"/trees/{TREE}"]["tree"][0]["mode"] = "120000"
    mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="invalid_rule_path"):
        fetch()


def test_rejects_oversize_tree_before_parsing(monkeypatch):
    responses = fixture()
    responses[f"/trees/{TREE}"] = b" " * (source.MAX_TREE_BYTES + 1)
    network = mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="github_response_too_large"):
        fetch()
    assert len(network.calls) == 2


def test_rejects_oversize_rule_declarations(monkeypatch):
    responses = fixture()
    responses[f"/trees/{TREE}"]["tree"][0]["size"] = source.MAX_BLOB_BYTES + 1
    network = mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="rule_too_large"):
        fetch()
    assert len(network.calls) == 2


def test_rejects_aggregate_rule_size_before_fetching_blobs(monkeypatch):
    responses = fixture()
    item = responses[f"/trees/{TREE}"]["tree"][0]
    responses[f"/trees/{TREE}"]["tree"] = [
        {**item, "path": f"rules/rule-{index}.yml", "size": source.MAX_BLOB_BYTES}
        for index in range(31)
    ]
    network = mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="rules_too_large"):
        fetch()
    assert len(network.calls) == 2


def test_rejects_oversize_blob_http_response(monkeypatch):
    responses = fixture()
    key = next(key for key in responses if key.startswith("/blobs/"))
    responses[key] = b" " * (source.MAX_BLOB_RESPONSE_BYTES + 1)
    network = mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError, match="github_response_too_large"):
        fetch()
    assert len(network.calls) == 3


def test_rejects_blob_hash_mismatch_without_leaking_content(monkeypatch):
    responses = fixture()
    key = next(key for key in responses if key.startswith("/blobs/"))
    responses[key]["content"] = base64.b64encode(b"X" * len(TEXT.encode())).decode()
    mock_network(monkeypatch, responses)
    with pytest.raises(source.RuleSourceError) as error:
        fetch()
    assert error.value.code == "blob_sha_mismatch"
    assert "secret" not in str(error.value)


def test_rejects_redirect_without_following_destination():
    handler = source._NoRedirect()
    with pytest.raises(source.RuleSourceError, match="redirect_rejected"):
        handler.redirect_request(None, None, 302, "moved", {}, "https://evil.example/")

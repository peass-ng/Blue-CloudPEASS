"""Read immutable Sigma YAML from one private GitHub commit.

No URL from a GitHub response is followed. The only permitted endpoints are
constructed here from a validated owner/repository name and Git object IDs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from contextlib import closing
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_TREE_BYTES = 2_000_000
MAX_BLOB_BYTES = 65_536
MAX_BLOB_RESPONSE_BYTES = 96_000
MAX_RULES = 256
MAX_TOTAL_BYTES = 2_000_000
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9._-])?\Z")
_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.yml\Z")


class RuleSourceError(Exception):
    """Stable, sanitized error code without provider response or token data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuleSourceError("redirect_rejected")


def _request_json(url: str, token: str, limit: int) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hacktricks-cspm-rule-reader",
    }, method="GET")
    try:
        with closing(build_opener(_NoRedirect()).open(request, timeout=15)) as response:
            if response.status != 200:
                raise RuleSourceError("github_read_failed")
            body = response.read(limit + 1)
    except RuleSourceError:
        raise
    except HTTPError as exc:
        if exc.code in (401, 403):
            code = "github_read_denied"
        elif exc.code == 404:
            code = "github_object_not_found"
        elif exc.code == 429:
            code = "github_rate_limited"
        else:
            code = "github_read_failed"
        raise RuleSourceError(code) from None
    except (URLError, OSError, TimeoutError, ValueError):
        raise RuleSourceError("github_read_failed") from None
    if len(body) > limit:
        raise RuleSourceError("github_response_too_large")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise RuleSourceError("invalid_github_response") from None
    if not isinstance(value, dict):
        raise RuleSourceError("invalid_github_response")
    return value


def _sha(value) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise RuleSourceError("invalid_github_object_sha")
    return value.lower()


def _rules_from_tree(tree: dict) -> list[tuple[str, str, int]]:
    if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise RuleSourceError("invalid_or_truncated_tree")
    rules: list[tuple[str, str, int]] = []
    seen = set()
    total = 0
    for entry in tree["tree"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RuleSourceError("invalid_tree_entry")
        path = entry["path"]
        if path == "rules" and entry.get("type") == "tree":
            continue
        if not path.startswith("rules/") and not path.lower().endswith((".yml", ".yaml")):
            continue
        if (not path.startswith("rules/") or path.count("/") != 1
                or entry.get("type") != "blob" or entry.get("mode") != "100644"
                or not _BASENAME.fullmatch(path[6:])):
            raise RuleSourceError("invalid_rule_path")
        name = path[6:]
        if name in seen:
            raise RuleSourceError("duplicate_rule")
        seen.add(name)
        size = entry.get("size")
        if type(size) is not int or size < 0 or size > MAX_BLOB_BYTES:
            raise RuleSourceError("rule_too_large")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise RuleSourceError("rules_too_large")
        if len(rules) >= MAX_RULES:
            raise RuleSourceError("too_many_rules")
        rules.append((name, _sha(entry.get("sha")), size))
    if not rules:
        raise RuleSourceError("no_rules")
    return rules


def _blob_text(blob: dict, expected_sha: str, expected_size: int) -> str:
    if (_sha(blob.get("sha")) != expected_sha or blob.get("encoding") != "base64"
            or type(blob.get("size")) is not int or blob["size"] != expected_size):
        raise RuleSourceError("invalid_blob")
    content = blob.get("content")
    if not isinstance(content, str) or len(content) > 90_000:
        raise RuleSourceError("invalid_blob")
    try:
        raw = base64.b64decode("".join(content.split()), validate=True)
    except (binascii.Error, ValueError):
        raise RuleSourceError("invalid_blob") from None
    if len(raw) != expected_size or len(raw) > MAX_BLOB_BYTES:
        raise RuleSourceError("invalid_blob")
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if actual != expected_sha:
        raise RuleSourceError("blob_sha_mismatch")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleSourceError("invalid_rule_encoding") from None


def fetch_rules(repo: str, commit_sha: str, token: str) -> dict[str, str]:
    """Return rule basenames and UTF-8 YAML pinned to one Git commit SHA.

    The token needs repository Contents: read. Callers own token storage and
    rule validation; this function only performs bounded immutable reads.
    """
    if not isinstance(repo, str) or repo.count("/") != 1:
        raise RuleSourceError("invalid_repo")
    owner, name = repo.split("/")
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name) or name.lower().endswith(".git"):
        raise RuleSourceError("invalid_repo")
    if not isinstance(commit_sha, str) or not _SHA.fullmatch(commit_sha):
        raise RuleSourceError("invalid_commit_sha")
    if not isinstance(token, str) or not token or len(token) > 4096 or any(ch.isspace() or ord(ch) < 32 for ch in token):
        raise RuleSourceError("invalid_token")
    base = f"https://api.github.com/repos/{owner}/{name}/git"
    commit_sha = commit_sha.lower()
    commit = _request_json(f"{base}/commits/{commit_sha}", token, 64_000)
    if _sha(commit.get("sha")) != commit_sha or not isinstance(commit.get("tree"), dict):
        raise RuleSourceError("invalid_commit")
    tree_sha = _sha(commit["tree"].get("sha"))
    tree = _request_json(f"{base}/trees/{tree_sha}?recursive=1", token, MAX_TREE_BYTES)
    if _sha(tree.get("sha")) != tree_sha:
        raise RuleSourceError("invalid_tree")
    rules = _rules_from_tree(tree)
    result = {}
    for filename, blob_sha, size in rules:
        blob = _request_json(f"{base}/blobs/{blob_sha}", token, MAX_BLOB_RESPONSE_BYTES)
        result[filename] = _blob_text(blob, blob_sha, size)
    return result

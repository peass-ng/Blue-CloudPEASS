"""Read bounded rules from one public GitHub commit without API rate limits."""

from __future__ import annotations

import hashlib
import io
import re
import tarfile
from contextlib import closing
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_ARCHIVE_BYTES = 3_000_000
MAX_MEMBER_BYTES = 65_536
MAX_PLAN_BYTES = 2_000_000
MAX_TOTAL_BYTES = 2_000_000
MAX_MEMBERS = 512
MAX_RULES = 256
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9._-])?\Z")
_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.yml\Z")
_SCRIPT_BASENAME = re.compile(r"[a-z][a-z0-9_]{0,63}\.py\Z")
_SERVICE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_PROVIDERS = {"aws", "azure", "gcp", "kubernetes"}


def _valid_rule_path(name: str) -> bool:
    parts = name.split("/")
    if len(parts) == 1:
        return bool(_BASENAME.fullmatch(parts[0]))
    if len(parts) == 2:
        return parts[0] in _PROVIDERS and bool(_BASENAME.fullmatch(parts[1]))
    if len(parts) == 3:
        return (parts[0] == "aws" and bool(_SERVICE.fullmatch(parts[1]))
                and bool(_BASENAME.fullmatch(parts[2])))
    return False


def _valid_rule_directory(name: str) -> bool:
    parts = name.split("/")
    return (len(parts) == 1 and parts[0] in _PROVIDERS
            or len(parts) == 2 and parts[0] == "aws" and bool(_SERVICE.fullmatch(parts[1])))


class RuleSourceError(Exception):
    """Stable error code without provider response data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuleSourceError("redirect_rejected")


def _read_archive(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "hacktricks-cspm-rule-reader"}, method="GET")
    try:
        with closing(build_opener(_NoRedirect()).open(request, timeout=15)) as response:
            if response.status != 200:
                raise RuleSourceError("rule_archive_read_failed")
            body = response.read(MAX_ARCHIVE_BYTES + 1)
    except RuleSourceError:
        raise
    except HTTPError as exc:
        code = "rule_archive_not_found" if exc.code == 404 else "rule_archive_read_failed"
        raise RuleSourceError(code) from None
    except (URLError, OSError, TimeoutError, ValueError):
        raise RuleSourceError("rule_archive_read_failed") from None
    if len(body) > MAX_ARCHIVE_BYTES:
        raise RuleSourceError("rule_archive_too_large")
    return body


def _parse_archive(body: bytes, root: str, expected_sha256: str | None) -> dict[str, str]:
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r|gz") as archive:
            for member in archive:
                count += 1
                if count > MAX_MEMBERS:
                    raise RuleSourceError("too_many_archive_entries")
                path = member.name
                if path in {root, f"{root}/rules"} and member.isdir():
                    continue
                if path == f"{root}/README.md" and member.isfile() and member.size <= MAX_MEMBER_BYTES:
                    continue
                if path == f"{root}/WORK_PLAN.md" and member.isfile() and member.size <= MAX_PLAN_BYTES:
                    continue
                if path == f"{root}/scripts" and member.isdir():
                    continue
                if (path.startswith(f"{root}/scripts/") and member.isfile()
                        and member.size <= MAX_MEMBER_BYTES
                        and _SCRIPT_BASENAME.fullmatch(path[len(f"{root}/scripts/"):])):
                    continue
                prefix = f"{root}/rules/"
                if path.startswith(prefix) and member.isdir() and _valid_rule_directory(path[len(prefix):].rstrip("/")):
                    continue
                if (not path.startswith(prefix) or not _valid_rule_path(path[len(prefix):]) or not member.isfile()
                        or member.issym() or member.islnk()):
                    raise RuleSourceError("invalid_rule_archive_path")
                name = path[len(prefix):]
                if name in seen:
                    raise RuleSourceError("duplicate_rule")
                seen.add(name)
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise RuleSourceError("rule_too_large")
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise RuleSourceError("rules_too_large")
                if len(result) >= MAX_RULES:
                    raise RuleSourceError("too_many_rules")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuleSourceError("invalid_rule_archive")
                raw = stream.read(member.size + 1)
                if len(raw) != member.size:
                    raise RuleSourceError("invalid_rule_archive")
                result[name] = raw
    except RuleSourceError:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError):
        raise RuleSourceError("invalid_rule_archive") from None
    if not result:
        raise RuleSourceError("no_rules")
    digest = hashlib.sha256()
    for name in sorted(result):
        digest.update(name.encode("utf-8") + b"\0" + result[name] + b"\0")
    if expected_sha256 is not None and digest.hexdigest() != expected_sha256.lower():
        raise RuleSourceError("rule_pack_hash_mismatch")
    try:
        return {name: raw.decode("utf-8") for name, raw in result.items()}
    except UnicodeDecodeError:
        raise RuleSourceError("invalid_rule_encoding") from None


def fetch_rules(repo: str, commit_sha: str, expected_sha256: str | None = None) -> dict[str, str]:
    """Fetch a single immutable codeload archive and validate every rule entry."""
    if not isinstance(repo, str) or repo.count("/") != 1:
        raise RuleSourceError("invalid_repo")
    owner, name = repo.split("/")
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name) or name.lower().endswith(".git"):
        raise RuleSourceError("invalid_repo")
    if not isinstance(commit_sha, str) or not _SHA.fullmatch(commit_sha):
        raise RuleSourceError("invalid_commit_sha")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256)):
        raise RuleSourceError("invalid_pack_hash")
    commit_sha = commit_sha.lower()
    root = f"{name}-{commit_sha}"
    url = f"https://codeload.github.com/{owner}/{name}/tar.gz/{commit_sha}"
    return _parse_archive(_read_archive(url), root, expected_sha256)

"""Select a reviewed immutable rule pack for one interactive analysis."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import re

from .github_source import fetch_rules, resolve_main_commit, rule_pack_sha256
from .rules import (
    DEFAULT_RULE_PACK_SHA256, DEFAULT_RULE_REF, DEFAULT_RULE_REPO,
    Rule, RuleSourceError, load_rules,
)


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class RuleCatalog:
    mode: str
    commit: str
    sha256: str
    rules: tuple[Rule, ...]

    def public_metadata(self) -> dict[str, str | int]:
        return {"mode": self.mode, "commit": self.commit,
                "sha256": self.sha256, "rule_count": len(self.rules)}


def _remote_catalog(repo: str, commit: str, expected_digest: str | None) -> tuple[str, tuple[Rule, ...]]:
    texts = fetch_rules(repo, commit, expected_digest)
    digest = rule_pack_sha256(texts)
    with TemporaryDirectory(prefix="peasso-rules-") as temporary:
        root = Path(temporary)
        for name, source in texts.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        rules = load_rules(root)
    return digest, rules


def select_catalog(mode: str = "latest", *, product: str | None = None,
                   commit: str | None = None, digest: str | None = None) -> RuleCatalog:
    """Resolve main at access check; a run reuses its exact commit and digest."""
    if mode not in {"pinned", "latest"}:
        raise RuleSourceError("invalid_rule_catalog_mode")
    if mode == "pinned":
        repo_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "")
        ref_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REF", "")
        local = os.getenv("HACKTRICKS_CSPM_RULES_DIR", "")
        if local and os.getenv("PEASO_AUTH_MODE") != "cognito" and not repo_override and not ref_override:
            try:
                root = Path(local)
                texts = {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
                         for path in root.rglob("*.yml")}
                actual_digest = rule_pack_sha256(texts)
                rules = load_rules(root)
            except Exception:
                raise RuleSourceError("rule_source_unavailable") from None
            if commit not in (None, "local") or digest not in (None, actual_digest):
                raise RuleSourceError("rule_catalog_changed")
            return RuleCatalog(mode, "local", actual_digest,
                               tuple(rule for rule in rules if product is None or rule.product == product))
        if repo_override and not ref_override:
            raise RuleSourceError("rule_source_ref_required")
        repo = repo_override or DEFAULT_RULE_REPO
        configured_ref = ref_override or DEFAULT_RULE_REF
        configured_digest = (DEFAULT_RULE_PACK_SHA256 if (repo, configured_ref) ==
                             (DEFAULT_RULE_REPO, DEFAULT_RULE_REF)
                             else os.getenv("HACKTRICKS_CSPM_RULES_PACK_SHA256") or None)
        if commit not in (None, configured_ref) or (digest is not None and configured_digest is not None
                                                   and digest != configured_digest):
            raise RuleSourceError("rule_catalog_changed")
        commit = configured_ref
        expected_digest = digest or configured_digest
        if (repo, commit, expected_digest) == (DEFAULT_RULE_REPO, DEFAULT_RULE_REF,
                                                DEFAULT_RULE_PACK_SHA256):
            try:
                from peaso.attack_detection import load_rules as public_load_rules
                rules = public_load_rules(product=product)
            except Exception:
                raise RuleSourceError("rule_source_unavailable") from None
            return RuleCatalog(mode, commit, expected_digest, rules)
    else:
        repo = DEFAULT_RULE_REPO
        expected_digest = digest
    if mode == "latest" and commit is None:
        try:
            commit = resolve_main_commit(DEFAULT_RULE_REPO)
        except Exception:
            raise RuleSourceError("rule_source_unavailable") from None
    if not isinstance(commit, str) or not _SHA.fullmatch(commit):
        raise RuleSourceError("invalid_rule_catalog_commit")
    if expected_digest is not None and (not isinstance(expected_digest, str) or not _DIGEST.fullmatch(expected_digest)):
        raise RuleSourceError("invalid_rule_catalog_digest")
    try:
        actual_digest, rules = _remote_catalog(repo, commit, expected_digest)
    except Exception:
        raise RuleSourceError("rule_source_unavailable") from None
    if digest is not None and digest != actual_digest:
        raise RuleSourceError("rule_catalog_changed")
    return RuleCatalog(mode, commit, actual_digest,
                       tuple(replace(rule, selection=deepcopy(rule.selection))
                             for rule in rules if product is None or rule.product == product))

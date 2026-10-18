"""Build a deterministic *candidate section* inventory from HackTricks Cloud.

This parses Markdown headings and nearby shell examples. It does not establish
that a section is an attack, has a usable audit signal, or is detected by CSPM.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


PROVIDERS = {
    "aws-security": "aws", "gcp-security": "gcp", "azure-security": "azure",
    "kubernetes-security": "k8s",
}
CATEGORIES = ("privilege_escalation", "persistence", "post_exploitation", "enumeration")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})([^`]*)$")
_COMMAND = re.compile(
    r"^(?:\$\s*)?(?:aws|gcloud|az|kubectl|helm|curl|docker|python(?:3)?|"
    r"terraform|oc|sudo|pwsh|powershell|Get-[\w-]+|Set-[\w-]+|New-[\w-]+|"
    r"Invoke-[\w-]+)\s+", re.IGNORECASE,
)
_BOILERPLATE = re.compile(
    r"^(?:references?|resources?|further reading|see also|summary|overview|"
    r"contents?|table of contents|logs? generated|detection|defens(?:e|ive)|"
    r"mitigations?|remediation|notes?|prerequisites?|requirements?|"
    r"exploitation steps|example|examples)$", re.IGNORECASE,
)
_CATEGORY_MARKERS = (
    ("privilege_escalation", re.compile(r"privilege.?escalat|privesc|elevat(?:e|ion).?privileg", re.I)),
    ("persistence", re.compile(r"persisten|backdoor", re.I)),
    ("post_exploitation", re.compile(r"post.?exploitat", re.I)),
    ("enumeration", re.compile(r"enumerat|\benum\b|reconnaissance", re.I)),
)


def _category(value: str) -> str | None:
    return next((name for name, pattern in _CATEGORY_MARKERS if pattern.search(value)), None)


def _slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"[`*_]", "", value)
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:100] or "section"


def _commands(lines: list[str]) -> tuple[int, list[str]]:
    inside = False
    language = ""
    count = 0
    examples: list[str] = []
    for line in lines:
        match = _FENCE.match(line)
        if match:
            inside = not inside
            language = match.group(2).strip().split(" ", 1)[0].lower() if inside else ""
            continue
        if not inside or language not in {"", "bash", "sh", "shell", "console", "powershell", "ps1"}:
            continue
        command = line.strip()
        if not _COMMAND.match(command):
            continue
        count += 1
        if len(examples) < 5:
            examples.append(re.sub(r"\s+", " ", command)[:300])
    return count, examples


def _body_length(lines: list[str]) -> int:
    """Count prose outside code fences, links, tables, and include directives."""
    inside = False
    total = 0
    for line in lines:
        if _FENCE.match(line):
            inside = not inside
            continue
        stripped = line.strip()
        if inside or not stripped or stripped.startswith(("|", "{{", "<!--", "[", "#")):
            continue
        total += len(re.sub(r"<[^>]+>", "", stripped))
    return total


def _page_sections(path: Path, relative: str, provider: str, path_category: str | None) -> list[dict]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    sections: list[dict] = []
    stack: list[tuple[int, str | None]] = []
    current: dict | None = None
    body: list[str] = []
    seen_slugs: Counter[str] = Counter()
    fenced = False

    def finish() -> None:
        nonlocal current, body
        if current is None:
            return
        command_count, command_examples = _commands(body)
        title = current["heading"]
        if (current["level"] >= 2 and current["category"] in CATEGORIES
                and not _BOILERPLATE.fullmatch(re.sub(r"[`*_]", "", title).strip())
                and (command_count > 0 or _body_length(body) >= 80)):
            sections.append({
                "id": current["id"], "provider": provider,
                "category": current["category"], "path": relative,
                "heading": title, "line": current["line"],
                "command_count": command_count, "command_examples": command_examples,
                "command_examples_truncated": command_count > len(command_examples),
            })
        current, body = None, []

    for number, line in enumerate(lines, 1):
        if _FENCE.match(line):
            fenced = not fenced
        match = _HEADING.match(line) if not fenced else None
        if match:
            finish()
            level, title = len(match.group(1)), match.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            category = _category(title) or (stack[-1][1] if stack else None) or path_category
            stack.append((level, category))
            slug = _slug(title)
            seen_slugs[slug] += 1
            suffix = f"-{seen_slugs[slug]}" if seen_slugs[slug] > 1 else ""
            current = {"id": f"{relative}#{slug}{suffix}", "heading": title,
                       "line": number, "level": level, "category": category}
        elif current is not None:
            body.append(line)
    finish()
    return sections


def build_inventory(corpus_root: Path, *, source_revision: str | None = None) -> dict:
    """Return sorted candidates from a pinned local corpus root or its `src` dir."""
    root = corpus_root / "src" / "pentesting-cloud"
    if not root.is_dir():
        root = corpus_root / "pentesting-cloud"
    if not root.is_dir():
        root = corpus_root
    if not root.is_dir() or not any((root / name).is_dir() for name in PROVIDERS):
        raise ValueError("corpus_root_missing_provider_directories")
    if source_revision is not None and not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ValueError("source_revision_must_be_full_git_sha")
    sections: list[dict] = []
    pages: set[str] = set()
    for directory, provider in PROVIDERS.items():
        for path in sorted((root / directory).rglob("*.md")):
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            path_category = next((_category(part) for part in path.relative_to(root / directory).parts if _category(part)), None)
            found = _page_sections(path, relative, provider, path_category)
            if found:
                pages.add(relative)
                sections.extend(found)
    sections.sort(key=lambda row: (row["provider"], row["path"], row["line"], row["id"]))
    counts: dict[str, dict[str, int]] = defaultdict(dict)
    for provider in PROVIDERS.values():
        for category in CATEGORIES:
            counts[provider][category] = sum(row["provider"] == provider and row["category"] == category for row in sections)
    return {
        "source_revision": source_revision,
        "meaning": "Heuristic Markdown section inventory; candidates are not validated techniques or detections",
        "counts": {"pages_with_candidates": len(pages), "candidate_sections": len(sections),
                   "sections_with_commands": sum(row["command_count"] > 0 for row in sections),
                   "by_provider_category": dict(counts)},
        "limitations": [
            "Headings and shell examples are parsed from Markdown; prose-only or cross-linked techniques can be missed.",
            "Nested headings may describe parts of one technique, so section counts are not unique attack counts.",
            "Commands are examples, not validated, executable, or necessarily malicious actions.",
            "No audit-log visibility, detection coverage, false-positive rate, or live exploitability is inferred.",
        ],
        "sections": sections,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--source-revision", help="Full commit SHA of the input snapshot")
    parser.add_argument("--output", type=Path, help="Write JSON here instead of stdout")
    args = parser.parse_args()
    result = build_inventory(args.corpus_root, source_revision=args.source_revision)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
        print(json.dumps(result["counts"], sort_keys=True))
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()

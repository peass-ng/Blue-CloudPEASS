"""Documentation links in a check must be distinguishable by their labels."""

import json
from pathlib import Path


RULEPACKS = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks"


def _reference_lists(value, location="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _reference_lists(child, f"{location}.{key}")
    elif isinstance(value, list):
        if any(isinstance(row, dict) and "title" in row and "url" in row for row in value):
            yield location, value
        for index, child in enumerate(value):
            yield from _reference_lists(child, f"{location}[{index}]")


def test_distinct_reference_urls_have_distinct_titles_across_all_checks():
    conflicts = []
    titles = {}

    def check(reference, location):
        if not isinstance(reference, dict):
            return
        title, url = reference.get("title"), reference.get("url")
        if not isinstance(title, str) or not isinstance(url, str):
            return
        normalized = title.strip().casefold()
        if normalized in titles and titles[normalized] != url:
            conflicts.append(f"{location}: {title!r}")
        titles[normalized] = url

    for path in sorted(RULEPACKS.glob("*.json")):
        data = json.loads(path.read_text())
        for location, references in _reference_lists(data):
            for reference in references:
                check(reference, f"{path.name}:{location}")

    # Reviewed overlays can supply references after the JSON shards load.
    from peaso.remediation import rules
    for check_id, entry in rules().items():
        if isinstance(entry, dict):
            for reference in entry.get("references", []):
                check(reference, check_id)

    assert not conflicts, "Different reference URLs share a title:\n" + "\n".join(conflicts)

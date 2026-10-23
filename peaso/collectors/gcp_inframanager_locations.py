"""Read project-visible Infrastructure Manager deployment locations."""

import re

from .gcp import ReadError


def collection_pages(collector, scope):
    seen = set()
    url = f"https://config.googleapis.com/v1/{scope}/locations"
    for page, request_id in collector.pages(url, scope, key="locations"):
        rows = []
        for item in page:
            name = item.get("name") if isinstance(item, dict) else None
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(scope) + r"/locations/[a-z][a-z0-9-]*", name)
                    or name in seen):
                raise ReadError("malformed", "inframanager_location_identity_unbound")
            seen.add(name)
            rows.append(item)
        yield rows, request_id

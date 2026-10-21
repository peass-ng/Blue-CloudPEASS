"""Complete the native forwarding-rule collection with the global list.

The existing aggregated/forwardingRules request enumerates regional rules.
This hook is called after native scope jobs and before snapshot construction.
"""
from __future__ import annotations

import re


def collect(collector):
    if 'forwarding_rule' not in collector.needed:
        return
    for scope in collector.scopes:
        if not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]', scope):
            continue
        def rows(scope=scope):
            yield from collector.pages(
                f'https://compute.googleapis.com/compute/v1/{scope}/global/forwardingRules',
                scope, key='items', page_size_key='maxResults',
                transform=lambda item: {**item, '_representation': 'full'})
        collector.add('forwarding_rule', scope, 'compute', rows)

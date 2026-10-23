"""Read principal permission details from tenant-owned immutable inventory."""
from concurrent.futures import ThreadPoolExecutor
from peaso.least_privilege_permissions import enrich


def resource_rows(artifacts, tenant, bundle):
    chunks = bundle.get('resource_chunks', [])
    if chunks:
        def read(chunk):
            return artifacts.get(tenant, chunk['reference'])['items']
        with ThreadPoolExecutor(max_workers=min(8, len(chunks))) as pool:
            rows = [row for group in pool.map(read, chunks) for row in group]
    else:
        rows = bundle.get('resources', [])
        if not rows and bundle.get('report_json'):
            rows = artifacts.get(tenant, bundle['report_json']).get('resources', [])
    return rows


def principal_detail(artifacts, tenant, bundle, card):
    summary = bundle.get('summary', bundle)
    return enrich(card, summary.get('provider', card.get('provider')),
                  resource_rows(artifacts, tenant, bundle), summary.get('created_at'))

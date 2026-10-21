"""Tenant/scan-scoped, bounded API presentation for optional image observations."""
from copy import deepcopy
import json
from fastapi import Depends, HTTPException, Query

from peaso.image_findings import build_report, SCHEMA

MAX_PAGE_BYTES = 1_000_000


def page_report(report, offset, limit):
    page = {key: deepcopy(value) for key, value in report.items() if key != 'rows'}
    page.update(rows=[], total=len(report['rows']), offset=offset, next_offset=None)
    for row in report['rows'][offset:offset + limit]:
        item = deepcopy(row)
        assets = item['affected_assets']
        item.update(affected_asset_count=len(assets), affected_assets=assets[:10],
                    assets_truncated=len(assets) > 10)
        candidate = dict(page, rows=page['rows'] + [item])
        if len(json.dumps(candidate, separators=(',', ':'), ensure_ascii=True).encode()) > MAX_PAGE_BYTES - 64:
            break
        page['rows'].append(item)
    consumed = offset + len(page['rows'])
    if consumed < len(report['rows']):
        page['next_offset'] = consumed
    return page


def install_routes(app, *, identity, owned_bundle, artifacts):
    """Reuse existing workspace authorization before reading any image artifact."""
    def report_for(tenant, ident):
        from peaso.storage.artifacts import job_prefix, check_reference
        _, bundle = owned_bundle(tenant, ident)
        metadata = bundle.get('image_vulnerability_scan')
        if metadata is None:
            return build_report([], selected=False)
        if type(metadata) is not dict or metadata.get('selected') is not True:
            return build_report([], selected=False)
        reference = metadata.get('artifact')
        if not isinstance(reference, str) or not reference.startswith(job_prefix(tenant, ident)):
            raise HTTPException(409, 'Image evidence is unavailable for this scan')
        try:
            check_reference(tenant, reference)
        except ValueError:
            raise HTTPException(409, 'Image evidence is unavailable for this scan') from None
        value = artifacts.get(tenant, reference)
        if (type(value) is not dict or value.get('schema') != SCHEMA or
            value.get('scan_id') != ident or type(value.get('observations')) is not list):
            raise HTTPException(409, 'Image evidence is unavailable for this scan')
        return build_report(value['observations'], selected=True)

    @app.get('/api/scans/{ident}/image-findings')
    def image_findings(ident: str, offset: int = Query(default=0, ge=0),
                       limit: int = Query(default=100, ge=1, le=100), user=Depends(identity)):
        return page_report(report_for(user.tenant_id, ident), offset, limit)

    @app.get('/api/scans/{ident}/image-findings/{finding_id}/assets')
    def image_assets(ident: str, finding_id: str, offset: int = Query(default=0, ge=0),
                     limit: int = Query(default=50, ge=1, le=50), user=Depends(identity)):
        report = report_for(user.tenant_id, ident)
        row = next((row for row in report['rows'] if row['id'] == finding_id), None)
        if row is None:
            raise HTTPException(404, 'Image finding not found')
        assets = row['affected_assets']
        selected = assets[offset:offset + limit]
        consumed = offset + len(selected)
        return {'items': selected, 'total': len(assets), 'offset': offset,
                'next_offset': consumed if consumed < len(assets) else None,
                'coverage': row['coverage']}

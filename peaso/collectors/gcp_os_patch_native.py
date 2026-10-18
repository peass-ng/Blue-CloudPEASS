"""Read-only OS Config schedules and fresh vulnerability reports.

Report timestamps describe scan freshness. They never supply package publication
or installation dates. Nonempty reports retain unresolved fix ages as UNKNOWN.
"""
import re


def scope_jobs(collector, scope):
    if 'os_patch_deployment' not in collector.needed or not scope.startswith('projects/'):
        return []
    seen = set()
    def keep(row):
        from .gcp import ReadError
        name = row.get('name')
        if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/patchDeployments/[A-Za-z0-9_-]+', name):
            raise ReadError('malformed', 'patch_deployment_foreign_identity')
        if name in seen:
            raise ReadError('malformed', 'patch_deployment_duplicate_identity')
        seen.add(name)
        return {**{k: row[k] for k in ('name', 'state', 'instanceFilter', 'recurringSchedule', 'oneTimeSchedule') if k in row},
                'native_model': 'osconfig_v1'}
    return [('os_patch_deployment', scope, 'osconfig', lambda: collector.pages(
        'https://osconfig.googleapis.com/v1/' + scope + '/patchDeployments', scope,
        key='patchDeployments', transform=keep))]


def collect(collector):
    from .gcp import ReadError
    from .gcp_compliance_wave import complete_parent
    jobs = []
    for scope in collector.scopes:
        if 'os_vulnerability_report' not in collector.needed or not scope.startswith('projects/'):
            continue
        def fetch(scope=scope):
            parent = complete_parent(collector, 'instance', scope)
            seen, failures = set(), []
            projects = complete_parent(collector, 'project', scope)['items']
            aliases = {scope.split('/')[1]}
            for project in projects:
                native = project.get('name', '')
                if project.get('projectId') == scope.split('/')[1] and isinstance(native, str) and re.fullmatch(r'projects/[0-9]+', native):
                    aliases.add(native.split('/')[1])
            for vm in parent['items']:
                name, number = vm.get('name'), str(vm.get('id', ''))
                zone = vm.get('zone') or vm.get('_aggregated_scope')
                zone = zone.rsplit('/', 1)[-1] if isinstance(zone, str) else None
                if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name)
                        or not number.isdecimal() or not isinstance(zone, str)
                        or not re.fullmatch(r'[a-z0-9-]+', zone) or (zone, number) in seen):
                    raise ReadError('malformed', 'vulnerability_vm_join_unresolved')
                seen.add((zone, number))
                expected = scope + '/locations/' + zone + '/instances/' + number + '/vulnerabilityReport'
                def keep(row, name=name, expected=expected):
                    native = row.get('name')
                    suffix = expected.split('/locations/', 1)[1]
                    if (not isinstance(native, str) or not re.fullmatch(r'projects/(?:' + '|'.join(re.escape(a) for a in aliases) + ')/locations/' + re.escape(suffix), native)
                            or not isinstance(row.get('updateTime'), str)):
                        raise ReadError('malformed', 'vulnerability_report_identity_or_time_unresolved')
                    findings = row.get('vulnerabilities', [])
                    if not isinstance(findings, list):
                        raise ReadError('malformed', 'vulnerability_report_findings_malformed')
                    normalized = []
                    for finding in findings:
                        if not isinstance(finding, dict) or not isinstance(finding.get('details'), dict):
                            raise ReadError('malformed', 'vulnerability_report_details_malformed')
                        severity = finding['details'].get('severity')
                        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'):
                            raise ReadError('unavailable', 'vulnerability_severity_unresolved')
                        items = finding.get('items')
                        if not isinstance(items, list) or not items:
                            raise ReadError('unavailable', 'vulnerability_fix_items_unresolved')
                        # The referenced available package contains no universal
                        # publication date. Do not substitute first observation.
                        normalized.append({'severity': severity, 'items': [
                            {'availableInventoryItemId': x.get('availableInventoryItemId')} for x in items if isinstance(x, dict)]})
                        if len(normalized[-1]['items']) != len(items):
                            raise ReadError('malformed', 'vulnerability_fix_item_malformed')
                    return {'name': native, 'instanceName': name, 'updateTime': row['updateTime'],
                            'native_model': 'osconfig_v1', 'vulnerabilities': normalized}
                try:
                    yield from collector.pages('https://osconfig.googleapis.com/v1/' + expected,
                                               scope, single=True, transform=keep)
                except ReadError as exc:
                    if getattr(exc, 'request_id', None):
                        yield [], exc.request_id
                    failures.append(exc)
            if failures:
                raise failures[0]
        jobs.append(('os_vulnerability_report', scope, 'osconfig', fetch))
    collector.run_jobs(jobs)

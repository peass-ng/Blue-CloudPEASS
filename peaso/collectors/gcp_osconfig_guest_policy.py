"""Read exact legacy guest-policy identities and recipe update metadata."""

from __future__ import annotations

import re

from .gcp import ReadError


def scope_jobs(collector, scope):
    if not scope.startswith('projects/'):
        return []
    def fetch():
        seen = set()

        def keep(row):
            name = row.get('name')
            match = re.fullmatch(r'projects/([^/]+)/guestPolicies/([a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)',
                                 name) if isinstance(name, str) else None
            if match and match[1] != scope.split('/', 1)[1]:
                binding = collector._data_project_binding(scope, require_alias=True)
                if match[1] not in {binding['project_id'], binding['project_number']}:
                    raise ReadError('malformed', 'guest_policy_foreign_project')
                name = scope + '/guestPolicies/' + match[2]
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(scope) + r'/guestPolicies/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', name)
                    or name in seen):
                raise ReadError('malformed', 'guest_policy_identity_invalid_or_duplicate')
            seen.add(name)
            recipes = row.get('recipes', [])
            if not isinstance(recipes, list):
                raise ReadError('malformed', 'guest_policy_recipes_malformed')
            return {'name': name, 'recipes': [
                {key: recipe[key] for key in ('name', 'version', 'desiredState', 'updateSteps') if key in recipe}
                for recipe in recipes if isinstance(recipe, dict)],
                'recipe_metadata_complete': all(isinstance(recipe, dict) for recipe in recipes)}

        yield from collector.pages('https://osconfig.googleapis.com/v1beta/' + scope + '/guestPolicies',
                                   scope, key='guestPolicies', transform=keep)

    jobs = []
    if 'osconfig_guest_policy' in collector.needed:
        jobs.append(('osconfig_guest_policy', scope, 'osconfig', fetch))
    if 'osconfig_project_feature_settings' in collector.needed:
        expected = scope + '/locations/global/projectFeatureSettings'

        def feature_settings():
            def keep(row):
                name = row.get('name')
                if (isinstance(name, str) and name.endswith('/locations/global/projectFeatureSettings')
                        and name != expected):
                    binding = collector._data_project_binding(scope, require_alias=True)
                    alias = name.split('/')[1] if name.startswith('projects/') else None
                    if alias not in {binding['project_id'], binding['project_number']}:
                        raise ReadError('malformed', 'osconfig_feature_settings_foreign_project')
                    name = expected
                if name != expected or row.get('patchAndConfigFeatureSet') not in (
                        'OSCONFIG_B', 'OSCONFIG_C'):
                    raise ReadError('malformed', 'osconfig_feature_settings_invalid')
                return {'name': expected, 'patchAndConfigFeatureSet': row['patchAndConfigFeatureSet']}

            yield from collector.pages('https://osconfig.googleapis.com/v1/' + expected,
                                       scope, single=True, transform=keep)

        jobs.append(('osconfig_project_feature_settings', scope, 'osconfig', feature_settings))
    if 'osconfig_os_policy_assignment' in collector.needed:
        def assignments():
            from .gcp_compliance_wave import complete_parent
            parent = complete_parent(collector, 'instance', scope)
            zones = set()
            for vm in parent['items']:
                zone = vm.get('zone') or vm.get('_aggregated_scope')
                zone = zone.rsplit('/', 1)[-1] if isinstance(zone, str) else None
                if not isinstance(zone, str) or not re.fullmatch(r'[a-z0-9-]+-[a-z]', zone):
                    raise ReadError('malformed', 'os_policy_vm_zone_unresolved')
                zones.add(zone)
            seen = set()
            for zone in sorted(zones):
                parent_name = scope + '/locations/' + zone

                def keep(row, zone=zone):
                    name = row.get('name')
                    match = re.fullmatch(r'projects/([^/]+)/locations/' + re.escape(zone) +
                                         r'/osPolicyAssignments/([a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)',
                                         name) if isinstance(name, str) else None
                    if match and match[1] != scope.split('/', 1)[1]:
                        binding = collector._data_project_binding(scope, require_alias=True)
                        if match[1] not in {binding['project_id'], binding['project_number']}:
                            raise ReadError('malformed', 'os_policy_assignment_foreign_project')
                    if not match:
                        raise ReadError('malformed', 'os_policy_assignment_identity_invalid')
                    canonical = parent_name + '/osPolicyAssignments/' + match[2]
                    if canonical in seen:
                        raise ReadError('malformed', 'os_policy_assignment_duplicate')
                    seen.add(canonical)
                    return {'name': canonical}

                yield from collector.pages('https://osconfig.googleapis.com/v1/' + parent_name +
                                           '/osPolicyAssignments', scope, key='osPolicyAssignments',
                                           params={'fields': 'osPolicyAssignments(name),nextPageToken'},
                                           transform=keep)

        jobs.append(('osconfig_os_policy_assignment', scope, 'osconfig', assignments))
    return jobs


def collect(collector):
    """Run after project identity has been collected for number/ID aliases."""
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])

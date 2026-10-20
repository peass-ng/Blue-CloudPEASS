"""Unregistered review proposal: selected Function telemetry-setting declaration.

Inputs are ephemeral ARM GET site and POST appsettings/list response dictionaries.
An integration must authenticate and bind both responses before calling this pure
function, discard raw settings before caching, and enforce explicit selection.
This function neither retrieves settings nor establishes telemetry delivery.
"""
import re

PROPOSED_ID = 'azure.review.function.application_insights_setting_declared'
API_VERSION = '2024-11-01'
_GUID = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
_SITE = re.compile(r'/subscriptions/(' + _GUID + r')/resourceGroups/[A-Za-z0-9_().-]+/providers/Microsoft\.Web/sites/[A-Za-z0-9-]+', re.I)
_KEYS = ('APPLICATIONINSIGHTS_CONNECTION_STRING', 'APPINSIGHTS_INSTRUMENTATIONKEY')


def evaluate_native(site, settings, *, selected_site, subscription_id,
                    site_status=200, settings_status=200):
    """Return only fixed prose/booleans, never a setting value or exception body."""
    unresolved = ('UNKNOWN', {'observed': 'The selected Function telemetry setting declaration could not be established.'})
    if (type(site_status) is not int or site_status != 200
            or type(settings_status) is not int or settings_status != 200):
        return unresolved
    match = _SITE.fullmatch(selected_site) if isinstance(selected_site, str) else None
    if (not match or not isinstance(subscription_id, str)
            or match[1].casefold() != subscription_id.casefold()
            or any(part in ('.', '..') for part in selected_site.split('/'))
            or not isinstance(site, dict) or not isinstance(settings, dict)):
        return unresolved
    if ('error' in site or not isinstance(site.get('id'), str) or site['id'].casefold() != selected_site.casefold()
            or str(site.get('type', '')).casefold() != 'microsoft.web/sites'
            or not isinstance(site.get('properties'), dict) or not isinstance(site.get('kind'), str)
            or 'functionapp' not in {part.strip().casefold() for part in site['kind'].split(',')}):
        return unresolved
    if ('error' in settings or not isinstance(settings.get('id'), str)
            or settings['id'].casefold() != (selected_site + '/config/appsettings').casefold()
            or str(settings.get('type', '')).casefold() != 'microsoft.web/sites/config'
            or settings.get('name') != 'appsettings' or not isinstance(settings.get('properties'), dict)):
        return unresolved
    properties = settings['properties']
    if len(properties) > 2048 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in properties.items()):
        return unresolved
    # The native dictionary has case-sensitive keys; ambiguous aliases are not
    # silently combined. References/masks do not prove a literal declaration.
    for key in _KEYS:
        if any(k.casefold() == key.casefold() and k != key for k in properties):
            return unresolved
    values = [properties.get(key, '') for key in _KEYS]
    if any(value.lstrip().casefold().startswith('@microsoft.keyvault')
           or value.strip() and set(value.strip()) <= {'*'} for value in values):
        return unresolved
    declared = any(value.strip() for value in values)
    return ('PASS' if declared else 'FAIL'), {
        'telemetry_setting_declared': bool(declared),
        'observed': ('The selected Function declares a nonempty Application Insights setting.' if declared
                     else 'The selected Function has no nonempty Application Insights setting.')
                    + ' Telemetry delivery and destination validity were not tested.'}

"""Brief native package observations, including attributable incomplete hits."""
import re
from peaso import azure_function_package_portable_20261020 as contract

CHECK = 'azure.review.function.selected_package_source_secret_indicators'


def observation(finding):
    try:
        if (finding.get('check_id') != CHECK or finding.get('provider') != 'azure'
                or finding.get('status') not in ('PASS', 'FAIL')):
            return None
        e = finding['evidence']
        contract.require(type(e.get('complete')) is bool
            and e.get('coverage') == 'selected_configured_stored_package_only'
            and e.get('credential_validation') == 'not_attempted'
            and e.get('runtime_bytes') == 'unknown'
            and e.get('cloud_authenticity') == 'not_established')
        parts = e['parts']
        contract.require(isinstance(parts, list) and 1 <= len(parts) <= contract.MAX_MEMBERS)
        stem = re.fullmatch(r'(azure_storage_selected_source:[0-9a-f]{64})\.file-1', parts[0]['path'])
        contract.require(stem is not None)
        for number, part in enumerate(parts, 1):
            contract.require(set(part) == {'path', 'bytes', 'complete', 'engines', 'leaks'}
                and part['path'] == stem[1] + '.file-' + str(number)
                and contract.integer(part['bytes'], 1, contract.MAX_MEMBER)
                and type(part['complete']) is bool)
            engines = part['engines']
            contract.require(isinstance(engines, list) and len(engines) == 2
                and [engine['engine'] for engine in engines] == list(contract.VERSIONS))
            for engine in engines:
                contract.require(set(engine) == {'engine', 'version', 'status'}
                    and engine['version'] == contract.VERSIONS[engine['engine']]
                    and engine['status'] in ('complete', 'unavailable'))
            contract.require(part['complete'] == all(x['status'] == 'complete' for x in engines))
            contract._leaks(part['leaks'], part['path'], {x['engine'] for x in engines if x['status'] == 'complete'})
        contract.require(sum(p['bytes'] for p in parts) <= contract.MAX_EXPANDED
            and e['secret_leaks'] == contract._merged(parts)
            and len(e['secret_leaks']) <= contract.MAX_LEAKS
            and sum(len(leak['locations']) for leak in e['secret_leaks']) <= contract.MAX_LOCATIONS
            and (finding['status'] == 'FAIL') == bool(e['secret_leaks']))
        if e['complete']:
            contract.require(all(p['complete'] for p in parts))
        elif finding['status'] != 'FAIL':
            return None
        if not e['secret_leaks']:
            return 'Both offline detectors found no supported secret in the selected stored deployment package.'
        return ('A likely secret was detected in the selected stored deployment package. Its value is hidden and was not validated'
                + ('.' if e['complete'] else '; inspection is incomplete.'))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None

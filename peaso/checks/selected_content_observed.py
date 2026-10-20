"""Brief observations from complete selected-literal scanner evidence."""
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

SUBJECTS = {
    ('azure', 'azure.review.app_service.selected_app_settings_secret_indicators'): 'selected literal app settings',
    ('k8s', 'k8s.review.selected_literals.secret_indicators'): 'selected workload and ConfigMap literals',
    ('azure', 'azure.review.acr.selected_image_secret_indicators'): 'the selected immutable ACR image',
    ('aws', 'aws.review.lambda.selected_environment_secret_indicators'): 'selected Lambda environment variables',
}


def observation(finding):
    from .selected_configuration_content_observed_20261020 import observation as current
    selected = current(finding)
    if selected:
        return selected
    try:
        subject = SUBJECTS.get((finding.get('provider'), finding.get('check_id')))
        status, evidence = finding.get('status'), finding.get('evidence')
        if subject is None or status not in ('PASS', 'FAIL') or not isinstance(evidence, dict):
            return None
        image = finding['check_id'] == 'azure.review.acr.selected_image_secret_indicators'
        environment = finding['check_id'] == 'aws.review.lambda.selected_environment_secret_indicators'
        if (evidence.get('complete') is not True
                or evidence.get('coverage') != ('selected_observed_literal_environment_only' if environment else 'selected_observed_image_content_only' if image else 'selected_observed_literals_only')
                or evidence.get('credential_validation') != 'not_attempted'):
            return None
        count = 'variable_count' if environment else 'literal_count'
        if not image and (type(evidence.get(count)) is not int or evidence[count] < 1):
            return None
        parts = [{'complete': True, 'engines': evidence.get('engines')}] if environment else evidence.get('parts')
        if (not isinstance(parts, list) or (len(parts) < 2 if image else len(parts) != 1)
                or image and [p.get('part') for p in parts[:2]] != ['manifest', 'config']):
            return None
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for part in parts:
            engines = part.get('engines')
            if (part.get('complete') is not True or not isinstance(engines, list) or len(engines) != 2
                    or {e.get('engine') for e in engines} != set(expected)
                    or any(e.get('status') != 'complete' or e.get('version') != expected.get(e.get('engine')) for e in engines)):
                return None
        leaks = evidence.get('secret_leaks')
        if not isinstance(leaks, list) or merge_leaks(leaks) != leaks or (status == 'FAIL') != bool(leaks):
            return None
        return (f'A likely secret was detected in {subject}.' if leaks else
                f'Both offline detectors found no supported secret in {subject}.')
    except (AttributeError, KeyError, TypeError, ValueError):
        return None

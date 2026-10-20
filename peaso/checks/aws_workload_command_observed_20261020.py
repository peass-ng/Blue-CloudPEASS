"""Brief observations for the selected definition-command content reader."""
import re
from peaso.secret_scanning import merge_leaks

CHECK = 'aws.review.workload.selected_command_literal_secret_indicators'
UNKNOWN = {
    'Selected command literal coverage was incomplete. Secret absence could not be assessed.',
    'Selected command literal evidence was unavailable. Secret absence could not be assessed.',
    'Selected command literal evidence was missing, unsupported, incomplete or unbound. Secret absence could not be assessed.',
    'Selected ECS/classic Batch command evidence was unavailable, incomplete or unbound; images, environment files and EKS Batch are outside this check.',
}


def observation(finding):
    try:
        if finding.get('provider') != 'aws' or finding.get('check_id') != CHECK:
            return None
        e = finding['evidence']
        if finding['status'] == 'UNKNOWN' and e.get('observed') in UNKNOWN:
            return 'The selected ECS or Batch command literals could not be completely inspected.'
        if e.get('credential_validation') != 'not_attempted':
            return None
        leaks = e['secret_leaks']
        if not isinstance(leaks, list) or merge_leaks(leaks) != leaks:
            return None
        if finding['status'] == 'PASS' and not leaks and e.get('complete') is True and e.get('coverage') == 'selected_definition_command_literals_only':
            return 'Both offline detectors found no supported secret in the selected ECS or Batch command literals.'
        if (finding['status'] != 'FAIL' or len(leaks) != 1
                or finding.get('linked_check_ids') != [CHECK]
                or finding.get('secret_fingerprint') != leaks[0]['fingerprint']):
            return None
        for loc in leaks[0]['locations']:
            if (not re.fullmatch(r'aws_selected_workload_command_literals:leak:[0-9a-f]{64}', loc.get('resource_id', ''))
                    or not re.fullmatch(r'aws_selected_workload_command_literals:[0-9a-f]{64}:[0-9a-f]{64}', loc['path'])
                    or not re.fullmatch(r'[0-9]{12}/[a-z0-9-]+', loc.get('scope', ''))):
                return None
        partial = e.get('complete') is False
        if partial and e.get('coverage') != 'incomplete':
            return None
        return ('A likely secret was detected in selected ECS or Batch command literals. Its value is hidden and was not validated'
                + ('; inspection is incomplete.' if partial else '.'))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None

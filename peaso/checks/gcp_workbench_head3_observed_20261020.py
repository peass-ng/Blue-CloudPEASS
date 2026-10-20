"""Specific Workbench observations from the exact captured setting values."""
import re

RULES = {
    'gcp.review.workbench.terminal_access_disabled': ('notebook-disable-terminal', 'disabled', 'The notebook terminal is {} in Workbench settings.'),
    'gcp.review.workbench.file_download_disabled': ('notebook-disable-downloads', 'disabled', 'JupyterLab file downloads are {} in Workbench settings.'),
    'gcp.review.workbench.auto_upgrade_schedule_declared': ('notebook-upgrade-schedule', 'schedule_declared', ''),
}


def observation(finding):
    try:
        rule=RULES.get(finding.get('check_id'))
        if not rule or finding.get('provider')!='gcp' or finding.get('status')not in ('PASS','FAIL'):return None
        e=finding['evidence'];value=e[rule[1]]
        if (type(value)is not bool or (finding['status']=='PASS')!=value
                or e.get('setting')!='gceSetup.metadata.'+rule[0]
                or not re.fullmatch(r'projects/[A-Za-z0-9_-]+/locations/[a-z0-9-]+/instances/[A-Za-z0-9_-]+',e['instance'])):return None
        if finding.get('scope') is not None and not e['instance'].startswith(finding['scope']+'/locations/'):return None
        if rule[1]=='schedule_declared':
            return ('An automatic upgrade schedule is configured for this Workbench instance.' if value else
                    'This Workbench instance has no automatic upgrade schedule configured.')
        return rule[2].format('disabled' if value else 'enabled')
    except (KeyError,TypeError,ValueError,AttributeError):
        return None

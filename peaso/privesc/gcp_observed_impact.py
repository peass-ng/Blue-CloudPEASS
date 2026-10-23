"""Three-line GCP privilege-path copy over validated modeled evidence."""

import json
import re
from pathlib import Path

from .finding_explanation import evidence_summary as validated_summary


IMPACT = json.loads(Path(__file__).with_suffix('.json').read_text())


_VERTEX_CREATE_ACTION = {
    'gcp-vertex-customjobs-create-actas': 'Vertex AI custom job creation',
    'gcp-vertex-pipelinejobs-create-actas': 'Vertex AI pipeline job creation',
    'gcp-vertex-hptuningjobs-create-actas': 'Vertex AI tuning job creation',
    'gcp-vertex-batchprediction-create-actas': 'Vertex AI batch prediction creation',
    'gcp-vertex-models-upload-endpoint-deploy-actas': 'Vertex AI model upload and endpoint deployment',
    'gcp-vertex-reasoningengines-create-actas': 'Vertex AI reasoning engine creation',
    'gcp-vertex-notebookexecutionjobs-create-actas': 'Vertex AI notebook execution job creation',
    'gcp-vertex-workbench-instances-create-actas': 'Workbench instance creation',
}


_WORKFLOW_WORKSTATION_FACTS = {
    'gcp-workflows-create-actas-execute': (
        'workflow creation, execution, and service-account use grants',
        'the workflow creation, execution, or service-account use grant'),
    'gcp-workflows-create-cross-project-actas': (
        'Workflows creation, execution, and cross-project account attachment grants',
        'the target account policy or Workflows service-agent grant'),
    'gcp-workflows-update-actas': (
        'workflow update, execution, and service-account use grants',
        'the workflow update, execution, or service-account use grant'),
    'gcp-workflows-update-source-retain-sa': (
        'workflow source update and execution grants',
        'the attached account, workflow update grant, or execution grant'),
    'gcp-workflows-update-source-await-execution': (
        'workflow source update grant and an external execution path',
        'the attached account, workflow update grant, or later execution path'),
    'gcp-workstations-config-create-actas': (
        'workstation configuration, workstation creation, and service-account use grants',
        'the workstation cluster, creation grant, or service-account use grant'),
    'gcp-workstations-config-update-code': (
        'workstation configuration update and service-account use grants',
        'the pinned account, configuration update grant, or service-account use grant'),
    'gcp-workstations-use-existing-workstation': (
        'workstation use grants',
        'the workstation state, pinned account, or use grant'),
    'gcp-workstations-create-from-existing-config': (
        'workstation creation grants',
        'the configuration, pinned account, or workstation creation grant'),
}


def _reviewed_specific_fact(cid, confidence, source, target, count):
    """Name the recorded setting behind selected reviewed paths."""
    if cid in _VERTEX_CREATE_ACTION:
        action = _VERTEX_CREATE_ACTION[cid]
        if confidence == 'unknown':
            if count == 0:
                return f'The target service account for {source} is unresolved.'
            return f'The {action} or actAs grant for {source} is unresolved.'
        return f'{source} has recorded {action} and actAs grants for {target}.'
    if cid == 'gcp-vertex-customjob-custom-code-agent':
        if confidence == 'unknown':
            return f'The custom job creation grant or Custom Code Service Agent binding for {source} is unresolved.'
        return f'{source} has a recorded Vertex AI custom job creation grant linked to {target}.'
    if cid == 'gcp-vertex-reasoningengines-create-default-agent':
        if confidence == 'unknown':
            return f'The reasoning engine creation grant or service agent binding for {source} is unresolved.'
        return f'{source} has a recorded reasoning engine creation grant linked to {target}.'
    if cid == 'gcp-vertex-workbench-instance-update-or-setiampolicy':
        if confidence == 'unknown':
            return f'The Workbench instance state, attached service account, or takeover grant for {source} is unresolved.'
        return f'{source} has recorded takeover grants on a Workbench instance attached to {target}.'
    if cid == 'gcp-vmmigration-migratingvm-metadata-clone':
        if confidence == 'unknown':
            return f'The migrating VM target account or update and clone grants for {source} are unresolved.'
        return f'{source} has recorded update and clone grants on a migrating VM configured with {target}.'
    if cid == 'gcp-vmwareengine-privateclouds-setiampolicy-private-cloud-self-grant':
        if confidence == 'unknown':
            return f'The private cloud policy change or effective credential-read grant for {source} is unresolved.'
        return f'{source} has a recorded private cloud policy change granting it vCenter credential-read access.'
    if cid in ('gcp-vmwareengine-show-vcenter-credentials-external-principal',
               'gcp-vmwareengine-show-nsx-credentials-external-principal'):
        plane = 'vCenter' if 'vcenter' in cid else 'NSX'
        if confidence == 'unknown':
            return f'The usable {plane} credential or new allowed action for {source} is unresolved.'
        return f'{source} has a recorded {plane} credential read linked to {target}.'
    if cid == 'gcp-configcontroller-kcc-service-account-key':
        if confidence == 'unknown':
            return f'The Config Connector key permission or target service account for {source} is unresolved.'
        return f'{source} has recorded Config Connector key access linked to {target}.'
    if cid == 'gcp-configcontroller-kcc-resource-write':
        if confidence == 'unknown':
            return f'The watched namespace or controller project IAM rights for {source} are missing or unresolved.'
        return f'{source} has a recorded Config Connector policy-resource write path to {target}.'
    self_grants = {
        'gcp-artifactregistry-repositories-setiampolicy-repository-self-grant':
            ('Artifact Registry repository', 'upload'),
        'gcp-bigtable-instances-setiampolicy-instance-admin-self-grant':
            ('Bigtable instance', 'update'),
        'gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant':
            ('Network Connectivity hub', 'group-use'),
    }
    if cid in self_grants:
        resource, gained = self_grants[cid]
        if confidence == 'unknown':
            return f'The {resource} policy change or new {gained} access for {source} is unresolved.'
        return f'{source} has a recorded {resource} policy change granting new {gained} access.'
    return None


def _short(value, fallback):
    if isinstance(value, str) and value.strip() and len(value) <= 100 and re.fullmatch(r'[A-Za-z0-9@:/._+\-]+', value.strip()):
        return value.strip()
    return fallback


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'gcp':
        return None
    cid, status = finding.get('check_id'), finding.get('status')
    pair = IMPACT.get(cid, {}).get(status)
    if not pair or validated_summary(finding) is None:
        return None
    e = finding['evidence']
    source = _short(e['source'].get('label'), 'the source identity')
    targets = e['targets']
    count = e['target_count']
    if count == 1 and len(targets) == 1:
        target = _short(targets[0].get('label'), 'the target identity or resource')
    elif count > 1:
        target = f'{count} recorded targets'
    else:
        target = 'unresolved targets'
    confidence = e['confidence']
    if cid in _WORKFLOW_WORKSTATION_FACTS:
        present, missing = _WORKFLOW_WORKSTATION_FACTS[cid]
        if confidence == 'unknown':
            unresolved = next((condition for condition in e.get('conditions', ())
                               if condition and not condition.startswith('blocker_')), None)
            if unresolved:
                missing = unresolved.replace('_', ' ').replace('unresolved', '').replace('incomplete', '').strip()
            fact = f'The {missing} for {source} is not fully recorded.'
        else:
            fact = f'{source} has recorded {present} linked to {target}.'
    else:
        fact = None
    reviewed_fact = _reviewed_specific_fact(cid, confidence, source, target, count)
    if fact is not None:
        pass
    elif reviewed_fact is not None:
        fact = (reviewed_fact.replace(' is unresolved.', ' is missing or unresolved.')
                .replace(' are unresolved.', ' are missing or unresolved.')
                if confidence == 'unknown' else reviewed_fact)
    elif cid == 'gcp-resourcemanager-organizations-setiampolicy':
        if confidence == 'unknown':
            fact = f'The organization policy or prior access facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded IAM grant may let {source} change the policy on {target}.'
        else:
            fact = f'The recorded IAM grant lets {source} change the policy on {target}.'
    elif cid in ('gcp-resourcemanager-organizations-setiampolicy-deny-admin',
                 'gcp-resourcemanager-organizations-setiampolicy-role-admin'):
        if confidence == 'unknown':
            fact = f'The organization IAM policy or prior access facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded IAM grant may let {source} change the policy on {target}.'
        else:
            fact = f'The recorded IAM grant lets {source} change the policy on {target}.'
    elif cid == 'gcp-resourcemanager-projects-setiampolicy':
        if confidence == 'unknown':
            fact = f'The project IAM policy or prior access facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded IAM grant may let {source} change the policy on {target}.'
        else:
            fact = f'The recorded IAM grant lets {source} change the policy on {target}.'
    elif cid == 'gcp-resourcemanager-projects-setiampolicy-project-delete':
        if confidence == 'unknown':
            fact = f'The project policy or deletion access facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded IAM grant may let {source} change the policy on {target}.'
        else:
            fact = f'The recorded IAM grant lets {source} change the policy on {target}.'
    elif cid == 'gcp-resourcemanager-projects-setiampolicy-sa-token':
        if confidence == 'unknown':
            fact = f'The project or service account IAM facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded project IAM grant may let {source} add a role covering {target}.'
        else:
            fact = f'The recorded project IAM grant lets {source} add a role covering {target}.'
    elif cid == 'gcp-run-instances-create-update-actas':
        if confidence == 'unknown':
            fact = f'The Cloud Run instance state or access grants for {source} are incomplete.'
        else:
            fact = f'The recorded Cloud Run and service account grants may let {source} use {target}.'
    elif cid == 'gcp-run-instances-create-update-cross-project-actas':
        if confidence == 'unknown':
            fact = f'The host action, target policy, or service-agent grant for {source} is incomplete.'
        else:
            fact = f'The recorded host and service-account grants may let {source} attach {target}.'
    elif cid == 'gcp-run-instances-ssh':
        if confidence == 'unknown':
            fact = f'The instance state or SSH grant for {source} is incomplete.'
        else:
            fact = f'The recorded root SSH and service-account grants may let {source} use an instance running as {target}.'
    elif cid == 'gcp-run-ssh-into-running-instance':
        if confidence == 'unknown':
            fact = f'The service SSH setting, state, or access grants for {source} are incomplete.'
        else:
            fact = f'The recorded root SSH and actAs grants may let {source} enter a service using {target}.'
    elif cid == 'gcp-run-workerpools-create-update-actas':
        if confidence == 'unknown':
            fact = f'The worker pool state, API state, or access grants for {source} are incomplete.'
        else:
            fact = f'The recorded pool and account grants may let {source} run a worker pool as {target}.'
    elif cid == 'gcp-run-workerpools-setiampolicy-actas':
        if confidence == 'unknown':
            fact = f'The pool policy, grantable role, or account access for {source} is incomplete.'
        else:
            fact = f'The recorded pool policy may let {source} add missing update rights to a pool using {target}.'
    elif cid == 'gcp-run-jobs-create-run-actas':
        if confidence == 'unknown':
            fact = f'A required job grant, service-account grant, or API state for {source} is unresolved.'
        else:
            fact = f'The recorded grants may let {source} create and run a job as {target}.'
    elif cid == 'gcp-run-jobs-create-run-cross-project-actas':
        if confidence == 'unknown':
            fact = f'A Cloud Run host job grant, target policy, or service-agent grant for {source} is unresolved.'
        else:
            fact = f'The recorded host and service-account grants may let {source} use {target} for a Cloud Run job.'
    elif cid == 'gcp-run-jobs-runwithoverrides':
        if confidence == 'unknown':
            fact = f'The job command, readiness, or override grant for {source} is unresolved.'
        else:
            fact = f'The recorded job grants and interpreter command may let {source} run code as {target}.'
    elif cid == 'gcp-run-jobs-setiampolicy':
        if confidence == 'unknown':
            fact = f'The job policy, grantable role, or execution path for {source} is incomplete.'
        else:
            fact = f'The recorded job policy lets {source} add missing execution rights on a job using {target}.'
    elif cid == 'gcp-run-jobs-update-run-actas':
        if confidence == 'unknown':
            fact = f'The job state, update or run grant, or service-account access for {source} is incomplete.'
        else:
            fact = f'The recorded grants let {source} update and run a ready job with {target} attached.'
    elif cid == 'gcp-run-services-create-actas':
        if confidence == 'unknown':
            fact = f'The service creation grant, Cloud Run API state, or account access for {source} is incomplete.'
        else:
            fact = f'The recorded grants let {source} create a service using {target} in its project.'
    elif cid == 'gcp-run-services-create-cross-project-actas':
        if confidence == 'unknown':
            fact = f'The Cloud Run service grant, API state, target policy, or service-agent access for {source} is incomplete.'
        else:
            fact = f'The recorded host grant and target policy may let {source} attach {target} to a new Cloud Run service.'
    elif cid == 'gcp-run-services-setiampolicy-actas':
        if confidence == 'unknown':
            fact = f'The service policy, grantable role, or account access for {source} is incomplete.'
        else:
            fact = f'The recorded service policy lets {source} add missing update rights on a service using {target}.'
    elif cid == 'gcp-run-services-update-actas':
        if confidence == 'unknown':
            fact = f'The service state, update grant, or account access for {source} is incomplete.'
        else:
            fact = f'The recorded grants let {source} update a ready service to use {target}.'
    elif cid == 'gcp-resourcemanager-folders-setiampolicy':
        if confidence == 'unknown':
            fact = f'The folder policy or prior access facts for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded IAM grant may let {source} change the policy on {target}.'
        else:
            fact = f'The recorded IAM grant lets {source} change the policy on {target}.'
    elif cid == 'gcp-healthcare-datasets-setiampolicy-dataset-self-grant':
        if confidence == 'unknown':
            fact = f'The dataset or FHIR store evidence for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded policy may let {source} change the dataset IAM policy covering {target}.'
        else:
            fact = f'The recorded policy lets {source} change the dataset IAM policy covering {target}.'
    elif cid == 'gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant':
        if confidence == 'unknown':
            fact = f'The DICOM store or parent dataset policy evidence for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded policy may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded policy lets {source} change the IAM policy of {target}.'
    elif cid == 'gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant':
        if confidence == 'unknown':
            fact = f'The FHIR store or parent dataset policy evidence for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded policy may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded policy lets {source} change the IAM policy of {target}.'
    elif cid == 'gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant':
        if confidence == 'unknown':
            fact = f'The HL7v2 store or parent dataset policy evidence for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded policy may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded policy lets {source} change the IAM policy of {target}.'
    elif cid in ('gcp-iap-tunnelinstances-setiampolicy-instance-self-grant',
                 'gcp-iap-tunnelzones-setiampolicy-zone-self-grant'):
        policy = ('the IAP zone policy covering' if 'tunnelzones' in cid
                  else 'the IAP policy for')
        if confidence == 'unknown':
            fact = f'The IAP or VM policy evidence for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded grant may let {source} change {policy} {target}.'
        else:
            fact = f'The recorded grant lets {source} change {policy} {target}.'
    elif cid == 'gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant':
        if confidence == 'unknown':
            fact = f'The tenant IAM policy or inherited grants for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded grant may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded grant lets {source} change the IAM policy of {target}.'
    elif cid == 'gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant':
        if confidence == 'unknown':
            fact = f'The host IAM policy or inherited grants for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded grant may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded grant lets {source} change the IAM policy of {target}.'
    elif cid == 'gcp-logging-views-setiampolicy-self-grant':
        if confidence == 'unknown':
            fact = f'The log view IAM policy or inherited grants for {source} are incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded grant may let {source} change the IAM policy of {target}.'
        else:
            fact = f'The recorded grant lets {source} change the IAM policy of {target}.'
    elif cid == 'gcp-inframanager-deployments-create-actas':
        if confidence == 'unknown':
            fact = f'The deployment location or run-as access for {source} is incomplete.'
        elif confidence == 'conditional':
            fact = f'The recorded grants may let {source} create a deployment using {target}.'
        else:
            fact = f'The recorded grants let {source} create a deployment using {target}.'
    elif cid in ('gcp-sourcerepos-update-build-trigger', 'gcp-sourcerepos-setiampolicy'):
        if confidence == 'unknown':
            fact = f'The repository grant, linked trigger, or build account access for {source} is unresolved.'
        elif cid == 'gcp-sourcerepos-setiampolicy':
            fact = f'{source} can change the policy of a Cloud Source repository linked to a trigger using {target}.'
        else:
            fact = f'{source} can update a Cloud Source repository linked to a trigger using {target}.'
    elif confidence == 'unknown':
        fact = (f'No target identity or resource was resolved for {source}.' if count == 0
                else f'The saved path facts for {source} are incomplete.')
    elif cid == 'admin-equivalent':
        verb = 'may give' if confidence == 'conditional' else 'give'
        fact = f'The recorded grants {verb} {source} administrator access to {target}.'
    elif confidence == 'conditional':
        fact = f'The recorded grants link {source} to {target}, with remaining conditions.'
    else:
        fact = f'The recorded grants may let {source} reach {target}.'
    effect, impact = (line.replace('alice', source) for line in pair)
    return '\n'.join((fact, effect, impact))

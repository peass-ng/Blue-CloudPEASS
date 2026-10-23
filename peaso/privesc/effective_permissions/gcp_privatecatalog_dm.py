"""Bound a shared Service Catalog version to consumer project IAM authority."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

from . import Node, inventory_status, items


UPDATE = 'cloudprivatecatalogproducer.products.update'
GAIN = 'resourcemanager.projects.setIamPolicy'
PREFIX = '//cloudresourcemanager.googleapis.com/'


@lru_cache(maxsize=1)
def _sensitive_mutations():
    categories = yaml.safe_load((Path(__file__).resolve().parents[3] /
                                 'gcp_permissions_cat.yaml').read_text())
    suffixes = ('.create', '.update', '.delete', '.setiampolicy',
                '.actas', '.getaccesstoken', '.signblob', '.signjwt')
    return tuple(sorted({permission.lower() for group in ('high', 'critical')
                         for permission in categories[group]
                         if permission.lower().endswith(suffixes)}))


def _other_sensitive_gain(model, agent, source, project):
    """Surface unmodeled downstream actions without asserting template execution."""
    agent_roles = [model.roles.get(role) for _, role, _, _ in agent.attrs.get('grants', ())]
    for permission in _sensitive_mutations():
        if permission == GAIN.lower() or not any(
                role is not None and role.has(permission) for role in agent_roles):
            continue
        allowed = model.check(agent, {'action': permission}, project)
        if allowed is None:
            continue
        prior = model.check(source, {'action': permission}, project)
        if prior is None or prior.confidence != 'derived':
            return True
    return False


def candidates(model):
    """Only named versions associated with a verified consumer hierarchy."""
    out = {}
    projects = []
    counts = {}
    for scope, row in items(model.snapshot, 'project'):
        project = model._norm_scope(scope)
        number = str(row.get('name', '')).removeprefix('projects/')
        if (not re.fullmatch(r'projects/[^/]+', project)
                or not number.isdecimal() or row.get('projectId') != project.split('/', 1)[1]):
            continue
        counts[project] = counts.get(project, 0) + 1
        projects.append((project, number))
    for version, row in model.service_catalog_versions.items():
        if (row.get('assetType') != 'google.deploymentmanager.Template'
                or row.get('validatedAssetPresent') is not True):
            continue
        targets = {model._norm_scope(value.removeprefix(PREFIX))
                   for value in row['consumerTargets'] if value.startswith(PREFIX)}
        for project, number in projects:
            if counts[project] != 1 or not targets.intersection(model.ancestors(project)):
                continue
            agent = 'serviceAccount:' + number + '@cloudservices.gserviceaccount.com'
            ident = 'gcp_verified_authority:privatecatalog-dm-project-iam:' + version + ':' + project
            out[ident] = Node(ident, 'gcp_verified_authority', 'gcp', project,
                              f'Project IAM control through {version} in {project}',
                              attrs={'resource': project, 'scope': project,
                                     'host_resource': version, 'consumer_agent': agent,
                                     'catalog': row['catalog']}, entity=True)
    return out


def select(model, candidates, source):
    if source is None or source.kind not in ('gcp_user', 'gcp_service_account'):
        return {}
    out = {}
    statuses = inventory_status(model.snapshot, 'service_catalog_version')
    project_status = inventory_status(model.snapshot, 'project')
    for ident, node in candidates.items():
        version = node.attrs['host_resource']
        project = node.scope
        org = model.ancestors(version)[-1]
        if statuses.get(org) != 'collected' or project_status.get(project) != 'collected':
            out[ident] = ('unknown', 'catalog_or_consumer_inventory_incomplete')
            continue
        update = model.check(source, {'action': UPDATE}, version)
        if update is None:
            continue
        agent = model.principals.get(node.attrs['consumer_agent'])
        if agent is None:
            out[ident] = ('unknown', 'consumer_service_agent_not_verified')
            continue
        target_access = model.check(agent, {'action': GAIN}, project)
        if target_access is None:
            if _other_sensitive_gain(model, agent, source, project):
                out[ident] = ('unknown', 'other_consumer_agent_authority_requires_template_review')
            continue
        prior = model.check(source, {'action': GAIN}, project)
        if prior is not None and prior.confidence == 'derived':
            continue
        if (update.confidence != 'derived' or target_access.confidence != 'derived'
                or prior is not None):
            out[ident] = ('unknown', 'catalog_update_or_new_consumer_iam_authority_unresolved')
            continue
        out[ident] = ('conditional', 'consumer_must_deploy_validated_shared_version')
    return out

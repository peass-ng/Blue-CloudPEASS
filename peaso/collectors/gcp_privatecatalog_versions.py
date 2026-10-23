"""Read exact Service Catalog versions and their consumer associations."""

from __future__ import annotations

import re

from .gcp import ReadError


HOST = 'https://cloudprivatecatalogproducer.googleapis.com/v1beta1/'
CATALOG = re.compile(r'catalogs/[^/]+')
PRODUCT = re.compile(r'catalogs/[^/]+/products/[^/]+')
VERSION = re.compile(r'catalogs/[^/]+/products/[^/]+/versions/[^/]+')
ASSOCIATION = re.compile(r'catalogs/[^/]+/associations/[^/]+')
TARGET = re.compile(r'//cloudresourcemanager.googleapis.com/(?:projects|folders|organizations)/[^/]+')


def scope_jobs(collector, scope):
    if 'service_catalog_version' not in collector.needed or not scope.startswith('organizations/'):
        return []

    def fetch():
        seen_catalogs = set()
        parent = '//cloudresourcemanager.googleapis.com/' + scope
        for catalogs, request_id in collector.pages(
                HOST + 'catalogs', scope, key='catalogs', params={'parent': parent}):
            yield [], request_id
            for catalog in catalogs:
                name = catalog.get('name')
                if (not isinstance(name, str) or not CATALOG.fullmatch(name)
                        or catalog.get('parent') != parent or name in seen_catalogs):
                    raise ReadError('malformed', 'service_catalog_identity_invalid')
                seen_catalogs.add(name)
                policies = []
                for page, policy_request in collector.pages(
                        HOST + name + ':getIamPolicy', scope, single=True):
                    policies.extend(page)
                    yield [], policy_request
                if (len(policies) != 1 or not isinstance(policies[0].get('bindings', []), list)
                        or any(not isinstance(binding, dict)
                               or not isinstance(binding.get('role'), str)
                               or not isinstance(binding.get('members'), list)
                               for binding in policies[0].get('bindings', []))):
                    raise ReadError('malformed', 'service_catalog_policy_invalid')
                policy = policies[0]
                targets = set()
                seen_associations = set()
                for associations, association_request in collector.pages(
                        HOST + name + '/associations', scope, key='associations'):
                    yield [], association_request
                    for association in associations:
                        association_name = association.get('name')
                        target = association.get('resource')
                        if (not isinstance(association_name, str)
                                or not ASSOCIATION.fullmatch(association_name)
                                or not association_name.startswith(name + '/')
                                or association_name in seen_associations
                                or not isinstance(target, str) or not TARGET.fullmatch(target)):
                            raise ReadError('malformed', 'service_catalog_association_invalid')
                        seen_associations.add(association_name)
                        targets.add(target)
                seen_products = set()
                for products, product_request in collector.pages(
                        HOST + name + '/products', scope, key='products'):
                    yield [], product_request
                    for product in products:
                        product_name = product.get('name')
                        if (not isinstance(product_name, str) or not PRODUCT.fullmatch(product_name)
                                or not product_name.startswith(name + '/')
                                or product_name in seen_products):
                            raise ReadError('malformed', 'service_catalog_product_invalid')
                        seen_products.add(product_name)
                        seen_versions = set()
                        for versions, version_request in collector.pages(
                                HOST + product_name + '/versions', scope, key='versions'):
                            for version in versions:
                                version_name = version.get('name')
                                if (not isinstance(version_name, str)
                                        or not VERSION.fullmatch(version_name)
                                        or not version_name.startswith(product_name + '/')
                                        or version_name in seen_versions):
                                    raise ReadError('malformed', 'service_catalog_version_invalid')
                                seen_versions.add(version_name)
                                yield [{
                                    'name': version_name,
                                    'product': product_name,
                                    'catalog': name,
                                    'catalogParent': parent,
                                    'catalogIamPolicy': policy,
                                    'assetType': product.get('assetType'),
                                    'validatedAssetPresent': isinstance(version.get('asset'), dict),
                                    'consumerTargets': sorted(targets),
                                }], version_request

    return [('service_catalog_version', scope, 'cloudprivatecatalogproducer', fetch)]


def collect(collector):
    scopes = set(collector.scopes) | set(getattr(collector, 'inherited_scopes', ()))
    collector.run_jobs([job for scope in sorted(scopes) for job in scope_jobs(collector, scope)])

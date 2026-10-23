"""Ordered candidates for native federated-credential identity correlations."""
from peaso.snapshot import FrozenDict


class AzureFederationIndex:
    def __init__(self, by_type):
        from .cloud_workload_index import CloudWorkloadIndex
        self.by_type = by_type
        self.index = CloudWorkloadIndex(by_type)

    def service_principals(self, credential):
        rows = self.by_type['directory_service_principal']
        if not rows or type(credential) is not FrozenDict:
            return rows
        app_id = credential.get('appId')
        if app_id is None or type(app_id) is str and not app_id:
            # The literal predicate never reads a service principal when the
            # credential has no appId; do not build an unused source index.
            return []
        if type(app_id) is not str:
            return rows
        return self.index.candidates('directory_service_principal', 'azure_federation_app_id', [app_id])

    def managed_identities(self, credential, parent):
        rows = self.by_type['managed_identity']
        if not rows or type(credential) is not FrozenDict:
            return rows
        return self.index.candidates('managed_identity', 'azure_federation_identity_id', [parent], lower=True)

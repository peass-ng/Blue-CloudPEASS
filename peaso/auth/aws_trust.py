"""Fail closed before using a shared collector to read customer accounts."""
import secrets


class UnsafeRoleTrust(Exception):
    pass


def require_external_id_boundary(assume, external_id):
    """The same AssumeRole request must reject absent and unrelated IDs.

    `assume` accepts an optional ExternalId and must otherwise use exactly the
    real exchange's principal, role, session name, duration and parameters.
    Discard any probe credentials; never use them for customer reads.
    """
    if not isinstance(external_id, str) or not external_id:
        raise UnsafeRoleTrust('external_id_required')
    # Keep our issued namespace so a wildcard accepting all CSPM workspaces
    # cannot masquerade as an exact customer/workspace binding.
    prefix = ('hacktricks-cspm-ws-' if external_id.startswith('hacktricks-cspm-ws-') else
              'hacktricks-cspm-' if external_id.startswith('hacktricks-cspm-') else 'peaso-')
    for probe in (None, prefix + secrets.token_urlsafe(48)):
        try:
            assume(probe)
        except Exception as exc:
            code = getattr(exc, 'code', None) or getattr(exc, 'response', {}).get('Error', {}).get('Code')
            if code in {'AccessDenied', 'AccessDeniedException'}:
                continue
            raise UnsafeRoleTrust('external_id_trust_unverified') from None
        raise UnsafeRoleTrust('external_id_not_required_by_trust')

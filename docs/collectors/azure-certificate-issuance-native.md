# Public X.509 certificate issuance evidence

`azure_certificate_issuance_native` projects `certificate_issuance` from the existing
`azure_swc.collect_current_certificates` / `key_vault_certificate` inventory. It
accepts no transport and makes no network requests. Selecting it requires the
existing current-certificate inventory and vault inventory; those existing readers
still perform their normal bounded metadata requests. No certificate-version,
secret, key, TLS handshake or private-key read is added by this projection.

For each exact, versioned native Get Certificate `cer`, the helper derives:

- `authority=x509_not_before` and `issued_at` from X.509 NotBefore as UTC ISO8601;
- `serial` as lowercase unsigned hexadecimal, padded to an even number of digits
  (`1` becomes `01`), without separators;
- `thumbprint` as lowercase SHA1 of the exact DER bytes, without separators;
- exact native certificate version ID, scoped ARM vault/name identity, original
  current GET request URI and API version, plus public DER SHA256 provenance.

SHA1 here is a certificate identifier for existing serial/thumbprint joins, not a
signature or trust decision. NotBefore is the certificate's validity start, not a
claim that a trusted CA issued it at that precise time. The signed SW20 contract
explicitly permits this `x509_not_before` authority. Vault `attributes.created`,
retention, version count, import time and policy issuance procedures are not used.
Certificate chains, CA trust, revocation and actual endpoint deployment are not
attested by this component.

The helper validates exact subscription/vault/name/version joins and native
provenance. It rejects malformed or foreign identities, missing/full-GET evidence,
malformed/oversized/noncanonical DER, duplicate current names or output IDs, and
ambiguous serial/thumbprint joins. Only allowlisted derived fields are emitted;
`sid`, private keys, arbitrary native properties, subject names and DER payloads
are never copied into the issuance collection. No link from a response is followed.

Projection is capped at 50,000 source certificates per scope and 131,072 base64
characters per public DER. It also uses the existing reader's resource budget.
A complete current-certificate source needs its native vault/page/current-version
coverage proof; its completeness means only that current Key Vault inventory.
Known facts from a partial source remain partial. Access denied remains denied;
timeout remains timeout. Missing, contradictory or ambiguous inputs remain
unavailable, and no completeness of the public TLS universe or certificate history
is inferred. No `vault_certificate` endpoint or public-TLS coverage is manufactured.
Both 90/180-day rotation controls remain UNKNOWN without separately collected
native active/served endpoint identity and full approved service-universe evidence.

## Integration owned by the Azure collector integrator

These are four hook sites, supplied as instructions; this component does not edit
`azure.py`, hosted validation or the signed evaluators.

1. Import `from . import azure_certificate_issuance_native` next to the other native helpers.
2. Add `"certificate_issuance"` to the existing `TYPES` tuple.
3. In `_selected`, add
   `selected.update(azure_certificate_issuance_native.required_types(selected))`
   before existing dependency expansion completes. This requests
   `key_vault_certificate` and `vault`, without a new source-collection alias.
4. After the existing `azure_swc.collect_current_certificates(...kind default...)`
   invocation has settled, invoke
   `azure_certificate_issuance_native.collect(reader, scopes, wanted)`.
   Keep the existing current-certificate reader call conditional so one selected
   source inventory is fetched exactly once.

## Focused offline validation

The portable test file uses normal package imports. It exercises the existing
native current-certificate reader with an inert in-process API response containing
public DER, then proves the projection adds zero requests. Other cases cover
identity/provenance rejection, duplicate and malformed data, source completeness,
resource limits and both signed rotation evaluators staying UNKNOWN. Synthetic
certificates are generated offline; no fixture key is persisted. These are offline
transport tests, not live Azure observations or a closure claim.

## Official references

- [Azure Key Vault Get Certificate, API 2025-07-01](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01): the `cer` response is public X.509 certificate content.
- [Cryptography X.509 reference](https://cryptography.io/en/stable/x509/reference/): `load_der_x509_certificate`, `not_valid_before_utc`, `serial_number`, `fingerprint`, and DER serialization.

Runtime parser dependency is already declared as `cryptography>=43`; this component
introduces no additional SDK, IAM/RBAC permission or outbound endpoint.

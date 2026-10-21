# AWS federation provider role consumers

Two native Hardening controls inspect current IAM SAML and OIDC providers:
`aws.iam.saml_provider_has_role_consumer` and
`aws.iam.oidc_provider_has_role_consumer`. They report a structural absence of
declared role consumers, not provider authentication or an unused-day interval.

`ListSAMLProviders` and `ListOpenIDConnectProviders` supply the global provider
ARNs. `GetAccountAuthorizationDetails` supplies the account-wide `RoleDetail`
trust documents. The evaluator requires an exact same-account provider ARN and
one matching scoped IAM collection projection. A role consumes the provider
when an Allow trust statement names its exact ARN as a Federated principal and
declares the matching STS SAML or web identity assume action. Conditions do not
erase that declaration. Deny statements alone are not consumers.

A known valid role reference produces PASS even when unrelated role enumeration
is partial. FAIL requires a complete role collection and complete, valid trust
documents for every captured role. Missing, denied, malformed, wildcard or
negative principal semantics leave absence unresolved. Provider list rows do
not carry a collector-added provenance object; the current global IAM
collection, account binding and exact resource projection establish their
native list source. Role rows require the collector's complete
`iam:GetAccountAuthorizationDetails` provenance marker.

Both checks use the engine's existing `MemoIndex` for one role trust scan per
scope. Their PASS, FAIL and UNKNOWN cases are SHA-256 bound at installation;
the focused test also exercises the real Hardening engine path. The root
integration owner adds the installation hook and catalog metadata.

## Official source review

The SHA-256 values below identify the downloaded HTML bytes reviewed on
2026-10-21. They are source records, not runtime evidence.

| AWS documentation | SHA-256 |
| --- | --- |
| [ListSAMLProviders](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListSAMLProviders.html) | `693797e7528d344a430baa1abd89f3568260bb0a5d7f4f25b98fb46a838e99bf` |
| [ListOpenIDConnectProviders](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListOpenIDConnectProviders.html) | `696bcd07f60d82833614447d8a33bb22b4fafde41cb30f985c0655af5da547e1` |
| [RoleDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleDetail.html) | `f7d727d81898d1a9ec42eab1febac0c6375d9c8ec4a3b2553be8564ad049cda3` |
| [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) | `ec4fae3eb4376c183890357e1ec2d624d45303f3a9d1a5528de02de6992c704b` |
| [Policy Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html) | `c70f6a144fcf426d272283c5500b876010b8c8f5c70461916a45a1addaa345db` |
| [Create a SAML provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml.html) | `a36d0a8e7b23252436c0b1560c5cc191bcd432ec88ef2b244606ca059222c43a` |
| [Create an OIDC provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) | `c69aea104f5fb072a2a2083e5a6008de9ef6d09e456f911752fb76cda52ec202` |

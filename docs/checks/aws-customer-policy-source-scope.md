# Customer-managed IAM wildcard source correction

Six mapped IAM checks now evaluate the customer-managed default-policy population used by the pinned Steampipe iam_policy_no_star_star and iam_all_policy_no_service_wild_card queries. Unattached customer policies remain in scope. AWS-owned managed policies and inline policy documents cannot fail these controls. The resource must be literal *, and Action follows the original full-administrator or service-wildcard predicate. These are configuration checks, not claims of effective access.

A complete ListPolicies request uses Scope=Local and OnlyAttached=False, followed by complete matching default-version documents. Denied, partial, malformed, foreign, duplicate or mismatched evidence cannot pass. The general AWS managed library remains explicitly collectible, while the default plan omits it when no selected consumer requires it. This avoids retrieving the provider policy library just to assess customer policies.

The previous broad local specifications are preserved as historical source records. Versioned successor metadata pins the frozen specification digest, original upstream SQL digest, current specification and predicate digests, and corrected scope. No broader local risk rule is credited as this upstream compliance control.

The pinned source is https://github.com/turbot/steampipe-mod-aws-compliance/blob/803dda1f7555ed5cea959aef30cfa0719b030d8c/conformance_pack/iam.pp (full-administrator query at lines782-820 and service-wildcard query at1240-1277). Tests cover source-scope exclusions, unattached violations, exact literal wildcard cases and failure-state preservation through SDK Stubber and the real engine. No new mutating API operation is introduced.

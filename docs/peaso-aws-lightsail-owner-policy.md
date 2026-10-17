# Explicit Lightsail bucket IAM review criteria

The owner declaration for `aws_cis_lightsail_bucket_iam_policy` belongs in
`options.compliance_parameters.aws_lightsail_bucket_iam`. It supplies the approved
management-policy criteria; it does not supply observed policy documents,
attachments, principal membership, credentials or effective authorization.

```json
{
  "compliance_parameters": {
    "aws_lightsail_bucket_iam": {
      "status": "collected",
      "scope": "111122223333/us-east-1",
      "observed_at": "2026-10-16T12:00:00+00:00",
      "max_age_seconds": 3600,
      "parameters": {
        "iam_required_lightsail_bucket_arns": [
          "arn:aws:lightsail:us-east-1:111122223333:Bucket/01234567-abcd-4321-abcd-012345678901"
        ],
        "approved_lightsail_principals": [
          "arn:aws:iam::111122223333:role/team/fixture-reader"
        ],
        "approved_lightsail_actions": ["lightsail:UpdateBucket"]
      }
    }
  }
}
```

These are fictional example identifiers, not a default approval. The operator
must provide actual intended bucket ARNs, IAM user/role ARNs and approved actions.
The declaration records an operator-supplied review; it does not independently
verify the reviewer or grant any of the named permissions.

The namespace accepts exactly `status`, `scope`, `observed_at`, `max_age_seconds`
and `parameters`, and exactly the three illustrated parameter names. `status`
must be `collected`. Time must be an explicitly timezone-aware ISO8601 string of
at most 64 characters. Review age must be an integer from 1 to 31,536,000 seconds;
booleans, floats and null values are rejected. The original approval timestamp is
preserved verbatim. When collection occurs before that time or after its approved
age, projected metadata has `status=unknown` and
`owner_authority_status=stale_or_future`; collection never refreshes approval.
The expiry boundary itself remains within the approved interval.

Bucket and principal lists contain 1–1,000 nonempty strings, each at most 2,048
characters, without exact duplicates. Bucket ARNs must identify a `Bucket` in the
same account, region and partition as the scope. Principal ARNs must be IAM users
or roles in the same account and partition; root, STS sessions, wildcard principals
and foreign account/partition principals are rejected. ARN resource identifiers
retain their original case. A regional scope must match the one explicit connector
scope exactly; absent, account-only, global, duplicate, different-region or multiple
connector scopes are rejected before AWS credential/session construction. The
partition follows the declared region (`aws`, `aws-cn`, or `aws-us-gov`); accepting
criteria for a partition is not a claim of deployed credential or regional support.

Actions must be explicit, distinct under case folding, and support bucket resource
scoping in the reviewed AWS service authorization table. This component admits
only `lightsail:` actions `CreateBucketAccessKey`, `DeleteBucket`,
`DeleteBucketAccessKey`, `SetResourceAccessForBucket`, `TagResource`, `UntagResource`,
`UpdateBucket`, and `UpdateBucketBundle`. It executes none of these actions.
Wildcards and other actions, including `CreateBucket`, `GetInstance` and
`GetBucketAccessKeys`, are rejected as criteria for this bounded resource-scoped
assessment. The approved-action list is bounded by the size of this action set.

[AWS Lightsail's Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_lightsail.html)
is the primary source for action/resource support. This declaration concerns
Lightsail management IAM policy statements; it does not prove S3-compatible
object-data access, successful API use or effective permission after SCPs, session
policies, permissions boundaries, resource policies and explicit denies.

Both local and Cognito connector intake validate the same namespace and reject
it for other providers. The existing hosted compliance-parameters JSON limit of
50,000 characters also applies, so a declaration can exceed the total hosted size
limit before reaching an individual list bound. Saving valid criteria is separate
from authenticating a connector. Hosted AWS authentication still requires its
existing approved schema; the offline tests use a fictional customer role and
server-generated-style ExternalID with `retries=1`, without requesting credentials
or accessing a cloud account.

## Isolation from observations and other approvals

Policy documents, attachments, observed state and extra fields are rejected in
this namespace. It cannot be combined with a raw `options.compliance_policy`
containing any flat approval-authority field (`status`, `scope`, `observed_at`,
`max_age_seconds`), `parameters`, or any of the three Lightsail criteria fields,
even when values match. This prevents later shallow bulk-evidence merges from
rebinding approval authority or replacing criteria. Independent namespace-only
reviews can coexist; their contents and original authority remain separate.
Internal metadata merging preserves unrelated namespaced reviews, deep-copies
inputs, and rejects conflicting existing flat values without mutating metadata.

The helper projects only owner criteria into `metadata.compliance_policy`. Actual
bucket and IAM attachment facts require separate native collectors and coverage
proof. Missing or unavailable native evidence is not replaced by this declaration.
The owner-policy tests cover only declaration validation, scope/credential
ordering and metadata behavior. They do not execute the new native attachment
collector, run cloud tests, establish effective authorization, or claim that the
Lightsail control or product is complete.

# Findings, observations and cloud scope

The findings view shows one result per check. A check that finds the same issue
in several Regions or resources has one card. Its observed evidence lists the
affected accounts, Regions and assets, with each asset's own evidence and status.
Long lists are paginated; pagination does not discard observations.

For example, missing GuardDuty detectors in several AWS Regions appear together.
Log groups with insufficient retention appear together with their individual
names, Regions and retention values. Account-wide IAM checks, including root
MFA, execute once per account and have no Region label.

## Verdicts and filters

A group fails if any observation fails. Unknown or denied observations remain
visible, including when another observation fails. Without a failure, unresolved
observations prevent a group from passing. The status counts show mixed results;
an incomplete assessment is never converted into a pass.

Filters apply to individual observations before grouping. Selecting UNKNOWN, for
example, shows the unresolved observations even if that check also has failures.
An individual observation can still be opened for its exact technical evidence.
Coverage continues to record the individual evaluations.

## Collection and evaluation

AWS global inventory is collected once per account. Scoped checks whose declared
dependencies are all global run once at `<account>/global`, unless their native
evaluator explicitly requires a regional context. This also applies when the
inventory is missing. Regional checks still evaluate every selected Region;
their results are combined for presentation. Resource checks evaluate each
resource. A globally enumerated resource can still have a physical Region,
such as an S3 bucket; global enumeration does not remove that location.

GCP checks use their project, folder, organization or resource scope. Azure checks
use subscription/resource scope, with tenant-wide checks using verified tenant
evidence. Neither provider acquires an artificial per-Region evaluation loop.
The same grouping rule also applies to Kubernetes findings.

## Reports and API

New CLI JSON and Markdown reports contain one entry per check. JSON group entries
retain every original observation in `observations`; `status_counts` records each
outcome. Statistics distinguish check groups from original observations.

The web app also groups historical scans without rerunning them or changing their
original evidence. Its download action requests a grouped copy of an old report.
Historical duplicates are retained as original observations; new account-wide
evaluations run only once per account.

The API accepts `aggregation=check` on findings, summary and report routes. Group
details are available at `/api/scans/{scan}/finding-groups/{group}` with
`members_offset` and `members_limit` (up to 100). The original observation-detail
route remains available. Without aggregation, the findings API retains its
individual-observation response for existing clients.

Scope classification and grouping are tested against every registered native
check. This verifies scope and presentation contracts; it does not claim that
every check has been exercised against a live customer cloud account.
The per-check classification is recorded in [the scope review](check-scope-review.csv),
including registered checks that are currently excluded from execution.

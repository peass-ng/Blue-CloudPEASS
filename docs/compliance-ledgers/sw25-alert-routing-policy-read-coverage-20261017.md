# SW25 alert routing: optional policy read coverage

The Azure alert-routing control can evaluate native configured action-group declarations without an owner-supplied required action-group ID. That default applies only when the SW25 policy fields are genuinely absent. A declared but unreadable `sw25_policy`, `compliance_policy`, or nested `sw25` field yields UNKNOWN, including a denied or partial `_coverage` entry whose value is omitted.

A valid modern SW25 policy containing requirements for other checks keeps the routing ID optional. An existing legacy requirement for the routing ID retains its documented precedence. The native declaration proves configured routing only; it does not establish receiver availability, notification delivery, or runtime alert firing.

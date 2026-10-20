# Selected Function configuration declarations (proposal)

These two unregistered checks assess declared Application Insights settings and
the automatic major4 Functions runtime update channel. They do not scan for
leaks, run detectors, test telemetry delivery, validate destinations, or resolve
the current runtime build. Existing groups are **Monitoring & alerts** and
**Patching & versions**. No numbered compliance equivalence is proposed.

Future integration must require all three selectors before authenticating:

- `content_secret_scans: true`, because the native response can contain secrets.
- At least one exact named check: `azure.review.function.application_insights_setting_declared`
  or `azure.review.function.runtime_major4_update_channel_declared`.
- `selected_azure_function_settings`: one to four exact Function app ARM IDs in
  explicitly selected subscription scopes, for example
  `/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Web/sites/selected-function`.

The flag name authorizes this sensitive configuration read; these particular
checks do **not** perform a secret scan. Global, category, framework, wildcard
or internal-inventory selection alone must not authorize the read. Slots,
arbitrary URLs, escaped paths and broad app enumeration are excluded.

The only native operations are:

| Read | API version | Minimum existing permission |
| --- | --- | --- |
| Exact selected subscription GET, verifying its subscription ID and tenant | `2022-12-01` | `Microsoft.Resources/subscriptions/read` |
| Exact selected `Microsoft.Web/sites` GET | `2025-03-01` | `Microsoft.Web/sites/read` |
| Exact selected site's `config/appsettings/list` POST, with no request body | `2025-03-01` | `Microsoft.Web/sites/config/list/action` |

ARM Reader alone does not grant the appsettings list action. This proposal
adds no role or grant. Scope any separately approved sensitive-read permission
to the selected apps. Subscription metadata permission is used for tenant
binding, not subscription enumeration. The POST is a documented read operation;
no keys/listKeys, secret-store payloads, reference resolution, app execution,
telemetry ingestion requests, deployment, or configuration writes occur.

All reads use `management.azure.com`; endpoint overrides and redirects are not
followed. At most twelve reads, two MiB per response, eight MiB total and a
sixty-second read window are permitted. Settings are additionally limited to
512 strings, 64 KiB per value and 256 KiB combined values. Native SDK credential
acquisition retains the existing transport's timeout/cancellation behavior;
the reader checks its deadline before and after token acquisition and performs
no HTTP read if that deadline has elapsed. It cannot forcibly preempt an
external credential implementation blocked inside `get_token`.

Only fixed typed declaration states and keyed locators leave the ephemeral
projection. Raw settings, setting names beyond the fixed indicators, connection
strings, native error bodies and credentials are not retained. The existing
matched-value union scrub runs after adding these metadata facts; its overflow
behavior still withholds output. SDK DEBUG logging is suppressed for this call's
thread and restored afterwards.

An absent/empty setting differs from a masked value or Key Vault reference.
References and masks remain unresolved. Two literal telemetry settings still
prove presence; their suitability or mutual configuration is outside this
declaration criterion. Flex Consumption manages the extension setting through
the platform, and custom images select their Function host, so the classic
update-channel criterion is not applicable there. A deliberate explicit major4
build pin fails only the automatic-channel declaration criterion; it is not
reported as an unsupported or outdated build. Unresolved native hosting remains
UNKNOWN for the runtime criterion.

Primary contracts: [Appsettings list](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-03-01),
[site GET](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get?view=rest-appservice-2025-03-01),
[Functions settings and Flex exceptions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-app-settings),
and [Functions monitoring](https://learn.microsoft.com/en-us/azure/azure-functions/configure-monitoring).

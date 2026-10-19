# Native Cloud SQL backup alert review

`gcp_cloudsql_backup_failure_alert` now consumes native alert and log-metric declarations instead of the nonexistent `filterMatchesFailedCloudSqlBackupRun` marker. The configured event is the final scheduled backup-window failure (`STATUS_FAILED`), not a recoverable failed attempt.

The bounded contract supports exact conjunctions for the Cloud SQL resource, automated-backup method and failed-window status; either a native direct LogMatch or a compatible integer-delta counter with an independent zero-threshold condition can establish configured coverage. Missing enabled state, unknown restrictions or unsupported threshold semantics remain UNKNOWN. Invalid policies do not establish an alert. This checks local configuration, not delivery, centralized alerting or actual incident detection.

Final directed acceptance: **70 passed**, including installed collector → engine positive, absent, disabled, restricted and denied paths, native evidence examples, current fixture parity and predicate source guards. A preceding affected-module cohort passed 5,503 tests before the final native validity safeguards. These receipts are separate, not a fresh complete suite or live-cloud certification. Exact hashes, APIs and limitations: [review record](backup-alert-native-review.json).

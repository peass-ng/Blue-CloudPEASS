# Native AWS Backup report plan applicability

The pinned upstream backup_report_plan_configured query is not applicable when a region has no backup plan. A complete empty backup-plan inventory now yields NOT_APPLICABLE rather than asking for owner review. With backup plans, complete report-plan presence passes and complete absence fails; missing, partial and denied evidence cannot pass.

ListReportPlans already has a native producer. Its SDK model can return NextToken without advertising a paginator. The collector now follows that token through the existing shared scheduler, preserving read budgets and account/region provenance. It does not add a duplicate enumeration or DescribeReportPlan call.

The engine existing empty-applicability gate retains denied report-plan evidence while accepting complete absence of backup plans as conclusive non-applicability. A denied or partial backup-plan inventory cannot take that path. Tests use real SDK Stubber responses through the collector and actual evaluator, not a live regional test.

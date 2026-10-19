"""Project short, check-specific observations without changing recorded findings."""


def evidence_summary(finding):
    if not isinstance(finding, dict):
        return None
    provider = finding.get('provider')
    cid = finding.get('check_id')
    if isinstance(cid, str) and cid.startswith('analysis.'):
        if cid == 'analysis.internet_exposure':
            evidence = finding.get('evidence')
            observed = evidence.get('observed') if isinstance(evidence, dict) else None
            if isinstance(observed, str) and observed.strip() and len(observed) <= 500:
                return observed.strip()
            return None
        from peaso.analysis.finding_clarity import evidence_summary as analysis
        return analysis(finding)
    if provider == 'k8s':
        # No static failure-prose fallback: malformed witnesses stay unclaimed.
        from peaso.checks.k8s_observed_configuration import evidence_summary as k8s
        return k8s(finding)
    if provider == 'gcp':
        from peaso.checks.gcp_observed_evidence import evidence_summary as gcp
        observation = gcp(finding)
        if observation:
            return observation
    if provider == 'azure':
        from peaso.checks.azure_bulk_observed_evidence import evidence_summary as azure
        observation = azure(finding)
        if observation:
            return observation
    if provider == 'aws':
        from peaso.checks.aws_scope_observed_evidence import evidence_summary as aws_scope
        from peaso.checks.aws_core_observed_evidence import evidence_summary as aws_core
        from peaso.checks.aws_typed_finding_summary import evidence_summary as aws
        from peaso.checks.aws_pass_observed_evidence import evidence_summary as aws_pass
        observation = aws_scope(finding) or aws_core(finding) or aws(finding) or aws_pass(finding)
        if observation:
            return observation
    from peaso.checks.gcp_remaining_finding_summary import evidence_summary as gcp_remaining
    from peaso.checks.aws_database_clarity_reviewed import evidence_summary as database
    from peaso.analysis.finding_clarity import evidence_summary as analysis
    from peaso.checks.azure_bulk_finding_summary import evidence_summary as azure_bulk
    from peaso.checks.aws_remaining_finding_summary import evidence_summary as aws_remaining
    from peaso.checks.aws_final_clarity_reviewed import evidence_summary as aws_final
    from peaso.checks.aws_bulk_finding_summary import evidence_summary as aws_bulk
    from peaso.checks.aws_compute_storage_finding_summary import evidence_summary as aws_compute
    return (aws_final(finding) or aws_bulk(finding) or aws_compute(finding)
            or aws_remaining(finding) or azure_bulk(finding) or analysis(finding)
            or database(finding) or gcp_remaining(finding))

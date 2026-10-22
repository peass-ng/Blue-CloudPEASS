"""Synthetic pinned Trivy log shapes; no private image or stderr fixtures."""
import json

from peaso import trivy_container_runner_20261020 as trivy


STAMP = '2026-10-22T19:25:54+02:00'
SEVERITY_NOTICE = ('Using severities from other vendors for some vulnerabilities. Read '
    'https://trivy.dev/docs/v0.68/guide/scanner/vulnerability#severity-selection for details.')


def line(level, message, *attributes):
    return ('\t'.join((STAMP, level, message, *attributes)) + '\n').encode()


def test_structured_info_path_words_do_not_become_diagnostics():
    raw = line('INFO', 'Loaded', 'file_path="/private/scratch/warning/error/trivy.yaml"')
    assert trivy._diagnostics(raw) == []
    assert trivy._diagnostics(line('INFO', 'The scanner reported an error')) == ['analysis_incomplete']


def test_real_warnings_remain_incomplete_and_precise_severity_notice_is_excluded():
    sbom = line('WARN', 'Third-party SBOM may lead to inaccurate vulnerability detection')
    advice = line('WARN', 'Recommend using Trivy to generate SBOMs')
    severity = line('WARN', SEVERITY_NOTICE)
    assert trivy._diagnostics(severity) == []
    assert trivy._diagnostics(sbom + advice + severity) == ['analysis_incomplete']
    assert trivy._diagnostics(line('WARN', 'Additional scanner warning')) == ['analysis_incomplete']
    assert trivy._diagnostics(line('ERROR', 'Unknown scanner issue')) == ['analysis_incomplete']
    assert trivy._diagnostics(line('FATAL', 'Unknown scanner issue')) == ['analysis_incomplete']


def test_specific_failures_and_malformed_lines_still_fail_closed():
    assert trivy._diagnostics(line('INFO', 'Failed to initialize DB')) == ['database_unavailable']
    assert trivy._diagnostics(line('INFO', 'Loaded', 'detail="database error"')) == [
        'database_unavailable']
    assert trivy._diagnostics(line('ERROR', 'Unable to initialize archive image')) == [
        'archive_or_image_unsupported', 'analysis_incomplete']
    assert trivy._diagnostics(line('INFO', 'OS is not on the EOL list')) == ['os_end_of_support']
    assert trivy._diagnostics(b'garbled\tINFO\tloaded from /warning/path\n') == ['analysis_incomplete']
    assert trivy._diagnostics(b'2026-99-99T19:25:54+02:00\tINFO\tLoaded\tfile_path="/error"\n') == [
        'analysis_incomplete']
    assert trivy._diagnostics(b'WARN\tunknown scanner condition\n') == ['analysis_incomplete']


def test_positive_report_preserved_while_actual_sbom_warning_keeps_coverage_unknown():
    digest = 'sha256:' + 'a' * 64
    config = 'sha256:' + 'b' * 64
    layer = 'sha256:' + 'c' * 64
    identity = {'provider': 'aws', 'scope': '123456789012/us-east-1',
        'immutable_reference': '123456789012.dkr.ecr.us-east-1.amazonaws.com/fixture/image@' + digest,
        'manifest_digest': digest, 'config_digest': config}
    finding = {'VulnerabilityID': 'CVE-2026-12345', 'PkgName': 'fixture-package',
        'InstalledVersion': '1.0', 'FixedVersion': '1.1', 'Status': 'fixed', 'Severity': 'HIGH'}
    report = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
        'Metadata': {'ImageID': config, 'DiffIDs': [layer],
                     'RepoDigests': [identity['immutable_reference']]},
        'Results': [{'Target': 'fixture-image', 'Class': 'os-pkgs', 'Type': 'alpine',
                     'Packages': [{'Name': 'fixture-package'}], 'Vulnerabilities': [finding]}]}
    payload = json.dumps(report).encode()
    baseline = trivy.parse_report(payload, 0, identity, diff_ids=[layer], database={'fresh': True})
    with_warning = trivy.parse_report(payload, 0, identity, diff_ids=[layer],
        database={'fresh': True}, stderr=line('WARN', 'Third-party SBOM may lead to inaccurate vulnerability detection'))
    assert baseline['status'] == 'FAIL' and baseline['complete'] is True
    assert with_warning['status'] == 'FAIL' and with_warning['complete'] is False
    assert with_warning['coverage_status'] == 'UNKNOWN'
    assert with_warning['reason'] == 'analysis_incomplete'
    assert with_warning['findings'] == baseline['findings']

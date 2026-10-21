"""Exact test-only initializer ancestry for the seven GCP content fixes."""
import hashlib

CURRENT_INITIALIZER_SHA256 = "8cd818f4733bd8d51d04cab583171ddfdcec6575fbff1a1b2222bdc6da15301e"
METADATA_INITIALIZER_SHA256 = "e828e145917364fcd20a5a2d6de7e24eb304eee5698fea1cb1bed8669fef01c6"
EDITS = (
    (b"from . import gcp_positive_conservation_shared_source_successor_20261020 as _positive_shared_source\n", b""),
    (b"aws_workload_command_shared_successor_20261020 = _positive_shared_source\n",
     b"aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source\n"),
    (b"from peaso import gcp_positive_conservation_source_admission_successor_20261020 as _positive_source\n"
     b"gcp_function_secret_page_admission_20261020.source_inputs = _positive_source.reviewed_inputs\n", b""),
)


RAWV2_INITIALIZER_SHA256 = '0fa143a274905e52dad14d6eecfb641fdc98ebbd17db90d54d9908594b458e08'
RAWV2_EDITS = ((b'collector_noop_authorization_shared_successor_20261020 = aws_workload_command_shared_successor_20261020\n',
  b''),
 (b'_rawv2_source.install_admission("gcp_dataproc_source_runtime_admission_20261020")\n',
  b'gcp_dataproc_source_runtime_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_declaration_secrets_admission_20261020")\n',
  b'azure_declaration_secrets_admission_20261020.install()\n'),
 (b'from peaso import rawv2_public_source_successor_20261021 as _rawv2_source\n', b''),
 (b'_rawv2_source.install_selected_aws()\n', b'aws_selected_configuration_admission_20261020.install()\n'),
 (b'_rawv2_source.install_selected_azure()\n', b'azure_selected_secrets_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_log_samples_admission_20261020")\n',
  b'azure_log_samples_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_ml_job_secrets_admission_20261020")\n',
  b'azure_ml_job_secrets_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_databricks_notebook_secrets_admission_20261020")\n',
  b'azure_databricks_notebook_secrets_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_ml_asset_secrets_admission_20261020")\n',
  b'azure_ml_asset_secrets_admission_20261020.install()\n'),
 (b'_rawv2_source.install_admission("azure_function_settings_runtime_admission_20261020")\n',
  b'azure_function_settings_runtime_admission_20261020.install()\n'))


def metadata_initializer_bytes(raw):
    """Accept either exact epoch; reverse only the reviewed three hunks."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest == 'ded9ac527c13d868469a465d7f30e4aa0b43b04adaba651cab8d038d148af7d9':
        from pathlib import Path
        import json
        receipt_raw = (Path(__file__).resolve().parents[1] / 'peaso/checks/private_secret_shared_source_successor_20261021.json').read_bytes()
        if hashlib.sha256(receipt_raw).hexdigest() != '9210192c6cbc37b63c802359fecec6970d5bf4c34b9499c9ed6115d02f9d5ff2':
            raise RuntimeError("Private initializer receipt changed")
        for before, after in reversed(json.loads(receipt_raw)['initializer_edits']):
            before, after = before.encode(), after.encode()
            if raw.count(after) != 1:
                raise RuntimeError("Private initializer reversal ambiguous")
            raw = raw.replace(after, before, 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != RAWV2_INITIALIZER_SHA256:
            raise RuntimeError("Private initializer predecessor changed")
    if digest == RAWV2_INITIALIZER_SHA256:
        for after, before in RAWV2_EDITS:
            if raw.count(after) != 1:
                raise RuntimeError("RawV2 initializer reversal ambiguous")
            raw = raw.replace(after, before, 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != CURRENT_INITIALIZER_SHA256:
            raise RuntimeError("RawV2 initializer predecessor changed")
    if digest == METADATA_INITIALIZER_SHA256:
        return raw
    if digest != CURRENT_INITIALIZER_SHA256:
        raise RuntimeError("Unreviewed GCP source initializer changed")
    for after, before in EDITS:
        if raw.count(after) != 1:
            raise RuntimeError("GCP source initializer reversal ambiguous")
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != METADATA_INITIALIZER_SHA256:
        raise RuntimeError("GCP source initializer predecessor changed")
    return raw


PREDECESSOR_ARCHIVE = "tests/fixtures/gcp_positive_conservation_predecessors_20261020.json.gz"
PREDECESSOR_ARCHIVE_SHA256 = "90678d4abb5dcbff1471736f00da2d67744c1628e67f53e08deffe1470be661c"


def restore_content_predecessors(destination):
    """Restore only twelve hash-bound leaves in an isolated historical tree."""
    import gzip
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    destination = Path(destination).resolve()
    if destination == root:
        raise RuntimeError("Historical restoration requires an isolated tree")
    raw = (root / PREDECESSOR_ARCHIVE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PREDECESSOR_ARCHIVE_SHA256:
        raise RuntimeError("GCP predecessor archive changed")
    archive = json.loads(gzip.decompress(raw))
    if archive['schema_version'] != 1 or len(archive['files']) != 12:
        raise RuntimeError("GCP predecessor roster changed")
    for relative, row in archive['files'].items():
        target = (destination / relative).resolve()
        if not target.is_relative_to(destination / 'peaso'):
            raise RuntimeError("GCP predecessor source path changed")
        if hashlib.sha256(target.read_bytes()).hexdigest() != row['after_sha256']:
            raise RuntimeError("GCP current source changed: " + relative)
        before = bytes.fromhex(row['before_hex'])
        if hashlib.sha256(before).hexdigest() != row['before_sha256']:
            raise RuntimeError("GCP predecessor bytes changed: " + relative)
        target.write_bytes(before)

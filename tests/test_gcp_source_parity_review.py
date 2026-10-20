"""Offline checks for source-accounting completeness and integrity boundaries."""
import importlib.util
import base64
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit_gcp_source_parity', ROOT / 'scripts/audit_gcp_source_parity.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
WORKBENCH_FIXTURE = ROOT / 'tests/fixtures/gcp-workbench-source-parity.json.gz'
WORKBENCH_FIXTURE_SHA256 = '955e82e3f88b7907c235123738172cddd3fa04dafa1fc2add799c32736962186'
WORKBENCH_PAYLOAD_SHA256 = '95adb1026940b0a96761b73763cca53594f1abfe298bb92b416ecbcedb661cc0'


def workbench_review_inputs():
    """Read only the pinned public payload and the upstream blobs it cites."""
    packed = WORKBENCH_FIXTURE.read_bytes()
    assert len(packed) <= 200_000 and hashlib.sha256(packed).hexdigest() == WORKBENCH_FIXTURE_SHA256
    expanded = gzip.decompress(packed)
    assert len(expanded) <= 1_500_000
    fixture = json.loads(expanded)
    assert fixture['schema_version'] == 1 and len(fixture['blobs']) == 5
    payload_raw = base64.b64decode(fixture['payload_b64'], validate=True)
    assert len(payload_raw) <= 50_000
    assert fixture['payload_sha256'] == WORKBENCH_PAYLOAD_SHA256
    assert hashlib.sha256(payload_raw).hexdigest() == WORKBENCH_PAYLOAD_SHA256
    payload = json.loads(payload_raw)
    referenced = {entry['path'] for row in payload['checks']
                  for entry in row['source_review']['source_blobs'] + row['source_review']['compliance_mapping_blobs']}
    referenced.update(row['upstream_evaluator']['source_path'] for row in payload['checks'])
    assert referenced == set(fixture['blobs'])
    blobs = {}
    for name, entry in fixture['blobs'].items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts
        raw = base64.b64decode(entry['content_b64'], validate=True)
        assert hashlib.sha256(raw).hexdigest() == entry['sha256']
        blobs[name] = raw
    return payload, blobs


class SourceParityTests(unittest.TestCase):
    def test_report_accounts_for_every_current_id_and_reviewed_omission(self):
        data = json.loads((ROOT / 'docs/gcp-review/source-parity.json').read_text())
        checks = data['checks']
        ids = {row['check_id'] for row in checks}
        self.assertEqual(len(ids), len(checks))
        self.assertEqual(len(ids), data['summary']['current_upstream_ids'])
        for row in checks:
            self.assertEqual(row['semantic_equivalence'], 'not_inferred_from_lineage_or_catalog_presence')
            self.assertTrue(row['source_blobs'])
            if row['status'] in ('missing', 'rejected', 'mapped-only-archived') or row['changes']:
                self.assertTrue(row['review']['assessment'])
                self.assertTrue(row['review']['classification'])
        for source in data['sources']:
            for query in source.get('query_inventory', []):
                self.assertTrue(query['control_ids'])
                self.assertLessEqual(set(query['control_ids']), ids)
        # An admitted check can move from missing to mapped-active without changing
        # this acceptance contract: both current upstream definitions must exist.
        self.assertIn('prowler.gcp.vertexai_workbench_instance_public_ip_disabled', ids)
        self.assertIn('prowler.gcp.vertexai_workbench_instance_root_access_disabled', ids)

    def test_shared_sql_is_bound_beyond_legacy_control_wrapper(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            directory = base / 'steampipe-mod-gcp-perimeter'
            directory.mkdir()
            path = directory / 'controls.pp'
            wrapper = 'control "resource_trust" {\n title = "Resource trust"\n sql = local.trust_sql\n}\n'
            local = 'locals {\n trust_sql = <<EOQ\n select case when allowed then \'ok\' else \'alarm\' end status;\n EOQ\n}\n'
            def enumerate_one(text):
                path.write_text(text)
                raw = path.read_bytes()
                source = {'repository': audit.REPOS[2], 'revision': 'a' * 40, 'license': 'Apache-2.0',
                          'files': [{'path': 'controls.pp', 'type': 'blob', 'sha': audit.blob_sha(raw), 'sha256': audit.digest(raw)}]}
                return audit.enumerate_sources(base, [source])[0]
            first = enumerate_one(wrapper + local)
            second = enumerate_one(wrapper + local.replace('when allowed', 'when forbidden'))
            self.assertEqual(first['upstream_evaluator']['sha256'], second['upstream_evaluator']['sha256'])
            self.assertNotEqual(first['upstream_evaluator']['resolved_sha256'], second['upstream_evaluator']['resolved_sha256'])
            self.assertIn('when forbidden', second['_evaluator_text'])

    def test_integrity_rejects_modified_blob_and_unlisted_source(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            sources = []
            for repo in audit.REPOS:
                directory = base / repo.split('/')[-1]
                directory.mkdir()
                files = []
                if repo != audit.REPOS[0]:
                    raw = b'control "x" {\n title = "Example"\n}\n'
                    (directory / 'x.pp').write_bytes(raw)
                    files = [{'path': 'x.pp', 'sha': audit.blob_sha(raw), 'sha256': audit.digest(raw)}]
                sources.append({'repository': repo, 'revision': 'a' * 40, 'files': files,
                                'corpus_sha256': audit.digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())})
            (base / 'sources.json').write_text(json.dumps(sources))
            audit.verify(base)
            file = base / 'steampipe-mod-gcp-perimeter/x.pp'
            original = file.read_bytes()
            file.write_bytes(original + b'changed')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                audit.verify(base)
            file.write_bytes(original)
            (file.parent / 'unlisted.pp').write_text('control "hidden" {}')
            with self.assertRaisesRegex(ValueError, 'differs from pinned inventory'):
                audit.verify(base)

    def test_native_catalog_presence_cannot_close_missing_manifest_mapping(self):
        upstream = next(iter(audit.WORKBENCH_IDS))
        native = audit.WORKBENCH_IDS[upstream]
        pending = audit.admission_state({'check_id': upstream}, [], {native: {}})
        self.assertEqual(pending['disposition'], 'awaiting-manifest-mapping')
        self.assertFalse(pending['manifest_mapping_present'])
        self.assertEqual(pending['requirements'], [])
        partial = audit.admission_state({'check_id': upstream}, [native], {native: {'requirement_controls': [{'framework_id': 'pci_4.0_gcp', 'requirement_id': '1.2.8.37', 'decision': 'PARTIAL'}]}})
        self.assertEqual(partial['requirement_mapping_assurance'], 'reviewed_partial')
        self.assertEqual(len(partial['requirements']), 1)
        self.assertEqual(audit.admission_state({'check_id': upstream}, [native], {})['disposition'],
                         'awaiting-catalog-regeneration')
        self.assertEqual(audit.admission_state({'check_id': upstream}, [native], {native: {}})['disposition'],
                         'mapped-active')

    def test_workbench_merge_payload_preserves_pins_and_verified_source(self):
        payload, blobs = workbench_review_inputs()
        self.assertEqual({row['check_id'] for row in payload['checks']}, set(audit.WORKBENCH_IDS))
        self.assertEqual(payload['extension_mapping']['requirements'], [])
        for row in payload['checks']:
            for key in ('provider', 'service', 'severity', 'dependencies', 'frameworks', 'reason',
                        'catalog_entry_type', 'native_evaluators', 'upstream_evaluator', 'expected_cost'):
                self.assertIn(key, row)
            native = audit.WORKBENCH_IDS[row['check_id']]
            self.assertEqual(row['native_checks'], [native])
            self.assertEqual(row['native_evaluators'][0]['dependencies'], ['workbench_instance'])
            self.assertEqual(row['revision'], '76cde39b08092b5d759e25a6cebde0da7e91e5fe')
            self.assertEqual(row['requirements'], [])
            self.assertIn('lineage_only', row['framework_mapping_assurance'])
            for entry in row['source_review']['source_blobs'] + row['source_review']['compliance_mapping_blobs']:
                raw = blobs[entry['path']]
                self.assertEqual(audit.blob_sha(raw), entry['sha'])
                self.assertEqual(audit.digest(raw), entry['sha256'])
            code = blobs[row['upstream_evaluator']['source_path']]
            self.assertEqual(audit.digest(code), row['upstream_evaluator']['sha256'])
        references = payload['numbered_requirement_review']['candidates']
        self.assertEqual(len(references), 13)
        self.assertEqual({(ref['framework_id'], ref['requirement_id']) for ref in references},
                         {(mapping['framework_id'], mapping['control_id']) for row in payload['checks'] for mapping in row['frameworks']})
        for ref in references:
            self.assertTrue(ref['canonical_requirement_exists'])
            self.assertEqual(ref['canonical_requirement_snapshot']['requirement_id'], ref['requirement_id'])
            self.assertEqual(ref['upstream_requirement']['Id'], ref['requirement_id'])
            self.assertIn(ref['upstream_check_id'].removeprefix('prowler.gcp.'), ref['upstream_requirement']['Checks'])
            self.assertEqual(ref['recommended_review_decision'], 'PARTIAL')
        before = payload['source_pin_update']['source_entry_before']
        after = payload['source_pin_update']['source_entry_after']
        for key in set(before) | set(after):
            if key in ('provider_revisions', 'provider_references'):
                for provider in set(before.get(key, {})) | set(after.get(key, {})):
                    if provider != 'gcp':
                        self.assertEqual(before[key][provider], after[key][provider])
            else:
                self.assertEqual(before[key], after[key])
        self.assertEqual(after['provider_revisions']['gcp'], payload['revision'])
        self.assertEqual(after['provider_references']['gcp']['revision'], payload['revision'])

    def test_manual_info_does_not_make_secret_content_unautomatable(self):
        row = {'check_id': 'gcp-compliance.control.cis_v400_1_17',
               'title': 'Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager',
               'source': 'https://github.com/turbot/example', '_evaluator_text': "'info' status, 'Manual verification required.' reason",
               'upstream_evaluator': {'resolved_sha256': '0' * 64}}
        review = audit.review_omission(row)
        self.assertEqual(review['classification'], 'useful_automatable_gap')
        self.assertIn('buildConfig.environmentVariables', review['proposal']['fields'])
        self.assertIn('redacted', review['assessment'])
        self.assertIn('names only', review['assessment'])


if __name__ == '__main__':
    unittest.main()

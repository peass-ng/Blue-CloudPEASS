# API SDK service models: reviewed 56bdf10b candidate

This build-only gate applies to the API and scheduler Lambda ZIP. It keeps complete botocore model trees for `accessanalyzer`, `cloudtrail`, `cognito-identity`, `cognito-idp`, `dynamodb`, `ec2`, `ecs`, `iam`, `organizations`, `s3`, `secretsmanager`, `sso`, `sso-oidc`, `stepfunctions`, and `sts`. It keeps all shared botocore data, including endpoints, partitions, retries, and SDK configuration. It does not prune the worker image or its SDK models, and it does not remove API source, static catalogs, source proofs, or tenant authorization code.

The pinned source epoch is commit `56bdf10bf55cf8c2ea53730efd03ad03a31ed443`. The gate compares every `peaso/**/*.py` and `risk_rules/**/*.py` file, plus the three bundled `bluepeass` Python files and `scripts/cloud_permission_risks.py` with the reviewed per-file manifest and an aggregate digest before deleting any model tree. It rejects dynamic or unlisted direct API/scheduler SDK clients, a changed AWS `_session` client-construction body, missing retained service trees, a different botocore version, and model-tree symlinks. The source pin also rejects later unrelated runtime edits deliberately; do not make the gate silently adapt to source changes.

## Review a new source epoch

1. Run `python scripts/peaso_api_service_model_gate.py --review-source .` from the candidate release checkout. This command only reports added, removed, or changed Python paths and current direct SDK client calls; it never writes a new pin.
2. Review every changed path and its API/scheduler call chain, including lazy imports, connector validation helpers, credential providers, and any imported collector functions the API invokes. Confirm every reachable service is literal and in the retained set, and distinguish imported collector code from a native scan invocation. If the closure is uncertain, keep all service models.
3. After review, regenerate the per-file SHA-256 inventory, compare it with `scripts/peaso_api_service_model_sources.json`, and update that manifest plus the aggregate and manifest digests in the build-only gate as one reviewed change. Never run a blind repin as a packaging repair.
   The read-only generator below prints the proposed per-file inventory and aggregate; compare it with the committed manifest before editing either pin:

   ```sh
   python - <<'PYCODE'
   import hashlib, json
   from scripts.peaso_api_service_model_gate import source_hashes
   files = source_hashes('.')
   digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
   print(json.dumps({'python_source_count': len(files), 'python_source_sha256': digest, 'files': files}, indent=2, sort_keys=True))
   PYCODE
   ```

   Then calculate the reviewed manifest file's SHA-256 and place that digest in `REVIEWED_MANIFEST_SHA256`; the source epoch and aggregate constants require the same explicit review.
4. Run `python -m pytest -q tests/test_peaso_api_service_model_gate.py tests/test_peaso_api_credential_models.py` using Python 3.12 with botocore 1.43.38. After staging the API package, run the credential test with that staging directory on `PYTHONPATH` and no network, then build and verify the official release ZIP and its source manifest.

The focused credential witness covers explicit credentials, environment task-role credentials, static and AssumeRole profiles, web identity, SSO role credentials, SSO-OIDC refresh, container credentials, and instance credentials. It uses synthetic configuration, Stubber responses, fake metadata HTTP fetchers, and a socket-connect blocker. The retained credential service models are STS, SSO, and SSO-OIDC; container and instance providers use HTTP metadata rather than botocore service models.

The isolated 56bdf10b staging comparison shrank a ZIP from 53,733,582 to 41,210,280 bytes, preserving every retained ZIP member byte. It used only the `bluepeass` files copied by the builder, reused a frozen Linux dependency installation, and omitted `release.json` because the isolated source freezer needed an intermediate history pack; the official release build and source verification remain required before adoption. The optional private S3 delivery route for ZIPs above the direct-upload limit is a separate contingency design, not an implemented part of this candidate. No startup CPU or RAM saving is claimed for model pruning.

Add these exact public reproduction inputs with the change: `scripts/peaso_api_service_model_gate.py`, `scripts/peaso_api_service_model_sources.json`, `tests/test_peaso_api_service_model_gate.py`, `tests/test_peaso_api_credential_models.py`, and `docs/api-sdk-model-prune.md`.

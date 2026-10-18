# Validation and release acceptance

Validation receipts apply to the exact source that produced them. Old test totals, a registered check or a synthetic positive fixture do not prove full live coverage. Keep generated XML, logs, screenshots, cloud snapshots and plans outside the repository.

## Local checks

Install the project's test dependencies into a virtual environment. Run affected modules while developing; run the broader release gate once the candidate is stable:

```sh
python -m pytest -q -p no:cacheprovider tests/test_peaso_engine.py tests/test_peaso_analysis.py
python scripts/peaso_compliance_materialize.py
npm --prefix frontend run typecheck
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

`tests/conftest.py` restores pinned synthetic fixture data from the compressed regression bundle and removes inputs it created when the session exits. Draft control registrars have isolation rules: tests for a draft run separately and must not contaminate the admitted runtime registry.

## CI

The repository's `Tests` workflow runs Python tests and fixture-backed Playwright checks. It checks unexpected skips separately. Some source-provenance, live-backend and scale tests require their documented pinned exports, tokens or explicit opt-in settings; a skip is not a pass. Frontend fixtures use an unreachable backend by default so an unmocked request cannot accidentally use a cloud account.

For provider code, verify successful, denied, empty, partial, malformed and paginated responses. Confirm redaction, read-only method allowlists, exact scope/identity binding and cancellation. Offline evaluation must work without provider calls. API tests must cover authentication, tenant/workspace ownership, quotas, storage and job lifecycle.

## Live and hosted acceptance

Read-only smoke tests use explicitly selected credentials and bounded inventories. They establish only the observed resources, permissions, regions and service responses. They do not prove complete coverage of every cloud configuration. Do not create resources or run privilege-escalation actions merely to validate the scanner.

Production publication follows the reviewed [Actions plan/apply sequence](peaso-aws.md#production-release). Verify the accepted source archive, health/HTML and affected authenticated application flows after deployment. Distinguish fixture behavior, real provider evidence, frontend tests and production checks in the receipt.

Use `examples/verify_installed_peaso.py` for an isolated, network-blocked package check and the benchmark helpers documented in [the engine guide](peaso-engine.md#validation-and-maintenance) for reproducible local measurements. Remove temporary build directories after validation.

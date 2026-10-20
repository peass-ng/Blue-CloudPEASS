"""Bounded post-scan agents. AI errors never discard deterministic results."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import unquote

from peaso.auth.secrets import redact, secret_values
from .crypto import AICipher
from peaso.server.config import Settings
from .auth import personal_token
from .contracts import validate_actions, validate_reviews, validate_network
from . import isolation


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, default=str)


def kill_tree(process):
    import psutil
    try:
        descendants = psutil.Process(process.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        descendants = []
    for child in reversed(descendants):
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def invoke(stage, platform, entries, token, findings, reviews, timeout):
    # Chack's Codex backend enables unrestricted shell tools. Refuse to start
    # it in the platform process namespace, even with a clean environment.
    remote = isolation.remote()
    if remote:
        from .fargate import configuration
        configuration()
    else:
        isolation.launcher()
    stop_at = time.monotonic() + timeout
    categories = {'hardening': {'hardening'}, 'exposure': {'exposure'},
                  'network': set(), 'priorities': {'hardening', 'exposure'}}
    if stage not in categories:
        raise ValueError('unknown_ai_stage')
    # Enforce the scope again before creating findings.json. A caller error
    # must never send passed, unresolved or unrelated checks to an agent.
    if any(row.get('status') != 'FAIL' or row.get('category') not in categories[stage]
           for row in findings):
        raise ValueError('ai_findings_out_of_scope')
    import psutil  # Require descendant cleanup before starting Chack/Codex.
    del psutil
    with tempfile.TemporaryDirectory(prefix='cspm-ai-') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        files = {'credentials': {'version': 2, 'entries': entries}}
        if not remote:
            files['codex-auth'] = {'access_token': token}
        if stage == 'priorities':
            from .briefing import build
            build(root, platform, findings, reviews, private_json)
        elif stage == 'network':
            from .network import build
            build(root, platform, reviews, private_json)
        elif stage in ('hardening', 'exposure'):
            # Reviewers never receive the complete report, inventory or graphs,
            # even if a caller accidentally passes a broader context object.
            files['findings'] = findings_document(platform.get('scan', {}), findings,
                                                  platform.get('resources', []))
        for name, data in files.items():
            private_json(root / (name + '.json'), data)
        if remote:
            from .fargate import invoke as invoke_remote
            return invoke_remote(stage, root, token, max(.001, stop_at - time.monotonic()))
        # Allowlist, never a copy of os.environ: scanner/cloud/platform credentials
        # and default credential discovery locations must not reach the agent.
        env = {'PATH': os.getenv('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': directory,
               'TMPDIR': directory, 'LANG': 'C.UTF-8', 'PYTHONUNBUFFERED': '1',
               'PYTHONPATH': str(Path(__file__).resolve().parents[2]),
               'CODEX_HOME': str(root / '.codex'), 'AWS_EC2_METADATA_DISABLED': 'true'}
        remaining = stop_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        command = isolation.wrap_command([sys.executable, '-m', 'peaso.ai.runner', stage], directory)
        from .deadline import ENVIRONMENT_KEY, timeout_seconds
        env[ENVIRONMENT_KEY] = str(timeout_seconds(remaining))
        process = subprocess.Popen(command, cwd=directory,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=max(0, stop_at - time.monotonic()))
            if process.returncode or not (root / 'result.json').is_file():
                raise RuntimeError('agent_failed')
            if (root / 'result.json').stat().st_size > 8_000_000:
                raise ValueError('agent_output_too_large')
            return json.loads((root / 'result.json').read_text())
        finally:
            kill_tree(process)


def invoke_before_deadline(stage, platform, entries, token, findings, reviews, end, limit):
    from .fargate import TaskStartupError
    for attempt in range(2):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        try:
            return invoke(stage, platform, entries, token, findings, reviews, min(limit, remaining))
        except TaskStartupError:
            if attempt:
                raise


def inputs(report):
    from peaso.engine import hydrate_finding
    rows = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
        report.get('check_meta_encoding'), report.get('remediation_templates')) for row in report.get('findings', [])]
    failed = [row for row in rows if row.get('status') == 'FAIL']
    hardening = [row for row in failed if row.get('category') == 'hardening']
    def key(row):
        return (row.get('check_id'), row.get('resource_id'), row.get('scope'))
    # Only exact control + resource + scope matches can share a review.
    known = {key(row): row['id'] for row in hardening}
    duplicates = {row['id']: known[key(row)] for row in failed if row.get('category') == 'exposure' and key(row) in known}
    exposure = [row for row in failed if row.get('category') == 'exposure' and row['id'] not in duplicates]
    return hardening, exposure, duplicates


def referenced_strings(value):
    """Exact resource references in this batch, never a whole-account inventory join."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from referenced_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from referenced_strings(item)


def review_context(report, inventory_by_id, findings):
    references = set(referenced_strings(findings))
    return {'scan': {key: report[key] for key in ('provider', 'snapshot_id', 'created_at') if key in report},
            'resources': [inventory_by_id[ident] for ident in sorted(references & inventory_by_id.keys())]}


def findings_document(scan, findings, resources=()):
    """Keep each finding's evidence and exact native references in one record."""
    inventory_by_id = {row['id']: row for row in resources}
    items = []
    for finding in findings:
        references = set(referenced_strings(finding)) & inventory_by_id.keys()
        items.append(dict(finding, supporting_resources=[inventory_by_id[ident] for ident in sorted(references)]))
    return {'scan': {key: scan[key] for key in ('provider', 'snapshot_id', 'created_at') if key in scan},
            'items': items}


def review_credentials(entries, provider, findings, context):
    """Select credential contexts and assigned targets for this reviewer batch.

    GCP/Azure OAuth audiences and the resolved Kubernetes cluster are captured
    access contexts, not independently downscopable per-resource credentials.
    """
    from .access import scopes_overlap
    selected = [entry for entry in entries if entry.get('provider') == provider]
    references = list(referenced_strings([findings, context.get('resources', [])]))
    requested_scopes = {row.get('scope') for row in findings + context.get('resources', []) if isinstance(row.get('scope'), str)}
    accounts = set()
    for value in references:
        match = re.match(r'^(?:arn:[^:]+:[^:]*:[^:]*:)?([0-9]{12})(?:/|:|$)', value)
        if match:
            accounts.add(match.group(1))
    out = []
    for entry in selected:
        if provider == 'aws' and entry.get('account_id') not in accounts:
            continue
        if provider == 'k8s' and entry.get('cluster_id'):
            clusters = set()
            def collect_clusters(value):
                if isinstance(value, dict):
                    if isinstance(value.get('cluster_id'), str):
                        clusters.add(value['cluster_id'])
                    for item in value.values():
                        collect_clusters(item)
                elif isinstance(value, (list, tuple)):
                    for item in value:
                        collect_clusters(item)
                elif isinstance(value, str) and value.startswith('k8s://'):
                    clusters.add(unquote(value[6:].split('/', 1)[0]))
            collect_clusters([findings, context.get('resources', [])])
            if clusters and entry['cluster_id'] not in clusters:
                continue
            if not clusters and len({e.get('cluster_id') for e in selected if e.get('cluster_id')}) > 1:
                continue  # Namespace alone cannot identify one of several clusters.
        if 'target_scopes' not in entry:
            # Compatibility for old captured artifacts before target bindings.
            out.append(dict(entry))
            continue
        targets = [scope for scope in entry['target_scopes']
                   if any(scopes_overlap(scope, requested) for requested in requested_scopes)
                   or (provider == 'k8s' and (scope == '*' or '*' in requested_scopes))]
        if provider == 'aws' and entry['target_scopes']:
            global_scope = entry['account_id'] + '/global'
            if global_scope in requested_scopes:
                targets = sorted(set(targets) | {global_scope})
        if not targets:
            continue
        if provider == 'k8s' and '*' in targets and '*' not in requested_scopes:
            targets = sorted(requested_scopes)
        narrowed = dict(entry, target_scopes=targets)
        if provider == 'azure':
            narrowed['subscription_ids'] = sorted({scope.split('/')[2] for scope in targets if scope.startswith('/subscriptions/')})
        if provider == 'k8s':
            narrowed['namespaces'] = targets
        out.append(narrowed)
    return out


def available_memory():
    """Available bytes inside the task limit, rather than the host's RAM."""
    import psutil
    available = psutil.virtual_memory().available
    for limit_path, usage_path in (
        ('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
        ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes'),
    ):
        try:
            limit = int(Path(limit_path).read_text().strip())
            usage = int(Path(usage_path).read_text().strip())
            available = min(available, max(0, limit - usage))
        except (OSError, ValueError):
            continue
    return available


def review_concurrency():
    requested = int(os.getenv('PEASO_AI_MAX_CONCURRENCY', '2'))
    if not 1 <= requested <= 6:
        raise ValueError('invalid_ai_concurrency')
    # Admission estimate, not an enforced per-process memory limit. Current
    # analyzer usage is already included in the cgroup's used memory.
    capacity = max(0, (available_memory() - 128 * 1024**2) // (512 * 1024**2))
    return min(requested, capacity)


def review_batches(report, inventory_by_id, entries, token, hardening, exposure, end, *, network=None):
    """Bounded work queue: overlap independent stages, preserve result order."""
    output = {'hardening': [], 'exposure': []}
    failed = False

    def batches():
        # Admit the holistic network review early; it shares the same memory
        # and concurrency limits as reviewer batches, never an extra pool.
        if network is not None:
            yield 'network', 0, []
        for offset in range(0, max(len(hardening), len(exposure)), 40):
            for stage, findings in (('hardening', hardening), ('exposure', exposure)):
                if offset < len(findings):
                    yield stage, offset, findings[offset:offset + 40]

    def run(stage, batch):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        if stage == 'network':
            access = review_credentials(entries, report['provider'], [], {'resources': network['inventory']})
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            data = invoke_before_deadline(stage, network, access, token, [], [], end, 600 if isolation.remote() else 150)
            return validate_network(data, network)
        context = review_context(report, inventory_by_id, batch)
        access = review_credentials(entries, report['provider'], batch, context)
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        data = invoke_before_deadline(stage, context, access, token, batch, [], end, 480 if isolation.remote() else 120)
        return validate_reviews(data, batch)['items']

    def record(task, future=None):
        nonlocal failed
        stage, offset, batch = task
        try:
            if future is None:
                raise TimeoutError()
            rows = future.result()
        except Exception:
            failed = True
            if stage == 'network':
                output['network'] = {'status': 'unavailable', 'explanation': '', 'findings': [],
                    'limitations': ['Network AI review was unavailable, timed out, or returned an invalid result.']}
                return
            rows = [{'finding_id': row['id'], 'verdict': 'UNKNOWN',
                     'reason': 'AI review was unavailable, timed out, or returned an invalid result; the original failure could not be verified.'}
                    for row in batch]
        if stage == 'network':
            output['network'] = dict(rows, status='completed')
        else:
            output[stage].append((offset, rows))

    tasks = iter(batches())
    slots = review_concurrency()
    if slots:
        with ThreadPoolExecutor(max_workers=slots, thread_name_prefix='cspm-ai') as executor:
            pending = {}
            exhausted = False
            while pending or not exhausted:
                # Recheck admission before starting another batch. Existing
                # agents retain their slots; no unbounded futures queue exists.
                capacity = min(slots, review_concurrency() + len(pending))
                while not exhausted and len(pending) < capacity and time.monotonic() < end:
                    task = next(tasks, None)
                    if task is None:
                        exhausted = True
                        break
                    pending[executor.submit(run, task[0], task[2])] = task
                if not pending:
                    break
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    record(pending.pop(future), future)
    for task in tasks:
        record(task)
    return {stage: batches if stage == 'network' else [row for _, rows in sorted(batches) for row in rows]
            for stage, batches in output.items()}, failed


def review_scan(report, snapshot, selectors, *, tenant, artifacts, deadline=None, context=None):
    result = {'version': 1, 'status': 'skipped', 'actions': [], 'reviews': {'hardening': [], 'exposure': []},
              'limitations': [], 'duplicates': {}, 'auth_source': None}
    if not selectors.get('ai_enabled', True):
        result['reason'] = 'disabled_for_scan'
        return result
    try:
        from peaso.storage.runtime import stores
        settings = Settings()
        if context:
            settings.state_dir = Path(context["state_dir"])
            settings.identity_dir = Path(context["identity_dir"])
        store, _ = stores(settings)
        cipher = AICipher(settings.identity_dir)
        ai_user = selectors.get('ai_user_id', tenant)
        if ai_user != tenant and store.workspace_role(tenant, ai_user) not in ('write', 'admin'):
            raise PermissionError('ai_owner_no_longer_authorized')
        token, result['auth_source'] = personal_token(store, cipher, selectors.get('ai_user_id', tenant))
        if not isolation.available():
            result.update(status='unavailable', reason='ai_isolation_unavailable')
            result['limitations'].append('AI agents were not started: this deployment has no configured isolation launcher. Deterministic scan findings remain available.')
            return result
        hardening, exposure, duplicates = inputs(report)
        result['duplicates'] = duplicates
        entries = []
        reference = snapshot.get('metadata', {}).get('ai_access_reference')
        if reference:
            entries = cipher.decrypt(artifacts.get(tenant, reference)['sealed'])['entries']
        from .access import bind_targets, eligible_entries
        entries = bind_targets(eligible_entries(entries, snapshot), snapshot)
        if not entries:
            result['limitations'].append('Live cloud credentials are unavailable; review is limited to captured evidence.')
        from peaso.snapshot import resources
        inventory = resources(snapshot)
        inventory_by_id = {row['id']: row for row in inventory}
        end = min(time.monotonic() + int(os.getenv('PEASO_AI_TIMEOUT_SECONDS', '600' if isolation.remote() else '300')),
                  time.monotonic() + max(0, deadline - time.time() - 10) if deadline else float('inf'))
        # Hosted priorities need their task startup and model budget after the
        # reviewer barrier, while both phases remain inside the scan deadline.
        review_end = end - min(600 if isolation.remote() else 60,
                              max(0, end - time.monotonic()) * (.3 if isolation.remote() else .2))
        from .network import prepare, with_findings
        network = prepare(report, inventory, snapshot)
        # Completion barrier: all reviewer futures and their agent processes
        # finish before we merge verdicts or build the priorities input.
        result['reviews'], failed_stage = review_batches(report, inventory_by_id, entries, token,
                                                       hardening, exposure, review_end, network=network)
        result['network'] = result['reviews'].pop('network', {
            'status': 'not_available', 'explanation': '', 'findings': [],
            'limitations': ['No network inventory or graph was collected for this scan.']})
        priorities_report = with_findings(report, result['network']['findings'])
        reviewed = result['reviews']['hardening'] + result['reviews']['exposure']
        by_id = {row['finding_id']: row for row in reviewed}
        for duplicate, original in duplicates.items():
            review = dict(by_id[original], finding_id=duplicate)
            result['reviews']['exposure'].append(review)
            reviewed.append(review)
        try:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            if review_concurrency() == 0:
                raise MemoryError('ai_memory_headroom_unavailable')
            from peaso.least_privilege import project
            platform = {'report': priorities_report, 'inventory': inventory,
                        'least_privilege': project(report['provider'], inventory, snapshot=snapshot),
                        'network_review': {key: result['network'][key] for key in ('status', 'explanation', 'limitations')}}
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            data = invoke_before_deadline('priorities', platform, entries, token, hardening + exposure, reviewed, end, 600 if isolation.remote() else 150)
            recommendations = validate_actions(data, priorities_report, reviewed)
            result['actions'] = recommendations['actions']
            result['limitations'].extend(recommendations['limitations'])
        except Exception:
            failed_stage = True
            result['limitations'].append('Prioritized recommendations could not be completed.')
        result['status'] = 'partial' if failed_stage else 'completed'
        result['coverage'] = {'hardening': len(hardening), 'exposure': len(exposure) + len(duplicates),
            'reviewed': sum(row['verdict'] in ('PASS', 'FAIL', 'NOT_APPLICABLE', 'EMPTY') for row in reviewed), 'total': len(reviewed)}
        # Redact exact cloud and Codex secret values before durable publication.
        # Retain public IDs/metadata: only credential-bearing fields are secrets.
        secrets = [token] + [value for entry in entries for key, value in entry.items()
            if key in ('token', 'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token') and isinstance(value, str)]
        for entry in entries:
            if entry.get('format') == 'kubeconfig':
                for user in entry['kubeconfig'].get('users', []):
                    secrets.extend(secret_values(user.get('user', {})))
        sanitized = redact(result, tuple(secrets))
        if 'network' in sanitized:
            sanitized['network']['explanation'] = sanitized['network']['explanation'][:1000]
        for rows in sanitized['reviews'].values():
            for row in rows:
                row['reason'] = row['reason'][:500]
        return sanitized
    except Exception:
        result.update(status='unavailable', reason='ai_setup_unavailable', actions=[], reviews={'hardening': [], 'exposure': []})
        result['limitations'].append('AI authentication, runtime or scan context is unavailable. Scan findings remain available.')
        return result

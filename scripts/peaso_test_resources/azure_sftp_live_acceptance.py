"""Validate an existing local-user SFTP credential path in an owned Azure lab.

Creates one uniquely tagged resource group and one HNS/SFTP account, a private
container, marker and local user. Confirms password regeneration and SSH-key
replacement with read/list access and denied writes, then tests the native
collector and evaluator. Deletes only the exact owned group in finally and waits
for confirmed absence. Azure credentials come from the selected az-cli session;
passwords, access tokens, account keys and private SSH keys are never persisted.
Requires the project cloud dependencies, Azure CLI and optional paramiko==4.0.0.
"""
import argparse
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
import base64
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--output', required=True, help='New private evidence directory; must not already exist')
    parser.add_argument('--location', default='westeurope')
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        parser.error('Run without -O: acceptance assertions must remain enabled')
    for value in (args.subscription, args.tenant):
        try:
            if str(uuid.UUID(value)) != value.lower():
                raise ValueError('noncanonical UUID')
        except ValueError:
            parser.error('subscription and tenant must be UUIDs')
    if not shutil.which('az'):
        parser.error('Azure CLI executable az is required')
    try:
        import paramiko
    except ImportError:
        parser.error('Install the optional live-test dependency paramiko==4.0.0')
    os.umask(63)
    ROOT = Path(__file__).resolve().parents[2]
    OUT = Path(args.output).resolve()
    OUT.mkdir(parents=True, mode=448, exist_ok=False)
    import paramiko
    os.umask(63)
    SUB = args.subscription
    TENANT = args.tenant
    owner = uuid.uuid4().hex
    rg = 'peas-qa-sftp-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + '-' + owner[:6]
    account = 'peasqa' + owner[:17]
    scope = '/subscriptions/' + SUB
    rgid = scope + '/resourceGroups/' + rg
    accountid = rgid + '/providers/Microsoft.Storage/storageAccounts/' + account
    userid = accountid + '/localUsers/qatest'
    container = 'qatests'
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    tags = {'owner': 'peaso-qa', 'test_id': owner, 'expires_at': expires}
    sensitive_values = []
    state = {'owner': owner, 'started_at': datetime.now(timezone.utc).isoformat(), 'subscription': SUB, 'tenant': TENANT, 'resource_group_id': rgid, 'resource_ids': [rgid, accountid, userid, accountid + '/blobServices/default/containers/' + container], 'tags': tags, 'cleanup_deadline': expires, 'phase': 'planned'}

    def save():
        (OUT / 'ledger.json').write_text(json.dumps(state, indent=2) + '\n')

    def az(args, *, body=None, allow=False, timeout=180, env=None):
        cmd = ['az', *args, '--subscription', SUB, '--only-show-errors', '-o', 'json']
        if body is not None:
            cmd += ['--body', '@-']
        result = subprocess.run(cmd, input=None if body is None else json.dumps(body), capture_output=True, text=True, timeout=timeout, env=env)
        if result.returncode and (not allow):
            diagnostic = result.stderr[-8000:]
            for value in [*sensitive_values, (env or {}).get('AZURE_STORAGE_KEY')]:
                if isinstance(value, str) and value:
                    diagnostic = diagnostic.replace(value, '[REDACTED]')
            (OUT / ('azure-error-' + str(time.time_ns()) + '.log')).write_text(diagnostic)
            raise RuntimeError('az ' + ' '.join(args[:3]) + ' failed (returncode ' + str(result.returncode) + ')')
        return result

    def data(args, **kw):
        return json.loads(az(args, **kw).stdout)

    def identity():
        row = data(['account', 'show'])
        if row.get('id') != SUB or row.get('tenantId') != TENANT:
            raise RuntimeError('Azure subscription or tenant mismatch')

    def owned():
        identity()
        row = data(['group', 'show', '--name', rg])
        if row.get('id', '').lower() != rgid.lower() or row.get('tags') != tags:
            raise RuntimeError('Resource group ownership mismatch')

    def rest(method, rid, body=None):
        owned()
        return data(['rest', '--method', method, '--url', 'https://management.azure.com' + rid + '?api-version=2023-05-01'], body=body)

    def auth(password=None, key=None, *, retries=1):
        last = None
        for attempt in range(retries):
            transport = None
            try:
                sock = socket.create_connection((account + '.blob.core.windows.net', 22), timeout=10)
                transport = paramiko.Transport(sock)
                transport.banner_timeout = 15
                transport.auth_timeout = 15
                transport.start_client(timeout=15)
                fingerprint = hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest()
                previous = state.get('sftp_host_key_sha256')
                if previous and previous != fingerprint:
                    raise RuntimeError('Owned SFTP endpoint host key changed')
                state['sftp_host_key_sha256'] = fingerprint
                if password is not None:
                    transport.auth_password(account + '.qatest', password, fallback=False)
                else:
                    transport.auth_publickey(account + '.qatest', key)
                client = paramiko.SFTPClient.from_transport(transport)
                return (transport, client)
            except (OSError, paramiko.SSHException) as exc:
                if transport:
                    transport.close()
                last = type(exc).__name__
                if attempt + 1 < retries:
                    time.sleep(5)
        raise RuntimeError('Owned SFTP authentication failed: ' + str(last))

    def verify_rights(password=None, key=None):
        transport, client = auth(password=password, key=key, retries=12)
        try:
            assert 'marker.txt' in client.listdir('.')
            with client.open('marker.txt', 'r') as handle:
                assert handle.read().decode() == owner
            try:
                client.open('must-be-denied.txt', 'w').close()
            except OSError as exc:
                assert exc.errno == 13, type(exc).__name__
            else:
                raise RuntimeError('Read/list-only local user unexpectedly wrote a blob')
        finally:
            client.close()
            transport.close()

    def stop(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    save()
    try:
        identity()
        token_row = data(['account', 'get-access-token', '--resource', 'https://management.azure.com/'])
        token_claims = json.loads(base64.urlsafe_b64decode(token_row['accessToken'].split('.')[1] + '==='))
        actor_id = token_claims['oid']
        assert token_claims['tid'] == TENANT
        del token_row, token_claims
        state['actor_id'] = actor_id
        save()
        assert az(['group', 'show', '--name', rg], allow=True).returncode != 0
        data(['group', 'create', '--name', rg, '--location', args.location, '--tags', *[k + '=' + v for k, v in tags.items()]])
        state['phase'] = 'resource_group_created'
        save()
        owned()
        data(['storage', 'account', 'create', '--name', account, '--resource-group', rg, '--location', args.location, '--sku', 'Standard_LRS', '--kind', 'StorageV2', '--enable-hierarchical-namespace', 'true', '--enable-sftp', 'true', '--enable-local-user', 'true', '--allow-blob-public-access', 'false', '--allow-shared-key-access', 'true', '--min-tls-version', 'TLS1_2', '--public-network-access', 'Enabled', '--https-only', 'true', '--tags', *[k + '=' + v for k, v in tags.items()]], timeout=300)
        state['phase'] = 'storage_created'
        save()
        print(json.dumps({'stage': state['phase'], 'account_id': accountid}), flush=True)
        owned()
        data(['storage', 'container-rm', 'create', '--name', container, '--storage-account', account, '--resource-group', rg, '--public-access', 'off', '--metadata', 'test_id=' + owner])
        key = paramiko.RSAKey.generate(3072)
        properties = {'hasSshPassword': True, 'hasSshKey': True, 'hasSharedKey': False, 'allowAclAuthorization': False, 'homeDirectory': container, 'sshAuthorizedKeys': [{'key': key.get_name() + ' ' + key.get_base64(), 'description': owner}], 'permissionScopes': [{'service': 'blob', 'resourceName': container, 'permissions': 'rl'}]}
        rest('put', userid, {'properties': properties})
        password = rest('post', userid + '/regeneratePassword')['sshPassword']
        sensitive_values.append(password)
        owned()
        keys = data(['storage', 'account', 'keys', 'list', '--account-name', account, '--resource-group', rg])
        marker = OUT / 'marker.txt'
        marker.write_text(owner)
        az(['storage', 'blob', 'upload', '--account-name', account, '--container-name', container, '--name', 'marker.txt', '--file', str(marker), '--auth-mode', 'key'], env={**os.environ, 'AZURE_STORAGE_KEY': keys[0]['value']})
        del keys
        verify_rights(password=password)
        state['password_authentication_verified'] = True
        save()
        print(json.dumps({'stage': 'password_auth_scope_verified', 'read': True, 'write_denied': True}), flush=True)
        replacement = paramiko.RSAKey.generate(3072)
        properties['sshAuthorizedKeys'] = [{'key': replacement.get_name() + ' ' + replacement.get_base64(), 'description': owner}]
        rest('put', userid, {'properties': properties})
        verify_rights(key=replacement)
        state['replacement_ssh_authentication_verified'] = True
        save()
        print(json.dumps({'stage': 'replacement_ssh_scope_verified', 'read': True, 'write_denied': True}), flush=True)
        from peaso.collectors import azure
        from peaso import privesc
        files = [ROOT / 'peaso/collectors/azure.py', *list((ROOT / 'peaso/privesc').rglob('*.py'))]
        hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        connector = {'provider': 'azure', 'auth': {'method': 'az-cli', 'tenant_id': TENANT}, 'scopes': [SUB], 'options': {'max_calls': 100, 'workers': 3}}
        snapshot = azure.collect(connector, requirements=['storage_account', 'storage_local_user', 'storage_container', 'role_assignment', 'role_definition', 'deny_assignment'])
        assert password not in json.dumps(snapshot)
        assert all((hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in hashes.items())), 'Source changed during collection'
        entries = [e for e in privesc.load_catalog()['entries'] if e['id'] in {'azure-audit-microsoftstoragestorageaccountslocalusersregeneratepasswordaction', 'azure-audit-microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageac'}]
        report = privesc.analyze(snapshot, entries=entries, include_admin_sources=True)
        target = 'azure_storage_local_user:' + userid.lower()
        matched = [e for e in report['graph']['edges'] if e['source'] == actor_id and e['target'] == target and (e['confidence'] == 'conditional')]
        (OUT / 'snapshot.json').write_text(json.dumps(snapshot) + '\n')
        (OUT / 'privesc-report.json').write_text(json.dumps(report) + '\n')
        found = {tech for edge in matched for tech in edge['techniques']}
        assert {e['id'] for e in entries} <= found, {'techniques': sorted(found), 'coverage': report['coverage']}
        state['acceptance'] = {'passed': True, 'password_regeneration': True, 'ssh_credential_replacement': True, 'read_list_only_scope': True, 'write_denied': True, 'native_snapshot_no_password': True, 'conditional_paths': len(matched), 'source_sha256': hashes, 'catalog_manifest_sha256': hashlib.sha256((ROOT / 'risk_rules/hacktricks-privesc-source.json').read_bytes()).hexdigest()}
        save()
        print(json.dumps({'stage': 'product_evaluator_verified', 'conditional_paths': len(matched)}), flush=True)
    except BaseException as exc:
        state['acceptance'] = {'passed': False, 'error_type': type(exc).__name__, 'error': str(exc)[:8000]}
        save()
        raise
    finally:
        try:
            identity()
            existing = az(['group', 'show', '--name', rg], allow=True)
            if existing.returncode == 0:
                owned()
                az(['group', 'delete', '--name', rg, '--yes', '--no-wait'], timeout=60)
                for attempt in range(180):
                    if data(['group', 'exists', '--name', rg]) is False:
                        break
                    time.sleep(3)
                else:
                    raise RuntimeError('Resource group deletion not confirmed')
            else:
                assert data(['group', 'exists', '--name', rg]) is False
            state['cleanup_verified'] = True
            state['phase'] = 'deleted'
            state['finished_at'] = datetime.now(timezone.utc).isoformat()
            save()
            print(json.dumps({'stage': 'cleanup', 'verified': True, 'resource_group_id': rgid}), flush=True)
        except BaseException as exc:
            state['cleanup_verified'] = False
            state['cleanup_error'] = str(exc)
            save()
            raise
if __name__ == '__main__':
    main()

"""Exercise one owned Argo Secret-mount path across two ephemeral kind clusters.

Requires a running Docker daemon, kind, kubectl, the project Python dependencies,
and a locally available Python proof image. Writes private receipts and always
attempts deletion of only its exact owned clusters and network. It never contacts
an external Kubernetes cluster or reads existing user kubeconfigs.
"""
import argparse
import shutil
from pathlib import Path
import subprocess, json, uuid, os, signal, hashlib, base64, time
from datetime import datetime, timezone, timedelta
import sys

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New private evidence directory; must not already exist')
    parser.add_argument('--kind', default=shutil.which('kind'), help='Path to kind executable')
    parser.add_argument('--proof-image', default='python:3.12-slim', help='Already available local image with Python 3')
    parser.add_argument('--node-image', default='kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5')
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        parser.error('Run without -O: acceptance assertions must remain enabled')
    if not args.kind or not all((shutil.which(name) for name in ('docker', 'kubectl'))):
        parser.error('docker, kubectl and kind executables are required')
    os.umask(63)
    ROOT = Path(__file__).resolve().parents[2]
    OUT = Path(args.output).resolve()
    OUT.mkdir(parents=True, mode=448, exist_ok=False)
    KIND = args.kind
    os.umask(63)
    owner = uuid.uuid4().hex
    prefix = 'peaso-argo-' + owner[:8]
    network = prefix + '-net'
    names = [prefix + '-source', prefix + '-remote']
    ns = 'peaso-argocd'
    remote_ns = 'peaso-remote'
    ledger = OUT / 'ledger.json'
    state = {'owner': owner, 'started_at': datetime.now(timezone.utc).isoformat(), 'cleanup_deadline': (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(), 'provider': 'local-k8s', 'cloud_resources_created': 0, 'network': {'name': network, 'status': 'planned'}, 'clusters': [{'name': n, 'status': 'planned'} for n in names]}
    configs = {n: OUT / (n + '.kubeconfig') for n in names}
    env = {**os.environ, 'KIND_EXPERIMENTAL_DOCKER_NETWORK': network, 'KIND_EXPERIMENTAL_PROVIDER': 'docker'}

    def save():
        ledger.write_text(json.dumps(state, indent=2) + '\n')

    def run(cmd, *, body=None, allow=False, timeout=180):
        p = subprocess.run(cmd, input=None if body is None else json.dumps(body), capture_output=True, text=True, timeout=timeout, env=env)
        if p.returncode and (not allow):
            raise RuntimeError('command failed: ' + cmd[0] + ' ' + ' '.join(cmd[1:3]) + '; command output withheld to protect credential material')
        return p

    def kube(n, args, **kw):
        return run(['kubectl', '--kubeconfig', str(configs[n]), '--context', 'kind-' + n, *args], **kw)

    def create(n, obj, *, actor=None):
        obj['metadata'].setdefault('labels', {})['peaso-test-owner'] = owner
        args = (['--as=' + actor] if actor else []) + ['create', '-f', '-', '-o', 'json']
        return json.loads(kube(n, args, body=obj).stdout)

    def identity():
        if run(['docker', 'info', '--format', '{{.ID}}']).stdout.strip() != daemon:
            raise RuntimeError('Docker identity changed')

    def containers(n):
        ids = run(['docker', 'ps', '-aq', '--filter', 'label=io.x-k8s.kind.cluster=' + n]).stdout.split()
        for i in ids:
            d = json.loads(run(['docker', 'inspect', i]).stdout)[0]
            if d['Config']['Labels'].get('io.x-k8s.kind.cluster') != n or d['Name'] != '/' + n + '-control-plane':
                raise RuntimeError('cluster ownership mismatch')
        return ids

    def stop(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    daemon = run(['docker', 'info', '--format', '{{.ID}}']).stdout.strip()
    state['docker_id'] = daemon
    save()
    source_paths = [p for p in (ROOT / 'peaso/privesc').rglob('*') if p.is_file() and p.suffix in {'.py', '.json', '.yaml'}] + [ROOT / 'risk_rules/hacktricks-privesc-source.json']
    source_files = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    try:
        info = json.loads(run(['docker', 'image', 'inspect', args.proof_image]).stdout)[0]
        state['proof_image_id'] = info['Id']
        save()
        run(['docker', 'image', 'save', '--platform', info['Os'] + '/' + info['Architecture'], '-o', str(OUT / 'proof-image.tar'), args.proof_image], timeout=180)
        for n in names:
            if containers(n):
                raise RuntimeError('name collision')
        identity()
        nid = run(['docker', 'network', 'create', '--label', 'peaso-test-owner=' + owner, network]).stdout.strip()
        state['network'].update(id=nid, status='created')
        save()
        for row in state['clusters']:
            n = row['name']
            cfg = OUT / (n + '.yaml')
            cfg.write_text('kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\nnodes:\n- role: control-plane\nkubeadmConfigPatches:\n- |\n  kind: ClusterConfiguration\n  apiServer:\n    certSANs:\n    - ' + names[1] + '-control-plane\n')
            identity()
            run([KIND, 'create', 'cluster', '--name', n, '--kubeconfig', str(configs[n]), '--config', str(cfg), '--image', args.node_image, '--wait', '120s'], timeout=240)
            row.update(status='created', container_ids=containers(n))
            save()
            print(json.dumps({'stage': 'cluster_ready', 'name': n}), flush=True)
        source, remote = names
        remote_ip = json.loads(run(['docker', 'inspect', remote + '-control-plane']).stdout)[0]['NetworkSettings']['Networks'][network]['IPAddress']
        run([KIND, 'load', 'image-archive', str(OUT / 'proof-image.tar'), '--name', source], timeout=180)
        create(remote, {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': remote_ns}})
        create(remote, {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'deployer', 'namespace': remote_ns}, 'automountServiceAccountToken': False})
        create(remote, {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'marker', 'namespace': remote_ns}, 'data': {'owner': owner}})
        create(remote, {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'read-marker', 'namespace': remote_ns}, 'rules': [{'apiGroups': [''], 'resources': ['configmaps'], 'resourceNames': ['marker'], 'verbs': ['get']}]})
        create(remote, {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'read-marker', 'namespace': remote_ns}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'read-marker'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'deployer', 'namespace': remote_ns}]})
        token = kube(remote, ['create', 'token', 'deployer', '-n', remote_ns, '--duration=600s']).stdout.strip()
        claims = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '==='))
        assert claims['sub'] == 'system:serviceaccount:' + remote_ns + ':deployer'
        rconfig = json.loads(kube(remote, ['config', 'view', '--raw', '--minify', '-o', 'json']).stdout)
        ca = rconfig['clusters'][0]['cluster']['certificate-authority-data']
        server = 'https://' + remote + '-control-plane:6443'
        create(source, {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': {'pod-security.kubernetes.io/enforce': 'restricted'}}})
        create(source, {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'author', 'namespace': ns}, 'automountServiceAccountToken': False})
        create(source, {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'author', 'namespace': ns}, 'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['create', 'get']}]})
        create(source, {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'author', 'namespace': ns}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'author'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'author', 'namespace': ns}]})
        secret = create(source, {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'remote-cluster', 'namespace': ns, 'labels': {'argocd.argoproj.io/secret-type': 'cluster'}}, 'type': 'Opaque', 'stringData': {'server': server, 'config': json.dumps({'bearerToken': token, 'tlsClientConfig': {'caData': ca}})}})
        actor = 'system:serviceaccount:' + ns + ':author'
        can_read = kube(source, ['auth', 'can-i', 'get', 'secrets', '-n', ns, '--as=' + actor], allow=True)
        assert can_read.stdout.strip() == 'no'
        code = "import json,ssl,base64,urllib.request,urllib.error\nconfig=json.load(open('/credential/config'));server=open('/credential/server').read();ctx=ssl.create_default_context(cadata=base64.b64decode(config['tlsClientConfig']['caData']).decode());headers={'Authorization':'Bearer '+config['bearerToken']}\ndef request(path,body=None):\n data=None if body is None else json.dumps(body).encode();h=dict(headers)\n if body is not None:h['Content-Type']='application/json'\n try:\n  with urllib.request.urlopen(urllib.request.Request(server+path,data=data,headers=h),context=ctx,timeout=20)as r:return r.status,json.load(r)\n except urllib.error.HTTPError as e:return e.code,{}\na,doc=request('/api/v1/namespaces/peaso-remote/configmaps/marker');b,_=request('/api/v1/namespaces/peaso-remote/secrets');c,review=request('/apis/authentication.k8s.io/v1/selfsubjectreviews',{'apiVersion':'authentication.k8s.io/v1','kind':'SelfSubjectReview'})\nprint(json.dumps({'configmap_status':a,'marker':doc.get('data',{}).get('owner'),'secrets_status':b,'identity_status':c,'subject':review.get('status',{}).get('userInfo',{}).get('username')}),flush=True)\n\n"
        pod = create(source, {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'mount-proof', 'namespace': ns}, 'spec': {'hostAliases': [{'ip': remote_ip, 'hostnames': [remote + '-control-plane']}], 'restartPolicy': 'Never', 'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name': 'proof', 'image': args.proof_image, 'imagePullPolicy': 'Never', 'command': ['python3', '-c', code], 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '200m', 'memory': '128Mi'}}, 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}, 'volumeMounts': [{'name': 'credential', 'mountPath': '/credential', 'readOnly': True}]}], 'volumes': [{'name': 'credential', 'secret': {'secretName': 'remote-cluster'}}]}}, actor=actor)
        pod_deadline = time.monotonic() + 120
        while time.monotonic() < pod_deadline:
            phase = kube(source, ['get', 'pod/mount-proof', '-n', ns,
                                  '-o', 'jsonpath={.status.phase}'], timeout=10).stdout.strip()
            if phase == 'Succeeded':
                break
            if phase == 'Failed':
                raise RuntimeError('Owned proof Pod failed; acceptance rejected')
            time.sleep(1)
        else:
            raise RuntimeError('Owned proof Pod did not finish within 120 seconds')
        proof = json.loads(kube(source, ['logs', 'mount-proof', '-n', ns]).stdout)
        observed_at = datetime.now(timezone.utc).isoformat()
        assert proof == {'configmap_status': 200, 'marker': owner, 'secrets_status': 403, 'identity_status': 201, 'subject': claims['sub']}, proof
        print(json.dumps({'stage': 'actual_mount_and_remote_auth', 'configmap_status': 200, 'secrets_status': 403, 'identity_status': 201, 'author_cannot_read_secret': True}), flush=True)
        from peaso.collectors import k8s
        from peaso import privesc
        from peaso.privesc.effective_permissions.credential_evidence import ARGOCD_MOUNT, ARGOCD_CONDITIONS
        connector = {'provider': 'k8s', 'auth': {'method': 'kubeconfig', 'kubeconfig': str(configs[source]), 'context': 'kind-' + source, 'cluster_id': source}, 'scopes': [ns], 'options': {'max_calls': 50, 'workers': 2}}
        snapshot = k8s.collect(connector, requirements=['role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'serviceaccount', 'namespace', 'secret_metadata', 'pod', 'node'])
        assert token not in json.dumps(snapshot), 'Credential leaked into native snapshot'
        source_id = 'k8s:' + source + ':sa:' + ns + ':author'
        target = 'k8s_remote_cluster:' + source + '/' + ns + '/remote-cluster'
        now = datetime.now(timezone.utc).isoformat()
        entry = next((e for e in privesc.load_catalog()['entries'] if e['id'] == ARGOCD_MOUNT))
        before = privesc.analyze(snapshot, entries=[entry])
        assert not any((e['confidence'] == 'conditional' and ARGOCD_MOUNT in e['techniques'] for e in before['graph']['edges']))
        observed = next((i for c in snapshot['collections'] if c['type'] == 'secret_metadata' for i in c['items'] if i['metadata']['name'] == 'remote-cluster'))
        aud = claims['aud'][0] if isinstance(claims['aud'], list) else claims['aud']
        fact = {'TechniqueId': ARGOCD_MOUNT, 'SourceId': source_id, 'TargetKind': 'k8s_remote_cluster', 'TargetId': target, 'TargetScope': source, 'Status': 'verified', 'VerifiedPreconditions': True, 'EvidenceRef': 'owned-live-kind-mount-and-remote-auth-' + owner, 'CredentialUsable': True, 'RevocationChecked': True, 'CredentialKind': 'k8s_bearer_token', 'CredentialSubjectId': claims['sub'], 'CredentialScope': remote, 'CredentialAudience': aud, 'RemoteAcceptedAudience': aud, 'RemoteClusterId': remote, 'RemoteServer': server, 'RemoteAuthorizationVerified': True, 'EffectiveRights': ['get:configmaps:' + remote_ns + '/marker'], 'EvidenceObservedAt': observed_at, 'CredentialExpiresAt': datetime.fromtimestamp(claims['exp'], timezone.utc).isoformat(), 'VerifiedConditionIds': list(ARGOCD_CONDITIONS), 'SecretName': 'remote-cluster', 'SecretNamespace': ns, 'SecretUID': observed['metadata']['uid'], 'SecretResourceVersion': observed['metadata']['resourceVersion'], 'WorkloadNamespace': ns, 'WorkloadResource': 'pods', 'WorkloadApiGroup': '', 'WorkloadAdmitted': True, 'SecretMountVerified': True}
        snapshot['collections'].append({'type': 'k8s_privesc_challenge_evidence', 'scope': source, 'status': 'collected', 'items': [fact], 'service': 'privesc', 'error': None})
        report = privesc.analyze(snapshot, entries=[entry])
        paths = [e for e in report['graph']['edges'] if e['source'] == source_id and e['target'] == target and (ARGOCD_MOUNT in e['techniques'])]
        assert len(paths) == 1 and paths[0]['confidence'] == 'conditional', (source_id, target, report['coverage'], report['graph'])
        (OUT / 'snapshot.json').write_text(json.dumps(snapshot) + '\n')
        (OUT / 'privesc-report.json').write_text(json.dumps(report) + '\n')
        assert token not in json.dumps(report)
        after = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
        assert source_files == after, 'privesc source changed during test'
        state['acceptance'] = {'passed': True, 'actual_mount': True, 'remote_configmap_get': 200, 'remote_secrets_get': 403, 'remote_identity_verified': True, 'native_metadata_only_snapshot': True, 'no_edge_without_reviewed_fact': True, 'conditional_edge_with_actual_proof': True, 'source_sha256': source_files, 'catalog_manifest_sha256': hashlib.sha256((ROOT / 'risk_rules/hacktricks-privesc-source.json').read_bytes()).hexdigest(), 'resources_created': {'kind_clusters': 2, 'private_docker_networks': 1, 'kubernetes_objects': 11}}
        save()
        print(json.dumps({'stage': 'product_evaluator_verified', 'conditional_paths': len(paths), 'native_calls': snapshot['stats'].get('calls') if isinstance(snapshot.get('stats'), dict) else None}), flush=True)
    except BaseException as exc:
        state['acceptance'] = {'passed': False, 'error_type': type(exc).__name__, 'error': str(exc)[:8000]}
        save()
        raise
    finally:
        cleanup = []
        for row in reversed(state['clusters']):
            n = row['name']
            try:
                identity()
                ids = containers(n)
                if ids:
                    run([KIND, 'delete', 'cluster', '--name', n, '--kubeconfig', str(configs[n])], timeout=120)
                assert not containers(n)
                configs[n].unlink(missing_ok=True)
                row.update(status='deleted', verification='exact_cluster_containers_absent_private_kubeconfig_removed')
                save()
            except Exception as exc:
                cleanup.append({'cluster': n, 'error': str(exc)})
        if state['network'].get('id'):
            try:
                identity()
                n = json.loads(run(['docker', 'network', 'inspect', state['network']['id']]).stdout)[0]
                assert n['Name'] == network and n.get('Labels', {}).get('peaso-test-owner') == owner and (not n['Containers'])
                run(['docker', 'network', 'rm', state['network']['id']])
                assert run(['docker', 'network', 'inspect', state['network']['id']], allow=True).returncode != 0
                state['network'].update(status='deleted', verification='network_not_found')
            except Exception as exc:
                cleanup.append({'network': network, 'error': str(exc)})
        state['cleanup_errors'] = cleanup
        state['cleanup_verified'] = not cleanup
        state['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({'stage': 'cleanup', 'verified': not cleanup, 'errors': cleanup}), flush=True)
        if cleanup:
            raise RuntimeError('owned resource cleanup needs attention')
if __name__ == '__main__':
    main()

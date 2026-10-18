"""Signed, snapshot-only remaining GCP native checks.

Adapted from the unimported sw draft families; each family is isolated in a
lexical namespace, and only the exact pending signed IDs are registered.
The companion disposition and focused fixtures document admission boundaries.
"""
# Source family: compliance_new_sw08.py
def _load_08():
    _ALLOWED = {'gcp.apikeys.active_service_restrictions', 'gcp.sql.mysql_admin_account_posture', 'gcp_artifact_registry_cleanup_policy', 'gcp_c5_classification_label', 'gcp_c5_kms_hsm', 'gcp_kms_approved_algorithm', 'gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650', 'gcp_pci_asset_6ee2fef37d98', 'gcp_workbench_approved_image', 'gcp_workbench_approved_vpc', 'gcp_workbench_download_disabled', 'gcp_workbench_no_public_ip', 'gcp_workbench_root_disabled', 'gcp_workbench_terminal_disabled'}
    'Signed GCP policy checks over complete, project-scoped read-only facts.\n\nOperator policy is carried in context.metadata.compliance_policy with an exact\nscope and collected status. Unavailable policy or inventory is never success.\n'
    import json
    import re
    from decimal import Decimal
    from collections import Counter
    from datetime import datetime
    from urllib.parse import quote
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, list_of_objects, omitted

    def _rows(index, kind, scope):
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('complete scoped collection unavailable: ' + kind)
        envelope = get({'envelope': envelopes[0]}, 'envelope', dict)
        if envelope.get('type') != kind or envelope.get('scope') != scope or envelope.get('status') not in ('collected', 'empty') or (envelope.get('coverage_status', 'collected') not in ('collected', 'empty')):
            raise Unavailable('complete scoped collection unavailable: ' + kind)
        rows = complete_items(index, kind)
        recorded = list_of_objects(get(envelope, 'items', list))
        encode = lambda row: json.dumps(row, sort_keys=True, separators=(',', ':'))
        if Counter(map(encode, rows)) != Counter(map(encode, recorded)) or (envelope.get('status') == 'empty' and rows):
            raise Unavailable('collection projection differs from envelope')
        names = set()
        for resource, row in zip(get(index, kind, list), rows):
            if get(resource, 'scope', str) != scope or get(resource, 'type', str) != kind or resource.get('provider', 'gcp') != 'gcp' or (get(row, '_provenance.scope', str) != scope):
                raise Unavailable('foreign resource fact')
            name = get(row, 'name', str)
            if not name or name in names:
                raise Unavailable('duplicate or malformed resource identity')
            names.add(name)
        return rows

    def _inventory(item, index, kind):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('GCP provider authority unavailable')
        scope = get(context, 'scope', str)
        if not re.fullmatch('projects/[A-Za-z0-9_-]+', scope):
            raise Unavailable('project scope unavailable')
        rows = _rows(index, kind, scope)
        if item not in rows:
            raise Unavailable('resource is not in the complete scoped inventory')
        return scope

    def _policy(index, scope):
        metadata = get(get(index, 'context', dict), 'metadata', dict)
        policy = get(metadata, 'compliance_policy', dict)
        if policy.get('status') != 'collected' or policy.get('scope') != scope:
            raise Unavailable('collected project-bound compliance policy unavailable')
        return policy

    def _names(policy, field):
        values = get(policy, field, list)
        if any((not isinstance(x, str) or not x.strip() for x in values)) or len(values) != len(set(values)):
            raise Unavailable('malformed policy list: ' + field)
        return set(values)

    def _workbench(item, index):
        scope = _inventory(item, index, 'workbench_instance')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/instances/[^/]+', name):
            raise Unavailable('Workbench instance identity malformed or foreign')
        return (name, _policy(index, scope))

    def _sensitivity(policy, name):
        values = get(policy, 'workbench_sensitive', dict)
        if name not in values or type(values[name]) is not bool:
            raise Unavailable('Workbench sensitivity classification unavailable')
        return values[name]

    def _metadata_flag(item, flag):
        value = get(item, 'gceSetup.metadata.' + flag, str)
        if value not in ('true', 'false'):
            raise Unavailable('unrecognized Workbench metadata flag: ' + flag)
        return value == 'true'

    def _image_ref(value, kind):
        if not isinstance(value, dict):
            raise Unavailable('malformed Workbench image')
        if kind == 'vmImage':
            project = get(value, 'project', str)
            selectors = [key for key in ('family', 'name') if key in value]
            if not project or len(selectors) != 1 or 'imageFamily' in value or ('imageName' in value):
                raise Unavailable('Workbench v2 VM image identity unavailable')
            selector = get(value, selectors[0], str)
            if not selector:
                raise Unavailable('Workbench VM image selector empty')
            return 'vm:' + project + '/' + selectors[0] + '/' + selector
        repository = get(value, 'repository', str)
        selector = get(value, 'tag', str)
        if not repository or not selector or 'digest' in value:
            raise Unavailable('Workbench v2 container image identity unavailable')
        return 'container:' + repository + '/' + selector

    def _approved_image(item, index):
        name, policy = _workbench(item, index)
        approved = _names(policy, 'approved_workbench_images')
        setup = get(item, 'gceSetup', dict)
        refs = [_image_ref(get(setup, kind, dict), kind) for kind in ('vmImage', 'containerImage') if kind in setup]
        if len(refs) != 1:
            return unknown('unique Workbench image metadata unavailable', instance=name)
        return result(any((ref not in approved for ref in refs)), instance=name, images=refs)

    def _approved_vpc(item, index):
        name, policy = _workbench(item, index)
        approved = _names(policy, 'approved_workbench_networks')
        interfaces = get(item, 'gceSetup.networkInterfaces', list)
        if not interfaces:
            return unknown('Workbench network metadata unavailable', instance=name)
        networks = [get(interface, 'network', str) for interface in interfaces]
        if any((not network for network in networks)):
            return unknown('Workbench network identity unavailable', instance=name)
        return result(any((network not in approved for network in networks)), instance=name, networks=networks)

    def _sensitive_flag(item, index, field, metadata=False):
        name, policy = _workbench(item, index)
        sensitive = _sensitivity(policy, name)
        if not sensitive:
            return ('NOT_APPLICABLE', {'instance': name, 'reason': 'policy classifies instance as nonsensitive'})
        disabled = _metadata_flag(item, field) if metadata else get(item, 'gceSetup.' + field, bool)
        return result(not disabled, instance=name, sensitive=True, configured=disabled)

    def _exception_flag(item, index, flag):
        name, policy = _workbench(item, index)
        sensitive = _sensitivity(policy, name)
        disabled = _metadata_flag(item, flag)
        if sensitive:
            return result(not disabled, instance=name, sensitive=True, disabled=disabled)
        if disabled:
            return result(False, instance=name, sensitive=False, disabled=True)
        exceptions = get(policy, 'approved_workbench_exceptions', dict)
        if name in exceptions and (not isinstance(exceptions[name], dict) or type(exceptions[name].get(flag)) is not bool):
            return unknown('malformed Workbench exception decision', instance=name)
        approved = exceptions.get(name, {}).get(flag, False)
        return result(not disabled and (not approved), instance=name, sensitive=False, disabled=disabled, approved_exception=approved)

    def _classification(item, index):
        scope = _inventory(item, index, 'bucket')
        name = get(item, 'name', str)
        policy = _policy(index, scope)
        in_scope = _names(policy, 'classified_buckets')
        if name not in in_scope:
            return ('NOT_APPLICABLE', {'bucket': name, 'reason': 'bucket outside approved classification scope'})
        key = get(policy, 'required_classification_key', str)
        if not key:
            raise Unavailable('classification key unavailable')
        approved = _names(policy, 'approved_classification_values')
        if 'labels' in item or 'labels' in item.get('_coverage', {}):
            labels = get(item, 'labels', dict)
        elif get(item, '_provenance.representation', str) == 'full':
            labels = {}
        else:
            raise Unavailable('bucket labels unavailable in partial representation')
        if any((not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items())):
            raise Unavailable('malformed bucket labels')
        return result(labels.get(key) not in approved, bucket=name, classification=labels.get(key))

    def _hsm(item, index):
        scope = _inventory(item, index, 'kms_key')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+', name):
            raise Unavailable('CryptoKey identity malformed or foreign')
        policy = _policy(index, scope)
        designated = _names(policy, 'designated_hsm_keys')
        if name not in designated:
            return ('NOT_APPLICABLE', {'key': name, 'reason': 'key is not HSM designated'})
        allowed = {'HSM'}
        external = policy.get('approved_external_vpc_keys', [])
        if not isinstance(external, list) or any((not isinstance(x, str) for x in external)):
            raise Unavailable('external VPC key policy malformed')
        if name in external:
            allowed.add('EXTERNAL_VPC')
        level = get(item, 'primary.protectionLevel', str)
        if level not in ('SOFTWARE', 'HSM', 'EXTERNAL', 'EXTERNAL_VPC'):
            raise Unavailable('unknown KMS protection level')
        return result(level not in allowed, key=name, protection_level=level)

    def _versions(item, index):
        scope = _inventory(item, index, 'kms_key')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+', name):
            raise Unavailable('CryptoKey identity malformed or foreign')
        versions = _rows(index, 'kms_key_version', scope)
        selected = []
        seen = set()
        for version in versions:
            version_name = get(version, 'name', str)
            if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+', version_name) or version_name in seen:
                raise Unavailable('foreign or inconsistent CryptoKeyVersion fact')
            seen.add(version_name)
            if version_name.startswith(name + '/cryptoKeyVersions/'):
                selected.append(version)
        scheduled = []
        for version in selected:
            state = get(version, 'state', str)
            if state not in ('PENDING_GENERATION', 'ENABLED', 'DISABLED', 'DESTROY_SCHEDULED', 'DESTROYED', 'PENDING_IMPORT', 'IMPORT_FAILED', 'GENERATION_FAILED'):
                raise Unavailable('unrecognized CryptoKeyVersion state')
            if state == 'DESTROY_SCHEDULED':
                destroy = get(version, 'destroyTime', str)
                if not re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})', destroy):
                    raise Unavailable('malformed scheduled destruction time')
                try:
                    datetime.fromisoformat(destroy.replace('Z', '+00:00'))
                except ValueError:
                    raise Unavailable('malformed scheduled destruction time')
                scheduled.append(version['name'])
        return result(bool(scheduled), key=name, scheduled_versions=scheduled)

    def _logging_retention(item, index):
        scope = _inventory(item, index, 'logging_bucket')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/buckets/[^/]+', name):
            raise Unavailable('Logging bucket identity malformed or foreign')
        context = get(index, 'context', dict)
        metadata = context.get('metadata', {})
        if not isinstance(metadata, dict):
            raise Unavailable('malformed snapshot metadata')
        threshold = metadata.get('MinRetentionTime', 365)
        if type(threshold) is not int or threshold <= 0:
            raise Unavailable('invalid MinRetentionTime')
        days = get(item, 'retentionDays', int)
        if days < 0:
            raise Unavailable('invalid Logging bucket retention')
        return result(days < threshold, bucket=name, retention_days=days, min_retention_days=threshold)
    _KMS_ALGORITHMS = {'GOOGLE_SYMMETRIC_ENCRYPTION', 'EXTERNAL_SYMMETRIC_ENCRYPTION', 'AES_256_KWP', *(f'AES_{bits}_{mode}' for bits in (128, 256) for mode in ('GCM', 'CBC', 'CTR')), *(f'RSA_SIGN_{padding}_{bits}_SHA256' for padding in ('PSS', 'PKCS1') for bits in (2048, 3072, 4096)), 'RSA_SIGN_PSS_4096_SHA512', 'RSA_SIGN_PKCS1_4096_SHA512', *(f'RSA_SIGN_RAW_PKCS1_{bits}' for bits in (2048, 3072, 4096)), *(f'RSA_DECRYPT_OAEP_{bits}_{digest}' for bits in (2048, 3072, 4096) for digest in ('SHA1', 'SHA256')), 'RSA_DECRYPT_OAEP_4096_SHA512', 'EC_SIGN_P256_SHA256', 'EC_SIGN_P384_SHA384', 'EC_SIGN_SECP256K1_SHA256', 'EC_SIGN_ED25519', *(f'HMAC_SHA{bits}' for bits in (1, 224, 256, 384, 512)), 'ML_KEM_768', 'ML_KEM_1024', 'KEM_XWING', 'KEM_ECDH_P256', 'KEM_ECDH_P384', *(f'PQ_SIGN_ML_DSA_{level}{suffix}' for level in (44, 65, 87) for suffix in ('', '_EXTERNAL_MU')), 'PQ_SIGN_SLH_DSA_SHA2_128S', 'PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256'}

    def _approved_algorithm(item, index):
        scope = _inventory(item, index, 'kms_key_version')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+', name):
            raise Unavailable('CryptoKeyVersion identity malformed or foreign')
        policy = _policy(index, scope)
        approved = _names(policy, 'approved_algorithms')
        state = get(item, 'state', str)
        if state not in ('PENDING_GENERATION', 'ENABLED', 'DISABLED', 'DESTROY_SCHEDULED', 'DESTROYED', 'PENDING_IMPORT', 'IMPORT_FAILED', 'GENERATION_FAILED'):
            raise Unavailable('unrecognized CryptoKeyVersion state')
        if state != 'ENABLED':
            return ('NOT_APPLICABLE', {'version': name, 'reason': 'version is not ENABLED'})
        algorithm = get(item, 'algorithm', str)
        if algorithm not in _KMS_ALGORITHMS:
            raise Unavailable('version algorithm unavailable or unrecognized')
        return result(algorithm not in approved, version=name, algorithm=algorithm)

    def _artifact_cleanup(item, index):
        scope = _inventory(item, index, 'artifact_repository')
        name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/repositories/[^/]+', name):
            raise Unavailable('Artifact Registry repository identity malformed or foreign')
        policy = _policy(index, scope)
        maximum = get(policy, 'max_artifact_age', int)
        if maximum <= 0:
            raise Unavailable('invalid max_artifact_age seconds')
        dry_run = omitted(item, 'cleanupPolicyDryRun', False, bool)
        policies = omitted(item, 'cleanupPolicies', {}, dict)
        if not policies or any((not isinstance(key, str) or not key or (not isinstance(value, dict)) for key, value in policies.items())):
            if policies:
                raise Unavailable('malformed cleanup policy map')
            return result(True, repository=name, reason='no cleanup policies') if not dry_run else result(True, repository=name, reason='cleanup is dry-run')
        qualifying = []
        for key, value in policies.items():
            action = get(value, 'action', str)
            if action not in ('DELETE', 'KEEP'):
                raise Unavailable('unrecognized cleanup policy action')
            if 'condition' in value and 'mostRecentVersions' in value:
                raise Unavailable('conflicting cleanup condition union')
            if 'condition' in value:
                condition = get(value, 'condition', dict)
                for field in ('tagPrefixes', 'versionNamePrefixes', 'packageNamePrefixes'):
                    if field in condition:
                        values = get(condition, field, list)
                        if any((not isinstance(x, str) or not x for x in values)):
                            raise Unavailable('malformed cleanup condition prefix')
                if 'tagState' in condition and get(condition, 'tagState', str) not in {'TAG_STATE_UNSPECIFIED', 'TAGGED', 'UNTAGGED', 'ANY'}:
                    raise Unavailable('unrecognized cleanup tag state')
                for field in ('olderThan', 'newerThan'):
                    if field in condition and (not re.fullmatch('[0-9]+(?:\\.[0-9]{1,9})?s', get(condition, field, str))):
                        raise Unavailable('malformed cleanup duration')
            elif 'mostRecentVersions' in value and action == 'KEEP':
                recent = get(value, 'mostRecentVersions', dict)
                if get(recent, 'keepCount', int) <= 0:
                    raise Unavailable('malformed cleanup keep count')
            else:
                raise Unavailable('cleanup policy condition unavailable')
            if action != 'DELETE':
                continue
            condition = get(value, 'condition', dict)
            if 'mostRecentVersions' in value:
                raise Unavailable('conflicting cleanup condition union')
            older = omitted({**condition, '_provenance': item.get('_provenance', {})}, 'olderThan', '', str)
            if not older:
                continue
            match = re.fullmatch('([0-9]+(?:\\.[0-9]{1,9})?)s', older)
            if not match:
                raise Unavailable('unrecognized cleanup policy duration')
            if Decimal(match.group(1)) <= maximum:
                qualifying.append(key)
        return result(dry_run or not qualifying, repository=name, qualifying_delete_policies=sorted(qualifying), dry_run=dry_run)

    def _api_key_services(item, index):
        scope = _inventory(item, index, 'api_key')
        key_name = get(item, 'name', str)
        if not re.fullmatch(re.escape(scope) + '/locations/[^/]+/keys/[^/]+', key_name):
            raise Unavailable('API key identity malformed or foreign')
        targets = get(item, 'restrictions.apiTargets', list)
        if not targets:
            return unknown('API key has no explicit service targets', api_key=key_name)
        requested = []
        for target in targets:
            service = get(target, 'service', str)
            if not re.fullmatch('[a-z][a-z0-9.-]+\\.googleapis\\.com', service):
                raise Unavailable('malformed API target service')
            requested.append(service)
        rows = _rows(index, 'service_usage', scope)
        states = {}
        for row in rows:
            name = get(row, 'name', str)
            state = get(row, 'state', str)
            if get(row, '_provenance.scope', str) != scope or not re.fullmatch(re.escape(scope) + '/services/[a-z][a-z0-9.-]+\\.googleapis\\.com', name) or name in states or (state not in ('ENABLED', 'DISABLED')):
                raise Unavailable('malformed or foreign Service Usage fact')
            states[name] = state
        if any((scope + '/services/' + service not in states for service in requested)):
            return unknown('target service absent from selected Service Usage inventory', api_key=key_name)
        disabled = sorted(set((service for service in requested if states[scope + '/services/' + service] == 'DISABLED')))
        if disabled:
            return result(True, api_key=key_name, disabled_target_services=disabled)
        return unknown('enabled service does not establish active key use', api_key=key_name)

    def _mysql_admin(item, index):
        scope = _inventory(item, index, 'sql_user')
        identity = get(item, 'name', str)
        if not identity.startswith(scope + '/instances/') or '/users/' not in identity:
            raise Unavailable('SQL user identity belongs to another project')
        instance_id = get(item, 'instanceId', str)
        if not instance_id or not identity.startswith(scope + '/instances/' + instance_id + '/users/'):
            raise Unavailable('SQL user parent instance identity unavailable')
        instances = _rows(index, 'sql_instance', scope)
        by_name = {}
        for instance in instances:
            instance_name = get(instance, 'name', str)
            if not instance_name or instance_name in by_name or get(instance, '_provenance.scope', str) != scope:
                raise Unavailable('foreign or duplicate SQL instance')
            by_name[instance_name] = instance
        if instance_id not in by_name:
            raise Unavailable('SQL user parent instance absent')
        version = get(by_name[instance_id], 'databaseVersion', str)
        if not re.fullmatch('MYSQL_[0-9]+(?:_[0-9]+)*', version):
            if re.fullmatch('(?:POSTGRES_[0-9]+(?:_[0-9]+)?|SQLSERVER_[0-9]+_(?:STANDARD|ENTERPRISE|EXPRESS|WEB))', version):
                return ('NOT_APPLICABLE', {'sql_user': identity, 'reason': 'parent instance is not MySQL'})
            raise Unavailable('unsupported SQL instance database version')
        username = get(item, 'userName', str)
        host = get(item, 'host', str)
        user_type = get(item, 'type', str)
        known_types = {'BUILT_IN', 'CLOUD_IAM_USER', 'CLOUD_IAM_SERVICE_ACCOUNT', 'CLOUD_IAM_GROUP', 'CLOUD_IAM_GROUP_USER', 'CLOUD_IAM_GROUP_SERVICE_ACCOUNT'}
        expected_identity = scope + '/instances/' + instance_id + '/users/' + quote(username, safe='') + '@' + quote(host, safe='')
        if not username or not host or user_type not in known_types or (identity != expected_identity):
            raise Unavailable('SQL user identity fields unavailable')
        failed = (username == 'root' or user_type == 'BUILT_IN') and host in ('%', '0.0.0.0/0')
        return result(failed, sql_user=identity, user_name=username, host=host, user_type=user_type)
    _DEFINITIONS = []

    def _install(identifier, category, kind, title, severity, hint, sha, evaluator, dependencies=None):

        @register(identifier, 'gcp', category if category in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening', kind, title, severity, 'CM-6', hint, dependencies=dependencies or [kind])
        def check(item, index):
            return evaluator(item, index)
        check.__name__ = identifier.replace('.', '_')
        registered = CHECKS[-1]
        if registered.id != identifier:
            raise RuntimeError('unexpected registry order')
        pass
        _DEFINITIONS.append((identifier, sha))
        return check
    _install('gcp_workbench_approved_image', 'compute', 'workbench_instance', 'Workbench instance uses an unapproved image', 'high', 'Recreate the Workbench instance with gceSetup.vmImage or containerImage from approved_workbench_images.', 'ed670835e571526ea18d080d056059e61fe87326d152bc4546d4f6e0fc2fc4bd', _approved_image, dependencies=['workbench_instance'])
    _install('gcp_workbench_approved_vpc', 'network', 'workbench_instance', 'Workbench instance uses an unapproved VPC', 'medium', 'Move or recreate the Workbench instance on a VPC in approved_workbench_networks.', 'f4f5feed1c78426146fec3ce0bbcaf09f039ab7bee7f39a175be69cbf5c0c111', _approved_vpc, dependencies=['workbench_instance'])
    _install('gcp_workbench_download_disabled', 'compute', 'workbench_instance', 'Sensitive Workbench instance allows file downloads', 'medium', 'Set gceSetup.metadata.notebook-disable-downloads=true on sensitive Workbench instances.', 'a604366f60551960af7b76911769643a196549adeaf205f383804b4dc1097678', lambda i, x: _sensitive_flag(i, x, 'notebook-disable-downloads', True), dependencies=['workbench_instance'])
    _install('gcp_workbench_no_public_ip', 'network', 'workbench_instance', 'Sensitive Workbench instance permits a public IP', 'medium', 'Set gceSetup.disablePublicIp=true on sensitive Workbench instances and use private access.', 'bf7b3cc245cd475915b7ef6210af00f072ab2e5eb723223856befcf7aae7db8d', lambda i, x: _sensitive_flag(i, x, 'disablePublicIp'), dependencies=['workbench_instance'])
    _install('gcp_workbench_root_disabled', 'compute', 'workbench_instance', 'Workbench root access violates classification policy', 'medium', 'Set gceSetup.metadata.notebook-disable-root=true on sensitive Workbench instances; document nonsensitive exceptions.', '16d65c05518f4aa17fd4390611160fe5fb1ffc0f96b1503242e4a86bf32362a0', lambda i, x: _exception_flag(i, x, 'notebook-disable-root'), dependencies=['workbench_instance'])
    _install('gcp_workbench_terminal_disabled', 'compute', 'workbench_instance', 'Workbench terminal access violates classification policy', 'medium', 'Set gceSetup.metadata.notebook-disable-terminal=true on sensitive Workbench instances; document nonsensitive exceptions.', '020c75fd76b06549135f21c1499fee6172b1e433cbe62980286065dc72a10f69', lambda i, x: _exception_flag(i, x, 'notebook-disable-terminal'), dependencies=['workbench_instance'])
    _install('gcp_c5_classification_label', 'asset_management', 'bucket', 'Cloud Storage bucket classification label', 'medium', 'Set the approved classification label and value on each in-scope Cloud Storage bucket with gcloud storage buckets update --update-labels.', 'eee3ae9bd7d11ebffeb52ee72c8704e4f322c4db72810645762bc9e7556e5fdc', _classification, dependencies=['bucket'])
    _install('gcp_c5_kms_hsm', 'key_management', 'kms_key', 'HSM-protected KMS key', 'medium', 'Create designated Cloud KMS keys with protectionLevel=HSM, or approved EXTERNAL_VPC, and migrate protected workloads.', '70698b8e45c47909338af939b701513e16da2d72a114777777772153c12817b7', _hsm, dependencies=['kms_key'])
    _install('gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650', 'hardening', 'kms_key', 'KMS key version is scheduled for destruction', 'medium', 'Cancel destruction of any KMS version in DESTROY_SCHEDULED state if deletion is not approved.', '8e9aff3409ed1c0ce2b30b898508439cb18006ec1f7b8b2ee94287b8d37c82e8', _versions, dependencies=['kms_key', 'kms_key_version'])
    _install('gcp_pci_asset_6ee2fef37d98', 'retention', 'logging_bucket', 'Cloud Logging bucket retention meets minimum', 'medium', 'Set each Cloud Logging bucket retentionDays to at least configured MinRetentionTime (365 days by default).', '076d04357099e5a69960c32b2106b4ff0fba622a6e2f2d1ee1b7068a49dcc276', _logging_retention, dependencies=['logging_bucket'])
    _install('gcp_kms_approved_algorithm', 'encryption', 'kms_key_version', 'KMS key version uses an unapproved algorithm', 'high', 'Rotate ENABLED KMS key versions using an algorithm in approved_algorithms and disable unapproved versions.', '71068c89df5053ff3a950dd33b6fc4b8af1896186e8ae7789a19714c9bbc6166', _approved_algorithm, dependencies=['kms_key_version'])
    _install('gcp_artifact_registry_cleanup_policy', 'data_lifecycle', 'artifact_repository', 'Artifact repository lacks age-based cleanup', 'medium', 'Add an Artifact Registry DELETE cleanupPolicy with an age condition at or below the approved max_artifact_age and disable dry run.', '73e2c420470a52c7a17b69a6b305a0b3b5cce7fe14a20f3102291682d56ae4e1', _artifact_cleanup, dependencies=['artifact_repository'])
    _install('gcp.apikeys.active_service_restrictions', 'least_privilege', 'api_key', 'API keys target only active enabled services', 'medium', "In APIs & Services > Credentials, edit the key's API restrictions to remove disabled services; delete unused keys.", '7c91d652644f5e1644dacb522fc4fd15d2f30eabdbe7ec4c9481e87fa85c69db', _api_key_services, dependencies=['api_key', 'service_usage'])
    _install('gcp.sql.mysql_admin_account_posture', 'least_privilege', 'sql_user', 'MySQL administrative accounts restrict remote connections', 'high', 'Restrict MySQL root or built-in account host from % and 0.0.0.0/0 using Cloud SQL Users settings.', 'ebded375bd9e341806de99ef9f490c3b17aec3c51e4fae9b3ff2beb57ff2e34c', _mysql_admin, dependencies=['sql_user', 'sql_instance'])
    from .facts import memoized as _batch_memoized
    _base_rows = _rows

    def _rows(index, kind, scope):
        return _batch_memoized(index, ('batch_sw08_rows', kind, scope), lambda: _base_rows(index, kind, scope))

    def _inventory(item, index, kind):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('GCP provider authority unavailable')
        scope = get(context, 'scope', str)
        if not re.fullmatch('projects/[A-Za-z0-9_-]+', scope):
            raise Unavailable('project scope unavailable')
        rows = _rows(index, kind, scope)
        fingerprints = _batch_memoized(index, ('batch_sw08_members', kind, scope), lambda: Counter((json.dumps(row, sort_keys=True, separators=(',', ':')) for row in rows)))
        try:
            identity = json.dumps(item, sort_keys=True, separators=(',', ':'))
        except (TypeError, ValueError) as exc:
            raise Unavailable('resource malformed') from exc
        if fingerprints[identity] != 1:
            raise Unavailable('resource is not in complete scoped inventory')
        return scope
_load_08()

# Source family: compliance_new_sw09.py
def _load_09():
    _ALLOWED = {'gcp.appengine.version_https_only', 'gcp.sql.iam_database_authentication', 'gcp_autoscaler_capacity_target', 'gcp_c5_iam_inventory', 'gcp_c5_network_separation', 'gcp_c5_network_topology', 'gcp_c5_tls_policy', 'gcp_certificate_validity', 'gcp_cloudbuild_trigger_trust', 'gcp_compute_approved_image', 'gcp_gke_client_certificate_enabled', 'gcp_https_proxy_mtls_required', 'gcp_network_auto_subnets_enabled', 'gcp_pci_firewall_2080b14f1361', 'gcp_resource_approved_location', 'gcp_resource_label_inventory', 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6', 'gcp_sql_trace3625_off', 'gcp_vpc_peering_allowlist'}
    'Signed GCP proposed checks implemented by the sw09 collector-aware wave.'
    import re
    import json
    from collections import Counter
    from dataclasses import replace
    from datetime import datetime, timezone
    from ipaddress import ip_network
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, guard, list_of_objects, full_representation, omitted
    META = {'gcp.appengine.version_https_only': {'category': 'network', 'description': 'Checks the App Engine Admin API securityLevel on each handler of SERVING versions; SECURE_ALWAYS redirects HTTP to HTTPS. Missing or masked handler settings cannot prove HTTPS enforcement.', 'proposed_spec_sha256': '31bf24910d36ea78c6a82f402310a5504c4800e38585aff1d879dfaea1554dbe', 'remediation_hint': 'Review handler routing with the service owner, set secure: always in app.yaml for the intended handlers, deploy a new version, and verify the Admin API securityLevel declaration.', 'resource_kind': 'app_engine_version', 'severity': 'high', 'title': 'App Engine serving versions enforce HTTPS'}, 'gcp.sql.iam_database_authentication': {'category': 'hardening', 'description': 'On supported Cloud SQL PostgreSQL and MySQL instances, detects when users.list contains no IAM database user; this leaves database access dependent on built-in credentials rather than IAM identities.', 'proposed_spec_sha256': '0fa6351e4358600196dc9658773cf10e4cece7acddc95bbe9cfe5b6a30c0b6b3', 'remediation_hint': 'Create an IAM database user on the Cloud SQL instance with gcloud sql users create --type=CLOUD_IAM_USER or CLOUD_IAM_SERVICE_ACCOUNT.', 'resource_kind': 'sql_instance', 'severity': 'medium', 'title': 'Cloud SQL has an IAM database user'}, 'gcp_autoscaler_capacity_target': {'category': 'availability', 'description': 'On autoscaler resources, detects when utilizationTarget exceeds 0.8 or maxNumReplicas cannot add at least one instance above current size; this matters because it can lead to service outage or failed recovery.', 'proposed_spec_sha256': 'f863fe5de239d95cacfaf54ec8ca29d724a8b89a8ff850e137172e8065d1e282', 'remediation_hint': 'Lower autoscalingPolicy.cpuUtilization.utilizationTarget to 0.8 or less and raise maxNumReplicas above the current MIG target size.', 'resource_kind': 'autoscaler', 'severity': 'medium', 'title': 'Autoscaler cannot expand at 80 percent capacity'}, 'gcp_c5_tls_policy': {'category': 'encryption', 'description': 'On target proxy resources, detects when an in-scope HTTPS or SSL proxy has a policy allowing a TLS version/cipher below the approved minimum; this matters because it can lead to unprotected sensitive data.', 'proposed_spec_sha256': 'ed286edd189b2231b318a52ffc6f8dbbd18617ca3f78575c1cbc76d95377483c', 'remediation_hint': 'Attach an SSL policy with approved minTlsVersion and cipher profile to every in-scope target HTTPS/SSL proxy.', 'resource_kind': 'target_proxy', 'severity': 'medium', 'title': 'Approved frontend TLS policy'}, 'gcp_certificate_validity': {'category': 'encryption', 'description': 'On certificate resources, detects when expireTime is past or managed.state is not ACTIVE; this matters because it can lead to unprotected sensitive data.', 'proposed_spec_sha256': '6a623dc5d64f07b6de945273d5d7237f880b0e3a028e722f8ad67fa043220084', 'remediation_hint': 'Renew or replace expired Certificate Manager certificates and attach an ACTIVE certificate to the map entry.', 'resource_kind': 'certificate', 'severity': 'high', 'title': 'Managed certificate is expired or inactive'}, 'gcp_cloudbuild_trigger_trust': {'category': 'supply_chain', 'description': 'On cloudbuild trigger resources, detects when an enabled trigger uses a repository or service account outside approved allowlists; this matters because it can lead to unverifiable software provenance.', 'proposed_spec_sha256': 'fb317c2787af526c9c6a44c9bb9c98837c475bd28e07335fcec705b02ff80d16', 'remediation_hint': 'Restrict enabled Cloud Build trigger repository selectors and serviceAccount to the approved source and identity lists.', 'resource_kind': 'cloudbuild_trigger', 'severity': 'high', 'title': 'Cloud Build trigger accepts unapproved source'}, 'gcp_cloudsql_failed_attempts_lockout': {'category': 'identity', 'description': 'On sql instance resources, detects when password policy or failedAttemptsCheck is false for an in-scope SQL instance; this matters because it can lead to account takeover or privilege misuse.', 'proposed_spec_sha256': 'e8a00a7a5e39d325f24a58ee7d6d5068554e680193c1447bdc3e803ed686f6ef', 'remediation_hint': 'Set Cloud SQL settings.passwordValidationPolicy.enablePasswordPolicy=true and failedAttemptsCheck=true on supported engines.', 'resource_kind': 'sql_instance', 'severity': 'medium', 'title': 'Cloud SQL password failed-attempt lockout is disabled'}, 'gcp_compute_approved_image': {'category': 'compute', 'description': 'On instance resources, detects when a VM boot disk sourceImage is outside approved_image_projects; this matters because VMs may inherit unvetted operating system content.', 'proposed_spec_sha256': '518042836f9498a3e1f199accb53b806f2f7a28b3e72e7e55c79e1886c1c234f', 'remediation_hint': 'Replace the VM boot disk with an image from approved_image_projects, then verify its disk.sourceImage.', 'resource_kind': 'instance', 'severity': 'high', 'title': 'VM uses an unapproved image'}, 'gcp_gke_client_certificate_enabled': {'category': 'identity', 'description': 'Records legacy GKE client-certificate issuance for an owner-approved exception review; disabling legacy issuance is the recommended security posture.', 'proposed_spec_sha256': '788f62a784cf46f983650da3e354ef6b2289e196dd037517e4847a7ad17f8699', 'remediation_hint': 'Review legacy certificate authentication with the cluster owner and use modern GKE authentication; do not enable certificate issuance solely for this historical control.', 'resource_kind': 'gke_cluster', 'severity': 'medium', 'title': 'GKE legacy client-certificate issuance requires policy review'}, 'gcp_https_proxy_mtls_required': {'category': 'encryption', 'description': 'On target https proxy resources, detects when an HTTPS proxy lacks a server TLS policy requiring REJECT_INVALID client certificates; this matters because it can lead to unprotected sensitive data.', 'proposed_spec_sha256': '9a13a18ff4e298ca90e176a41355195492cd6d508ab5d1e9f60194a543b88913', 'remediation_hint': 'Attach a Network Security serverTlsPolicy to each HTTPS proxy with mtlsPolicy.clientValidationMode=REJECT_INVALID.', 'resource_kind': 'target_https_proxy', 'severity': 'high', 'title': 'HTTPS proxy does not require client certificates'}, 'gcp_network_auto_subnets_enabled': {'category': 'network', 'description': 'On a VPC required to use automatic subnet creation, detects autoCreateSubnetworks=false; the VPC lacks regional subnetworks required by the approved design.', 'proposed_spec_sha256': 'baee4c53108558634672b2aaaa0013b32e57e578d2aadfdf530184b65656094e', 'remediation_hint': 'Set autoCreateSubnetworks=true on the VPC only if automatic regional subnet creation is the approved network design.', 'resource_kind': 'network', 'severity': 'medium', 'title': 'VPC automatically creates regional subnetworks where required'}, 'gcp_pci_firewall_2080b14f1361': {'category': 'network', 'description': 'On firewall resources, detects when any active ingress allow rule admits public source 0.0.0.0/0 or ::/0 for the ports and protocols in scope; this matters because internet hosts can connect to the allowed ports.', 'proposed_spec_sha256': '0492786d4f15b0ec06330e86eb57d9e042864815ffb238d8eac9f509c78a2a18', 'remediation_hint': 'Restrict firewall sourceRanges from 0.0.0.0/0 and ::/0 to approved CIDRs for each allowed port/protocol.', 'resource_kind': 'firewall', 'severity': 'medium', 'title': 'VPC firewall public ingress'}, 'gcp_pci_iam_policy_9a8ce875703d': {'category': 'logging', 'description': 'On iam policy resources, detects when effective auditConfigs omit the required Pub/Sub Data Access log types; this matters because Pub/Sub data access may not appear in audit logs.', 'proposed_spec_sha256': '2e15b4bf0d6053de740b6ebac702394241a61c999cc2a9f59c2d898e6e632c7b', 'remediation_hint': 'Add effective Pub/Sub auditConfigs with required DATA_READ and DATA_WRITE types and remove relevant exemptions.', 'resource_kind': 'iam_policy', 'severity': 'medium', 'title': 'Pub/Sub Data Access audit logging'}, 'gcp_pci_iam_policy_ca1281da7ab2': {'category': 'logging', 'description': 'On iam policy resources, detects when effective auditConfigs omit the required Spanner Data Access log types; this matters because Spanner data access may not appear in audit logs.', 'proposed_spec_sha256': '8beebc607b85d140d1a91893e1a7ceb75cc2ed8f136622fe87b5ccf7631228e6', 'remediation_hint': 'Add effective Spanner auditConfigs with required DATA_READ and DATA_WRITE types and remove relevant exemptions.', 'resource_kind': 'iam_policy', 'severity': 'medium', 'title': 'Spanner Data Access audit logging'}, 'gcp_resource_approved_location': {'category': 'data_residency', 'description': 'On cloud asset resources, detects when a collected resource location is absent from the explicit approved_locations allowlist; this matters because it can lead to processing outside approved regions.', 'proposed_spec_sha256': '0f5f46d8008cd59aa112912de3c4927c07436e682d4627e970282f34479f5766', 'remediation_hint': 'Move resources to an approved location or update the approved_locations policy for explicitly authorized regions.', 'resource_kind': 'cloud_asset', 'severity': 'high', 'title': 'Resource location is not approved'}, 'gcp_resource_label_inventory': {'category': 'asset_management', 'description': 'On cloud asset resources, detects when an in-scope asset lacks required owner,criticality,data_classification labels; this matters because it can lead to incomplete ownership and risk inventory.', 'proposed_spec_sha256': '36f85f16df8fe45d6bfc59eb0e339adaba6d790d437b49c55c8a45a544d02366', 'remediation_hint': 'Add required owner, criticality and data_classification labels to each in-scope Cloud Asset resource.', 'resource_kind': 'cloud_asset', 'severity': 'medium', 'title': 'Cloud asset lacks inventory labels'}, 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6': {'category': 'least_privilege', 'description': 'On sql instance resources, detects when a PostgreSQL instance lacks cloudsql.iam_authentication=on or a MySQL instance lacks cloudsql_iam_authentication=on in settings.databaseFlags; this matters because it can lead to excessive access or misuse of credentials.', 'proposed_spec_sha256': 'cad29977e6a92560969e484fc3ea920903a5bd63c45f13f70acf92c23cbe285a', 'remediation_hint': 'Set the Cloud SQL engine-specific IAM authentication flag to on in settings.databaseFlags and restart if required.', 'resource_kind': 'sql_instance', 'severity': 'high', 'title': 'Cloud SQL IAM database authentication flag enabled'}, 'gcp_sql_trace3625_off': {'category': 'configuration', 'description': 'Detects explicit enabling of SQL Server trace flag 3625 against the signed off requirement; modern guidance and owner policy require separate review.', 'proposed_spec_sha256': '4d66f0f95070505aadeca1a4020620b4d40fff6436e41cb92d733a6ab1dcbb1f', 'remediation_hint': 'Inspect trace flag 3625 with the database owner and review the signed off expectation against current guidance before an approved change.', 'resource_kind': 'sql_instance', 'severity': 'medium', 'title': 'SQL Server trace flag 3625 is off'}, 'gcp_vpc_peering_allowlist': {'category': 'network', 'description': 'On network resources, detects when an ACTIVE peering target is absent from approved_peer_networks; this matters because an unvetted peer network can reach trusted VPC routes.', 'proposed_spec_sha256': 'acc84a2a6fca1b31883e7d4199febab2d3ed6ee1e688e11b115d60e6e3f830bf', 'remediation_hint': 'Delete unapproved ACTIVE VPC peerings or add only vetted peer networks to approved_peer_networks.', 'resource_kind': 'network', 'severity': 'high', 'title': 'VPC peers with an unapproved network'}}
    META = {k: v for k, v in META.items() if k in _ALLOWED}
    _ACCEPTED_CATEGORIES = {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}

    def signed(check_id, *dependencies):
        """Keep the signed category despite the older registry's narrow validator."""
        meta = META[check_id]

        def decorate(function):
            register(check_id, 'gcp', meta['category'] if meta['category'] in _ACCEPTED_CATEGORIES else 'hardening', meta['resource_kind'], meta['title'], meta['severity'], 'CM-6', meta['remediation_hint'], dependencies=list(dependencies or (meta['resource_kind'],)))(function)
            if CHECKS[-1].id != check_id:
                raise RuntimeError('unexpected registry order')
            pass
            return function
        return decorate

    def _scope(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('GCP provider authority unavailable')
        scope = get(context, 'scope', str)
        if not re.fullmatch('projects/[A-Za-z0-9_-]+', scope):
            raise Unavailable('GCP scope authority unavailable')
        return scope

    def _inventory(item, index, kind):
        scope = _scope(index)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable(kind + ' collection scope unavailable')
        envelope = envelopes[0]
        if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
            raise Unavailable(kind + ' collection foreign scope')
        if envelope.get('coverage_status', 'collected') not in ('collected', 'empty'):
            raise Unavailable(kind + ' collection coverage incomplete')
        rows = complete_items(index, kind)
        envelope_items = list_of_objects(get(envelope, 'items', list))
        if len(envelope_items) != len(rows) or (envelope.get('status') == 'empty' and rows):
            raise Unavailable(kind + ' collection/resource count mismatch')
        encode = lambda row: json.dumps(row, sort_keys=True, separators=(',', ':'), default=str)
        if Counter(map(encode, envelope_items)) != Counter(map(encode, rows)):
            raise Unavailable(kind + ' collection/resource data mismatch')
        seen = set()
        for resource in get(index, kind, list):
            if get(resource, 'scope', str) != scope or get(resource, 'type', str) != kind or resource.get('provider', 'gcp') != 'gcp':
                raise Unavailable(kind + ' resource foreign scope')
            row = get(resource, 'data', dict)
            if get(row, '_provenance.scope', str) != scope:
                raise Unavailable(kind + ' native provenance foreign scope')
            identity = next((get(row, key, str) for key in ('native_id', '_resource_id', 'selfLink', 'name', 'id') if key in row), None)
            if not identity or identity in seen:
                raise Unavailable(kind + ' duplicate or missing native identity')
            seen.add(identity)
            name = row.get('name', '')
            if name.startswith('projects/') and (not name.startswith(scope + '/')) and (name != scope):
                raise Unavailable(kind + ' native name foreign scope')
        if item is not None:
            if 'name' in item or 'name' in item.get('_coverage', {}):
                get(item, 'name', str)
            matches = [row for row in rows if row == item]
            if len(matches) != 1:
                raise Unavailable(kind + ' resource not unique in scoped inventory')
        return rows

    def _policy(index, key, expected):
        scope = _scope(index)
        policy = get(get(get(index, 'context', dict), 'metadata', dict), 'sw09_policy', dict)
        if get(policy, 'scope', str) != scope or get(policy, 'status', str) != 'collected':
            raise Unavailable('approved policy not bound to this scope')
        return get(policy, key, expected)

    def _strings(value, label):
        if not isinstance(value, list) or any((not isinstance(x, str) or not x.strip() for x in value)) or len(set(value)) != len(value):
            raise Unavailable('malformed ' + label)
        return value

    def _flags(item):
        rows = list_of_objects(get(item, 'settings.databaseFlags', list))
        flags = {}
        for row in rows:
            name, value = (get(row, 'name', str), get(row, 'value', str))
            if name == '3625 (trace flag)':
                name = '3625'
            if not name or name in flags:
                raise Unavailable('duplicate or malformed Cloud SQL flag')
            flags[name] = value.lower()
        return flags

    def _sql_engine(item):
        version = get(item, 'databaseVersion', str)
        if not re.fullmatch('(?:MYSQL_[0-9]+(?:_[0-9]+)*|POSTGRES_[0-9]+(?:_[0-9]+)?|SQLSERVER_[0-9]+_(?:STANDARD|ENTERPRISE|EXPRESS|WEB))', version):
            raise Unavailable('Cloud SQL database version malformed or unrecognized')
        for prefix in ('POSTGRES', 'MYSQL', 'SQLSERVER'):
            if version.startswith(prefix + '_'):
                return prefix
        raise Unavailable('Cloud SQL engine applicability unavailable')

    @signed('gcp.sql.iam_database_authentication', 'sql_instance')
    def sql_iam_database_user(item, index):
        _inventory(item, index, 'sql_instance')
        if _sql_engine(item) not in {'POSTGRES', 'MYSQL'}:
            return ('NOT_APPLICABLE', {'reason': 'IAM database user rule applies to PostgreSQL and MySQL'})
        users = get(item, 'usersList', dict)
        if get(users, 'status', str) != 'collected' or get(users, 'instance', str) != get(item, 'name', str):
            raise Unavailable('complete instance-bound users.list unavailable')
        rows = list_of_objects(get(users, 'items', list))
        found = False
        for row in rows:
            kind = get(row, 'type', str)
            if not get(row, 'name', str) or kind not in {'BUILT_IN', 'CLOUD_IAM_USER', 'CLOUD_IAM_SERVICE_ACCOUNT', 'CLOUD_IAM_GROUP', 'CLOUD_IAM_GROUP_USER', 'CLOUD_IAM_GROUP_SERVICE_ACCOUNT'}:
                raise Unavailable('malformed or unrecognized Cloud SQL user')
            if row.get('instanceId', get(item, 'name', str)) != get(item, 'name', str):
                raise Unavailable('SQL user foreign instance')
            # Imported snapshots may retain the optional provider URL-bound fields.
            if 'instance' in row and get(row, 'instance', str) != get(item, 'name', str):
                raise Unavailable('SQL user foreign raw instance')
            if 'project' in row and get(row, 'project', str) != _scope(index).split('/', 1)[1]:
                raise Unavailable('SQL user foreign raw project')
            if '_provenance' in row and get(row, '_provenance.scope', str) != _scope(index):
                raise Unavailable('SQL user foreign scope')
            found |= kind in {'CLOUD_IAM_USER', 'CLOUD_IAM_SERVICE_ACCOUNT'}
        return result(not found, sql_instance=get(item, 'name', str), iam_user_found=found)

    @signed('gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6', 'sql_instance')
    def sql_iam_flag(item, index):
        _inventory(item, index, 'sql_instance')
        engine = _sql_engine(item)
        if engine not in {'POSTGRES', 'MYSQL'}:
            return unknown('IAM authentication flag rule is not established for this engine')
        flag = 'cloudsql.iam_authentication' if engine == 'POSTGRES' else 'cloudsql_iam_authentication'
        configured = _flags(item).get(flag)
        if configured not in (None, 'on', 'off'):
            return unknown('unrecognized IAM database authentication flag', flag=flag)
        return result(configured != 'on', flag=flag, value=configured)

    @signed('gcp_sql_trace3625_off', 'sql_instance')
    def sql_trace3625(item, index):
        _inventory(item, index, 'sql_instance')
        if _sql_engine(item) != 'SQLSERVER':
            return ('NOT_APPLICABLE', {'reason': 'trace flag 3625 is SQL Server specific'})
        value = _flags(item).get('3625')
        if value not in {'on', 'off'}:
            return unknown('effective trace flag 3625 value unavailable')
        return result(value == 'on', trace_flag_3625=value)

    @signed('gcp_compute_approved_image', 'instance', 'disk')
    def approved_image(item, index):
        _inventory(item, index, 'instance')
        allowed = _strings(_policy(index, 'approved_image_projects', list), 'approved image projects')
        disks = _inventory(None, index, 'disk')
        boot = [d for d in list_of_objects(get(item, 'disks', list)) if get(d, 'boot', bool)]
        if len(boot) != 1:
            raise Unavailable('unique boot disk unavailable')
        source = get(boot[0], 'source', str)
        matches = [d for d in disks if get(d, 'selfLink', str) == source]
        if len(matches) != 1:
            raise Unavailable('boot disk source join unavailable')
        image = get(matches[0], 'sourceImage', str)
        match = re.search('/projects/([^/]+)/global/images/[^/]+$', image)
        if not match:
            raise Unavailable('boot disk image origin unavailable')
        return result(match.group(1) not in allowed, image=image, image_project=match.group(1))

    def _effective_audit(item, index, service):
        _inventory(item, index, 'iam_policy')
        scope = _scope(index)
        if not scope.startswith('projects/') or get(item, 'name', str) != scope:
            raise Unavailable('project root IAM policy unavailable')
        coverage = get(item, '_coverage.effectiveAuditConfigs', dict)
        if get(coverage, 'status', str) != 'collected' or get(coverage, 'ancestry_known', bool) is not True or coverage.get('missing_scopes', []) != []:
            raise Unavailable('effective ancestor audit policy incomplete')
        required = set(_strings(_policy(index, 'required_audit_principals', list), 'required audit principals'))
        granted = set()
        exempted = set()
        entries = list_of_objects(get(item, 'effectiveAuditConfigs', list))
        scopes = [get(ancestor, 'scope', str) for ancestor in entries]
        inherited = _strings(get(get(index, 'context', dict), 'metadata', dict).get('inherited_scopes', []), 'inherited scopes')
        if scope not in scopes or len(scopes) != len(set(scopes)) or any((name != scope and (name not in inherited or not re.fullmatch('(?:folders|organizations)/[0-9]+', name)) for name in scopes)):
            raise Unavailable('effective audit ancestry foreign, duplicate or missing project root')
        for ancestor in entries:
            for config in list_of_objects(get(ancestor, 'auditConfigs', list)):
                name = get(config, 'service', str)
                if name not in ('allServices', service):
                    continue
                for row in list_of_objects(get(config, 'auditLogConfigs', list)):
                    log_type = get(row, 'logType', str)
                    if log_type not in {'ADMIN_READ', 'DATA_READ', 'DATA_WRITE'}:
                        raise Unavailable('unrecognized audit log type')
                    if log_type in {'DATA_READ', 'DATA_WRITE'}:
                        granted.add(log_type)
                        if 'exemptedMembers' in row:
                            exempted.update(set(_strings(get(row, 'exemptedMembers', list), 'exempted principals')) & required)
        return result(granted != {'DATA_READ', 'DATA_WRITE'} or bool(exempted), service=service, effective_types=sorted(granted), exempted_required=sorted(exempted))

    @signed('gcp_network_auto_subnets_enabled', 'network')
    def auto_subnet_design(item, index):
        _inventory(item, index, 'network')
        name = get(item, 'selfLink', str)
        required = _strings(_policy(index, 'auto_subnet_vpcs', list), 'automatic subnet VPC scope')
        if name not in required:
            return ('NOT_APPLICABLE', {'reason': 'VPC outside approved automatic-subnet scope'})
        enabled = get(item, 'autoCreateSubnetworks', bool)
        return result(not enabled, network=name, auto_create_subnetworks=enabled)

    @signed('gcp_vpc_peering_allowlist', 'network')
    def peering_allowlist(item, index):
        _inventory(item, index, 'network')
        approved = set(_strings(_policy(index, 'approved_peer_networks', list), 'approved peers'))
        peers = list_of_objects(omitted(item, 'peerings', [], list))
        active = []
        for peer in peers:
            state = get(peer, 'state', str)
            if state not in {'ACTIVE', 'INACTIVE'}:
                raise Unavailable('unrecognized peering state')
            if state == 'ACTIVE':
                active.append(get(peer, 'network', str))
        bad = sorted(set(active) - approved)
        return result(bool(bad), unapproved_active_peers=bad, active_peers=sorted(set(active)))

    @signed('gcp_certificate_validity', 'certificate')
    def certificate_validity(item, index):
        _inventory(item, index, 'certificate')
        expires = _time(get(item, 'expireTime', str))
        now = _time(get(get(index, 'context', dict), 'created_at', str))
        if 'managed' in item and 'selfManaged' in item:
            raise Unavailable('conflicting certificate type union')
        if 'selfManaged' in item:
            get(item, 'selfManaged', dict)
            return result(expires <= now, certificate_type='selfManaged', expire_time=expires.isoformat())
        state = get(item, 'managed.state', str)
        if state not in {'ACTIVE', 'PROVISIONING', 'FAILED'}:
            raise Unavailable('unrecognized managed certificate state')
        return result(expires <= now or state != 'ACTIVE', state=state, expire_time=expires.isoformat())

    def _time(value):
        if not re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})', value):
            raise Unavailable('malformed RFC3339 timestamp')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            raise Unavailable('malformed timestamp')
        if parsed.tzinfo is None:
            raise Unavailable('timestamp lacks timezone')
        return parsed.astimezone(timezone.utc)

    @signed('gcp_cloudbuild_trigger_trust', 'cloudbuild_trigger')
    def cloudbuild_trigger_trust(item, index):
        _inventory(item, index, 'cloudbuild_trigger')
        if not full_representation(item):
            raise Unavailable('full trigger configuration unavailable')
        if omitted(item, 'disabled', False, bool):
            return ('NOT_APPLICABLE', {'reason': 'trigger disabled'})
        repos = set(_strings(_policy(index, 'approved_repositories', list), 'approved repositories'))
        accounts = set(_strings(_policy(index, 'approved_build_service_accounts', list), 'approved build accounts'))
        service_account = get(item, 'serviceAccount', str)
        selectors = []
        if 'triggerTemplate' in item:
            template = get(item, 'triggerTemplate', dict)
            selectors.append('projects/' + omitted(item, 'triggerTemplate.projectId', _scope(index).removeprefix('projects/'), str) + '/repos/' + get(template, 'repoName', str))
        if 'github' in item:
            github = get(item, 'github', dict)
            selectors.append('github/' + get(github, 'owner', str) + '/' + get(github, 'name', str))
        if 'repositoryEventConfig' in item:
            selectors.append(get(item, 'repositoryEventConfig.repository', str))
        if len(selectors) != 1:
            raise Unavailable('unique trigger repository selector unavailable')
        return result(selectors[0] not in repos or service_account not in accounts, repository=selectors[0], service_account=service_account)

    @signed('gcp_resource_approved_location', 'cloud_asset')
    def approved_location(item, index):
        _inventory(item, index, 'cloud_asset')
        approved = set(_strings(_policy(index, 'approved_locations', list), 'approved locations'))
        location = get(item, 'location', str)
        get(item, 'name', str)
        get(item, 'assetType', str)
        if not location:
            raise Unavailable('asset location unavailable')
        return result(location not in approved, location=location)

    @signed('gcp_resource_label_inventory', 'cloud_asset')
    def asset_inventory_labels(item, index):
        _inventory(item, index, 'cloud_asset')
        required = set(_strings(_policy(index, 'required_label_keys', list), 'required label keys'))
        if not {'owner', 'criticality', 'data_classification'} <= required:
            raise Unavailable('required inventory labels not supplied')
        labels = get(item, 'labels', dict)
        if any((not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items())):
            raise Unavailable('malformed asset labels')
        missing = sorted((key for key in required if not labels.get(key)))
        return result(bool(missing), missing_labels=missing)

    @signed('gcp_gke_client_certificate_enabled', 'gke_cluster')
    def legacy_client_certificate(item, index):
        _inventory(item, index, 'gke_cluster')
        exceptions = set(_strings(_policy(index, 'legacy_client_certificate_exceptions', list), 'legacy certificate exceptions'))
        name = get(item, 'name', str)
        enabled = get(item, 'masterAuth.clientCertificateConfig.issueClientCertificate', bool)
        return result(enabled and name not in exceptions, cluster=name, issuance_enabled=enabled, exception_approved=name in exceptions)
    _TLS_ORDER = {'TLS_1_0': 0, 'TLS_1_1': 1, 'TLS_1_2': 2, 'TLS_1_3': 3}

    @signed('gcp_c5_tls_policy', 'target_proxy', 'ssl_policy')
    def frontend_tls_policy(item, index):
        _inventory(item, index, 'target_proxy')
        approved_min = _policy(index, 'approved_min_tls', str)
        if approved_min not in _TLS_ORDER:
            raise Unavailable('unrecognized approved TLS minimum')
        approved_ciphers = set(_strings(_policy(index, 'approved_ciphers', list), 'approved ciphers'))
        reference = get(item, 'sslPolicy', str)
        policies = _inventory(None, index, 'ssl_policy')
        matches = [p for p in policies if get(p, 'selfLink', str) == reference]
        if len(matches) != 1:
            raise Unavailable('SSL policy reference unresolved')
        policy = matches[0]
        minimum = get(policy, 'minTlsVersion', str)
        if minimum not in _TLS_ORDER:
            raise Unavailable('unrecognized SSL policy minimum TLS version')
        profile = get(policy, 'profile', str)
        if profile != 'CUSTOM':
            raise Unavailable('built-in SSL policy cipher expansion unavailable')
        features = set(_strings(get(policy, 'customFeatures', list), 'custom SSL features'))
        if not features:
            raise Unavailable('CUSTOM SSL policy features empty')
        return result(_TLS_ORDER[minimum] < _TLS_ORDER[approved_min] or not features <= approved_ciphers, min_tls_version=minimum, unapproved_ciphers=sorted(features - approved_ciphers))

    @signed('gcp.appengine.version_https_only', 'app_engine_version')
    def appengine_https_only(item, index):
        _inventory(item, index, 'app_engine_version')
        scope = _scope(index)
        name = get(item, 'name', str)
        if not name.startswith('apps/' + scope.removeprefix('projects/') + '/services/'):
            raise Unavailable('App Engine version foreign scope')
        status = get(item, 'servingStatus', str)
        if status == 'STOPPED':
            return ('NOT_APPLICABLE', {'reason': 'version stopped'})
        if status != 'SERVING':
            raise Unavailable('serving status unavailable or unrecognized')
        if not full_representation(item) or item.get('_field_mask'):
            raise Unavailable('signed spec requires an unmasked full App Engine handler list')
        handlers = list_of_objects(get(item, 'handlers', list))
        if not handlers:
            raise Unavailable('serving handler coverage unavailable')
        levels = []
        for handler in handlers:
            level = get(handler, 'securityLevel', str)
            if level not in {'SECURE_ALWAYS', 'SECURE_DEFAULT', 'SECURE_NEVER', 'SECURE_OPTIONAL'}:
                raise Unavailable('unrecognized handler security level')
            levels.append(level)
        return result(any((level != 'SECURE_ALWAYS' for level in levels)), handler_levels=levels)

    @signed('gcp_https_proxy_mtls_required', 'target_https_proxy', 'server_tls_policy')
    def https_proxy_mtls(item, index):
        _inventory(item, index, 'target_https_proxy')
        if not full_representation(item):
            raise Unavailable('full HTTPS proxy representation unavailable')
        reference = omitted(item, 'serverTlsPolicy', '', str)
        if not reference:
            return result(True, reason='no server TLS policy attached')
        policies = _inventory(None, index, 'server_tls_policy')
        matches = [p for p in policies if get(p, 'name', str) == reference]
        if len(matches) != 1:
            raise Unavailable('server TLS policy lookup incomplete')
        mode = get(matches[0], 'mtlsPolicy.clientValidationMode', str)
        if mode not in {'REJECT_INVALID', 'ALLOW_INVALID_OR_MISSING_CLIENT_CERT'}:
            raise Unavailable('unrecognized client validation mode')
        return result(mode != 'REJECT_INVALID', client_validation_mode=mode)

    @signed('gcp_autoscaler_capacity_target', 'autoscaler', 'instance_group_manager')
    def autoscaler_capacity(item, index):
        _inventory(item, index, 'autoscaler')
        target = get(item, 'target', str)
        managers = _inventory(None, index, 'instance_group_manager')
        matches = [row for row in managers if get(row, 'selfLink', str) == target]
        if len(matches) != 1:
            raise Unavailable('target MIG size unavailable')
        size = get(matches[0], 'targetSize', int)
        if size < 0:
            raise Unavailable('negative target MIG size')
        cpu = get(item, 'autoscalingPolicy.cpuUtilization.utilizationTarget', (int, float))
        if type(cpu) not in (int, float):
            raise Unavailable('malformed autoscaler CPU target')
        max_replicas = get(item, 'autoscalingPolicy.maxNumReplicas', int)
        if not 0 < cpu <= 1 or max_replicas < 0:
            raise Unavailable('malformed autoscaler bounds')
        return result(cpu > 0.8 or max_replicas <= size, cpu_target=cpu, max_replicas=max_replicas, target_size=size)

    @signed('gcp_pci_firewall_2080b14f1361', 'firewall')
    def public_ingress_firewall(item, index):
        _inventory(item, index, 'firewall')
        if not full_representation(item):
            raise Unavailable('full Compute firewall representation unavailable')
        direction = omitted(item, 'direction', 'INGRESS', str)
        if direction not in {'INGRESS', 'EGRESS'}:
            raise Unavailable('unrecognized firewall direction')
        if direction == 'EGRESS' or omitted(item, 'disabled', False, bool):
            return ('NOT_APPLICABLE', {'reason': 'not an active ingress firewall rule'})
        tags = _strings(omitted(item, 'sourceTags', [], list), 'firewall source tags')
        accounts = _strings(omitted(item, 'sourceServiceAccounts', [], list), 'firewall source accounts')
        sources = _strings(omitted(item, 'sourceRanges', [], list), 'firewall source ranges')
        if not sources and (not tags) and (not accounts):
            sources = ['0.0.0.0/0']
        public = False
        for source in sources:
            try:
                network = ip_network(source, strict=False)
            except ValueError:
                raise Unavailable('malformed firewall source CIDR')
            public |= network.prefixlen == 0
        allowed = list_of_objects(omitted(item, 'allowed', [], list))
        protocols = []
        for entry in allowed:
            protocol = get(entry, 'IPProtocol', str)
            if protocol not in {'tcp', 'udp', 'icmp', 'esp', 'ah', 'sctp', 'ipip', 'all'} and (not (protocol.isdecimal() and 0 <= int(protocol) <= 255)):
                raise Unavailable('malformed or unrecognized firewall protocol')
            if 'ports' in entry:
                if protocol not in {'tcp', 'udp', '6', '17'}:
                    raise Unavailable('ports on non-port firewall protocol')
                for port in _strings(get(entry, 'ports', list), 'firewall ports'):
                    match = re.fullmatch('([0-9]{1,5})(?:-([0-9]{1,5}))?', port)
                    if not match or not 0 <= int(match.group(1)) <= int(match.group(2) or match.group(1)) <= 65535:
                        raise Unavailable('malformed firewall port range')
            protocols.append(protocol)
        return result(public and bool(protocols), public_source=public, allowed_protocols=protocols)
    META.update({'gcp_c5_iam_inventory': {'category': 'identity', 'description': 'On iam policy resources, detects when an in-scope principal has a prohibited effective role or an unapproved privileged grant; this matters because it can lead to account takeover or privilege misuse.', 'proposed_spec_sha256': '6075f72737eaf598de67931fedf320534c39a7c8614ab272324774cba9be6a01', 'remediation_hint': 'Remove prohibited IAM roles and unapproved privileged members from the affected resource or ancestor policy bindings.', 'resource_kind': 'iam_policy', 'severity': 'medium', 'title': 'IAM principal and privilege inventory'}, 'gcp_c5_network_separation': {'category': 'network', 'description': 'On network resources, detects when two inventoried Compute instances tagged env=production and env=nonproduction have the same networkInterfaces.subnetwork selfLink when the approved segregation policy requires distinct subnets; this matters because production and nonproduction workloads can share a subnet trust zone.', 'proposed_spec_sha256': 'f7b5b6896117881de40ea2dab4a367f80fd3692cccbbfae1814bebe6011c281f', 'remediation_hint': 'Move production and nonproduction VMs to separate approved subnetworks using Compute networkInterfaces settings.', 'resource_kind': 'network', 'severity': 'medium', 'title': 'Production network separation'}, 'gcp_c5_network_topology': {'category': 'network', 'description': 'On network resources, detects when an in-scope VPC/subnet or firewall asset referenced by the approved topology register is absent or its recorded region/network relationship disagrees with current metadata; this matters because unrecorded network paths may escape review.', 'proposed_spec_sha256': 'b198065c82c12ec16ee923223e3cc2934269de02e7c8b18de93a65f990a03bf8', 'remediation_hint': 'Update the approved topology register for observed VPC, subnet and firewall names/regions, or restore missing resources.', 'resource_kind': 'network', 'severity': 'medium', 'title': 'Network topology inventory consistency'}})

    @signed('gcp_c5_network_separation', 'network', 'instance')
    def production_subnet_separation(item, index):
        _inventory(item, index, 'network')
        network = get(item, 'selfLink', str)
        segregated = set(_strings(_policy(index, 'segregated_vpcs', list), 'approved segregated VPCs'))
        if network not in segregated:
            return ('NOT_APPLICABLE', {'reason': 'VPC outside approved environment segregation scope'})
        instances = _inventory(None, index, 'instance')
        by_environment = {'production': set(), 'nonproduction': set()}
        for vm in instances:
            get(vm, 'name', str)
            interfaces = list_of_objects(get(vm, 'networkInterfaces', list))
            if not interfaces:
                raise Unavailable('VM network interface inventory empty')
            connected = [interface for interface in interfaces if get(interface, 'network', str) == network]
            if not connected:
                continue
            env = get(vm, 'labels.env', str)
            if env not in by_environment:
                raise Unavailable('VM environment label outside approved production/nonproduction classification')
            for interface in connected:
                subnet = get(interface, 'subnetwork', str)
                if not subnet:
                    raise Unavailable('VM subnetwork identity empty')
                by_environment[env].add(subnet)
        shared = sorted(by_environment['production'] & by_environment['nonproduction'])
        return result(bool(shared), network=network, shared_environment_subnets=shared, semantics='logical subnet separation only')

    @signed('gcp_c5_network_topology', 'network', 'subnetwork', 'firewall')
    def approved_network_topology(item, index):
        _inventory(item, index, 'network')
        expected = list_of_objects(_policy(index, 'topology_register', list))
        if not expected:
            raise Unavailable('approved topology register is empty')
        actual = {'network': _inventory(None, index, 'network'), 'subnetwork': _inventory(None, index, 'subnetwork'), 'firewall': _inventory(None, index, 'firewall')}
        deviations = []
        seen = set()
        for record in expected:
            kind = get(record, 'kind', str)
            if kind not in actual:
                raise Unavailable('unrecognized approved topology resource kind')
            name = get(record, 'name', str)
            if (kind, name) in seen:
                raise Unavailable('duplicate approved topology entry')
            seen.add((kind, name))
            if not name:
                raise Unavailable('topology register identity empty')
            approved_network = get(record, 'network', str) if kind in {'subnetwork', 'firewall'} else None
            approved_region = get(record, 'region', str) if kind == 'subnetwork' else None
            if approved_network == '' or approved_region == '':
                raise Unavailable('topology register relationship empty')
            matches = [row for row in actual[kind] if get(row, 'selfLink', str) == name]
            if len(matches) > 1:
                raise Unavailable('duplicate collected topology asset')
            if not matches:
                deviations.append({'kind': kind, 'name': name, 'reason': 'absent'})
                continue
            if kind in {'subnetwork', 'firewall'}:
                if get(matches[0], 'network', str) != approved_network:
                    deviations.append({'kind': kind, 'name': name, 'reason': 'network mismatch'})
            if kind == 'subnetwork':
                if get(matches[0], 'region', str) != approved_region:
                    deviations.append({'kind': kind, 'name': name, 'reason': 'region mismatch'})
        return result(bool(deviations), deviations=deviations, semantics='only assets named in the approved topology register')

    @signed('gcp_c5_iam_inventory', 'iam_policy')
    def iam_approved_roster(item, index):
        _inventory(item, index, 'iam_policy')
        roster = list_of_objects(_policy(index, 'approved_iam_roster', list))
        allowed = set()
        seen = set()
        for entry in roster:
            identity = (get(entry, 'resource', str), get(entry, 'role', str), get(entry, 'principal', str))
            if any((not part for part in identity)) or identity in seen:
                raise Unavailable('duplicate or malformed IAM roster tuple')
            seen.add(identity)
            if get(entry, 'approved', bool):
                allowed.add(identity)
        scope = _scope(index)
        envelope = get(index, 'collections', dict)['iam_policy'][0]
        requests = list_of_objects(get(get(get(index, 'context', dict), 'metadata', dict), 'source_requests', list))
        search_ids = {get(row, 'id', str) for row in requests if row.get('url') == 'https://cloudasset.googleapis.com/v1/' + scope + ':searchAllIamPolicies' and row.get('method') == 'GET' and (row.get('status') == 'collected')}
        if not search_ids or not search_ids <= set(get(envelope, 'source_requests', list)):
            raise Unavailable('complete Cloud Asset IAM search provenance unavailable')
        if not search_ids.intersection(get(item, '_provenance.source_requests', list)):
            raise Unavailable('IAM policy is not a Cloud Asset IAM search result')
        resource = get(item, 'name', str)
        unapproved = []
        for binding in list_of_objects(get(item, 'bindings', list)):
            role = get(binding, 'role', str)
            if not role:
                raise Unavailable('IAM role identity empty')
            members = _strings(get(binding, 'members', list), 'IAM binding members')
            for member in members:
                identity = (resource, role, member)
                if identity not in allowed:
                    unapproved.append({'resource': resource, 'role': role, 'principal': member})
        return result(bool(unapproved), unapproved_bindings=unapproved, semantics='observed policy bindings compared with a complete approved roster')
    from .facts import memoized as _batch_memoized
    _base_inventory = _inventory

    def _inventory(item, index, kind):
        scope = _scope(index)
        rows = _batch_memoized(index, ('batch_sw09_inventory', kind, scope), lambda: _base_inventory(None, index, kind))
        if item is not None:
            if 'name' in item or 'name' in item.get('_coverage', {}):
                get(item, 'name', str)
            fingerprints = _batch_memoized(index, ('batch_sw09_members', kind, scope), lambda: Counter((json.dumps(row, sort_keys=True, separators=(',', ':'), default=str) for row in rows)))
            try:
                identity = json.dumps(item, sort_keys=True, separators=(',', ':'), default=str)
            except (TypeError, ValueError) as exc:
                raise Unavailable('resource malformed') from exc
            if fingerprints[identity] != 1:
                raise Unavailable(kind + ' resource not unique in scoped inventory')
        return rows
_load_09()

# Source family: compliance_new_sw50.py
def _load_50():
    _ALLOWED = {'gcp_c5_deletion_recoverability', 'gcp_c5_log_retention', 'gcp_gcs_replication_status', 'gcp_pci_bucket_157fb0c69361'}
    'Signed GCP audit and Storage checks over complete, scoped snapshot facts.'
    from datetime import datetime, timezone
    import re
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, guard
    SPECS = {'gcp_logging_detect_t1110': ('audit_log', 'threat_detection', 'high', 'Suspicious authentication brute force', '5ffef6aa6a40ccb10a633064ac062b8411845ab63ac56f9c12710eb29df7aaf4'), 'gcp_logging_detect_t1119': ('audit_log', 'threat_detection', 'medium', 'Suspicious automated data collection', '66e5fce6561ceca874fe845046ad37d6beffd75ee76852a0e8ae4957357aea5f'), 'gcp_logging_detect_t1136': ('audit_log', 'threat_detection', 'high', 'Suspicious service account creation', 'd2782530ef565b6eefd57e53b5285ca696ae7d126e27115f16535d98333c6751'), 'gcp_logging_detect_t1490': ('audit_log', 'threat_detection', 'high', 'Suspicious backup deletion or disablement', '5d5485a169748ae8c43f6b843eba284256c10af530934195441fa6192a2be70b'), 'gcp_logging_detect_t1518': ('audit_log', 'threat_detection', 'medium', 'Suspicious software discovery', '6eff634e1b98101d1be3537c42555a6af3b46a8452e65144cbb06945f5c2e017'), 'gcp_logging_detect_t1526': ('audit_log', 'threat_detection', 'medium', 'Suspicious cloud service discovery', '967532b78c4d80ad250b04f7600cc441f2c01a21084c6cb38306e3ad633d40de'), 'gcp_logging_detect_t1546': ('audit_log', 'threat_detection', 'high', 'Suspicious event trigger creation', 'f3fa73c1b6b9996c10320ec67a0326cdcde64c33d410502e6736a9d5eee31c11'), 'gcp_logging_detect_t1614': ('audit_log', 'threat_detection', 'medium', 'Suspicious region discovery', '5739c4716bfcc8d7ad27f321db17f2044e909315839c4209b92b52ce221fad4e'), 'gcp_logging_detect_t1619': ('audit_log', 'threat_detection', 'medium', 'Suspicious storage object discovery', '31d35fd0ef4faddd8f9d0478d82b8e9f6e5a6b180741f6167f83092df5e7f94a'), 'gcp_logging_detect_t1648': ('audit_log', 'threat_detection', 'high', 'Suspicious serverless execution', 'a2378cd131f703ad09dc392fd935080f6ce02fdd2fc02ef92f030016211c8a6b'), 'gcp_logging_detect_t1651': ('audit_log', 'threat_detection', 'high', 'Suspicious cloud administration change', '669982d86f34cb0ff0ac6ba065f8db36e96fffa6334be656f084698711ce319d'), 'gcp_c5_deletion_recoverability': ('bucket', 'data_lifecycle', 'medium', 'Cloud Storage recovery window after deletion', 'da1a5d6067d30edb69ba140dc6597340372a1762b770d5153c64081168185ffc'), 'gcp_c5_log_retention': ('bucket', 'logging', 'medium', 'SIEM and audit log retention', '1742b3dd522ad1ca649bf125eacee39db8084cd7744b299efcac78b5f796254f'), 'gcp_gcs_replication_status': ('bucket', 'availability', 'medium', 'Bucket replication topology or health is unavailable', '8ae750fe8a6c2df834bddb54382e72f560262969ed8b5ed2748ea7d448900b38'), 'gcp_pci_bucket_157fb0c69361': ('bucket', 'exposure', 'high', 'Cloud Storage bucket has no public read grant', 'ac67fb9a740b240793b03f6439ce1f0e96b8bb7ed2edeaba4b79aeb06fcfee11')}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}
    PROPOSED_SPEC_SHA256 = {key: spec[4] for key, spec in SPECS.items()}
    PROPOSED_SPEC_SHA256 = {k: v for k, v in PROPOSED_SPEC_SHA256.items() if k in _ALLOWED}

    def _time(value):
        if not isinstance(value, str):
            raise Unavailable('timestamp missing')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('invalid timestamp') from exc
        if parsed.tzinfo is None:
            raise Unavailable('timestamp lacks timezone')
        return parsed.astimezone(timezone.utc)

    def _inventory(index, kind, item):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        if not re.fullmatch('projects/[A-Za-z0-9][A-Za-z0-9._-]*', scope):
            raise Unavailable('project scope missing')
        envs = get(index, 'collections', dict).get(kind)
        if not isinstance(envs, list) or len(envs) != 1:
            raise Unavailable('complete scoped collection missing')
        env = envs[0]
        if not isinstance(env, dict) or env.get('type') != kind or env.get('scope') != scope or (env.get('status') not in ('collected', 'empty')):
            raise Unavailable('incomplete or foreign collection')
        rows = complete_items(index, kind)
        wrapped = get(index, kind, list)
        listed = get(env, 'items', list)
        if env['status'] == 'empty' and rows:
            raise Unavailable('empty collection contains resources')
        if rows != listed or len(wrapped) != len(rows) or any((not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or (w.get('data') != row) for w, row in zip(wrapped, rows))):
            raise Unavailable('collection projection mismatch')
        if sum((row == item for row in rows)) != 1:
            raise Unavailable('subject missing or ambiguous')
        return (context, env, rows)

    def _policy(context, key, expected):
        return get(get(context, 'metadata', dict), key, expected)

    def _strings(values):
        if not isinstance(values, list) or any((not isinstance(v, str) or not v for v in values)) or len(values) != len(set(values)):
            raise Unavailable('malformed policy string list')
        return set(values)

    def _audit(index, item):
        context, env, rows = _inventory(index, 'audit_log', item)
        coverage = get(env, 'audit_coverage', dict)
        if get(coverage, 'complete', bool) is not True or get(coverage, 'all_pages', bool) is not True:
            raise Unavailable('audit entry coverage incomplete')
        start, end = (_time(get(coverage, 'start', str)), _time(get(coverage, 'end', str)))
        if start > end:
            raise Unavailable('invalid audit coverage interval')
        normalized = []
        project = context['scope'].split('/', 1)[1]
        seen = set()
        for row in rows:
            identity = get(row, 'insertId', str)
            if not identity or identity in seen:
                raise Unavailable('audit identity missing or duplicated')
            seen.add(identity)
            log_name = get(row, 'logName', str)
            if not log_name.startswith(context['scope'] + '/logs/cloudaudit.googleapis.com%2F'):
                raise Unavailable('audit log provenance or project mismatch')
            if get(row, 'resource.labels.project_id', str) != project:
                raise Unavailable('foreign audit resource')
            timestamp = _time(get(row, 'timestamp', str))
            if not start <= timestamp <= end:
                raise Unavailable('audit event outside covered interval')
            method = get(row, 'protoPayload.methodName', str)
            principal = get(row, 'protoPayload.authenticationInfo.principalEmail', str)
            code = get(row, 'protoPayload.status.code', int)
            if not method or not principal or code < 0:
                raise Unavailable('malformed audit method, principal or status')
            normalized.append((timestamp, method, principal, code, row))
        return (context, coverage, normalized)

    def _bursts(events, threshold, predicate, *, group_ip=False):
        groups = {}
        for timestamp, method, principal, code, row in events:
            if not predicate(method, code, row):
                continue
            ip = get(row, 'protoPayload.requestMetadata.callerIp', str) if group_ip else None
            if group_ip and (not ip):
                raise Unavailable('caller IP missing')
            groups.setdefault((principal, ip), []).append(timestamp)
        for (principal, ip), times in groups.items():
            times.sort()
            left = 0
            for right, value in enumerate(times):
                while (value - times[left]).total_seconds() > 300:
                    left += 1
                if right - left + 1 > threshold:
                    return (principal, ip, right - left + 1)
        return None
    _RATE_METHODS = {'gcp_logging_detect_t1119': lambda m: m.endswith('.List') or m.endswith('.Get'), 'gcp_logging_detect_t1518': lambda m: m == 'osconfig.inventories.get', 'gcp_logging_detect_t1526': lambda m: m == 'serviceusage.services.list', 'gcp_logging_detect_t1614': lambda m: m in ('compute.regions.list', 'compute.zones.list'), 'gcp_logging_detect_t1619': lambda m: m == 'storage.objects.list'}
    _ALLOW_METHODS = {'gcp_logging_detect_t1136': ('approved_identity_admins', {'google.iam.admin.v1.CreateServiceAccount'}), 'gcp_logging_detect_t1546': ('approved_automation_admins', {'google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger', 'google.cloud.scheduler.v1.CloudScheduler.CreateJob'}), 'gcp_logging_detect_t1648': ('approved_invokers', {'run.routes.invoke', 'cloudfunctions.functions.call'}), 'gcp_logging_detect_t1651': ('approved_cloud_admins', {'SetIamPolicy', 'UpdateProject'})}

    def _audit_check(check_id, item, index):
        context, coverage, events = _audit(index, item)
        if check_id == 'gcp_logging_detect_t1110':
            if get(coverage, 'authentication_events', bool) is not True:
                raise Unavailable('authentication audit logging unavailable')
            for _, _, _, _, row in events:
                get(row, 'authenticationEvent', bool)
            hit = _bursts(events, 9, lambda m, c, r: r['authenticationEvent'] and c != 0, group_ip=True)
        elif check_id in _RATE_METHODS:
            policy = 'approved_read_rate' if check_id.endswith('t1119') else 'approved_list_rate'
            limit = _policy(context, policy, int)
            if limit < 0:
                raise Unavailable('negative approved rate')
            hit = _bursts(events, limit, lambda m, c, r: c == 0 and _RATE_METHODS[check_id](m))
        elif check_id == 'gcp_logging_detect_t1490':
            approved = _strings(_policy(context, 'approved_backup_admins', list))
            hits = []
            for _, method, principal, code, row in events:
                if code != 0:
                    continue
                relevant = method == 'cloudsql.backupRuns.delete'
                if method == 'cloudsql.instances.update':
                    request = get(row, 'protoPayload.request', dict)
                    try:
                        enabled = get(request, 'settings.backupConfiguration.enabled', bool)
                    except Unavailable:
                        raise Unavailable('backup update request intent unavailable')
                    relevant = enabled is False
                if relevant and principal not in approved:
                    hits.append(principal)
            hit = (hits[0], None, 1) if hits else None
        else:
            policy, methods = _ALLOW_METHODS[check_id]
            approved = _strings(_policy(context, policy, list))
            if check_id == 'gcp_logging_detect_t1648':
                for _, method, _, code, row in events:
                    if code == 0 and method in methods:
                        expected_type = 'cloud_run_revision' if method == 'run.routes.invoke' else 'cloud_function'
                        if get(row, 'resource.type', str) != expected_type:
                            raise Unavailable('serverless audit resource type mismatch')
            hits = [principal for _, method, principal, code, _ in events if code == 0 and method in methods and (principal not in approved)]
            hit = (hits[0], None, 1) if hits else None
        if hit:
            return result(True, principal=hit[0], caller_ip=hit[1], count=hit[2])
        return result(False, inspected_entries=len(events), interval=[coverage['start'], coverage['end']])

    def _bucket(index, item):
        context, _, rows = _inventory(index, 'bucket', item)
        project = context['scope'].split('/', 1)[1]
        names = set()
        for row in rows:
            name = get(row, 'name', str)
            if not name or name in names:
                raise Unavailable('bucket identity missing or duplicated')
            names.add(name)
            if get(row, '_provenance.scope', str) != context['scope']:
                raise Unavailable('bucket provenance differs from project scope')
        return (context, item['name'])

    def _deletion(item, index):
        context, name = _bucket(index, item)
        rules = _policy(context, 'approved_bucket_deletions', dict)
        if name not in rules:
            return ('NOT_APPLICABLE', {'bucket': name, 'reason': 'no approved immediate-deletion rule'})
        rule = get(rules, name, dict)
        if get(rule, 'immediate_deletion', bool) is not True:
            return ('NOT_APPLICABLE', {'bucket': name, 'reason': 'approved rule is not immediate deletion'})
        deadline = _time(get(rule, 'deadline', str))
        now = _time(get(context, 'created_at', str))
        if now <= deadline:
            return ('NOT_APPLICABLE', {'bucket': name, 'reason': 'approved deadline has not passed'})
        soft = get(item, 'softDeletePolicy.retentionDurationSeconds', str)
        retention = get(item, 'retentionPolicy.retentionPeriod', str)
        versioning = get(item, 'versioning.enabled', bool)
        if not soft.isdecimal() or not retention.isdecimal():
            raise Unavailable('retention duration malformed')
        blockers = [key for key, bad in [('softDeletePolicy', int(soft) > 0), ('versioning', versioning), ('retentionPolicy', int(retention) > 0)] if bad]
        return result(bool(blockers), bucket=name, recovery_blockers=blockers)

    def _log_retention(item, index):
        context, _, rows = _inventory(index, 'bucket', item)
        name = get(item, 'name', str)
        names = [get(row, 'name', str) for row in rows]
        if len(names) != len(set(names)) or get(item, '_provenance.scope', str) != context['scope']:
            raise Unavailable('Logging bucket identity or scope ambiguous')
        policy = _policy(context, 'approved_log_retention', dict)
        minimum = get(policy, 'minimum_days', int)
        maximum = get(policy, 'maximum_days', int)
        lock_required = get(policy, 'lock_required', bool)
        deadline = _time(get(policy, 'deletion_deadline', str))
        if minimum < 0 or maximum < minimum:
            raise Unavailable('invalid retention bounds')
        if not re.fullmatch(re.escape(context['scope']) + '/locations/[a-z0-9-]+/buckets/[^/]+', name):
            raise Unavailable('Cloud Logging bucket identity unavailable')
        if get(item, 'destinationExternal', bool):
            return unknown('external log destination cannot be evaluated')
        days = get(item, 'retentionDays', int)
        locked = get(item, 'locked', bool)
        if days < 0:
            raise Unavailable('negative retention')
        late = _time(get(context, 'created_at', str)) > deadline
        return result(days < minimum or (late and days > maximum) or (lock_required and (not locked)), bucket=name, retention_days=days, locked=locked)

    def _replication(item, index):
        context, name = _bucket(index, item)
        expected = _policy(context, 'expected_replica_locations', dict)
        locations = _strings(get(expected, name, list))
        if not locations:
            raise Unavailable('approved replica locations empty')
        location = get(item, 'location', str)
        if 'customPlacementConfig' in item:
            actual = _strings(get(item, 'customPlacementConfig.dataLocations', list))
        else:
            actual = {location}
        health = get(item, 'replicationHealth.status', str)
        if health != 'HEALTHY':
            return unknown('replication health is unavailable or unrecognized', status=health)
        if actual != locations:
            return result(True, bucket=name, actual_locations=sorted(actual), expected_locations=sorted(locations))
        return result(False, bucket=name, actual_locations=sorted(actual), replication_health=health)
    _READ_ROLES = {'roles/owner', 'roles/editor', 'roles/viewer', 'roles/storage.objectViewer', 'roles/storage.objectAdmin', 'roles/storage.admin', 'roles/storage.legacyObjectReader', 'roles/storage.legacyObjectOwner'}
    _PUBLIC = {'allUsers', 'allAuthenticatedUsers'}

    def _pci(item, index):
        _, name = _bucket(index, item)
        policy = get(item, 'iamPolicy', dict)
        bindings = get(policy, 'bindings', list)
        if any((not isinstance(b, dict) for b in bindings)):
            raise Unavailable('malformed IAM binding')
        unknown_role = False
        grants = []
        for binding in bindings:
            role = get(binding, 'role', str)
            members = _strings(get(binding, 'members', list))
            if members & _PUBLIC:
                if 'condition' in binding:
                    raise Unavailable('conditional public IAM binding requires condition evaluation')
                if role in _READ_ROLES:
                    grants.append(('iam', role))
                else:
                    unknown_role = True
        uniform = get(item, 'iamConfiguration.uniformBucketLevelAccess.enabled', bool)
        if not uniform:
            for key in ('bucketAccessControls', 'objectAccessControls'):
                envelope = get(item, key, dict)
                if get(envelope, 'status', str) != 'collected' or get(envelope, 'all_pages', bool) is not True:
                    raise Unavailable('ACL inventory incomplete')
                if key == 'objectAccessControls' and get(envelope, 'all_objects', bool) is not True:
                    raise Unavailable('object ACL inventory does not cover every object')
                rows = get(envelope, 'items', list)
                for row in rows:
                    if get(row, 'bucket', str) != name:
                        raise Unavailable('foreign ACL bucket')
                    entity = get(row, 'entity', str)
                    role = get(row, 'role', str)
                    public_read_roles = ('READER', 'OWNER', 'WRITER') if key == 'bucketAccessControls' else ('READER', 'OWNER')
                    if entity in ('allUsers', 'allAuthenticatedUsers') and role in public_read_roles:
                        grants.append((key, entity))
                    if role not in ('READER', 'OWNER', 'WRITER'):
                        raise Unavailable('unrecognized ACL role')
        if grants:
            return result(True, bucket=name, grants=grants)
        if unknown_role:
            return unknown('public IAM role read permission unresolved')
        return result(False, bucket=name, inspected_iam_bindings=len(bindings), uniform_bucket_access=uniform)
    _EVALUATORS = {**{key: lambda item, index, cid=key: _audit_check(cid, item, index) for key in SPECS if key.startswith('gcp_logging_detect_')}, 'gcp_c5_deletion_recoverability': _deletion, 'gcp_c5_log_retention': _log_retention, 'gcp_gcs_replication_status': _replication, 'gcp_pci_bucket_157fb0c69361': _pci}
    for _id, (_kind, _category, _severity, _title, _sha) in SPECS.items():
        _accepted = _category if _category in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'

        @register(_id, 'gcp', _accepted, _kind, _title, _severity, 'CM-6', 'Review the signed proposed specification and remediate the observed grant or event.', dependencies=[_kind])
        def _evaluate(item, index, cid=_id):
            return _EVALUATORS[cid](item, index)
        if _accepted != _category:
            pass
_load_50()

# Source family: compliance_new_sw51.py
def _load_51():
    _ALLOWED = {'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3', 'gcp_c5_asset_risk_label', 'gcp_c5_cloud_armor_waf', 'gcp_c5_key_versions', 'gcp_c5_region', 'gcp_cloud_armor_cidr_deny', 'gcp_cloud_armor_rate_limit', 'gcp_cloudcdn_cache_policy', 'gcp_pci_backend_service_2ce96d36d0bf', 'gcp_pci_backend_service_571fd0bfec67'}
    'Signed GCP defensive compliance checks (sw51).\n\nSnapshot policy inputs are explicit, project-bound metadata.sw51_policy values.\nAbsence checks require complete scoped inventories; no live API calls occur here.\n'
    import json
    import re
    from collections import Counter
    from dataclasses import replace
    from datetime import datetime, timezone
    from ipaddress import ip_network
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, guard, list_of_objects, omitted
    META = {'gcp_pci_bucket_56c6b1b7f813': {'kind': 'bucket', 'category': 'exposure', 'severity': 'high', 'title': 'Cloud Storage bucket has no public write grant', 'remediation': 'Remove public object-write IAM grants and active bucket/object ACL grants; enable uniformBucketLevelAccess where feasible.', 'sha': '10bab721e5644eec6d4c39da00437c73e3fc0d7c6d31ca3d1a4c44ac81bc7e85'}, 'gcp_pci_bucket_7dc6cb8c2e05': {'kind': 'bucket', 'category': 'exposure', 'severity': 'high', 'title': 'Non-excluded bucket is not publicly accessible', 'remediation': 'Remove effective public IAM and bucket ACL grants from non-excluded buckets; document only approved exclusions.', 'sha': '2de02460d76e52a0d846971b3741197fbf6db06cfb1702c8dd37869dcf85f610'}, 'gcp_c5_asset_change_audit': {'kind': 'asset', 'category': 'logging', 'severity': 'medium', 'title': 'Asset changes have audit events', 'remediation': 'Enable and retain Admin Activity audit logs for asset changes; reconcile each unlogged CAI snapshot change with its API event.', 'sha': '8199ab43d6d7067f32762b574d8c605ab3ffe7e5e6af73da7b30afafc9b1d958'}, 'gcp_c5_asset_inventory': {'kind': 'asset', 'category': 'asset_management', 'severity': 'medium', 'title': 'In-scope cloud asset inventory coverage', 'remediation': 'Expand Cloud Asset Inventory collection to the missing assetType and preserve name, assetType and updateTime metadata.', 'sha': 'b099f12db72aa6f8ad80289e37c20dc79fad13e94fa96507d034a2350bcea9fd'}, 'gcp_c5_asset_risk_label': {'kind': 'asset', 'category': 'asset_management', 'severity': 'medium', 'title': 'Cloud resource risk classification label', 'remediation': 'Set the approved risk classification label or tag on each in-scope asset using its service label settings.', 'sha': '088b31580ce910b3d2ec038d677c67409eff7d49a331bbb5efee4e5dabb39a6a'}, 'gcp_c5_region': {'kind': 'asset', 'category': 'data_residency', 'severity': 'medium', 'title': 'Resource location within approved region', 'remediation': 'Move or recreate resources in their contract-approved region; update bucket, SQL, GKE or KMS location settings through migration.', 'sha': 'ceec2649bfe1002405d9f3a77d4949fea30d9e879d782a2fed6211ab5ec8d56a'}, 'gcp_c5_key_versions': {'kind': 'kms_key', 'category': 'key_management', 'severity': 'medium', 'title': 'KMS key version lifecycle', 'remediation': 'Disable or destroy KMS key versions according to the approved lifecycle schedule; rotate expired ENABLED versions.', 'sha': 'b53d1e9dd33bc288b01bcdcf8d9f2d448ec38164aa546958776150276b9fdd2f'}, 'gcp_pci_kms_key_a3927a5f3b84': {'kind': 'kms_key', 'category': 'least_privilege', 'severity': 'medium', 'title': 'KMS key has at most three distinct users', 'remediation': 'Have the IAM and key owners review key-local and inherited cryptographic-use grants, groups and conditions before reducing access to three approved principals.', 'sha': 'b2c779d401c536c0b11ee40cf8fa76d430016ae95c73d3dc585d79b131854f1c'}, 'gcp_c5_cloud_armor_waf': {'kind': 'backend_service', 'category': 'network', 'severity': 'medium', 'title': 'Administration interface WAF policy', 'remediation': 'Attach a Cloud Armor securityPolicy to each in-scope admin backend and add the approved WAF expression/action rule.', 'sha': '89b8f646481fde32ae3c1c9c20e77cd4a0c72f7c7a1e7165523dca737a9ceeb5'}, 'gcp_cloudcdn_cache_policy': {'kind': 'backend_service', 'category': 'data_protection', 'severity': 'medium', 'title': 'Sensitive backend has an unapproved CDN cache policy', 'remediation': 'Disable CDN on sensitive backends or set an approved cdnPolicy.cacheMode, clientTtl and defaultTtl.', 'sha': 'da02e6a9437959d0be4643981b88dd16ed3bf8a7463aea5ef3f8a910765c9c16'}, 'gcp_pci_backend_service_2ce96d36d0bf': {'kind': 'backend_service', 'category': 'encryption', 'severity': 'medium', 'title': 'Cloud CDN viewer TLS minimum is 1.2', 'remediation': 'Attach an SSL policy with minTlsVersion=TLS_1_2 or later to every HTTPS proxy serving a CDN-enabled backend.', 'sha': 'd69aad31c2e14a573184e5b14e5d41f93e9b2b1bf4cefe36e92ad5f02123b161'}, 'gcp_pci_backend_service_571fd0bfec67': {'kind': 'backend_service', 'category': 'logging', 'severity': 'medium', 'title': 'Cloud Armor protected backend request logging', 'remediation': 'Enable backendServices.logConfig.enable and create the required matching Cloud Logging sink destination/filter.', 'sha': '776eb78ab55be00ba1663ee96e3f4e4fd80c03579d6a0aeca67617751dd10f94'}, 'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3': {'kind': 'security_policy', 'category': 'network', 'severity': 'medium', 'title': 'Cloud Armor policy has a non-default rule', 'remediation': 'Add a non-default Cloud Armor security policy rule with an explicit match and action before priority 2147483647.', 'sha': '338ce668f5f5aa66e9b9448477cc2218b15fcc37aef6a249ac0d057280f110d0'}, 'gcp_cloud_armor_cidr_deny': {'kind': 'security_policy', 'category': 'network', 'severity': 'high', 'title': 'Load balancer allows callers outside approved CIDRs', 'remediation': 'Add a Cloud Armor DENY rule for sources outside approved_cidrs on each internet-facing backend security policy.', 'sha': 'bc4adfa7ae07e09c9f217caf0a1b535b18ee94e4793286dc20870155b2fc5012'}, 'gcp_cloud_armor_rate_limit': {'kind': 'security_policy', 'category': 'network', 'severity': 'high', 'title': 'Public backend lacks request rate limiting', 'remediation': 'Add a Cloud Armor throttle or rate-based-ban rule at 2000 requests/300 seconds or less with banDurationSec >=60.', 'sha': '71b7c4b089afa7b4fe85d4d80f8c81c2866f965519736a31bdce818d7de8bf3f'}}
    META = {k: v for k, v in META.items() if k in _ALLOWED}

    def signed(check_id, *dependencies, target='resource'):
        meta = META[check_id]

        def decorate(function):
            native = meta['category'] if meta['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
            register(check_id, 'gcp', native, meta['kind'], meta['title'], meta['severity'], 'CM-6', meta['remediation'], target=target, dependencies=list(dependencies or (meta['kind'],)))(function)
            pass
            return function
        return decorate

    def _scope(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        if not re.fullmatch('projects/[A-Za-z0-9_-]+', scope):
            raise Unavailable('project scope unavailable')
        return scope

    def _rows(index, kind, item=None):
        scope = _scope(index)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable(kind + ' collection missing or ambiguous')
        envelope = envelopes[0]
        if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
            raise Unavailable(kind + ' foreign collection')
        if get(envelope, 'status', str) not in ('collected', 'empty') or envelope.get('coverage_status', 'collected') not in ('collected', 'empty'):
            raise Unavailable(kind + ' incomplete collection')
        rows = complete_items(index, kind)
        declared = list_of_objects(get(envelope, 'items', list))
        encode = lambda row: json.dumps(row, sort_keys=True, separators=(',', ':'), default=str)
        if Counter(map(encode, declared)) != Counter(map(encode, rows)) or (envelope['status'] == 'empty' and rows):
            raise Unavailable(kind + ' collection and index disagree')
        wrappers = get(index, kind, list)
        if len(wrappers) != len(rows):
            raise Unavailable(kind + ' wrapper count differs')
        seen = set()
        for wrapper in wrappers:
            if get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str) != scope or wrapper.get('provider', 'gcp') != 'gcp':
                raise Unavailable(kind + ' foreign resource scope')
            row = get(wrapper, 'data', dict)
            if get(row, '_provenance.scope', str) != scope:
                raise Unavailable(kind + ' foreign native provenance')
            identity = next((get(row, key, str) for key in ('selfLink', 'name', 'id') if key in row), None)
            if not identity or identity in seen:
                raise Unavailable(kind + ' duplicate or missing identity')
            if identity.startswith('projects/') and (not identity.startswith(scope + '/')):
                raise Unavailable(kind + ' foreign resource identity')
            seen.add(identity)
        if item is not None and sum((row == item for row in rows)) != 1:
            raise Unavailable(kind + ' subject absent or duplicated')
        return rows

    def _policy(index, key, expected):
        scope = _scope(index)
        policy = get(get(get(index, 'context', dict), 'metadata', dict), 'sw51_policy', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str) != scope:
            raise Unavailable('approved policy unavailable or foreign')
        return get(policy, key, expected)

    def _strings(value):
        if not isinstance(value, list) or any((not isinstance(v, str) or not v for v in value)) or len(value) != len(set(value)):
            raise Unavailable('malformed policy string list')
        return value

    def _native_name(row):
        return get(row, 'name', str)

    def _by(rows, path):
        result_map = {}
        for row in rows:
            key = get(row, path, str)
            if key in result_map:
                raise Unavailable('duplicate joined identity')
            result_map[key] = row
        return result_map

    def _datetime(value):
        if not isinstance(value, str):
            raise Unavailable('malformed timestamp')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('malformed timestamp') from exc
        if parsed.tzinfo is None:
            raise Unavailable('timestamp lacks timezone')
        return parsed.astimezone(timezone.utc)

    def _read_time(index, kind):
        envelopes = get(get(index, 'collections', dict), kind, list)
        if len(envelopes) != 1:
            raise Unavailable('snapshot read time unavailable')
        return _datetime(get(envelopes[0], 'readTime', str))

    def _bucket(item, index):
        _rows(index, 'bucket', item)
        name = _native_name(item)
        if not name or '/' in name:
            raise Unavailable('malformed bucket name')
        return name

    def _public_iam(item, *, write_only=False):
        bindings = list_of_objects(get(item, 'iamPolicy.bindings', list))
        found = False
        for binding in bindings:
            members = _strings(get(binding, 'members', list))
            role = get(binding, 'role', str)
            if not role:
                raise Unavailable('missing IAM role')
            if 'condition' in binding:
                raise Unavailable('conditional IAM grant needs effective evaluation')
            if not write_only:
                found |= bool({'allUsers', 'allAuthenticatedUsers'} & set(members))
            elif {'allUsers', 'allAuthenticatedUsers'} & set(members):
                if role in {'roles/storage.objectCreator', 'roles/storage.objectAdmin', 'roles/storage.admin', 'roles/owner', 'roles/editor', 'roles/storage.legacyBucketWriter', 'roles/storage.legacyObjectOwner'}:
                    found = True
                elif role not in {'roles/storage.objectViewer', 'roles/storage.legacyBucketReader', 'roles/storage.legacyObjectReader', 'roles/viewer'}:
                    raise Unavailable('unresolved public IAM role permissions')
        return found

    def _acl_public(rows, bucket, *, write_only=False):
        found = False
        for row in rows:
            if get(row, 'bucket', str) != bucket:
                raise Unavailable('foreign ACL bucket')
            entity = get(row, 'entity', str)
            role = get(row, 'role', str)
            if role not in {'OWNER', 'WRITER', 'READER'}:
                raise Unavailable('unknown ACL role')
            if entity in {'allUsers', 'allAuthenticatedUsers'}:
                found |= role in {'OWNER', 'WRITER'} if write_only else True
        return found

    def _effective_bucket_public(index, bucket, field):
        row = _by(_rows(index, 'bucket_effective_iam'), 'name').get(bucket)
        if row is None or get(row, 'resolutionComplete', bool) is not True:
            raise Unavailable('effective bucket IAM resolution incomplete')
        return get(row, field, bool)

    @signed('gcp_c5_asset_risk_label', 'asset')
    def asset_risk_label(item, index):
        _rows(index, 'asset', item)
        types = _strings(_policy(index, 'risk_asset_types', list))
        key = _policy(index, 'required_risk_label', str)
        approved = _strings(_policy(index, 'approved_risk_values', list))
        if not key or not approved or (not types):
            raise Unavailable('risk label policy incomplete')
        typ = get(item, 'assetType', str)
        if typ not in types:
            return ('NOT_APPLICABLE', {'reason': 'asset type outside risk-label scope'})
        labels = get(item, 'resource.data.labels', dict)
        if any((not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items())):
            raise Unavailable('malformed resource labels')
        return result(labels.get(key) not in approved, asset=get(item, 'name', str), label=key, value=labels.get(key))

    @signed('gcp_c5_region', 'asset', 'bucket', 'sql_instance', 'gke_cluster', 'kms_key')
    def asset_region(item, index):
        _rows(index, 'asset', item)
        name, typ = (get(item, 'name', str), get(item, 'assetType', str))
        mapping = _policy(index, 'asset_locations', dict)
        approved = _policy(index, 'approved_regions_by_asset', dict)
        if name not in approved:
            return ('NOT_APPLICABLE', {'asset': name, 'reason': 'no approved residency scope for asset'})
        regions = _strings(approved[name])
        if not regions:
            raise Unavailable('approved region set empty')
        entry = mapping.get(name)
        if not isinstance(entry, dict):
            raise Unavailable('approved asset location mapping unavailable')
        kind, resource_name = (get(entry, 'kind', str), get(entry, 'resource_name', str))
        if kind not in {'bucket', 'sql_instance', 'gke_cluster', 'kms_key'}:
            raise Unavailable('unsupported location service')
        rows = _rows(index, kind)
        row = _by(rows, 'name').get(resource_name)
        if row is None:
            raise Unavailable('mapped service resource absent')
        if kind == 'bucket':
            location = get(row, 'location', str)
        elif kind == 'sql_instance':
            location = get(row, 'region', str)
        elif kind == 'gke_cluster':
            location = get(row, 'location', str)
        else:
            location = get(row, 'name', str).split('/locations/')[1].split('/')[0] if '/locations/' in row['name'] else ''
        if not location:
            raise Unavailable('resource location absent')
        resolved = _policy(index, 'location_region_mapping', dict)
        if location not in resolved and (not re.fullmatch('[a-z]+(?:-[a-z0-9]+)+[0-9]', location)):
            raise Unavailable('multi-region or zonal location mapping unavailable')
        effective = resolved.get(location, [location])
        effective = _strings(effective)
        if not effective:
            raise Unavailable('location mapping empty')
        return result(not set(effective).issubset(regions), asset=name, location=location, resolved_regions=effective)

    @signed('gcp_c5_key_versions', 'kms_key', 'kms_key_version')
    def key_versions(item, index):
        _rows(index, 'kms_key', item)
        name = get(item, 'name', str)
        policy = _policy(index, 'key_version_schedule', dict)
        schedule = policy.get(name)
        if not isinstance(schedule, dict):
            raise Unavailable('key version schedule unavailable')
        as_of = _datetime(get(get(index, 'context', dict), 'created_at', str))
        versions = [v for v in _rows(index, 'kms_key_version') if get(v, 'name', str).startswith(name + '/cryptoKeyVersions/')]
        if not versions:
            raise Unavailable('key version inventory empty or key has no versions')
        for v in versions:
            version_name = get(v, 'name', str)
            dates = schedule.get(version_name)
            if not isinstance(dates, dict):
                raise Unavailable('approved version dates unavailable')
            expiry = _datetime(get(dates, 'enabled_expiry', str))
            destroy_after = _datetime(get(dates, 'destroy_not_before', str))
            state = get(v, 'state', str)
            if state not in {'ENABLED', 'DISABLED', 'DESTROY_SCHEDULED', 'DESTROYED', 'IMPORT_FAILED', 'PENDING_IMPORT', 'PENDING_GENERATION'}:
                raise Unavailable('unrecognized key version state')
            if state == 'ENABLED' and as_of > expiry:
                return result(True, key=name, version=v['name'], reason='enabled after approved expiry')
            if state == 'DESTROYED':
                destroyed = _datetime(get(v, 'destroyTime', str))
                if destroyed < destroy_after:
                    return result(True, key=name, version=v['name'], reason='destroyed before approved schedule')
        return result(False, key=name, checked_versions=len(versions))

    def _backend(item, index):
        _rows(index, 'backend_service', item)
        return get(item, 'selfLink', str)

    def _url_backend_refs(url_map):
        if url_map.get('_representation') != 'full':
            raise Unavailable('URL map backend references unavailable')
        refs = set()

        def walk(value):
            if isinstance(value, dict):
                guard(value)
                for key, child in value.items():
                    if key in {'service', 'defaultService', 'backendService'}:
                        if not isinstance(child, str) or not child:
                            raise Unavailable('malformed URL map backend reference')
                        refs.add(child)
                    elif isinstance(child, (dict, list)):
                        walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(url_map)
        return refs

    def _security_policy(item, index):
        _rows(index, 'security_policy', item)
        return get(item, 'selfLink', str)

    def _policy_backends(item, index):
        ref = _security_policy(item, index)
        backends = _rows(index, 'backend_service')
        attached = []
        for backend in backends:
            if 'securityPolicy' in backend and get(backend, 'securityPolicy', str) == ref:
                attached.append(backend)
        return attached

    def _rules(item):
        rules = list_of_objects(get(item, 'rules', list))
        priorities = set()
        for rule in rules:
            priority = get(rule, 'priority', int)
            if priority < 0 or priority > 2147483647 or priority in priorities:
                raise Unavailable('invalid or duplicate Cloud Armor rule priority')
            priorities.add(priority)
            get(rule, 'match', dict)
            get(rule, 'action', str)
        if 2147483647 not in priorities:
            raise Unavailable('default Cloud Armor rule unavailable')
        return rules

    @signed('gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3', 'security_policy', 'backend_service')
    def armor_nondefault_rule(item, index):
        attached = _policy_backends(item, index)
        if not attached:
            return ('NOT_APPLICABLE', {'reason': 'no backend attaches policy'})
        rules = _rules(item)
        found = any((get(rule, 'priority', int) < 2147483647 and bool(get(rule, 'match', dict)) for rule in rules))
        return result(not found, policy=get(item, 'selfLink', str))

    @signed('gcp_c5_cloud_armor_waf', 'backend_service', 'security_policy', 'url_map', 'target_https_proxy', 'forwarding_rule')
    def admin_waf(item, index):
        name = _backend(item, index)
        mapping = _policy(index, 'admin_backend_mapping', dict)
        marker = get(mapping, name, dict)
        if get(marker, 'in_scope', bool) is not True or get(marker, 'internet_reachable', bool) is not True:
            return ('NOT_APPLICABLE', {'backend': name, 'reason': 'not an internet-reachable in-scope admin backend'})
        if get(marker, 'topology_verified', bool) is not True:
            raise Unavailable('admin backend topology mapping unverified')
        expression = _policy(index, 'approved_waf_expression', str)
        action = _policy(index, 'approved_waf_action', str)
        if not expression or action not in {'deny(403)', 'deny(404)', 'deny(502)', 'redirect'}:
            raise Unavailable('approved WAF rule unavailable')
        for kind in ('url_map', 'target_https_proxy', 'forwarding_rule'):
            _rows(index, kind)
        ref = item.get('securityPolicy')
        if ref is None:
            if '_representation' not in item or item['_representation'] != 'full':
                raise Unavailable('backend security policy field may be omitted')
            return result(True, backend=name, reason='no attached Cloud Armor policy')
        if not isinstance(ref, str) or not ref:
            raise Unavailable('malformed backend security policy reference')
        policy = _by(_rows(index, 'security_policy'), 'selfLink').get(ref)
        if policy is None:
            raise Unavailable('attached security policy absent')
        rules = _rules(policy)
        for rule in rules:
            if get(rule, 'priority', int) == 2147483647:
                continue
            if get(rule, 'disabled', bool):
                continue
            if get(rule, 'match.expr.expression', str) == expression and get(rule, 'action', str) == action:
                return result(False, backend=name, policy=ref)
        return result(True, backend=name, policy=ref, reason='approved enabled WAF rule absent')

    def _public_policy(item, index):
        attached = _policy_backends(item, index)
        public = []
        for backend in attached:
            public_marker = get(backend, 'internetFacing', bool)
            if public_marker:
                public.append(backend)
        return public

    @signed('gcp_cloud_armor_cidr_deny', 'security_policy', 'backend_service')
    def armor_cidr_deny(item, index):
        public = _public_policy(item, index)
        if not public:
            return ('NOT_APPLICABLE', {'reason': 'no proven internet-facing attached backend'})
        approved = _strings(_policy(index, 'approved_cidrs', list))
        if not approved:
            raise Unavailable('approved CIDRs unavailable')
        try:
            canonical = [str(ip_network(cidr, strict=False)) for cidr in approved]
        except ValueError as exc:
            raise Unavailable('malformed approved CIDR') from exc
        expected = _policy(index, 'approved_cidr_deny_expression', str)
        if not expected or get(_policy(index, 'cidr_expression_review', dict), 'cidrs', list) != canonical:
            raise Unavailable('approved CIDR expression review unavailable')
        rules = _rules(item)
        if get(item, 'cidrRulePrecedenceVerified', bool) is not True:
            raise Unavailable('Cloud Armor rule precedence not verified')
        found = any((get(rule, 'priority', int) < 2147483647 and get(rule, 'action', str).startswith('deny(') and (get(rule, 'match.expr.expression', str) == expected) and (get(rule, 'disabled', bool) is False) for rule in rules if 'expr' in rule.get('match', {})))
        return result(not found, policy=get(item, 'selfLink', str), internet_backends=len(public))

    @signed('gcp_cloud_armor_rate_limit', 'security_policy', 'backend_service')
    def armor_rate_limit(item, index):
        public = _public_policy(item, index)
        if not public:
            return ('NOT_APPLICABLE', {'reason': 'no proven internet-facing attached backend'})
        rules = _rules(item)
        if get(item, 'rateRulePrecedenceVerified', bool) is not True:
            raise Unavailable('rate-limit rule precedence unavailable')
        approved_key = _policy(index, 'rate_limit_enforce_on_key', str)
        approved_match = _policy(index, 'rate_limit_match_expression', str)
        if not approved_key or not approved_match:
            raise Unavailable('approved rate-limit match and client key unavailable')
        found = False
        for rule in rules:
            action = get(rule, 'action', str)
            if action not in {'throttle', 'rate_based_ban'} or get(rule, 'priority', int) == 2147483647:
                continue
            if get(rule, 'disabled', bool) or get(rule, 'match.expr.expression', str) != approved_match:
                continue
            options = get(rule, 'rateLimitOptions', dict)
            threshold = get(options, 'rateLimitThreshold', dict)
            count, interval = (get(threshold, 'count', int), get(threshold, 'intervalSec', int))
            ban = get(options, 'banDurationSec', int)
            key = get(options, 'enforceOnKey', str)
            if count <= 0 or interval <= 0 or ban < 0:
                raise Unavailable('invalid rate-limit values')
            if key == approved_key and count <= 2000 and (interval <= 300) and (ban >= 60):
                found = True
        return result(not found, policy=get(item, 'selfLink', str), internet_backends=len(public))

    @signed('gcp_cloudcdn_cache_policy', 'backend_service')
    def cdn_cache_policy(item, index):
        name = _backend(item, index)
        sensitive = _policy(index, 'sensitive_backend_services', list)
        _strings(sensitive)
        if name not in sensitive:
            return ('NOT_APPLICABLE', {'backend': name, 'reason': 'not in approved sensitive-backend scope'})
        enabled = get(item, 'enableCDN', bool)
        if not enabled:
            return ('NOT_APPLICABLE', {'backend': name, 'reason': 'CDN disabled'})
        approved = _policy(index, 'approved_cache_policy', dict)
        modes = _strings(get(approved, 'cache_modes', list))
        max_client = get(approved, 'max_client_ttl', int)
        max_default = get(approved, 'max_default_ttl', int)
        if not modes or min(max_client, max_default) < 0:
            raise Unavailable('malformed approved cache policy')
        mode = get(item, 'cdnPolicy.cacheMode', str)
        client = get(item, 'cdnPolicy.clientTtl', int)
        default = get(item, 'cdnPolicy.defaultTtl', int)
        if min(client, default) < 0:
            raise Unavailable('malformed CDN TTL')
        return result(mode not in modes or client > max_client or default > max_default, backend=name, cache_mode=mode, client_ttl=client, default_ttl=default)

    @signed('gcp_pci_backend_service_2ce96d36d0bf', 'backend_service', 'url_map', 'target_https_proxy', 'ssl_policy')
    def cdn_viewer_tls(item, index):
        name = _backend(item, index)
        enabled = get(item, 'enableCDN', bool)
        if not enabled:
            return ('NOT_APPLICABLE', {'backend': name, 'reason': 'CDN disabled'})
        maps = _rows(index, 'url_map')
        proxies = _rows(index, 'target_https_proxy')
        policies = _by(_rows(index, 'ssl_policy'), 'selfLink')
        serving_maps = []
        for row in maps:
            refs = _url_backend_refs(row)
            if name in refs:
                serving_maps.append(get(row, 'selfLink', str))
        if not serving_maps:
            raise Unavailable('serving URL map association absent')
        attached = [row for row in proxies if get(row, 'urlMap', str) in serving_maps]
        if not attached:
            raise Unavailable('serving HTTPS proxy absent')
        weak = []
        for proxy in attached:
            ref = get(proxy, 'sslPolicy', str)
            policy = policies.get(ref)
            if policy is None:
                raise Unavailable('attached SSL policy absent')
            version = get(policy, 'minTlsVersion', str)
            if version not in {'TLS_1_0', 'TLS_1_1', 'TLS_1_2', 'TLS_1_3'}:
                raise Unavailable('unrecognized TLS minimum')
            if version in {'TLS_1_0', 'TLS_1_1'}:
                weak.append(get(proxy, 'selfLink', str))
        return result(bool(weak), backend=name, weak_https_proxies=weak, serving_https_proxies=len(attached))

    @signed('gcp_pci_backend_service_571fd0bfec67', 'backend_service', 'log_sink')
    def armor_backend_logging(item, index):
        name = _backend(item, index)
        security_policy = item.get('securityPolicy')
        if security_policy is None:
            if item.get('_representation') != 'full':
                raise Unavailable('security policy attachment unavailable')
            return ('NOT_APPLICABLE', {'backend': name, 'reason': 'no Cloud Armor policy attached'})
        if not isinstance(security_policy, str) or not security_policy:
            raise Unavailable('malformed security policy reference')
        enabled = get(item, 'logConfig.enable', bool)
        if not enabled:
            return result(True, backend=name, reason='request logging disabled')
        requirement = _policy(index, 'required_armor_log_sink', dict)
        if get(requirement, 'required', bool):
            destination = get(requirement, 'destination', str)
            filter_text = get(requirement, 'filter', str)
            sinks = _rows(index, 'log_sink')
            matches = [s for s in sinks if get(s, 'destination', str) == destination and get(s, 'filter', str) == filter_text]
            if not matches:
                return result(True, backend=name, reason='required destination sink absent')
        return result(False, backend=name, logging_enabled=True)
    from .facts import memoized as _batch_memoized
    _base_rows = _rows

    def _rows(index, kind, item=None):
        scope = _scope(index)
        rows = _batch_memoized(index, ('batch_sw51_rows', kind, scope), lambda: _base_rows(index, kind, None))
        if item is not None:
            fingerprints = _batch_memoized(index, ('batch_sw51_members', kind, scope), lambda: Counter((json.dumps(row, sort_keys=True, separators=(',', ':'), default=str) for row in rows)))
            try:
                identity = json.dumps(item, sort_keys=True, separators=(',', ':'), default=str)
            except (TypeError, ValueError) as exc:
                raise Unavailable('item malformed') from exc
            if fingerprints[identity] != 1:
                raise Unavailable(kind + ' subject absent or duplicated')
        return rows
_load_51()

# Source family: compliance_new_sw52.py
def _load_52():
    _ALLOWED = {'gcp.identity.non_service_account_mfa', 'gcp.identity.super_admin_recovery_group', 'gcp.identity.super_admin_separation', 'gcp.orgpolicy.central_constraints', 'gcp_c5_secret_access', 'gcp_c5_security_event_route', 'gcp_cloud_armor_waf_enabled', 'gcp_cloudbuild_private_pool', 'gcp_lb_server_header_rewrite', 'gcp_pci_url_map_9ed56c323a05', 'gcp_source_repo_access_restricted'}
    'Signed GCP compliance predicates over scoped, complete snapshot facts.'
    from dataclasses import replace
    from datetime import datetime
    import re
    from . import CHECKS, register as _native_register, result, unknown
    from .facts import Unavailable, complete_items, get, guard
    SPECS = {'gcp_cloud_armor_waf_enabled': {'provider': 'gcp', 'resource_kind': 'security_policy', 'category': 'network', 'severity': 'high', 'title': 'Public backend has no web application filtering', 'remediation_hint': 'Attach a Cloud Armor policy containing an enabled evaluatePreconfiguredWaf expression to each public backend.', 'proposed_spec_sha256': '26ddc0e84e87442459f99dea96b95243ae4300a3af7561aefb1d5f2ea7e6b9cc'}, 'gcp.identity.non_service_account_mfa': {'provider': 'gcp', 'resource_kind': 'workspace_user', 'category': 'hardening', 'severity': 'high', 'title': 'Non-service Google Cloud users lack enforced two-step verification', 'remediation_hint': 'Require and enroll two-step verification for each active Workspace user with Cloud IAM access in the Admin console.', 'proposed_spec_sha256': 'd47e76135cb7322aa96d9e23d0e171e07074319572a55831b6459d88b0942d32'}, 'gcp.identity.super_admin_recovery_group': {'provider': 'gcp', 'resource_kind': 'workspace_user', 'category': 'hardening', 'severity': 'high', 'title': 'Super-admin recovery email belongs to a multi-person group', 'remediation_hint': "Set each super admin's recoveryEmail to a Directory group containing at least two active recovery operators.", 'proposed_spec_sha256': '8f5ee8597513ce09dc640f45a7526530863dfb721884c30976bfbd061594cfa6'}, 'gcp_c5_sbom': {'provider': 'gcp', 'resource_kind': 'artifact_repository', 'category': 'secure_development', 'severity': 'medium', 'title': 'Deployed image has an SBOM', 'remediation_hint': 'Publish an SBOM_REFERENCE Artifact Analysis occurrence for each deployed Artifact Registry image digest.', 'proposed_spec_sha256': '769d35633a8c0bce6be2c9458165676852e80a0182e1a1b27dc3d200544e5359'}, 'gcp_lb_server_header_rewrite': {'provider': 'gcp', 'resource_kind': 'url_map', 'category': 'network', 'severity': 'medium', 'title': 'Load balancer does not rewrite Server header', 'remediation_hint': 'Set replace=true for the Server response header with value lb on every route of the public URL map.', 'proposed_spec_sha256': '4fdaa30bde498f7d1c541e786f2368cf81f14affd07b6beb6072de7f73438b9b'}, 'gcp_pci_url_map_9ed56c323a05': {'provider': 'gcp', 'resource_kind': 'url_map', 'category': 'encryption', 'severity': 'medium', 'title': 'HTTP load balancer frontends redirect to HTTPS', 'remediation_hint': 'Set urlMaps.defaultUrlRedirect.httpsRedirect=true and equivalent redirects for every HTTP path matcher/route.', 'proposed_spec_sha256': '9c176e93f19b1f35d7e0345178da2542aff2f7cfae01f5acb1c5c1ac7726a2c8'}, 'gcp_c5_log_event_fields': {'provider': 'gcp', 'resource_kind': 'log_entry', 'category': 'logging', 'severity': 'medium', 'title': 'Audit event timestamp and actor fields', 'remediation_hint': 'Ensure the audit producer supplies protoPayload.authenticationInfo.principalEmail and a valid timestamp; investigate malformed events.', 'proposed_spec_sha256': '0dee7707ea39dbf03e9aaa91e7fe3991039a2caaa405feb758037aa1d6e54180'}, 'gcp_c5_security_event_route': {'provider': 'gcp', 'resource_kind': 'monitoring_alert_policy', 'category': 'incident_detection', 'severity': 'medium', 'title': 'Security event notification route', 'remediation_hint': 'Link each approved security log metric to an enabled Monitoring alert policy and enabled verified notification channel.', 'proposed_spec_sha256': 'f6d8b9e6973e05d1e01e26300cc1eadf8cf636efd32a9d4b4da196f32fc3b3a4'}, 'gcp_c5_secret_access': {'provider': 'gcp', 'resource_kind': 'secret', 'category': 'identity', 'severity': 'medium', 'title': 'Credential secret access restriction', 'remediation_hint': 'Remove allUsers and unapproved secretAccessor IAM bindings from credential secrets, including inherited grants.', 'proposed_spec_sha256': '2313cbb4186e8f35aea97c05621f9ab9149d23464f41132ec4a79c9efdbe5bb1'}, 'gcp.identity.super_admin_separation': {'provider': 'gcp', 'resource_kind': 'workspace_role_assignment', 'category': 'least_privilege', 'severity': 'high', 'title': 'Workspace super admins are separate from routine Google Cloud administrators', 'remediation_hint': 'Remove roles/owner, roles/editor and administrative IAM bindings for Workspace super admins; use separate routine-admin identities.', 'proposed_spec_sha256': '91e8d5cbe97be325cc288584e091a335f3f70367ec79c0de9c1b74cbfb2630fa'}, 'gcp.orgpolicy.central_constraints': {'provider': 'gcp', 'resource_kind': 'org_policy_effective', 'category': 'hardening', 'severity': 'medium', 'title': 'Organization policies enforce centralized constraints', 'remediation_hint': 'Set the required Org Policy constraints at the organization or folder; correct descendant exceptions and allowedValues.', 'proposed_spec_sha256': '1acf8aa9b49281416b5289764a7cf98bce26993f820a008e35db42e7cf08d8df'}, 'gcp.network.private_service_connect_google_apis': {'provider': 'gcp', 'resource_kind': 'forwarding_rule', 'category': 'network', 'severity': 'medium', 'title': 'VPCs use Private Service Connect for Google APIs', 'remediation_hint': 'Create a Google APIs Private Service Connect forwarding rule in each required VPC and point required private DNS A records at its IP.', 'proposed_spec_sha256': 'a717f4090611be6eae3657d3c82a09c5bcf1431d7d8f6cec426864d7cae5bf47'}, 'gcp_cloudbuild_private_pool': {'provider': 'gcp', 'resource_kind': 'worker_pool', 'category': 'network', 'severity': 'high', 'title': 'Cloud Build worker pool is reachable outside approved network', 'remediation_hint': 'Set privatePoolV1Config.networkConfig.peeredNetwork to an approved VPC on enabled Cloud Build worker pools.', 'proposed_spec_sha256': '1a63d653ef2162412671bb096e5c9075101c2d5e38909e3cd58a89886f5e504f'}, 'gcp_source_repo_access_restricted': {'provider': 'gcp', 'resource_kind': 'source_repository', 'category': 'identity', 'severity': 'high', 'title': 'Source repository permits unapproved access', 'remediation_hint': 'Remove allUsers/allAuthenticatedUsers and principals outside approved_developers from repository IAM bindings.', 'proposed_spec_sha256': 'ffd64fae6f133c699a42943f0ddfaad5d3a4fefc225a507ead8685fe15e6b985'}}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}
    SPEC_SHA256 = {key: value['proposed_spec_sha256'] for key, value in SPECS.items()}

    def register(check_id, dependencies, *, target='resource'):
        """Use native safe wrapper while retaining the signed category verbatim."""
        spec = SPECS[check_id]
        native = spec['category'] if spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'

        def decorate(fn):
            _native_register(check_id, 'gcp', native, spec['resource_kind'], spec['title'], spec['severity'], 'CM-6', spec['remediation_hint'], dependencies=dependencies, target=target)(fn)
            position = next((i for i, check in enumerate(CHECKS) if check.id == check_id))
            pass
            return fn
        return decorate

    def _scope(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('GCP snapshot authority unavailable')
        scope = get(context, 'scope', str)
        if not re.fullmatch('(projects|folders|organizations)/[A-Za-z0-9._-]+', scope):
            raise Unavailable('malformed GCP scope')
        return scope

    def _rows(index, kind):
        scope = _scope(index)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('missing or ambiguous collection: ' + kind)
        envelope = envelopes[0]
        if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
            raise Unavailable('foreign collection: ' + kind)
        status = get(envelope, 'status', str)
        if status not in ('collected', 'empty'):
            raise Unavailable('incomplete collection: ' + kind)
        native = get(envelope, 'items', list)
        if any((not isinstance(row, dict) for row in native)) or (status == 'empty') != (len(native) == 0):
            raise Unavailable('malformed collection: ' + kind)
        rows = complete_items(index, kind)
        wrappers = get(index, kind, list)
        if len(rows) != len(native) or len(wrappers) != len(native):
            raise Unavailable('inconsistent collection projection: ' + kind)
        for wrapper, row, original in zip(wrappers, rows, native):
            if get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str) != scope or row != original:
                raise Unavailable('foreign or inconsistent projection: ' + kind)
        return rows

    def _member(item, index, kind):
        rows = _rows(index, kind)
        if sum((row == item for row in rows)) != 1:
            raise Unavailable('resource is not uniquely in scoped inventory: ' + kind)
        return rows

    def _policy(index, field, typ=list):
        policy = get(index, 'context.metadata.sw52', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str) != _scope(index):
            raise Unavailable('scoped operator policy unavailable')
        value = get(policy, field, typ)
        if typ is list and (any((not isinstance(x, str) or not x for x in value)) or len(value) != len(set(value))):
            raise Unavailable('malformed operator policy list: ' + field)
        return value

    def _list(row, path):
        values = get(row, path, list)
        if any((not isinstance(value, dict) for value in values)):
            raise Unavailable('malformed object list: ' + path)
        return values

    def _bindings(policy):
        return _list(policy, 'bindings')

    def _identity(row):
        return get(row, 'name', str)

    def _iam_members(binding):
        members = get(binding, 'members', list)
        if any((not isinstance(value, str) or not value for value in members)):
            raise Unavailable('malformed IAM member')
        return members

    def _super_admin_ids(index):
        roles = _rows(index, 'workspace_role')
        role_ids = {get(role, 'roleId', str) for role in roles if get(role, 'isSuperAdminRole', bool)}
        if len(role_ids) != sum((get(role, 'isSuperAdminRole', bool) for role in roles)):
            raise Unavailable('duplicate super-admin role')
        assignments = _rows(index, 'workspace_role_assignment')
        return {get(a, 'assignedTo', str) for a in assignments if get(a, 'roleId', str) in role_ids}

    def _full_omitted(row, field, default, *, full=False):
        guard(row)
        if field in row:
            return get(row, field)
        if (full or row.get('_representation') == 'full') and field not in row.get('_coverage', {}):
            return default
        raise Unavailable('missing field without full representation: ' + field)

    @register('gcp.identity.non_service_account_mfa', ['workspace_user', 'iam_policy'])
    def non_service_account_mfa(item, index):
        _member(item, index, 'workspace_user')
        email = get(item, 'primaryEmail', str).lower()
        if not email or get(item, 'suspended', bool):
            return ('NOT_APPLICABLE', {'reason': 'suspended or no active human identity'})
        if get(item, 'identityProvider', str) != 'workspace' or not get(item, 'inDomain', bool):
            return unknown('external or unsupported identity provider')
        policies = _rows(index, 'iam_policy')
        principals = set()
        for policy in policies:
            for binding in _bindings(policy):
                principals.update(_iam_members(binding))
        if 'user:' + email not in principals:
            if not _policy(index, 'principal_expansion_complete', bool):
                return unknown('human IAM principal expansion incomplete')
            expanded = _policy(index, 'effective_iam_user_emails')
            if email not in expanded:
                return ('NOT_APPLICABLE', {'reason': 'user has no Cloud IAM access in complete principal expansion'})
        enrolled = get(item, 'isEnrolledIn2Sv', bool)
        return result(not enrolled, principal=email, isEnrolledIn2Sv=enrolled)

    @register('gcp.identity.super_admin_recovery_group', ['workspace_user', 'workspace_role', 'workspace_role_assignment', 'group', 'group_membership'])
    def super_admin_recovery_group(item, index):
        _member(item, index, 'workspace_user')
        email = get(item, 'primaryEmail', str).lower()
        if get(item, 'suspended', bool) or get(item, 'id', str) not in _super_admin_ids(index):
            return ('NOT_APPLICABLE', {'reason': 'user is not an active assigned super admin'})
        recovery_value = _full_omitted(item, 'recoveryEmail', '')
        if not isinstance(recovery_value, str):
            return unknown('malformed recovery email')
        recovery = recovery_value.lower()
        groups = _rows(index, 'group')
        members = _rows(index, 'group_membership')
        matched = [group for group in groups if get(group, 'email', str).lower() == recovery]
        if not recovery or not matched:
            return result(True, principal=email, recovery_email=recovery, reason='missing or non-group recovery address')
        if len(matched) != 1:
            return unknown('ambiguous Directory group identity')
        group_id = get(matched[0], 'id', str)
        active = set()
        for member in members:
            if get(member, 'groupId', str) != group_id:
                continue
            status = get(member, 'status', str)
            if status not in ('ACTIVE', 'INACTIVE', 'SUSPENDED'):
                return unknown('unrecognized Directory group member status')
            if status == 'ACTIVE':
                member_email = get(member, 'email', str).lower()
                if not member_email or member_email in active:
                    return unknown('malformed or duplicate active group member')
                active.add(member_email)
        return result(len(active) < 2, principal=email, recovery_email=recovery, active_member_count=len(active))

    @register('gcp.identity.super_admin_separation', ['workspace_role_assignment', 'workspace_role', 'workspace_user', 'iam_policy', 'group', 'group_membership'])
    def super_admin_separation(item, index):
        # Keep the signed control identity and registration; dispatch only its native evidence path.
        from hashlib import sha256
        from pathlib import Path
        source = Path(__file__).with_name('sw52_native_successor.py')
        if sha256(source.read_bytes()).hexdigest() != '1933637f4f70a43decb946cbf9ecf69637acdd2a258f9a2a6aff65a815ab58b8':
            return unknown('reviewed SW52 native source hash mismatch')
        from .sw52_native_successor import super_admin_separation as native_evaluate
        return native_evaluate(item, index)























    @register('gcp.orgpolicy.central_constraints', ['org_policy_effective'], target='scope')
    def central_constraints(item, index):
        if get(item, 'scope', str) != _scope(index):
            return unknown('scope subject does not match snapshot')
        required = _policy(index, 'required_constraints', dict)
        if not required:
            return unknown('required constraint catalogue is empty')
        constraints = _rows(index, 'org_policy_effective')
        seen = set()
        failures = []
        for name, config in required.items():
            if not isinstance(name, str) or not isinstance(config, dict) or get(config, 'type', str) not in ('boolean', 'list'):
                return unknown('malformed required constraint policy')
            rows = [row for row in constraints if get(row, 'constraint', str) == name]
            if len(rows) != 1:
                return unknown('required effective policy missing or ambiguous', constraint=name)
            row = rows[0]
            rules = _list(row, 'spec.rules')
            if not rules:
                return unknown('effective policy has no evaluable rules')
            if config['type'] == 'boolean':
                for rule in rules:
                    if get(rule, 'enforce', bool) is False:
                        failures.append(name)
            else:
                approved = get(config, 'allowedValues', list)
                if any((not isinstance(value, str) for value in approved)):
                    return unknown('malformed approved values')
                for rule in rules:
                    values = get(rule, 'values.allowedValues', list)
                    if any((not isinstance(value, str) for value in values)):
                        return unknown('malformed effective values')
                    if any((value not in approved for value in values)):
                        failures.append(name)
            seen.add(name)
        return result(bool(failures), violated_constraints=sorted(set(failures)))

    @register('gcp_cloud_armor_waf_enabled', ['security_policy', 'backend_service'])
    def cloud_armor_waf_enabled(item, index):
        _member(item, index, 'security_policy')
        policy_name = get(item, 'selfLink', str)
        backends = _rows(index, 'backend_service')
        associated = [backend for backend in backends if get(backend, 'securityPolicy', str) == policy_name]
        if not associated:
            return ('NOT_APPLICABLE', {'reason': 'policy is not attached to a backend'})
        public = [backend for backend in associated if get(backend, 'internetFacing', bool)]
        if not public:
            return ('NOT_APPLICABLE', {'reason': 'no associated internet-facing backend'})
        rules = _list(item, 'rules')
        has_waf = any((get(rule, 'action', str) == 'deny' and 'evaluatePreconfiguredWaf' in get(rule, 'match.expr.expression', str) for rule in rules))
        return result(not has_waf, policy=policy_name, public_backends=[get(b, 'name', str) for b in public])

    @register('gcp_cloudbuild_private_pool', ['worker_pool'])
    def cloudbuild_private_pool(item, index):
        _member(item, index, 'worker_pool')
        state = get(item, 'state', str)
        if state == 'DELETED':
            return ('NOT_APPLICABLE', {'reason': 'worker pool is deleted'})
        if state != 'RUNNING':
            return unknown('unrecognized worker pool state')
        approved = _policy(index, 'approved_worker_networks')
        config = get(item, 'privatePoolV1Config.networkConfig', dict)
        network = _full_omitted(config, 'peeredNetwork', '', full=item.get('_representation') == 'full')
        if not isinstance(network, str):
            return unknown('malformed worker peered network')
        return result(not network or network not in approved, worker_pool=_identity(item), peered_network=network)

    @register('gcp_source_repo_access_restricted', ['source_repository'])
    def source_repo_access_restricted(item, index):
        _member(item, index, 'source_repository')
        approved = set(_policy(index, 'approved_developers'))
        bindings = _bindings(get(item, 'iamPolicy', dict))
        unauthorized = []
        for binding in bindings:
            role = get(binding, 'role', str)
            if role not in ('roles/source.reader', 'roles/source.writer', 'roles/source.admin', 'roles/owner', 'roles/editor'):
                if role.startswith(('projects/', 'organizations/')) and '/roles/' in role:
                    return unknown('custom repository role permissions unavailable', role=role)
                continue
            unauthorized.extend((member for member in _iam_members(binding) if member in ('allUsers', 'allAuthenticatedUsers') or member not in approved))
        return result(bool(unauthorized), repository=_identity(item), unauthorized_members=sorted(set(unauthorized)))

    @register('gcp_c5_secret_access', ['secret', 'iam_policy'])
    def c5_secret_access(item, index):
        _member(item, index, 'secret')
        credential_names = _policy(index, 'credential_secrets')
        if _identity(item) not in credential_names:
            return ('NOT_APPLICABLE', {'reason': 'secret is not classified as a credential'})
        approved = set(_policy(index, 'approved_secret_readers'))
        inherited = _rows(index, 'iam_policy')
        parents = _policy(index, 'complete_iam_policy_levels')
        if not {'project', 'folder', 'organization'} <= set(parents):
            return unknown('inherited IAM policy level unavailable')
        hierarchy = _policy(index, 'iam_policy_resource_names')
        if not hierarchy or _scope(index) not in hierarchy:
            return unknown('scoped IAM hierarchy unavailable')
        selected = [policy for policy in inherited if get(policy, 'name', str) in hierarchy]
        if len(selected) != len(hierarchy) or {get(policy, 'name', str) for policy in selected} != set(hierarchy):
            return unknown('inherited IAM policy read incomplete')
        bindings = _bindings(get(item, 'iamPolicy', dict))
        for policy in selected:
            bindings.extend(_bindings(policy))
        unauthorized = []
        for binding in bindings:
            role = get(binding, 'role', str)
            if role not in ('roles/secretmanager.secretAccessor', 'roles/secretmanager.admin', 'roles/owner', 'roles/editor'):
                if role.startswith(('projects/', 'organizations/')) and '/roles/' in role:
                    return unknown('custom secret role permissions unavailable', role=role)
                continue
            unauthorized.extend((member for member in _iam_members(binding) if member in ('allUsers', 'allAuthenticatedUsers') or member not in approved))
        return result(bool(unauthorized), secret=_identity(item), unauthorized_members=sorted(set(unauthorized)))

    @register('gcp_c5_security_event_route', ['monitoring_alert_policy', 'logging_metric', 'monitoring_notification_channel'], target='scope')
    def c5_security_event_route(item, index):
        if get(item, 'scope', str) != _scope(index):
            return unknown('scope subject does not match snapshot')
        required = _policy(index, 'approved_security_event_metrics')
        metrics = _rows(index, 'logging_metric')
        policies = _rows(index, 'monitoring_alert_policy')
        channels = _rows(index, 'monitoring_notification_channel')
        metric_names = {get(metric, 'name', str) for metric in metrics}
        if len(metric_names) != len(metrics):
            return unknown('duplicate Logging metric name')
        if not required:
            return unknown('approved event catalogue is empty')
        channel_map = {get(channel, 'name', str): get(channel, 'enabled', bool) for channel in channels}
        if len(channel_map) != len(channels):
            return unknown('duplicate notification channel name')
        missing = []
        for metric in required:
            if metric not in metric_names:
                missing.append(metric)
                continue
            matched = []
            for policy in policies:
                if not get(policy, 'enabled', bool):
                    continue
                for condition in _list(policy, 'conditions'):
                    filt = get(condition, 'conditionThreshold.filter', str)
                    if re.search('user/' + re.escape(metric.rsplit('/', 1)[-1]) + '(?=[\\s"\\\']|$)', filt):
                        matched.append(policy)
                        break
            if not any((any((channel_map.get(name) is True for name in get(policy, 'notificationChannels', list))) for policy in matched)):
                missing.append(metric)
        return result(bool(missing), unrouted_metrics=missing)

    def _server_rewrite(action):
        return any((get(row, 'headerName', str).lower() == 'server' and get(row, 'headerValue', str) == 'lb' and get(row, 'replace', bool) for row in _optional_objects(action, 'responseHeadersToAdd')))

    def _optional_object(row, field):
        guard(row)
        if field not in row:
            if field in row.get('_coverage', {}):
                raise Unavailable('optional route field unreadable: ' + field)
            return {}
        return get(row, field, dict)

    def _optional_objects(row, field):
        guard(row)
        if field not in row:
            if field in row.get('_coverage', {}):
                raise Unavailable('optional route list unreadable: ' + field)
            return []
        return _list(row, field)

    @register('gcp_lb_server_header_rewrite', ['url_map'])
    def lb_server_header_rewrite(item, index):
        _member(item, index, 'url_map')
        if not get(item, 'internetFacing', bool):
            return ('NOT_APPLICABLE', {'reason': 'URL map is not public'})
        if get(item, 'routeCoverageComplete', bool) is not True:
            return unknown('URL map route coverage incomplete')
        routes = _list(item, 'effectiveRoutes')
        if not routes:
            return unknown('complete public URL map has no route projection')
        ids = [get(route, 'routeId', str) for route in routes]
        if len(ids) != len(set(ids)):
            return unknown('duplicate effective URL map route')
        missing = [route_id for route_id, action in zip(ids, routes) if not _server_rewrite(action)]
        return result(bool(missing), url_map=_identity(item), unrewritten_route_indexes=missing)

    def _redirect(route):
        guard(route)
        if 'httpsRedirect' not in route:
            if 'httpsRedirect' in route.get('_coverage', {}):
                raise Unavailable('redirect field unreadable')
            return False
        return get(route, 'httpsRedirect', bool)

    @register('gcp_pci_url_map_9ed56c323a05', ['url_map', 'target_proxy', 'forwarding_rule'])
    def pci_url_map_redirect(item, index):
        _member(item, index, 'url_map')
        url = get(item, 'selfLink', str)
        proxies = _rows(index, 'target_proxy')
        frontends = _rows(index, 'forwarding_rule')
        proxy_urls = {get(proxy, 'selfLink', str) for proxy in proxies}
        if len(proxy_urls) != len(proxies):
            return unknown('duplicate target proxy identity')
        if any((('targetHttpProxies/' in get(frontend, 'target', str) or get(frontend, 'target', str).startswith('http-proxy:')) and get(frontend, 'target', str) not in proxy_urls for frontend in frontends)):
            return unknown('HTTP frontend target proxy unresolved')
        http_proxies = [proxy for proxy in proxies if get(proxy, 'proxyType', str) == 'HTTP' and get(proxy, 'urlMap', str) == url]
        attached = [frontend for frontend in frontends if any((get(frontend, 'target', str) == get(proxy, 'selfLink', str) for proxy in http_proxies))]
        if not attached:
            return ('NOT_APPLICABLE', {'reason': 'no HTTP frontend targets this URL map'})
        if get(item, 'routeCoverageComplete', bool) is not True:
            return unknown('URL map path/default route coverage incomplete')
        routes = [_optional_object(item, 'defaultUrlRedirect')]
        for matcher in _optional_objects(item, 'pathMatchers'):
            routes.append(_optional_object(matcher, 'defaultUrlRedirect'))
            for rule in _optional_objects(matcher, 'pathRules'):
                routes.append(_optional_object(rule, 'urlRedirect'))
            for rule in _optional_objects(matcher, 'routeRules'):
                routes.append(_optional_object(rule, 'urlRedirect'))
        unredirected = [i for i, route in enumerate(routes) if not _redirect(route)]
        return result(bool(unredirected), url_map=url, unredirected_routes=unredirected)
    from .facts import memoized as _batch_memoized
    from collections import Counter as _batch_Counter
    import json as _batch_json
    _base_rows = _rows

    def _rows(index, kind):
        return _batch_memoized(index, ('batch_sw52_rows', kind, _scope(index)), lambda: _base_rows(index, kind))

    def _member(item, index, kind):
        rows = _rows(index, kind)
        fingerprints = _batch_memoized(index, ('batch_sw52_members', kind, _scope(index)), lambda: _batch_Counter((_batch_json.dumps(row, sort_keys=True) for row in rows)))
        try:
            identity = _batch_json.dumps(item, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise Unavailable('item malformed') from exc
        if fingerprints[identity] != 1:
            raise Unavailable('resource is not uniquely in scoped inventory: ' + kind)
        return rows
_load_52()

# Source family: compliance_new_sw53.py
def _load_53():
    _ALLOWED = {'gcp.logging.access_transparency_entries', 'gcp_c5_iam_change_timeliness', 'gcp_c5_iam_conditions', 'gcp_c5_iam_expiry', 'gcp_c5_malware_telemetry', 'gcp_c5_software_inventory', 'gcp_c5_sql_backup_run', 'gcp_cloudsql_backup_failure_alert', 'gcp_compute_approved_packages'}
    'Signed GCP compliance checks over scoped, read-only snapshot evidence.'
    META = {'gcp_c5_backup_remote_location': {'kind': 'sql_instance', 'category': 'backup', 'severity': 'medium', 'title': 'Offsite backup location', 'hint': 'Place the in-scope backup target in an approved separate failure region using the Cloud SQL or Storage backup destination setting.', 'sha': '44f9ae1fcbd05d2d79d22eb2c5bbeff9ba66cb651bf15358a9787cebb3e55bf2'}, 'gcp_c5_restore_destination': {'kind': 'sql_instance', 'category': 'backup', 'severity': 'medium', 'title': 'Restore target access parity', 'hint': 'Restore Cloud SQL to an approved target, disable public IPv4 if absent on the source, and remove new public IAM grants.', 'sha': '489a05964f3f3aa345e68efacd3fd465994f1417200ed1ec278d6b47ed26c503'}, 'gcp_c5_restore_test': {'kind': 'sql_instance', 'category': 'backup', 'severity': 'medium', 'title': 'Cloud SQL restore test event', 'hint': 'Run and validate a Cloud SQL restore or clone test within 365 days; retain a successful operation record.', 'sha': 'bc278e450ceda0b95f15ce05354b73707fe39ed25921bd0dcb466c943dfc988c'}, 'gcp_c5_sql_backup_run': {'kind': 'sql_instance', 'category': 'backup', 'severity': 'medium', 'title': 'Recent successful Cloud SQL backup', 'hint': 'Enable automated Cloud SQL backups and correct backup schedules until a SUCCESSFUL run falls inside the approved RPO window.', 'sha': '64efff290cb9e0a049c36c1e21a2094dc77e8ef9eb9370c08ac9347074d27b6f'}, 'gcp.compute.os_patch_compliance': {'kind': 'instance', 'category': 'hardening', 'severity': 'high', 'title': 'VM operating systems have current security patches', 'hint': 'Apply outstanding OS Config security patches with a patch deployment and verify fresh VM inventory against the approved grace period.', 'sha': '626d66df389fad108c4ff5756dab62e31e90cd05d884abbabcb6bb15dc001d54'}, 'gcp_c5_malware_telemetry': {'kind': 'instance', 'category': 'malware', 'severity': 'medium', 'title': 'VM malware protection inventory signal', 'hint': 'Install the approved VM protection agent through OS Config and verify its package appears in current guest inventory.', 'sha': 'c4574fd6dacef9c8cbe2cc53a1fcab073e6b3f65d06945122c739c3ec8ebaccc'}, 'gcp_c5_patch_deployment': {'kind': 'instance', 'category': 'patch_management', 'severity': 'medium', 'title': 'Compute VM patch deployment coverage', 'hint': 'Assign every in-scope VM an enabled recurring OS Config patch deployment and apply packages beyond the approved age.', 'sha': '33494a459016f1d7a5b0aef9b71b2a007d3749a9867205b8157006d4202e8761'}, 'gcp_c5_software_inventory': {'kind': 'instance', 'category': 'asset_management', 'severity': 'medium', 'title': 'Compute VM installed-software inventory', 'hint': 'Enable OS Config guest inventory for each in-scope VM and reconcile installed package names/versions with the software register.', 'sha': '5d700da584c7992e36e8fc0e029d574480ca4916e42bd6b1f555f183251d717b'}, 'gcp_compute_approved_packages': {'kind': 'instance', 'category': 'vulnerability', 'severity': 'medium', 'title': 'VM contains unapproved installed software', 'hint': 'Remove unapproved OS packages or pin them to approved version ranges using OS Config package management.', 'sha': 'ff1af87f9f1dc0a6dc51b2568ecc11c969d28cf76bc314e599f48183b66495dc'}, 'gcp_compute_os_patch_compliance': {'kind': 'instance', 'category': 'vulnerability', 'severity': 'high', 'title': 'VM security patches exceed approved SLA', 'hint': 'Apply critical OS Config security updates within the approved SLA and refresh inventory and vulnerability reports.', 'sha': '3d98981ed677d9a44cc339c524e705a5df0d6e5d9b8124d71511c4d520c4f0ce'}, 'gcp_c5_iam_change_timeliness': {'kind': 'iam_policy', 'category': 'identity', 'severity': 'medium', 'title': 'IAM grant revocation timeliness', 'hint': 'Remove IAM grants past the approved 48-hour or 14-day personnel-change deadline using the resource IAM policy editor.', 'sha': '56fdc625b31d8bbc24b2f8572dd69f7cd10ab36c198c82c20f69ff468357f17b'}, 'gcp_c5_iam_conditions': {'kind': 'iam_policy', 'category': 'identity', 'severity': 'medium', 'title': 'Contextual IAM binding conditions', 'hint': 'Add a binding condition.expression covering the required time, resource or principal attributes to each contextual IAM grant.', 'sha': 'b6cd52900ea97ed2263a3181b0feeea862c23f71dccbd2dc97ee6e80b6ce2ffe'}, 'gcp_c5_iam_expiry': {'kind': 'iam_policy', 'category': 'identity', 'severity': 'medium', 'title': 'Privileged IAM binding expiry', 'hint': 'Add a request.time expiry condition to each privileged IAM binding that requires a time limit.', 'sha': '017702d3c791cd415e1b1b4f16d4242ce7274dfd44a81b174f1aff1bfbc1c585'}, 'gcp.logging.access_transparency_entries': {'kind': 'project', 'category': 'hardening', 'severity': 'medium', 'title': 'Access Transparency log signal is available', 'hint': 'Enable Access Transparency for supported services and retain its Cloud Logging entries; investigate missing 30-day evidence manually.', 'sha': 'bb2bbe32cffa23862441e31e60163ac71ed572a8de523586f0c05a9539db5cac'}, 'gcp_cloudsql_backup_failure_alert': {'kind': 'project', 'category': 'backup', 'severity': 'high', 'title': 'Cloud SQL backup failures lack an alert', 'hint': 'Create a Logging metric for failed Cloud SQL backup events and link it to an enabled Monitoring alert policy and channel.', 'sha': '1b136117fa2d4fe85988f749cd7654433f701835de2c965c50f1e390b8f19c88'}}
    META = {k: v for k, v in META.items() if k in _ALLOWED}
    from dataclasses import replace
    from collections import Counter
    import json
    from datetime import datetime, timedelta, timezone
    import re
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get

    def _ctx(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        if not scope.startswith('projects/') or len(scope.split('/')) != 2:
            raise Unavailable('project scope unavailable')
        return (context, scope)

    def _rows(index, kind):
        _, scope = _ctx(index)
        envelopes = get(get(index, 'collections', dict), kind, list)
        if not envelopes or any((get(e, 'scope', str) != scope or get(e, 'type', str) != kind for e in envelopes)):
            raise Unavailable('foreign or absent collection scope')
        rows = complete_items(index, kind)
        declared = []
        for envelope in envelopes:
            payload = get(envelope, 'items', list)
            if get(envelope, 'status', str) == 'empty' and payload:
                raise Unavailable('empty collection contains resources')
            declared.extend(payload)
        if Counter((json.dumps(x, sort_keys=True, default=str) for x in declared)) != Counter((json.dumps(x, sort_keys=True, default=str) for x in rows)):
            raise Unavailable('collection items differ from resource index')
        for resource in get(index, kind, list):
            if get(resource, 'scope', str) != scope or get(resource, 'type', str) != kind:
                raise Unavailable('foreign resource scope')
        return rows

    def _identity(row, kind):
        if kind == 'instance':
            return get(row, 'name', str)
        return get(row, 'name', str)

    def _base(item, index, kind):
        rows = _rows(index, kind)
        ident = _identity(item, kind)
        matches = [row for row in rows if _identity(row, kind) == ident]
        if len(matches) != 1 or matches[0] != item:
            raise Unavailable('resource identity not unique in scoped inventory')
        return ident

    def _policy(index):
        context, _ = _ctx(index)
        return get(context, 'policy', dict)

    def _time(value):
        if not isinstance(value, str):
            raise Unavailable('timestamp missing or malformed')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('malformed timestamp') from exc
        if parsed.tzinfo is None:
            raise Unavailable('timestamp timezone missing')
        return parsed.astimezone(timezone.utc)

    def _now(index):
        context, _ = _ctx(index)
        return _time(get(context, 'created_at', str))

    def _hours(policy, field):
        value = get(policy, field, int)
        if value <= 0:
            raise Unavailable('invalid approved duration')
        return value

    def _scope(policy, field, ident):
        names = get(policy, field, list)
        if any((not isinstance(n, str) or not n for n in names)) or len(names) != len(set(names)):
            raise Unavailable('malformed approved scope')
        return ident in names

    def _joined(index, kind, key, ident):
        rows = _rows(index, kind)
        matches = [r for r in rows if get(r, key, str) == ident]
        if len(matches) > 1:
            raise Unavailable('duplicate joined fact')
        return matches[0] if matches else None

    def _packages(inventory):
        packages = get(inventory, 'items.installedPackages', list)
        if any((not isinstance(p, dict) or not isinstance(p.get('name'), str) or (not p['name']) or (not isinstance(p.get('version'), str)) or (not p['version']) for p in packages)):
            raise Unavailable('malformed installed package inventory')
        return packages

    def _inventory(index, ident):
        inv = _joined(index, 'os_inventory', 'instanceName', ident)
        if inv is None:
            raise Unavailable('guest inventory absent')
        now = _now(index)
        at = _time(get(inv, 'updateTime', str))
        if at > now or now - at > timedelta(hours=24):
            raise Unavailable('guest inventory stale')
        return inv

    def _na(reason):
        return ('NOT_APPLICABLE', {'reason': reason})

    def _software(item, index):
        ident = _base(item, index, 'instance')
        policy = _policy(index)
        if not _scope(policy, 'vm_scope', ident):
            return _na('VM outside approved software scope')
        register = get(policy, 'approved_software_register', list)
        approved = {(get(x, 'name', str), get(x, 'version', str)) for x in register}
        inventory = _joined(index, 'os_inventory', 'instanceName', ident)
        if inventory is None:
            return result(True, instance=ident, reason='no guest inventory record in complete collection')
        now = _now(index)
        observed = _time(get(inventory, 'updateTime', str))
        if observed > now or now - observed > timedelta(hours=24):
            return result(True, instance=ident, reason='no current guest inventory record')
        packages = _packages(inventory)
        bad = sorted({(p['name'], p['version']) for p in packages} - approved)
        return result(bool(bad), instance=ident, unregistered_packages=bad)

    def _allowed_version(version, rules):
        if version in rules:
            return True
        comparisons = [r for r in rules if isinstance(r, str) and r.startswith(('>=', '<=', '>', '<', '=='))]
        if any((not isinstance(r, str) or not r or '*' in r or r.startswith(('~', '^')) for r in rules)):
            raise Unavailable('unrecognized approved package version rule')
        if not comparisons:
            return False
        if not re.fullmatch('\\d+(?:\\.\\d+)*', version):
            raise Unavailable('package version cannot be compared to approved range')
        current = tuple(map(int, version.split('.')))
        for rule in comparisons:
            pieces = rule.split(',')
            satisfied = True
            for piece in pieces:
                match = re.fullmatch('(>=|<=|>|<|==)\\s*(\\d+(?:\\.\\d+)*)', piece.strip())
                if not match:
                    raise Unavailable('unrecognized approved version range')
                target = tuple(map(int, match.group(2).split('.')))
                width = max(len(current), len(target))
                left, right = (current + (0,) * (width - len(current)), target + (0,) * (width - len(target)))
                op = match.group(1)
                satisfied = satisfied and {'>=': left >= right, '<=': left <= right, '>': left > right, '<': left < right, '==': left == right}[op]
            if satisfied:
                return True
        return False

    def _approved_packages(item, index):
        ident = _base(item, index, 'instance')
        policy = _policy(index)
        if not _scope(policy, 'vm_scope', ident):
            return _na('VM outside approved package scope')
        allowed = get(policy, 'approved_packages', dict)
        for name, versions in allowed.items():
            if not isinstance(name, str) or not isinstance(versions, list) or any((not isinstance(v, str) for v in versions)):
                raise Unavailable('malformed package allowlist')
        packages = _packages(_inventory(index, ident))
        bad = sorted({(p['name'], p['version']) for p in packages if not _allowed_version(p['version'], allowed.get(p['name'], []))})
        return result(bool(bad), instance=ident, unapproved_packages=bad)

    def _malware(item, index):
        ident = _base(item, index, 'instance')
        policy = _policy(index)
        required = get(policy, 'approved_agent_package_by_vm', dict)
        if ident not in required:
            return _na('no protection agent required by approved VM policy')
        agent = required[ident]
        if not isinstance(agent, str) or not agent:
            raise Unavailable('malformed approved agent name')
        packages = _packages(_inventory(index, ident))
        return result(not any((p['name'] == agent for p in packages)), instance=ident, required_package=agent)

    def _vulnerabilities(item, index, critical_only, sla_field):
        ident = _base(item, index, 'instance')
        if get(item, 'status', str) != 'RUNNING':
            return _na('VM is not RUNNING')
        policy = _policy(index)
        if not _scope(policy, 'vm_scope', ident):
            return _na('VM outside approved patch scope')
        grace = timedelta(hours=_hours(policy, sla_field))
        _packages(_inventory(index, ident))
        report = _joined(index, 'os_vulnerability_report', 'instanceName', ident)
        if report is None:
            raise Unavailable('vulnerability report absent')
        findings = get(report, 'vulnerabilities', list)
        now = _now(index)
        overdue = []
        for finding in findings:
            severity = get(finding, 'severity', str)
            if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'):
                raise Unavailable('unknown vulnerability severity')
            if critical_only and severity != 'CRITICAL':
                continue
            for package in get(finding, 'items', list):
                available = get(package, 'availableInventoryItem', dict)
                name = get(available, 'name', str)
                published = _time(get(available, 'publishedTime', str))
                if not name or published > now:
                    raise Unavailable('invalid available package age')
                if now - published > grace:
                    overdue.append(name)
        return result(bool(overdue), instance=ident, overdue_packages=sorted(set(overdue)))

    def _patch_deployment(item, index):
        ident = _base(item, index, 'instance')
        policy = _policy(index)
        if not _scope(policy, 'vm_scope', ident):
            return _na('VM outside approved patch scope')
        max_age = timedelta(hours=_hours(policy, 'approved_patch_age_hours'))
        packages = _packages(_inventory(index, ident))
        deployments = _rows(index, 'os_patch_deployment')
        applicable = []
        for deployment in deployments:
            enabled = get(deployment, 'enabled', bool)
            targets = get(deployment, 'instanceFilter.instanceNames', list)
            if any((not isinstance(n, str) for n in targets)):
                raise Unavailable('malformed patch filter')
            schedule = get(deployment, 'recurringSchedule', dict)
            if enabled and ident in targets and get(schedule, 'active', bool):
                applicable.append(get(deployment, 'name', str))
        now = _now(index)
        overdue = []
        for package in packages:
            installed = _time(get(package, 'installTime', str))
            if installed > now:
                raise Unavailable('future package install time')
            if now - installed > max_age:
                overdue.append(package['name'])
        return result(not applicable or bool(overdue), instance=ident, applicable_deployments=applicable, packages_over_age=sorted(set(overdue)))

    def _sql(item, index):
        ident = _base(item, index, 'sql_instance')
        policy = _policy(index)
        if not _scope(policy, 'sql_scope', ident):
            return (ident, policy, _na('SQL instance outside approved scope'))
        return (ident, policy, None)

    def _backup_run(item, index):
        ident, policy, na = _sql(item, index)
        if na:
            return na
        if get(item, 'instanceType', str) != 'CLOUD_SQL_INSTANCE':
            return _na('SQL instance is not primary')
        enabled = get(item, 'settings.backupConfiguration.enabled', bool)
        if not enabled:
            return result(True, instance=ident, reason='automated backups disabled')
        rpo = timedelta(hours=_hours(policy, 'approved_rpo_hours'))
        runs = _rows(index, 'sql_backup_run')
        now = _now(index)
        relevant = [r for r in runs if get(r, 'instanceName', str) == ident and get(r, 'type', str) == 'AUTOMATED']
        fresh = []
        for run in relevant:
            status = get(run, 'status', str)
            if status not in ('SUCCESSFUL', 'FAILED', 'RUNNING', 'PENDING'):
                raise Unavailable('unknown backup run status')
            if status == 'SUCCESSFUL':
                ended = _time(get(run, 'endTime', str))
                if ended <= now and now - ended <= rpo:
                    fresh.append(run)
        return result(not fresh, instance=ident, successful_runs_in_rpo=len(fresh))

    def _remote(item, index):
        ident, policy, na = _sql(item, index)
        if na:
            return na
        required = get(policy, 'approved_offsite_policy', bool)
        if not required:
            return _na('offsite separation not required by approved policy')
        source_region = get(item, 'region', str)
        targets = _rows(index, 'backup_target')
        related = [r for r in targets if get(r, 'sourceInstance', str) == ident]
        if not related:
            raise Unavailable('backup target join unavailable')
        regions = [get(r, 'failureRegion', str) for r in related]
        if any((not r for r in regions)) or not source_region:
            raise Unavailable('backup failure region unavailable')
        return result(any((r == source_region for r in regions)), instance=ident, target_regions=regions)

    def _operations(index, source):
        rows = _rows(index, 'sql_operation')
        return [r for r in rows if get(r, 'sourceInstance', str) == source and get(r, 'operationType', str) in ('RESTORE_VOLUME', 'CLONE')]

    def _restore_test(item, index):
        ident, policy, na = _sql(item, index)
        if na:
            return na
        targets = get(policy, 'approved_restore_test_targets', list)
        if any((not isinstance(t, str) for t in targets)):
            raise Unavailable('malformed restore test scope')
        now = _now(index)
        valid = []
        for op in _operations(index, ident):
            if get(op, 'targetId', str) not in targets:
                continue
            if get(op, 'status', str) != 'DONE':
                continue
            if get(op, 'validated', bool) is not True:
                raise Unavailable('restore validation result unavailable')
            error = get(op, 'error', dict)
            if error:
                continue
            ended = _time(get(op, 'endTime', str))
            if ended <= now and now - ended <= timedelta(days=365):
                valid.append(op)
        return result(not valid, instance=ident, validated_restore_events=len(valid))

    def _public_members(index, resource):
        policies = _rows(index, 'iam_policy')
        matches = [r for r in policies if get(r, 'name', str) == resource]
        if len(matches) != 1:
            raise Unavailable('source or target IAM policy unavailable')
        if get(matches[0], '_representation', str) != 'full':
            raise Unavailable('IAM policy representation not complete')
        members = set()
        for binding in get(matches[0], 'bindings', list):
            for member in get(binding, 'members', list):
                if not isinstance(member, str):
                    raise Unavailable('malformed IAM member')
                if member in ('allUsers', 'allAuthenticatedUsers'):
                    members.add(member)
        return members

    def _restore_destination(item, index):
        ident, policy, na = _sql(item, index)
        if na:
            return na
        approved = get(policy, 'approved_restoration_instances', list)
        if any((not isinstance(t, str) for t in approved)):
            raise Unavailable('malformed approved restore destinations')
        instances = {get(r, 'name', str): r for r in _rows(index, 'sql_instance')}
        source_public = get(item, 'settings.ipConfiguration.ipv4Enabled', bool)
        source_members = _public_members(index, ident)
        bad = []
        for op in _operations(index, ident):
            if get(op, 'status', str) != 'DONE' or get(op, 'error', dict):
                continue
            target_id = get(op, 'targetId', str)
            target = instances.get(target_id)
            if target is None:
                raise Unavailable('restore target instance not inventoried')
            target_public = get(target, 'settings.ipConfiguration.ipv4Enabled', bool)
            target_members = _public_members(index, target_id)
            if target_id not in approved or (target_public and (not source_public)) or target_members - source_members:
                bad.append(target_id)
        return result(bool(bad), instance=ident, unsafe_restore_targets=sorted(set(bad)))

    def _iam(item, index):
        ident = _base(item, index, 'iam_policy')
        if get(item, '_representation', str) != 'full':
            raise Unavailable('IAM policy representation not complete')
        context, _ = _ctx(index)
        if get(context, 'inherited_iam_complete', bool) is not True:
            raise Unavailable('inherited IAM policy coverage incomplete')
        return (ident, _policy(index), get(item, 'bindings', list))

    def _binding_keys(bindings):
        for binding in bindings:
            role = get(binding, 'role', str)
            members = get(binding, 'members', list)
            if any((not isinstance(m, str) for m in members)):
                raise Unavailable('malformed IAM binding members')
            yield (binding, role, members)

    def _conditions(item, index):
        ident, policy, bindings = _iam(item, index)
        required = get(policy, 'required_condition_attributes', list)
        for row in required:
            get(row, 'resource', str)
            get(row, 'role', str)
            get(row, 'member', str)
            attrs = get(row, 'attributes', list)
            if not attrs or any((a not in ('request.time', 'resource.name', 'resource.type', 'principal.email') for a in attrs)):
                raise Unavailable('unrecognized required condition attribute')
        bad = []
        seen = set()
        for binding, role, members in _binding_keys(bindings):
            expression = binding.get('condition', {}).get('expression') if isinstance(binding.get('condition', {}), dict) else None
            if expression is not None and (not isinstance(expression, str)):
                raise Unavailable('malformed IAM condition expression')
            for member in members:
                for row in required:
                    if row['resource'] == ident and row['role'] == role and (row['member'] == member):
                        seen.add((ident, role, member))
                        if not expression or any((attr not in expression for attr in row['attributes'])):
                            bad.append((role, member))
        expected = {(r['resource'], r['role'], r['member']) for r in required if r['resource'] == ident}
        if expected - seen:
            raise Unavailable('required grant absent from bound IAM inventory')
        return result(bool(bad), policy=ident, bindings_missing_attributes=bad)

    def _expiry(item, index):
        ident, policy, bindings = _iam(item, index)
        required = get(policy, 'expiring_privileged_grants', list)
        expected = {(get(r, 'resource', str), get(r, 'role', str), get(r, 'member', str)) for r in required}
        bad, seen = ([], set())
        for binding, role, members in _binding_keys(bindings):
            condition = binding.get('condition', {})
            if not isinstance(condition, dict):
                raise Unavailable('malformed IAM binding condition')
            expression = condition.get('expression')
            if expression is not None and (not isinstance(expression, str)):
                raise Unavailable('malformed expiry expression')
            for member in members:
                key = (ident, role, member)
                if key in expected:
                    seen.add(key)
                    if not expression or 'request.time' not in expression:
                        bad.append((role, member))
                    else:
                        expiry = re.fullmatch('\\s*request\\.time\\s*<\\s*timestamp\\("([^"]+)"\\)\\s*', expression)
                        if expiry is None:
                            raise Unavailable('IAM expiry expression semantics unavailable')
                        _time(expiry.group(1))
        if {k for k in expected if k[0] == ident} - seen:
            raise Unavailable('required privileged grant absent from policy')
        return result(bool(bad), policy=ident, grants_without_expiry=bad)

    def _timeliness(item, index):
        ident, policy, bindings = _iam(item, index)
        events = get(policy, 'personnel_changes', list)
        if get(policy, 'personnel_change_feed_complete', bool) is not True:
            raise Unavailable('personnel change feed incomplete')
        now = _now(index)
        retained = []
        grants = {(role, member) for _, role, members in _binding_keys(bindings) for member in members}
        for event in events:
            if get(event, 'resource', str) != ident:
                continue
            principal = get(event, 'principal', str)
            role = get(event, 'forbiddenRole', str)
            tier = get(event, 'tier', str)
            if tier not in ('privileged', 'other'):
                raise Unavailable('unrecognized personnel change tier')
            effective = _time(get(event, 'effectiveTime', str))
            if effective > now:
                raise Unavailable('future personnel change event')
            deadline = timedelta(hours=48 if tier == 'privileged' else 14 * 24)
            if now - effective > deadline and (role, principal) in grants:
                retained.append((principal, role))
        return result(bool(retained), policy=ident, overdue_grants=retained)

    def _transparency(item, index):
        ident = _base(item, index, 'project')
        _, scope = _ctx(index)
        if ident != scope:
            raise Unavailable('project identity differs from scope')
        entries = _rows(index, 'access_transparency_entry')
        now = _now(index)
        suffix = '/logs/cloudaudit.googleapis.com%2Faccess_transparency'
        recent = 0
        for entry in entries:
            if get(entry, 'project', str) != scope:
                raise Unavailable('foreign Access Transparency entry')
            log_name = get(entry, 'logName', str)
            stamp = _time(get(entry, 'timestamp', str))
            if log_name.endswith(suffix) and stamp <= now and (now - stamp <= timedelta(days=30)):
                recent += 1
        return result(False, project=scope, recent_access_transparency_entries=recent) if recent else unknown('no recent Access Transparency entry; provider access may not have occurred')

    def _backup_alert(item, index):
        ident = _base(item, index, 'project')
        _, scope = _ctx(index)
        if ident != scope:
            raise Unavailable('project identity differs from scope')
        metrics = _rows(index, 'logging_metric')
        alerts = _rows(index, 'monitoring_alert_policy')
        names = set()
        for metric in metrics:
            metric_id = get(metric, 'metricId', str)
            get(metric, 'filter', str)
            if get(metric, 'name', str) != scope + '/metrics/' + metric_id:
                raise Unavailable('foreign logging metric identity')
            if not metric_id or '/' in metric_id:
                raise Unavailable('malformed logging metric identity')
            if get(metric, 'filterMatchesFailedCloudSqlBackupRun', bool) and (not get(metric, 'disabled', bool)):
                names.add('logging.googleapis.com/user/' + metric_id)
        active = []
        for alert in alerts:
            if not get(alert, 'enabled', bool):
                continue
            for condition in get(alert, 'conditions', list):
                expression = get(condition, 'conditionThreshold.filter', str)
                clauses = [part.strip() for part in expression.split(' AND ')]
                matches = []
                for clause in clauses:
                    metric_ref = re.fullmatch('metric\\.type\\s*=\\s*"([^"]+)"', clause)
                    resource_ref = re.fullmatch('resource\\.type\\s*=\\s*"([^"]+)"', clause)
                    if metric_ref:
                        matches.append(metric_ref.group(1))
                    elif not resource_ref:
                        raise Unavailable('alert filter semantics unavailable')
                if len(matches) != 1:
                    raise Unavailable('alert metric reference unavailable or ambiguous')
                if matches[0] in names:
                    active.append(get(alert, 'name', str))
        return result(not active, project=scope, enabled_alert_policies=sorted(set(active)))
    EVALUATORS = {'gcp_c5_software_inventory': _software, 'gcp_compute_approved_packages': _approved_packages, 'gcp_c5_malware_telemetry': _malware, 'gcp.compute.os_patch_compliance': lambda i, x: _vulnerabilities(i, x, False, 'approved_patch_grace_hours'), 'gcp_compute_os_patch_compliance': lambda i, x: _vulnerabilities(i, x, True, 'approved_patch_sla_hours'), 'gcp_c5_patch_deployment': _patch_deployment, 'gcp_c5_sql_backup_run': _backup_run, 'gcp_c5_backup_remote_location': _remote, 'gcp_c5_restore_test': _restore_test, 'gcp_c5_restore_destination': _restore_destination, 'gcp_c5_iam_conditions': _conditions, 'gcp_c5_iam_expiry': _expiry, 'gcp_c5_iam_change_timeliness': _timeliness, 'gcp.logging.access_transparency_entries': _transparency, 'gcp_cloudsql_backup_failure_alert': _backup_alert}
    EXTRA = {'gcp_c5_software_inventory': ['os_inventory'], 'gcp_compute_approved_packages': ['os_inventory'], 'gcp_c5_malware_telemetry': ['os_inventory'], 'gcp.compute.os_patch_compliance': ['os_inventory', 'os_vulnerability_report'], 'gcp_compute_os_patch_compliance': ['os_inventory', 'os_vulnerability_report'], 'gcp_c5_patch_deployment': ['os_inventory', 'os_patch_deployment'], 'gcp_c5_sql_backup_run': ['sql_backup_run'], 'gcp_c5_backup_remote_location': ['backup_target'], 'gcp_c5_restore_test': ['sql_operation'], 'gcp_c5_restore_destination': ['sql_operation', 'iam_policy'], 'gcp_c5_iam_conditions': [], 'gcp_c5_iam_expiry': [], 'gcp_c5_iam_change_timeliness': [], 'gcp.logging.access_transparency_entries': ['access_transparency_entry'], 'gcp_cloudsql_backup_failure_alert': ['logging_metric', 'monitoring_alert_policy']}
    for _id, _meta in META.items():
        _category = _meta['category']
        _native = _category if _category in ('hardening', 'exposure', 'least_privilege', 'iam_graph', 'network') else 'hardening'

        def _evaluate(item, index, check_id=_id):
            return EVALUATORS[check_id](item, index)
        _evaluate.__name__ = _id.replace('.', '_')
        register(_id, 'gcp', _native, _meta['kind'], _meta['title'], _meta['severity'], 'CM-6', _meta['hint'], dependencies=[_meta['kind'], *EXTRA[_id]])(_evaluate)
        if _native != _category:
            pass
    from .facts import memoized as _batch_memoized
    _base_rows = _rows

    def _rows(index, kind):
        return _batch_memoized(index, ('batch_sw53_rows', kind, _ctx(index)[1]), lambda: _base_rows(index, kind))

    def _indexed(index, kind, key):

        def build():
            table = {}
            for row in _rows(index, kind):
                identity = get(row, key, str)
                if identity in table:
                    raise Unavailable('duplicate joined fact')
                table[identity] = row
            return table
        return _batch_memoized(index, ('batch_sw53_join', kind, key, _ctx(index)[1]), build)

    def _joined(index, kind, key, ident):
        return _indexed(index, kind, key).get(ident)

    def _base(item, index, kind):
        ident = _identity(item, kind)
        row = _indexed(index, kind, 'name').get(ident)
        if row is None or row != item:
            raise Unavailable('resource identity not unique in scoped inventory')
        return ident
_load_53()

# Source family: compliance_new_sw54.py
def _load_54():
    _ALLOWED = {'gcp_c5_cloudbuild_gate', 'gcp_c5_log_export', 'gcp_c5_log_isolation', 'gcp_c5_logging_redundancy', 'gcp_c5_siem_sink', 'gcp_c5_workforce_federation', 'gcp_certificate_renewal_30_days', 'gcp_certificate_rotation_180_days', 'gcp_certificate_rotation_90_days', 'gcp_gke_small_cluster_auto_upgrade', 'gcp_iam_workforce_mfa', 'gcp_kms_key_destroy_alert', 'gcp_logging_enumeration_alert', 'gcp_logging_query_rate_alert'}
    'Signed GCP configuration checks. All joins require complete scoped snapshot facts.'
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone
    import re
    from cryptography import x509
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, list_of_objects
    PROPOSED_SPEC_SHA256 = {'gcp_kms_key_destroy_alert': '23536ad706b18859e6756f3b3cc63816b444dfcd260143233607727c84f22609', 'gcp_logging_enumeration_alert': '06fa0a5f22f10938f8c464bf242c4f19b83340a01740668067d98ed25dc280ed', 'gcp_logging_query_rate_alert': '7c6b15c194e950d0a969d2903f9d2d595ef2880138636792ede359c892e81e5b', 'gcp_c5_log_export': '55e999bd83e46eb1b1b4d0c2079c2f16a1497b7a114963cd6facba780f13b4fe', 'gcp_c5_log_isolation': 'b86a70176edb56f2925e8f15edb9c348c52176fecf08bafa76da3a5b0f7f3b83', 'gcp_c5_logging_redundancy': 'ed7d2440d422ac29cc30039d65ba3a2614469bf95b7c0f81e3042c643011c103', 'gcp_c5_siem_sink': '65e3d163770298c4b2e4ce7cce45ea08371f5f2889f4a2e59f8ed3dbb7108cf8', 'gcp_certificate_renewal_30_days': '6fa7627a63c7f8e02438aa30d6ee2e3acc4426cc717ef4de6943126006fbe0bd', 'gcp_certificate_rotation_180_days': '7495d4bce8373e88ce246a2dbf70e5418ebe81762c53509c7475639624dd9126', 'gcp_certificate_rotation_90_days': 'cb9fe2ebb0c097908b5fea9dae9179c4909a856a91a36d66cdfe9ea3ef5fde6f', 'gcp_c5_build_provenance': '87c24b21f4c4bb9640a6574fa17c7d38fc977a0e1810869b49a76ef8851113c2', 'gcp_c5_cloudbuild_gate': 'c2a9456ccb5442122913fb2b8881b35e170ffb80dd4fd290fad55be2265a9be4', 'gcp_c5_workforce_federation': '35c0bfddbf151d9d1a2d5b6a769e3993afca15dcdd34f051dce32f9190d09f33', 'gcp_iam_workforce_mfa': '47adf9c6c5e65059d7b299fd323ddd0500c75d97affa037e988ad6a5e523a371', 'gcp_gke_small_cluster_auto_upgrade': '02a6a49152b3b74ae683f86a5c27d9a3b861e1f941d9b68ee73041056478d5ab'}
    PROPOSED_SPEC_SHA256 = {k: v for k, v in PROPOSED_SPEC_SHA256.items() if k in _ALLOWED}
    IDS = tuple(PROPOSED_SPEC_SHA256)

    def _scope(index, prefix):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('GCP provider authority unavailable')
        scope = get(context, 'scope', str)
        suffix = scope[len(prefix):] if scope.startswith(prefix) else ''
        if not re.fullmatch('[A-Za-z0-9-]+', suffix):
            raise Unavailable('GCP scope unavailable')
        return scope

    def _inventory(index, kind, prefix='projects/'):
        scope = _scope(index, prefix)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1 or (not isinstance(envelopes[0], dict)):
            raise Unavailable('scoped inventory unavailable: ' + kind)
        envelope = envelopes[0]
        if envelope.get('type') != kind or envelope.get('scope') != scope:
            raise Unavailable('foreign inventory: ' + kind)
        rows = complete_items(index, kind)
        declared = get(envelope, 'items', list)
        wrappers = index.get(kind, [])
        if not isinstance(wrappers, list):
            raise Unavailable('malformed resource wrappers: ' + kind)
        if len(rows) != len(declared) or len(rows) != len(wrappers) or declared != rows or ((envelope['status'] == 'empty') != (not rows)):
            raise Unavailable('inconsistent inventory: ' + kind)
        for row, native in zip(wrappers, rows):
            if get(row, 'type', str) != kind or get(row, 'scope', str) != scope or get(row, 'data', dict) != native:
                raise Unavailable('foreign or inconsistent resource: ' + kind)
        return rows

    def _member(item, rows, name='name'):
        identity = get(item, name, str)
        if not identity or sum((get(row, name, str) == identity for row in rows)) != 1 or item not in rows:
            raise Unavailable('resource absent or duplicate in complete inventory')
        return identity

    def _policy(index, section, prefix='projects/'):
        scope = _scope(index, prefix)
        p = get(index, 'context.metadata.compliance_policy', dict)
        if get(p, 'status', str) != 'collected' or get(p, 'scope', str) != scope:
            raise Unavailable('approved policy unavailable or foreign scope')
        return get(p, section, dict)

    def _instant(value):
        if not isinstance(value, str):
            raise Unavailable('timestamp unavailable')
        try:
            t = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('malformed timestamp') from exc
        if t.tzinfo is None:
            raise Unavailable('naive timestamp')
        return t.astimezone(timezone.utc)

    def _now(index):
        return _instant(get(index, 'context.created_at', str))

    def _strings(obj, field):
        values = get(obj, field, list)
        if any((not isinstance(v, str) or not v for v in values)) or len(values) != len(set(values)):
            raise Unavailable('malformed list: ' + field)
        return values

    def _sink_rows(item, index):
        rows = _inventory(index, 'log_sink')
        scope = _scope(index, 'projects/')
        if get(item, 'provider', str) != 'gcp' or get(item, 'scope', str) != scope:
            raise Unavailable('foreign project scope context')
        names = []
        for row in rows:
            name = get(row, 'name', str)
            if not name.startswith(scope + '/sinks/') or not name[len(scope) + 7:]:
                raise Unavailable('foreign log sink')
            names.append(name)
        if len(names) != len(set(names)):
            raise Unavailable('duplicate log sink')
        return rows

    def _sink_policy(index):
        p = _policy(index, 'logging')
        if get(p, 'ancestor_inventory_complete', bool) is not True:
            raise Unavailable('ancestor sink inventory unavailable')
        ancestors = list_of_objects(get(p, 'ancestor_sinks', list))
        for sink in ancestors:
            if not re.fullmatch('(?:organizations|folders)/[^/]+/sinks/[^/]+', get(sink, 'name', str)):
                raise Unavailable('foreign ancestor sink')
            if get(sink, 'includeChildren', bool) is not True:
                raise Unavailable('ancestor sink coverage uncertain')
        return (p, ancestors)

    def _filter_covers(value, log_class):
        """Only prove an unfiltered sink or a simple equality/OR query."""
        if not isinstance(value, str):
            raise Unavailable('log filter unavailable')
        if value == '':
            return True
        terms = re.split('\\s+OR\\s+', value)
        found = []
        for term in terms:
            match = re.fullmatch('\\s*protoPayload\\.methodName\\s*=\\s*"([^"\\s]+)"\\s*', term)
            if not match:
                raise Unavailable('complex log filter cannot be proven')
            found.append(match.group(1))
        return log_class in found

    def _sink_covers(row, log_class):
        disabled = get(row, 'disabled', bool)
        destination = get(row, 'destination', str)
        if not destination:
            raise Unavailable('sink destination unavailable')
        covered = _filter_covers(get(row, 'filter', str), log_class)
        for exclusion in list_of_objects(get(row, 'exclusions', list)):
            if get(exclusion, 'disabled', bool) is False and _filter_covers(get(exclusion, 'filter', str), log_class):
                covered = False
        return not disabled and covered

    def _logging(item, index, mode):
        rows = _sink_rows(item, index)
        p, ancestors = _sink_policy(index)
        all_sinks = rows + ancestors
        if mode == 'isolation':
            buckets = set(_strings(p, 'customer_data_buckets'))
            exceptions = list_of_objects(get(p, 'separation_exceptions', list))
            allowed = {(get(x, 'sink', str), get(x, 'bucket', str)) for x in exceptions}
            if get(p, 'bucket_register_complete', bool) is not True:
                raise Unavailable('customer bucket register incomplete')
            unsafe = []
            external = False
            for sink in all_sinks:
                if get(sink, 'disabled', bool):
                    continue
                destination = get(sink, 'destination', str)
                if destination.startswith('storage.googleapis.com/'):
                    bucket = destination.removeprefix('storage.googleapis.com/')
                    if not bucket or '/' in bucket:
                        raise Unavailable('malformed bucket sink destination')
                    if bucket in buckets and (get(sink, 'name', str), bucket) not in allowed:
                        unsafe.append(get(sink, 'name', str))
                else:
                    external = True
            if unsafe:
                return result(True, unsafe_sinks=sorted(unsafe))
            if external:
                return unknown('external sink destination separation unavailable')
            return result(False, sink_count=len(all_sinks))
        classes = _strings(p, 'required_log_classes' if mode != 'redundancy' else 'critical_log_classes')
        if not classes:
            raise Unavailable('required log class contract empty')
        if mode == 'redundancy' and get(p, 'require_two_destinations', bool) is not True:
            return ('NOT_APPLICABLE', {'reason': 'approved architecture does not require two destinations'})
        destination = None
        if mode == 'export':
            destination = get(p, 'approved_customer_destination', str)
        if mode == 'siem':
            destination = get(p, 'approved_siem_destination', str)
        if destination == '':
            raise Unavailable('approved destination empty')
        lacking = []
        uncertain_independence = []
        independent = set()
        if mode == 'redundancy':
            for pair in list_of_objects(get(p, 'independent_destination_pairs', list)):
                values = _strings(pair, 'destinations')
                if len(values) != 2 or values[0] == values[1]:
                    raise Unavailable('malformed destination independence approval')
                independent.add(frozenset(values))
        for log_class in classes:
            candidates = [sink for sink in all_sinks if destination is None or get(sink, 'destination', str) == destination]
            covered = {get(sink, 'destination', str) for sink in candidates if _sink_covers(sink, log_class)}
            if len(covered) < (2 if mode == 'redundancy' else 1):
                lacking.append(log_class)
            elif mode == 'redundancy' and (not any((pair <= covered for pair in independent))):
                uncertain_independence.append(log_class)
        if lacking:
            return result(True, missing_classes=lacking, checked_classes=classes)
        if uncertain_independence:
            return unknown('destination independence unverified', log_classes=uncertain_independence)
        return result(False, missing_classes=[], checked_classes=classes)

    def _cert(item, index, mode):
        rows = _inventory(index, 'certificate')
        name = _member(item, rows)
        if not re.fullmatch(re.escape(_scope(index, 'projects/')) + '/locations/[^/]+/certificates/[^/]+', name):
            raise Unavailable('foreign certificate')
        now = _now(index)
        deployment = get(item, 'deployment', dict)
        if get(deployment, 'status', str) != 'collected':
            raise Unavailable('certificate deployment association unavailable')
        deployed = get(deployment, 'deployed', bool)
        if not deployed:
            return ('NOT_APPLICABLE', {'certificate': name, 'reason': 'not deployed'})
        if mode == 'renewal':
            expiry = _instant(get(item, 'expireTime', str))
            domains = set(_strings(get(item, 'managed', dict), 'domains'))
            if not domains:
                raise Unavailable('certificate domains unavailable')
            if expiry - timedelta(days=30) > now:
                return result(False, certificate=name, threshold_crossed=False)
            replacements = list_of_objects(get(deployment, 'replacements', list))
            threshold = expiry - timedelta(days=30)
            timely = False
            for candidate in replacements:
                if get(candidate, 'name', str) == name:
                    continue
                if get(candidate, 'state', str) != 'ACTIVE':
                    continue
                covered = set(_strings(candidate, 'domains'))
                activated = _instant(get(candidate, 'deployedAt', str))
                if domains <= covered and activated <= min(now, threshold + timedelta(hours=24)):
                    timely = True
            if get(deployment, 'replacement_inventory_complete', bool) is not True:
                raise Unavailable('replacement inventory incomplete')
            if not timely and now < threshold + timedelta(hours=24):
                return unknown('24-hour replacement window remains open', certificate=name)
            return result(not timely, certificate=name, threshold_crossed=True)
        if mode == '180':
            state = get(item, 'managed.state', str)
            if state != 'ACTIVE':
                return ('NOT_APPLICABLE', {'certificate': name, 'reason': 'not ACTIVE'})
            age = now - _instant(get(item, 'createTime', str))
            if age < timedelta(0):
                raise Unavailable('future certificate creation')
            return result(age > timedelta(days=180), certificate=name, age_days=age.days)
        pem = get(item, 'pemCertificate', str)
        if not pem.startswith('-----BEGIN CERTIFICATE-----'):
            raise Unavailable('leaf PEM unavailable')
        try:
            issued = x509.load_pem_x509_certificate(pem.encode('ascii')).not_valid_before_utc
        except (ValueError, UnicodeError) as exc:
            raise Unavailable('malformed leaf PEM') from exc
        age = now - issued
        if age < timedelta(0):
            raise Unavailable('future certificate issuance')
        return result(age > timedelta(days=90), certificate=name, age_days=age.days)

    def _build(item, index, mode):
        rows = _inventory(index, 'cloudbuild_trigger')
        name = _member(item, rows, 'id')
        p = _policy(index, 'cloudbuild')
        if get(p, 'deployment_coverage', str) != 'cloudbuild_only':
            raise Unavailable('deployments outside Cloud Build unresolved')
        if get(p, 'production_trigger_scope_complete', bool) is not True:
            raise Unavailable('production trigger scope incomplete')
        ids = _strings(p, 'production_trigger_ids')
        if name not in ids:
            return ('NOT_APPLICABLE', {'trigger': name, 'reason': 'outside approved production scope'})
        if mode == 'gate':
            required = get(p, 'approval_required', bool)
            approval = get(item, 'approvalConfig.approvalRequired', bool)
            step = get(p, 'security_test_step', str)
            if not step:
                raise Unavailable('required security test undefined')
            definition = get(item, 'buildDefinition', dict)
            if get(definition, 'status', str) != 'collected':
                raise Unavailable('file-backed build definition unreadable')
            steps = list_of_objects(get(definition, 'steps', list))
            ids = [get(s, 'id', str) for s in steps]
            return result(required and (not approval) or step not in ids, trigger=name, approval_required=required, security_test_step=step)
        builds = _inventory(index, 'cloudbuild_build')
        matched = [b for b in builds if get(b, 'triggerId', str) == name]
        build_ids = [get(b, 'id', str) for b in builds]
        if len(build_ids) != len(set(build_ids)):
            raise Unavailable('duplicate Cloud Build build')
        if not matched:
            raise Unavailable('no production deployment build association')
        bad = []
        for build in matched:
            build_id = get(build, 'id', str)
            if get(build, 'productionDeployment', bool) is not True:
                continue
            status = get(build, 'status', str)
            if status not in {'SUCCESS', 'FAILURE', 'CANCELLED', 'TIMEOUT', 'WORKING', 'QUEUED', 'EXPIRED', 'INTERNAL_ERROR'}:
                raise Unavailable('unrecognized build status')
            provenance = get(build, 'sourceProvenance.resolvedRepoSource.commitSha', str)
            substitution = get(build, 'substitutions.COMMIT_SHA', str)
            if status != 'SUCCESS' or not (provenance or substitution):
                bad.append(build_id)
        if not matched or not any((get(b, 'productionDeployment', bool) for b in matched)):
            raise Unavailable('production build association incomplete')
        return result(bool(bad), trigger=name, unsafe_builds=bad)

    def _workforce(item, index, mode):
        rows = _inventory(index, 'workforce_pool', 'organizations/')
        name = _member(item, rows)
        scope = _scope(index, 'organizations/')
        if not name.startswith('locations/global/workforcePools/'):
            raise Unavailable('foreign workforce pool')
        p = _policy(index, 'workforce', 'organizations/')
        if get(p, 'mapping_complete', bool) is not True:
            raise Unavailable('customer provider mapping incomplete')
        mapping = list_of_objects(get(p, 'customer_provider_mapping', list))
        applicable = [m for m in mapping if get(m, 'pool', str) == name]
        if not applicable:
            return ('NOT_APPLICABLE', {'pool': name, 'reason': 'outside approved customer mapping'})
        providers = _inventory(index, 'workforce_provider', 'organizations/')
        provider_ids = [get(v, 'name', str) for v in providers]
        valid_pool_names = {get(pool, 'name', str) for pool in rows}
        if len(provider_ids) != len(set(provider_ids)) or any((not any((v.startswith(pool_name + '/providers/') and v[len(pool_name) + 11:] and ('/' not in v[len(pool_name) + 11:]) for pool_name in valid_pool_names)) for v in provider_ids)):
            raise Unavailable('duplicate or foreign workforce provider')
        mapped_ids = [get(m, 'provider', str) for m in applicable]
        if len(mapped_ids) != len(set(mapped_ids)):
            raise Unavailable('duplicate customer provider mapping')
        if mode == 'federation' and get(item, 'state', str) != 'ACTIVE':
            return result(True, pool=name, reason='pool not ACTIVE')
        bad = []
        seen = []
        for contract in applicable:
            provider_name = get(contract, 'provider', str)
            matches = [v for v in providers if get(v, 'name', str) == provider_name]
            if len(matches) != 1 or not provider_name.startswith(name + '/providers/'):
                raise Unavailable('mapped workforce provider unavailable')
            provider = matches[0]
            seen.append(provider_name)
            if mode == 'federation':
                issuer = get(contract, 'issuer', str)
                audiences = set(_strings(contract, 'audiences'))
                configured = set(_strings(get(provider, 'oidc', dict), 'allowedAudiences'))
                if not issuer or not audiences:
                    raise Unavailable('approved issuer/audience contract empty')
                if get(provider, 'state', str) != 'ACTIVE' or get(provider, 'oidc.issuerUri', str) != issuer or (not configured) or (not configured <= audiences):
                    bad.append(provider_name)
            else:
                if get(provider, 'state', str) != 'ACTIVE':
                    continue
                claim = get(contract, 'mfa_claim', str)
                expected = get(contract, 'mfa_mapping', str)
                assurance = get(contract, 'idp_assurance_verified', bool)
                if not claim or not expected or (not assurance):
                    raise Unavailable('IdP MFA assurance contract unavailable')
                attrs = get(provider, 'attributeMapping', dict)
                if attrs.get(claim) != expected:
                    bad.append(provider_name)
        return result(bool(bad), pool=name, checked_providers=seen, unsafe_providers=bad)

    def _gke(item, index):
        rows = _inventory(index, 'gke_cluster')
        name = _member(item, rows)
        if not re.fullmatch(re.escape(_scope(index, 'projects/')) + '/locations/[^/]+/clusters/[^/]+', name):
            raise Unavailable('foreign GKE cluster')
        pools = list_of_objects(get(item, 'nodePools', list))
        if not pools:
            raise Unavailable('node pool inventory unavailable')
        managers = _inventory(index, 'instance_group_manager')
        by_url = {get(m, 'instanceGroup', str): m for m in managers}
        if len(by_url) != len(managers):
            raise Unavailable('duplicate instance group manager')
        project_path = '/projects/' + _scope(index, 'projects/').removeprefix('projects/') + '/'
        if any((project_path not in url or '/instanceGroups/' not in url for url in by_url)):
            raise Unavailable('foreign instance group')
        total = 0
        disabled = []
        for pool in pools:
            pool_name = get(pool, 'name', str)
            urls = _strings(pool, 'instanceGroupUrls')
            if not urls:
                raise Unavailable('node pool instance groups unavailable')
            auto = get(pool, 'management.autoUpgrade', bool)
            if not auto:
                disabled.append(pool_name)
            for url in urls:
                if url not in by_url:
                    raise Unavailable('instance group targetSize unavailable')
                size = get(by_url[url], 'targetSize', int)
                if size < 0:
                    raise Unavailable('negative instance group targetSize')
                total += size
        return result(total < 3 and bool(disabled), cluster=name, target_nodes=total, pools_without_auto_upgrade=disabled)

    def _alerts(item, index, mode):
        scope = _scope(index, 'projects/')
        if get(item, 'provider', str) != 'gcp' or get(item, 'scope', str) != scope:
            raise Unavailable('foreign project scope context')
        metrics = _inventory(index, 'logging_metric')
        policies = _inventory(index, 'alert_policy')
        if mode == 'query':
            p = _policy(index, 'monitoring')
            approved = get(p, 'approved_query_count', int)
            if approved < 1:
                raise Unavailable('invalid approved query count')
        metric_names = [get(metric, 'name', str) for metric in metrics]
        policy_names = [get(policy, 'name', str) for policy in policies]
        if len(metric_names) != len(set(metric_names)) or len(policy_names) != len(set(policy_names)):
            raise Unavailable('duplicate metric or alert identity')
        for metric in metrics:
            metric_name = get(metric, 'name', str)
            prefix = scope + '/metrics/'
            if not metric_name.startswith(prefix) or not metric_name[len(prefix):] or '/' in metric_name[len(prefix):]:
                raise Unavailable('metric identity unavailable or foreign')
            metric_id = metric_name[len(prefix):]
            if 'metricId' in metric and get(metric, 'metricId', str) != metric_id:
                raise Unavailable('metric ID conflicts with native name')
            if 'disabled' in metric and get(metric, 'disabled', bool):
                continue
            flt = get(metric, 'filter', str)
            if mode == 'kms':
                clauses = re.split('\\s+OR\\s+', flt)
                names = []
                for clause in clauses:
                    match = re.fullmatch('protoPayload\\.methodName\\s*=\\s*"([^"\\s]+)"', clause.strip())
                    if not match:
                        raise Unavailable('KMS metric filter semantics unrecognized')
                    names.append(match.group(1))
                disable = {'DisableCryptoKeyVersion', 'google.cloud.kms.v1.KeyManagementService.DisableCryptoKeyVersion'}
                destroy = {'DestroyCryptoKeyVersion', 'google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion'}
                target = any((x in disable for x in names)) and any((x in destroy for x in names))
            elif mode == 'enumeration':
                if flt != 'protoPayload.methodName =~ "\\.(list|get)$"':
                    raise Unavailable('enumeration metric filter semantics unrecognized')
                target = True
            else:
                if flt != 'protoPayload.methodName="logging.entries.list"':
                    raise Unavailable('query metric filter semantics unrecognized')
                target = True
            if mode != 'kms' and target:
                extractors = get(metric, 'labelExtractors', dict)
                principal_labels = {key for key, value in extractors.items() if value == 'EXTRACT(protoPayload.authenticationInfo.principalEmail)'}
                target = bool(principal_labels)
            if not target:
                continue
            for policy in policies:
                if not get(policy, 'enabled', bool):
                    continue
                channels = _strings(policy, 'notificationChannels')
                if mode != 'kms' and (not channels):
                    continue
                for condition in list_of_objects(get(policy, 'conditions', list)):
                    threshold = get(condition, 'conditionThreshold', dict)
                    series = get(threshold, 'filter', str)
                    if series != f'metric.type="logging.googleapis.com/user/{metric_id}"':
                        continue
                    if mode == 'kms':
                        return result(False, metric=metric_name, alert=get(policy, 'name', str))
                    if get(threshold, 'comparison', str) != 'COMPARISON_GT':
                        continue
                    limit = get(threshold, 'thresholdValue', (int, float))
                    if limit < 0 or limit > (approved if mode == 'query' else 10):
                        continue
                    aggs = list_of_objects(get(threshold, 'aggregations', list))
                    if any((get(a, 'alignmentPeriod', str) == '300s' and get(a, 'perSeriesAligner', str) in ('ALIGN_SUM', 'ALIGN_COUNT') and any((s in {'metric.label.' + label for label in principal_labels} for s in _strings(a, 'groupByFields'))) for a in aggs)):
                        return result(False, metric=metric_name, alert=get(policy, 'name', str))
        return result(True, project=scope, reason='no qualifying enabled alert in complete inventories')

    def _signed(id, category, kind, title, severity, remediation, deps, target='resource'):

        def decorate(fn):
            registered = register(id, 'gcp', 'hardening', kind, title, severity, 'CM-6', remediation, dependencies=deps, target=target)(fn)
            pass
            return registered
        return decorate

    @_signed('gcp_kms_key_destroy_alert', 'monitoring', 'project', 'KMS key disable or destroy events lack an alert', 'high', 'Create an enabled alert on log metrics matching Cloud KMS key-version disable and destroy API method names.', ['logging_metric', 'alert_policy'], 'scope')
    def kms_key_destroy_alert(item, index):
        return _alerts(item, index, 'kms')

    @_signed('gcp_logging_enumeration_alert', 'monitoring', 'project', 'Cloud resource enumeration lacks an alert', 'medium', 'Create a log metric filtering .list/.get audit methods by principal and an enabled five-minute alert at ten events with a channel.', ['logging_metric', 'alert_policy'], 'scope')
    def logging_enumeration_alert(item, index):
        return _alerts(item, index, 'enumeration')

    @_signed('gcp_logging_query_rate_alert', 'monitoring', 'project', 'Excessive log queries lack an alert', 'medium', 'Create a log metric for logging.entries.list by principal and an enabled 300-second threshold alert using approved_query_count.', ['logging_metric', 'alert_policy'], 'scope')
    def logging_query_rate_alert(item, index):
        return _alerts(item, index, 'query')

    @_signed('gcp_c5_log_export', 'logging', 'log_sink', 'Customer audit log export availability', 'medium', 'Create an enabled Cloud Logging sink to the approved customer-access destination with filters covering required audit classes.', ['log_sink'], 'scope')
    def c5_log_export(item, index):
        return _logging(item, index, 'export')

    @_signed('gcp_c5_log_isolation', 'logging', 'log_sink', 'Log and customer-data storage isolation', 'medium', 'Change the sink destination to a dedicated log bucket outside the customer-data bucket register, or record the approved exception.', ['log_sink'], 'scope')
    def c5_log_isolation(item, index):
        return _logging(item, index, 'isolation')

    @_signed('gcp_c5_logging_redundancy', 'availability', 'log_sink', 'Critical log destination redundancy', 'medium', 'Create a second enabled sink to an independent approved destination for each critical log class.', ['log_sink'], 'scope')
    def c5_logging_redundancy(item, index):
        return _logging(item, index, 'redundancy')

    @_signed('gcp_c5_siem_sink', 'logging', 'log_sink', 'Audit log export to approved SIEM', 'medium', 'Create an enabled project or organization sink for required audit classes to the approved SIEM destination; remove exclusions.', ['log_sink'], 'scope')
    def c5_siem_sink(item, index):
        return _logging(item, index, 'siem')

    @_signed('gcp_certificate_renewal_30_days', 'encryption', 'certificate', 'Certificate lacks timely renewal', 'high', 'Deploy an ACTIVE replacement Certificate Manager certificate for the same domains at least 30 days before expiry.', ['certificate'])
    def certificate_renewal(item, index):
        return _cert(item, index, 'renewal')

    @_signed('gcp_certificate_rotation_180_days', 'encryption', 'certificate', 'Deployed certificate exceeds 180-day rotation limit', 'high', 'Replace deployed certificates before their createTime exceeds 180 days and update the certificate map entry.', ['certificate'])
    def certificate_rotation_180(item, index):
        return _cert(item, index, '180')

    @_signed('gcp_certificate_rotation_90_days', 'encryption', 'certificate', 'Deployed certificate exceeds 90-day rotation limit', 'high', 'Replace deployed certificates before their leaf issuance age exceeds 90 days and update the certificate map entry.', ['certificate'])
    def certificate_rotation_90(item, index):
        return _cert(item, index, '90')

    @_signed('gcp_c5_cloudbuild_gate', 'secure_development', 'cloudbuild_trigger', 'Production build security gate', 'medium', 'Enable approvalConfig.approvalRequired and add the required security-test build step to each production Cloud Build trigger.', ['cloudbuild_trigger'])
    def c5_cloudbuild_gate(item, index):
        return _build(item, index, 'gate')

    @_signed('gcp_c5_workforce_federation', 'identity', 'workforce_pool', 'Customer identity federation configuration', 'medium', 'Enable the approved workforce pool and provider, and set oidc.issuerUri and allowedAudiences to the customer mapping.', ['workforce_pool', 'workforce_provider'])
    def c5_workforce_federation(item, index):
        return _workforce(item, index, 'federation')

    @_signed('gcp_iam_workforce_mfa', 'identity', 'workforce_pool', 'Workforce federation lacks MFA assurance', 'high', "Map and require a verified MFA assurance claim in each enabled workforce provider's attributeMapping/IdP policy.", ['workforce_pool', 'workforce_provider'])
    def iam_workforce_mfa(item, index):
        return _workforce(item, index, 'mfa')

    @_signed('gcp_gke_small_cluster_auto_upgrade', 'vulnerability', 'gke_cluster', 'Small GKE cluster lacks node auto upgrade', 'medium', 'Enable nodePools[].management.autoUpgrade on every node pool in clusters with fewer than three target nodes.', ['gke_cluster', 'instance_group_manager'])
    def gke_small_cluster_auto_upgrade(item, index):
        return _gke(item, index)
    from .facts import memoized as _batch_memoized
    _base_inventory = _inventory

    def _inventory(index, kind, prefix='projects/'):
        return _batch_memoized(index, ('batch_sw54_inventory', kind, prefix, index.get('context', {}).get('scope')), lambda: _base_inventory(index, kind, prefix))
_load_54()

# Source family: compliance_new_sw55.py
def _load_55():
    _ALLOWED = {'gcp.bigquery.table_classification_tags', 'gcp.network.vpc_service_controls_supported_services', 'gcp.resourcemanager.folder_environment_structure'}
    'Signed GCP compliance predicates over complete, scope-bound snapshot facts.'
    from dataclasses import replace
    from collections import Counter
    from datetime import datetime, timezone
    import json
    import re
    from . import CHECKS, register, result, unknown
    from .facts import Unavailable, complete_items, get, guard
    SPECS = {'gcp.bigquery.table_classification_tags': ('bigquery_table', 'hardening', 'medium', 'BigQuery table columns carry approved classification tags', 'd57612c4e2fa6b368382a6651f0730b0be95137145cd8b38aba7144ffe08fe9e'), 'gcp.network.vpc_service_controls_supported_services': ('service_perimeter', 'network', 'high', 'VPC Service Controls cover every approved supported service', '5cbcb911696eb2a0dbf6138bb75079f7fe2f65ddaf0c9bee3636a21675755095'), 'gcp.resourcemanager.folder_environment_structure': ('folder', 'hardening', 'medium', 'Folders separate projects by environment and sensitivity', '6a1ac2b8164694d49ad02c19f4734881ee13849baf3e8ad0b33ed9d680086061'), 'gcp_c5_access_approval': ('access_approval_settings', 'identity', 'medium', 'Customer consent before provider access', '941fa5534735309073b50a08f0001b8728c0a54cd1e896c866affb70d0bb13a5'), 'gcp_logging_scc_findings_alert': ('organization', 'monitoring', 'high', 'High severity SCC findings lack an alert route', 'c7b21dcae287922260517dfbff0a3a241eb2d188761dfbfe4481a5e79b057f11')}
    SPECS = {k: v for k, v in SPECS.items() if k in _ALLOWED}

    def _signed(check_id, *dependencies):
        kind, category, severity, title, _ = SPECS[check_id]

        def decorate(function):
            register(check_id, 'gcp', category if category in {'hardening', 'network'} else 'hardening', kind, title, severity, 'CM-6', 'Review the approved policy and correct the recorded GCP configuration.', dependencies=list(dependencies))(function)
            if category not in {'hardening', 'network'}:
                pass
            return function
        return decorate

    def _scope(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        scope = get(context, 'scope', str)
        if not re.fullmatch('(?:projects|folders|organizations)/[A-Za-z0-9][A-Za-z0-9._:-]*', scope):
            raise Unavailable('invalid GCP scope')
        return scope

    def _inventory(index, kind, scope):
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable(kind + ' inventory unavailable')
        env = envelopes[0]
        if get(env, 'type', str) != kind or get(env, 'scope', str) != scope or get(env, 'status', str) not in ('collected', 'empty'):
            raise Unavailable(kind + ' inventory incomplete or foreign scope')
        if env.get('coverage_status', 'collected') not in ('collected', 'empty'):
            raise Unavailable(kind + ' coverage incomplete')
        rows = complete_items(index, kind)
        items = get(env, 'items', list)
        if len(items) != len(rows) or (env['status'] == 'empty') != (len(rows) == 0):
            raise Unavailable(kind + ' inventory count mismatch')
        wrappers = get(index, kind, list)
        if len(wrappers) != len(rows):
            raise Unavailable(kind + ' wrapper count mismatch')
        for wrapper in wrappers:
            if get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str) != scope or wrapper.get('provider', 'gcp') != 'gcp' or (get(wrapper, 'data', dict) not in items):
                raise Unavailable(kind + ' wrapper foreign or inconsistent')
        encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        if Counter(map(encode, items)) != Counter(map(encode, rows)):
            raise Unavailable(kind + ' envelope and resource rows disagree')
        for row in rows:
            guard(row)
            provenance = row.get('_provenance')
            if isinstance(provenance, dict) and 'scope' in provenance and (provenance['scope'] != scope):
                raise Unavailable(kind + ' native provenance foreign scope')
        return rows

    def _anchor(item, rows):
        if sum((row == item for row in rows)) != 1:
            raise Unavailable('anchor absent or duplicate')

    def _policy(index, scope):
        policy = get(get(get(index, 'context', dict), 'metadata', dict), 'sw55_policy', dict)
        if get(policy, 'scope', str) != scope or get(policy, 'status', str) != 'collected':
            raise Unavailable('approved policy absent or foreign scope')
        return policy

    def _strings(value, *, nonempty=False):
        if not isinstance(value, list) or (nonempty and (not value)) or any((not isinstance(x, str) or not x for x in value)) or (len(set(value)) != len(value)):
            raise Unavailable('invalid approved string list')
        return set(value)

    def _time(value):
        if not isinstance(value, str) or not value:
            raise Unavailable('invalid timestamp')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('invalid timestamp') from exc
        if parsed.tzinfo is None:
            raise Unavailable('timestamp lacks timezone')
        return parsed.astimezone(timezone.utc)

    @_signed('gcp.bigquery.table_classification_tags', 'bigquery_table')
    def table_classification(item, index):
        scope = _scope(index)
        if not scope.startswith('projects/'):
            raise Unavailable('table requires project scope')
        rows = _inventory(index, 'bigquery_table', scope)
        _anchor(item, rows)
        policy = _policy(index, scope)
        required = get(policy, 'required_classification', dict)
        table_ref = get(item, 'tableReference', dict)
        table_key = '.'.join((get(table_ref, 'projectId', str), get(table_ref, 'datasetId', str), get(table_ref, 'tableId', str)))
        if table_ref['projectId'] != scope.split('/', 1)[1] or not all(table_ref.values()):
            raise Unavailable('foreign table reference')
        if not required:
            raise Unavailable('classification inventory empty')
        for table, columns in required.items():
            if not isinstance(table, str) or not isinstance(columns, dict) or (not columns):
                raise Unavailable('malformed classification inventory')
            for path, tags in columns.items():
                if not isinstance(path, str) or not path or any((not part for part in path.split('.'))):
                    raise Unavailable('malformed column path')
                _strings(tags, nonempty=True)
        if table_key not in required:
            return unknown('table absent from required classification inventory; unlisted columns are unproven', table=table_key)
        if get(item, '_provenance', dict).get('schema_full') is not True:
            raise Unavailable('complete tables.get schema unavailable')
        fields = get(get(item, 'schema', dict), 'fields', list)
        observed = {}

        def walk(nodes, prefix=''):
            for field in nodes:
                name = get(field, 'name', str)
                if not name or '.' in name or prefix + name in observed:
                    raise Unavailable('malformed or duplicate schema field')
                path = prefix + name
                tags = field.get('policyTags')
                if tags is None:
                    if 'policyTags' in field.get('_coverage', {}):
                        get(field, 'policyTags', dict)
                    names = []
                else:
                    names = get(get(field, 'policyTags', dict), 'names', list)
                observed[path] = _strings(names)
                if 'fields' in field:
                    walk(get(field, 'fields', list), path + '.')
        walk(fields)
        missing = [path for path in required[table_key] if path not in observed]
        if missing:
            return unknown('required column absent from complete table schema', columns=sorted(missing))
        bad = sorted((path for path, approved in required[table_key].items() if not observed[path].intersection(approved)))
        return result(bool(bad), table=table_key, unclassified_columns=bad, checked_columns=sorted(required[table_key]))

    @_signed('gcp.resourcemanager.folder_environment_structure', 'folder', 'project')
    def folder_structure(item, index):
        scope = _scope(index)
        folders = _inventory(index, 'folder', scope)
        _anchor(item, folders)
        projects = _inventory(index, 'project', scope)
        policy = _policy(index, scope)
        environments = _strings(get(policy, 'environment_labels', list), nonempty=True)
        sensitivities = _strings(get(policy, 'sensitivity_labels', list), nonempty=True)
        by_name = {}
        for folder in folders:
            name = get(folder, 'name', str)
            if not re.fullmatch('folders/[0-9]+', name) or name in by_name:
                raise Unavailable('invalid or duplicate folder')
            get(folder, 'displayName', str)
            get(folder, 'parent', str)
            by_name[name] = folder
        if not projects:
            return ('NOT_APPLICABLE', {'reason': 'complete scope has no projects'})
        bad = []
        seen_projects = set()
        for project in projects:
            name = get(project, 'name', str)
            if not name.startswith('projects/') or name in seen_projects:
                raise Unavailable('invalid or duplicate project')
            seen_projects.add(name)
            parent = get(project, 'parent', str)
            labels, visited = (set(), set())
            while parent.startswith('folders/'):
                if parent in visited or parent not in by_name:
                    raise Unavailable('folder parent chain incomplete or cyclic')
                visited.add(parent)
                folder = by_name[parent]
                labels.add(get(folder, 'displayName', str))
                parent = get(folder, 'parent', str)
            if parent != scope and (not (scope.startswith('folders/') and scope in visited and re.fullmatch('organizations/[0-9]+', parent))):
                raise Unavailable('project parent chain outside audited scope')
            if not labels.intersection(environments) or not labels.intersection(sensitivities):
                bad.append(name)
        return result(bool(bad), projects_missing_labels=sorted(bad), checked_projects=sorted(seen_projects))

    @_signed('gcp.network.vpc_service_controls_supported_services', 'service_perimeter', 'service_usage')
    def vpc_supported_services(item, index):
        scope = _scope(index)
        if not scope.startswith('projects/'):
            raise Unavailable('perimeter requires project scope')
        perimeters = _inventory(index, 'service_perimeter', scope)
        _anchor(item, perimeters)
        services = _inventory(index, 'service_usage', scope)
        policy = _policy(index, scope)
        protected = _strings(get(policy, 'protected_project_numbers', list), nonempty=True)
        supported = _strings(get(policy, 'supported_services', list), nonempty=True)
        if any((not re.fullmatch('[0-9]+', number) for number in protected)):
            raise Unavailable('invalid protected project number')
        if get(policy, 'project_number', str) not in protected:
            raise Unavailable('current project not in protected inventory')
        if get(policy, 'project_id', str) != scope.split('/', 1)[1]:
            raise Unavailable('policy project identity mismatch')
        enabled = set()
        names = set()
        for service in services:
            name = get(service, 'name', str)
            if not name.startswith(scope + '/services/') or name in names:
                raise Unavailable('invalid or duplicate service')
            names.add(name)
            state = get(service, 'state', str)
            if state not in {'ENABLED', 'DISABLED'}:
                raise Unavailable('unrecognized service state')
            if state == 'ENABLED':
                enabled.add(name.split('/services/', 1)[1])
        covered, restricted, perimeter_names = (set(), set(), set())
        for perimeter in perimeters:
            perimeter_name = get(perimeter, 'name', str)
            if not re.fullmatch('accessPolicies/[0-9]+/servicePerimeters/[A-Za-z0-9_-]+', perimeter_name) or perimeter_name in perimeter_names:
                raise Unavailable('invalid or duplicate service perimeter')
            perimeter_names.add(perimeter_name)
            if get(perimeter, '_representation', str) != 'full':
                raise Unavailable('partial perimeter representation')
            status = get(perimeter, 'status', dict)
            resources = _strings(get(status, 'resources', list))
            restricted_services = _strings(get(status, 'restrictedServices', list))
            if any((not re.fullmatch('projects/[0-9]+', r) for r in resources)):
                raise Unavailable('malformed perimeter resources')
            included = {r.split('/', 1)[1] for r in resources} & protected
            covered.update(included)
            if get(policy, 'project_number', str) in included:
                restricted.update(restricted_services)
        missing_projects = sorted(protected - covered)
        missing_services = sorted((enabled & supported) - restricted)
        return result(bool(missing_projects or missing_services), missing_project_numbers=missing_projects, missing_enabled_supported_services=missing_services)
    _FILTER_TERM = re.compile('(?:finding\\.)?(state|severity)\\s*=\\s*"(ACTIVE|INACTIVE|HIGH|CRITICAL|MEDIUM|LOW|UNSPECIFIED)"')

    def _matches_filter(expression, finding):
        if not isinstance(expression, str) or not expression:
            return None
        parts = re.split('\\s+OR\\s+', expression)
        values = []
        for part in parts:
            terms = re.split('\\s+AND\\s+', part)
            parsed = [_FILTER_TERM.fullmatch(term.strip()) for term in terms]
            if any((term is None for term in parsed)):
                return None
            values.append(all((finding[term.group(1)] == term.group(2) for term in parsed)))
        return any(values)
    from .facts import memoized as _batch_memoized
    _base_inventory = _inventory

    def _inventory(index, kind, scope):
        return _batch_memoized(index, ('batch_sw55_inventory', kind, scope), lambda: _base_inventory(index, kind, scope))
_load_55()

# Source family: compliance_new_gcp_gke.py
def _load_ke():
    _ALLOWED = {'gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d'}
    'Signed GKE public-IP endpoint predicate over the cached cluster inventory.'
    from . import register, result, unknown
    from .facts import complete_items, get

    @register('gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d', 'gcp', 'exposure', 'gke_cluster', 'GKE clusters explicitly disable the public IP control-plane endpoint', 'high', 'SC-7', 'Review control-plane access, then disable the public IP endpoint after an alternative access path is ready.', target='scope', dependencies=['gke_cluster'])
    def gke_public_ip_endpoint_disabled(item, index):
        clusters = complete_items(index, 'gke_cluster')
        if not clusters:
            return ('NOT_APPLICABLE', {'reason': 'no GKE clusters in the complete scoped inventory'})
        public = []
        for cluster in clusters:
            name = get(cluster, 'name', str)
            enabled = get(cluster, 'controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint', bool)
            if enabled:
                public.append(name)
        return result(bool(public), cluster_count=len(clusters), public_ip_endpoint_clusters=public, field='controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint', semantics='Public IP endpoint declaration only; DNS endpoint exposure is separate')
_load_ke()


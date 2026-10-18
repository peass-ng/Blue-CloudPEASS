"""Signed AWS compliance slice 41. Conservative snapshot-only evaluators."""
from __future__ import annotations

from dataclasses import replace
from ipaddress import ip_address, ip_network
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard

# Immutable reviewed metadata; hashes are generated from the ten-field entries.
SPECS = {
 'aws_kms_imported_key_origin_spec': ('kms_key','compliance','medium','Imported KMS key has approved origin and algorithm','7d4d2a16d014be54653869b7ce23706d01fb23dc9e27e064822fa5422a47eb57'),
 'aws_nitro_attestation_key_policy': ('kms_key','hardening','high','Nitro Enclave key release requires measured attestation','62259b0642a3e8726f5199cb88267b62a2278bc986566d0d4ac156dca2e2195a'),
 'aws_cis_lambda_config_recorded': ('lambda_function','hardening','medium','AWS Config records Lambda functions','c5b5aecad1b83976c117b1413ddb575ac5a7742373d09b2c489b15a94277a255'),
 'aws_cis_lambda_database_secrets_manager': ('lambda_function','hardening','high','Lambda database credentials use Secrets Manager','fc6f02fcd9b081246d6f6b3180cf8889db160840c0e46449d3cb9e57748f5b6e'),
 'aws_cis_lambda_execution_role_no_admin': ('lambda_function','least_privilege','high','Lambda execution roles lack administrator access','4640499243c3cfd82d10b336e749c355397b918de5983c0a8637fb961bf41ae0'),
 'aws_cis_lambda_resource_policy_trusted_accounts': ('lambda_function','exposure','high','Lambda policies allow only trusted accounts','19617c1e58779a02b7de11e3aa13f00e104ebacf02f0a9698c02dc29fde5f102'),
 'aws_nist_lambda_function_use_latest_runtime': ('lambda_function','compliance','medium','Lambda functions should use latest runtimes','4c6961a1de945dd0ceadd11414316ca61f19f7716917755d5ee40af2c07a96c5'),
 'aws.pci.vpc.approved_egress': ('security_group','network','high','CDE security group egress is limited to approved flows','73c7bacb1c697235700ef802664ac6d93d5b6ddf272e219f9b75e5c1f80d3c9a'),
 'aws.pci.vpc.world_ingress_authorized_ports': ('security_group','network','medium','World ingress uses only approved ports','1d58e1f8e053f924f7e22bf8298cf09304d3187189f2ebba18977bf94a768cb0'),
 'aws.nist.emr_master_nodes_no_public_ip': ('emr_cluster','hardening','medium','EMR master instances have no public IP addresses','14a953853c35910e692cb583303750de4a2153dbf5db8d503a389751edf1a1a6'),
 'aws_fedramp_emr_master_no_public_ip': ('emr_cluster','compliance','medium','EMR primary nodes have no public IP','9a13536e2b9f17e52f77b3c530481bfb17540b29b2a34bdde6f3fa4b9afd77c0'),
 'aws_g6_emr_master_nodes_no_public_address': ('emr_cluster','exposure','high','EMR master nodes have no public address','e6ce0723548a7e429e9beaa325fb9a9f1d9f9b78a047b281f36a3ffec404fd30'),
 'aws_nist_emr_cluster_master_nodes_no_public_ip': ('emr_cluster','compliance','medium','EMR cluster master nodes should not have public IP addresses','86276ac24103e6aa5147099c5da821b7760a214ea8640647c87c72ae7e9a0228'),
 'aws_cis_route53_dns_firewall': ('vpc','hardening','medium','VPC DNS Firewall protection is associated','c7ec21b891e9804763d14f39789a6abcbb1da2d308b197cd906dd691ca30e05d'),
 'aws_nist_vpc_configured_to_use_vpc_endpoints': ('vpc','compliance','medium','VPC should be configured to use VPC endpoints','84e252467db46bd9554335661863124b05e227091b9994f4feb3a291d0e672ce'),
}
PROPOSED_SPEC_SHA256 = {key: value[4] for key, value in SPECS.items()}


def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'[0-9]{12}/[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]', scope):
        raise Unavailable('regional AWS scope required')
    return scope


def _rows(index, kind, *, global_scope=False):
    scope = _scope(index)
    if global_scope:
        scope = scope.split('/')[0] + '/global'
    env = get(index, 'collections', dict).get(kind)
    if not isinstance(env, list) or len(env) != 1:
        raise Unavailable('missing or ambiguous inventory: ' + kind)
    e = env[0]
    if not isinstance(e, dict) or e.get('type') != kind or e.get('scope') != scope or e.get('status') not in ('collected','empty') or not isinstance(e.get('items'), list):
        raise Unavailable('incomplete or foreign inventory: ' + kind)
    if ('account_id' in e and get(e,'account_id',str)!=scope.split('/')[0]) or ('global' in e and get(e,'global',bool)!=global_scope):
        raise Unavailable('foreign inventory account or global marker: '+kind)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows) or rows != e['items'] or (e['status'] == 'empty' and rows):
        raise Unavailable('inventory projection mismatch: ' + kind)
    if any(not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or w.get('data') != row or ('provider' in w and w['provider']!='aws') for w,row in zip(wrappers,rows)):
        raise Unavailable('foreign inventory projection: ' + kind)
    return rows


def _own(item,index,kind):
    rows = _rows(index,kind)
    if sum(row == item for row in rows) != 1:
        raise Unavailable('resource absent or duplicated in scoped inventory')
    field = {'kms_key':'KeyId','lambda_function':'FunctionArn','security_group':'GroupId','emr_cluster':'Id','vpc':'VpcId'}[kind]
    ids = [get(row,field,str) for row in rows]
    if any(not x for x in ids) or len(ids) != len(set(ids)):
        raise Unavailable('missing or duplicate resource identity')
    account,region = _scope(index).split('/')
    for row in rows:
        if kind == 'security_group' and get(row,'OwnerId',str) != account:
            raise Unavailable('foreign security group')
        arn_field = {'kms_key':'KeyArn','lambda_function':'FunctionArn','emr_cluster':'ClusterArn'}.get(kind)
        if arn_field and arn_field in row:
            arn = get(row,arn_field,str)
            service = {'kms_key':'kms','lambda_function':'lambda','emr_cluster':'elasticmapreduce'}[kind]
            if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:'+service+':'+region+':'+account+r':.+',arn):
                raise Unavailable('foreign resource ARN')
    return rows


def _param(index,name,expected):
    params = get(index,'context.metadata.parameters',dict)
    return get(params,name,expected)


def _objects(value):
    if not isinstance(value,list) or any(not isinstance(x,dict) for x in value):
        raise Unavailable('malformed object list')
    return value


def _strings(value):
    if not isinstance(value,list) or any(not isinstance(x,str) or not x for x in value) or len(value)!=len(set(value)):
        raise Unavailable('malformed string list')
    return value


def _document(value):
    if isinstance(value,str):
        try: value=json.loads(value)
        except ValueError as exc: raise Unavailable('malformed policy JSON') from exc
    statements=_objects([value] if isinstance(value,dict) and 'Effect' in value else get(value,'Statement',list))
    return statements


def _actions(value):
    if isinstance(value,str): return [value]
    return _strings(value)


def _kms_origin(item,index):
    _own(item,index,'kms_key')
    metadata=get(item,'Metadata',dict)
    if get(metadata,'collection_status',str)!='collected': raise Unavailable('KMS DescribeKey incomplete')
    key=get(metadata,'KeyMetadata',dict)
    if get(key,'KeyId',str)!=get(item,'KeyId',str): raise Unavailable('KMS key identity mismatch')
    origin=get(key,'Origin',str)
    if origin!='EXTERNAL':
        if origin not in ('AWS_KMS','AWS_CLOUDHSM','EXTERNAL_KEY_STORE'): raise Unavailable('unknown KMS origin')
        return 'NOT_APPLICABLE',{'reason':'key material is not imported'}
    spec=get(key,'KeySpec',str); usage=get(key,'KeyUsage',str)
    return result(spec not in {'RSA_2048','RSA_3072','RSA_4096','ECC_NIST_P256'} or usage not in {'ENCRYPT_DECRYPT','SIGN_VERIFY'},key_id=get(item,'KeyId',str),key_spec=spec,key_usage=usage)


def _attestation(item,index):
    _own(item,index,'kms_key')
    # Applicability must be an explicit scoped key-to-enclave declaration.
    enclave_keys=_strings(_param(index,'nitro_enclave_key_arns',list))
    arn=get(item,'KeyArn',str)
    if arn not in enclave_keys: return 'NOT_APPLICABLE',{'reason':'key is outside declared enclave scope'}
    policy=get(item,'Policy',dict)
    if get(policy,'collection_status',str)!='collected': raise Unavailable('KMS GetKeyPolicy incomplete')
    statements=_document(get(policy,'Policy'))
    relevant=0
    missing=[]
    for stmt in statements:
        if get(stmt,'Effect',str)!='Allow': continue
        if 'NotAction' in stmt:
            raise Unavailable('key-release NotAction requires effective policy analysis')
        acts=_actions(get(stmt,'Action'))
        if not any(a=='*' or a.lower()=='kms:*' or a.lower()=='kms:decrypt' or a.lower().startswith('kms:generatedatakey') for a in acts): continue
        relevant+=1
        # Conditions on source account or other keys do not constrain recipient measurements.
        conditions=get(stmt,'Condition',dict) if 'Condition' in stmt else {}
        measured=False
        ambiguous=False
        for operator,values in conditions.items():
            if not isinstance(operator,str) or not isinstance(values,dict): raise Unavailable('malformed KMS condition')
            for key,value in values.items():
                if key!='kms:RecipientAttestation:ImageSha384' and not key.startswith('kms:RecipientAttestation:PCR'):
                    continue
                vals=[value] if isinstance(value,str) else _strings(value)
                if not vals or any(not isinstance(v,str) or not v for v in vals):
                    raise Unavailable('empty attestation measurement')
                if operator in ('StringEquals','StringEqualsIgnoreCase','ForAnyValue:StringEquals') and all('*' not in v and '?' not in v for v in vals):
                    measured=True
                else:
                    ambiguous=True
        if ambiguous and not measured:
            raise Unavailable('attestation condition does not prove required measurement')
        if not measured: missing.append(stmt.get('Sid'))
    if not relevant: return unknown('no applicable key-release Allow statement proven',key_arn=arn)
    if missing: return result(True,key_arn=arn,unconditional_statements=missing)
    return result(False,key_arn=arn,checked_statements=relevant)


def _lambda(item,index):
    _own(item,index,'lambda_function')
    arn=get(item,'FunctionArn',str)
    if not get(item,'FunctionName',str): raise Unavailable('missing Lambda name')
    return arn


def _config(item,index):
    arn=_lambda(item,index)
    recorders=_rows(index,'config_recorder')
    if not recorders: return result(True,function_arn=arn,reason='no Config recorder')
    effective=[]
    for rec in recorders:
        name=get(rec,'name',str)
        status=get(rec,'Status',dict)
        if get(status,'collection_status',str)!='collected': raise Unavailable('Config recorder status unavailable')
        rows=_objects(get(status,'ConfigurationRecordersStatus',list))
        match=[x for x in rows if get(x,'name',str)==name]
        if len(match)!=1: raise Unavailable('Config recorder status identity mismatch')
        if not get(match[0],'recording',bool): continue
        group=get(rec,'recordingGroup',dict)
        strategy=get(group,'recordingStrategy.useOnly',str) if 'recordingStrategy' in group else None
        if strategy not in (None,'ALL_SUPPORTED_RESOURCE_TYPES','INCLUSION_BY_RESOURCE_TYPES','EXCLUSION_BY_RESOURCE_TYPES'):
            raise Unavailable('unknown Config recording strategy')
        if strategy=='EXCLUSION_BY_RESOURCE_TYPES':
            excluded=_strings(get(group,'resourceTypes',list))
            if 'AWS::Lambda::Function' not in excluded: effective.append(name)
        elif strategy=='ALL_SUPPORTED_RESOURCE_TYPES' or (strategy is None and get(group,'allSupported',bool)):
            effective.append(name)
        else:
            included=_strings(get(group,'resourceTypes',list))
            if 'AWS::Lambda::Function' in included: effective.append(name)
    return result(not effective,function_arn=arn,effective_recorders=effective)


def _runtime(item,index):
    arn=_lambda(item,index)
    package=get(item,'PackageType',str)
    if package!='Zip':
        if package=='Image': return unknown('image runtime is outside Zip runtime policy',function_arn=arn)
        raise Unavailable('unrecognized Lambda package type')
    runtime=get(item,'Runtime',str)
    if runtime.startswith('provided'): return unknown('custom runtime requires manual language resolution',function_arn=arn)
    language=re.match(r'^(python|nodejs|java|dotnet|ruby)(?:[0-9]|$)',runtime)
    if not language: return unknown('Lambda runtime language unavailable',function_arn=arn)
    approved=get(_param(index,'required_runtime_by_language',dict),language.group(1),list)
    approved=_strings(approved)
    if not approved or any(not x.startswith(language.group(1)) for x in approved): raise Unavailable('malformed latest-runtime policy')
    return result(runtime not in approved,function_arn=arn,runtime=runtime,approved=approved)


def _lambda_policy(item,index):
    arn=_lambda(item,index)
    trusted=set(_strings(_param(index,'trusted_account_ids',list)))
    if not trusted or any(not re.fullmatch(r'[0-9]{12}',a) for a in trusted): raise Unavailable('trusted account policy unavailable')
    policy=get(item,'Policy',dict)
    state=get(policy,'collection_status',str)
    if state=='empty' and get(policy,'absent',bool): return result(False,function_arn=arn,policy_statements=0)
    if state!='collected': raise Unavailable('Lambda GetPolicy incomplete')
    statements=_document(get(policy,'Policy'))
    untrusted=[]
    constrained=[]
    wildcard=False
    for stmt in statements:
        if get(stmt,'Effect',str)!='Allow': continue
        if 'NotAction' in stmt: raise Unavailable('Lambda NotAction requires effective policy analysis')
        actions=_actions(get(stmt,'Action'))
        if not any(action.lower() in ('*','lambda:*','lambda:invokefunction','lambda:invokefunctionurl') for action in actions):
            continue
        principal=get(stmt,'Principal')
        aws=principal if isinstance(principal,str) else get(principal,'AWS')
        principals=_actions(aws)
        condition=stmt.get('Condition',{})
        if not isinstance(condition,dict): raise Unavailable('malformed Lambda condition')
        for p in principals:
            account=p if re.fullmatch(r'[0-9]{12}',p) else None
            if not account:
                m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::([0-9]{12}):(?:root|.+)',p)
                account=m.group(1) if m else None
            if account is None:
                if p=='*':
                    wildcard=True
                    continue
                raise Unavailable('unrecognized Lambda AWS principal')
            if account in trusted: continue
            # A source-account or organization restriction can narrow the actual caller.
            has_constraint=bool(condition)
            if has_constraint: constrained.append(account)
            else: untrusted.append(account)
    if wildcard or constrained:
        return unknown('wildcard or conditioned principal requires effective condition analysis',function_arn=arn)
    if untrusted: return result(True,function_arn=arn,untrusted_accounts=sorted(set(untrusted)))
    return result(False,function_arn=arn,policy_statements=len(statements))


def _role(item,index):
    arn=_lambda(item,index)
    role_arn=get(item,'Role',str)
    account=_scope(index).split('/')[0]
    if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::'+account+r':role/.+',role_arn): raise Unavailable('foreign or malformed execution role')
    roles=_rows(index,'iam_role',global_scope=True)
    match=[r for r in roles if get(r,'Arn',str)==role_arn]
    if len(match)!=1: raise Unavailable('execution role not resolved uniquely')
    return arn,match[0]


def _admin(item,index):
    arn,role=_role(item,index)
    # This fact must be derived from complete identity policy documents, boundaries,
    # session/SCP constraints and explicit Deny, not merely attachment names.
    analysis=get(role,'EffectiveAdminAccess',dict)
    if get(analysis,'collection_status',str)!='collected' or get(analysis,'role_arn',str)!=get(role,'Arn',str) or get(analysis,'complete',bool) is not True:
        raise Unavailable('effective role policy analysis incomplete')
    admin=get(analysis,'unconditional_action_resource_star',bool)
    return result(admin,function_arn=arn,role_arn=get(role,'Arn',str))


def _secrets(item,index):
    arn,role=_role(item,index)
    names=_strings(_param(index,'approved_database_connection_environment_variable_names',list))
    if not names: raise Unavailable('database variable-name policy unavailable')
    projection=get(item,'DatabaseCredentialReferences',dict)
    if get(projection,'collection_status',str) not in ('collected','empty') or get(projection,'complete',bool) is not True:
        raise Unavailable('database environment reference classification unavailable')
    values=_objects(get(projection,'items',list))
    if len({get(v,'name',str) for v in values})!=len(values): raise Unavailable('duplicate database variable name')
    for value in values:
        kind=get(value,'value_kind',str)
        if kind=='secret_arn': get(value,'secret_arn',str)
        elif kind!='literal': raise Unavailable('unrecognized database variable classification')
    selected=[v for v in values if get(v,'name',str) in names]
    if not selected: return 'NOT_APPLICABLE',{'reason':'no approved database connection variable present','function_arn':arn}
    secrets=_rows(index,'secret')
    arns={get(s,'ARN',str) for s in secrets}
    policy=get(role,'SecretReadAuthorization',dict)
    if get(policy,'collection_status',str)!='collected' or get(policy,'complete',bool) is not True or get(policy,'role_arn',str)!=get(role,'Arn',str):
        raise Unavailable('role secret-read authorization unavailable')
    allowed=set(_strings(get(policy,'get_secret_value_arns',list)))
    resolved=[]
    for value in selected:
        kind=get(value,'value_kind',str)
        if kind=='secret_arn': resolved.append(get(value,'secret_arn',str))
        elif kind!='literal': raise Unavailable('unrecognized database variable classification')
    resolved=[value for value in resolved if value in arns]
    if not resolved: return result(True,function_arn=arn,reason='database variable does not reference inventoried secret ARN')
    return result(not any(v in allowed for v in resolved),function_arn=arn,resolved_secret_arns=sorted(resolved))


def _net(value,version):
    try: network=ip_network(value,strict=False)
    except (ValueError,TypeError) as exc: raise Unavailable('malformed CIDR') from exc
    if network.version!=version: raise Unavailable('CIDR address family mismatch')
    return network


def _permissions(item,index,direction):
    _own(item,index,'security_group')
    return _objects(get(item,'IpPermissions' + ('Egress' if direction=='egress' else ''),list))


def _ranges(rule):
    out=[]
    for field,key,version in [('IpRanges','CidrIp',4),('Ipv6Ranges','CidrIpv6',6)]:
        for entry in _objects(get(rule,field,list)):
            out.append(_net(get(entry,key,str),version))
    return out


def _ports(rule):
    proto=get(rule,'IpProtocol',str).lower()
    if proto in ('6','tcp'): proto='tcp'
    elif proto in ('17','udp'): proto='udp'
    elif proto!='-1': raise Unavailable('non TCP/UDP protocol requires separate policy')
    if proto=='-1': return proto,0,65535
    lo=get(rule,'FromPort',int); hi=get(rule,'ToPort',int)
    if not 0<=lo<=hi<=65535: raise Unavailable('malformed port range')
    return proto,lo,hi


def _world(item,index):
    rules=_permissions(item,index,'ingress')
    allowed=_objects(_param(index,'approved_ports',list))
    approvals=[]
    for a in allowed:
        p=get(a,'protocol',str).lower(); lo=get(a,'from_port',int); hi=get(a,'to_port',int)
        if p not in ('tcp','udp') or not 0<=lo<=hi<=65535: raise Unavailable('malformed approved port')
        approvals.append((p,lo,hi))
    violations=[]
    for n,rule in enumerate(rules):
        ranges=_ranges(rule); _objects(get(rule,'UserIdGroupPairs',list))
        proto,lo,hi=_ports(rule)
        if any(net.prefixlen==0 for net in ranges):
            if proto=='-1' or not any(p==proto and a<=lo and hi<=b for p,a,b in approvals):
                violations.append(n)
    return result(bool(violations),group_id=get(item,'GroupId',str),violating_rule_indexes=violations,world_rules_checked=len(rules))


def _egress(item,index):
    rules=_permissions(item,index,'egress')
    cde=set(_strings(_param(index,'cde_security_group_ids',list)))
    group=get(item,'GroupId',str)
    if group not in cde: return 'NOT_APPLICABLE',{'reason':'security group outside declared CDE','group_id':group}
    approved=_objects(_param(index,'approved_cde_egress',list))
    flows=[]
    for a in approved:
        p=get(a,'protocol',str).lower(); lo=get(a,'from_port',int); hi=get(a,'to_port',int)
        if p not in ('tcp','udp') or not 0<=lo<=hi<=65535: raise Unavailable('malformed approved egress flow')
        flows.append((p,lo,hi,_net(get(a,'cidr',str),ip_network(get(a,'cidr',str),strict=False).version)))
    violations=[]
    for n,rule in enumerate(rules):
        proto,lo,hi=_ports(rule)
        ranges=_ranges(rule)
        pairs=_objects(get(rule,'UserIdGroupPairs',list))
        if not ranges and not pairs: raise Unavailable('egress destination unavailable')
        if pairs:
            for pair in pairs: get(pair,'GroupId',str)
            violations.append(n)
            continue
        if proto=='-1' and any(net.prefixlen==0 for net in ranges):
            violations.append(n)
            continue
        if any(not any(p==proto and a<=lo and hi<=b and net.subnet_of(allowed) for p,a,b,allowed in flows if net.version==allowed.version) for net in ranges):
            violations.append(n)
    return result(bool(violations),group_id=group,violating_rule_indexes=violations,egress_rules_checked=len(rules))


def _emr(item,index,primary=False):
    _own(item,index,'emr_cluster')
    state=get(item,'Status.State',str)
    if state not in ('RUNNING','WAITING'):
        if state in ('STARTING','BOOTSTRAPPING','TERMINATING','TERMINATED','TERMINATED_WITH_ERRORS'):
            return 'NOT_APPLICABLE',{'reason':'cluster not running or waiting'}
        raise Unavailable('unrecognized EMR state')
    masters=get(item,'MasterInstances',dict)
    if get(masters,'collection_status',str) not in ('collected','empty') or get(masters,'complete',bool) is not True:
        raise Unavailable('EMR master inventory incomplete')
    master_rows=_objects(get(masters,'items',list))
    if not master_rows: raise Unavailable('no current EMR master resolved')
    ids=[get(x,'Ec2InstanceId',str) for x in master_rows]
    if len(ids)!=len(set(ids)) or any(not x for x in ids): raise Unavailable('duplicate or missing master instance ID')
    if primary:
        primary_id=get(masters,'PrimaryEc2InstanceId',str)
        if primary_id not in ids: raise Unavailable('primary EMR instance not resolved')
        ids=[primary_id]
    instances=_rows(index,'instance')
    byid={get(x,'InstanceId',str):x for x in instances}
    if len(byid)!=len(instances): raise Unavailable('duplicate EC2 instance ID')
    public_hits=[]
    for mid in ids:
        inst=byid.get(mid)
        if inst is None: raise Unavailable('master EC2 instance absent')
        if get(inst,'State.Name',str) not in ('running','pending','stopping','stopped'):
            raise Unavailable('master instance state unresolved')
        enis=_objects(get(inst,'NetworkInterfaces',list))
        if not enis: raise Unavailable('master ENI inventory empty')
        top=inst.get('PublicIpAddress')
        if top is not None:
            if not isinstance(top,str) or not top: raise Unavailable('malformed public IPv4')
            ip=ip_address(top)
            if ip.version!=4: raise Unavailable('malformed public IPv4')
            public_hits.append((mid,top))
        for eni in enis:
            assoc=eni.get('Association',{})
            if not isinstance(assoc,dict): raise Unavailable('malformed ENI association')
            public=assoc.get('PublicIp')
            if public is not None:
                if not isinstance(public,str): raise Unavailable('malformed public IPv4')
                ip=ip_address(public)
                if ip.version!=4: raise Unavailable('malformed public IPv4')
                public_hits.append((mid,public))
            for address in _objects(get(eni,'Ipv6Addresses',list)):
                ip=ip_address(get(address,'Ipv6Address',str))
                if ip.version!=6: raise Unavailable('malformed IPv6 address')
                if ip.is_global: public_hits.append((mid,str(ip)))
    return result(bool(public_hits),cluster_id=get(item,'Id',str),public_addresses=public_hits,master_instances_checked=len(ids))


def _dns(item,index):
    _own(item,index,'vpc')
    approved=set(_strings(_param(index,'approved_firewall_domain_list_ids',list)))
    if not approved: raise Unavailable('approved DNS Firewall domain-list IDs unavailable')
    vpc=get(item,'VpcId',str)
    associations=_rows(index,'resolver_firewall_rule_group_association')
    groups=set()
    for association in associations:
        associated_vpc=get(association,'VpcId',str)
        group=get(association,'FirewallRuleGroupId',str)
        status=get(association,'Status',str)
        if status not in ('COMPLETE','CREATING','UPDATING','DELETING','FAILED'):
            raise Unavailable('unknown DNS Firewall association status')
        if associated_vpc==vpc and status=='COMPLETE': groups.add(group)
    rules=_rows(index,'resolver_firewall_rule')
    matching=[]
    for rule in rules:
        group=get(rule,'FirewallRuleGroupId',str)
        action=get(rule,'Action',str)
        domain=get(rule,'FirewallDomainListId',str)
        if action not in ('ALLOW','ALERT','BLOCK'): raise Unavailable('unknown DNS Firewall action')
        if group in groups and action=='BLOCK' and domain in approved: matching.append(group)
    return result(not matching,vpc_id=vpc,approved_block_rule_groups=sorted(set(matching)))


def _endpoint(item,index):
    _own(item,index,'vpc')
    service=_param(index,'required_service_name',str)
    if not service: raise Unavailable('required endpoint service unavailable')
    endpoints=_rows(index,'vpc_endpoint')
    vpc=get(item,'VpcId',str)
    matching=[]
    for ep in endpoints:
        eid=get(ep,'VpcEndpointId',str)
        evpc=get(ep,'VpcId',str)
        eservice=get(ep,'ServiceName',str)
        state=get(ep,'State',str)
        if state not in ('pendingAcceptance','pending','available','deleting','deleted','rejected','failed','expired'):
            raise Unavailable('unknown VPC endpoint state')
        if evpc==vpc and eservice==service and state=='available': matching.append(eid)
    return result(not matching,vpc_id=vpc,service_name=service,available_endpoint_ids=matching)

EVALUATORS = {
 'aws_kms_imported_key_origin_spec':_kms_origin,'aws_nitro_attestation_key_policy':_attestation,
 'aws_cis_lambda_config_recorded':_config,'aws_cis_lambda_database_secrets_manager':_secrets,
 'aws_cis_lambda_execution_role_no_admin':_admin,'aws_cis_lambda_resource_policy_trusted_accounts':_lambda_policy,
 'aws_nist_lambda_function_use_latest_runtime':_runtime,'aws.pci.vpc.approved_egress':_egress,
 'aws.pci.vpc.world_ingress_authorized_ports':_world,
 'aws.nist.emr_master_nodes_no_public_ip':lambda item,index:_emr(item,index),
 'aws_fedramp_emr_master_no_public_ip':lambda item,index:_emr(item,index,True),
 'aws_g6_emr_master_nodes_no_public_address':lambda item,index:_emr(item,index),
 'aws_nist_emr_cluster_master_nodes_no_public_ip':lambda item,index:_emr(item,index),
 'aws_cis_route53_dns_firewall':_dns,'aws_nist_vpc_configured_to_use_vpc_endpoints':_endpoint,
}
DEPENDENCIES = {
 'aws_cis_lambda_config_recorded':['lambda_function','config_recorder'],
 'aws_cis_lambda_database_secrets_manager':['lambda_function','iam_role','secret'],
 'aws_cis_lambda_execution_role_no_admin':['lambda_function','iam_role'],
 'aws.pci.vpc.approved_egress':['security_group'],
 'aws.pci.vpc.world_ingress_authorized_ports':['security_group'],
 'aws.nist.emr_master_nodes_no_public_ip':['emr_cluster','instance'],
 'aws_fedramp_emr_master_no_public_ip':['emr_cluster','instance'],
 'aws_g6_emr_master_nodes_no_public_address':['emr_cluster','instance'],
 'aws_nist_emr_cluster_master_nodes_no_public_ip':['emr_cluster','instance'],
 'aws_cis_route53_dns_firewall':['vpc','resolver_firewall_rule_group_association','resolver_firewall_rule'],
 'aws_nist_vpc_configured_to_use_vpc_endpoints':['vpc','vpc_endpoint'],
}
for _id,(_kind,_category,_severity,_title,_sha) in SPECS.items():
    # The legacy decorator accepts only defensive categories. Preserve the
    # signed 'compliance' category in the immutable registered Check record.
    @register(_id,'aws',_category if _category!='compliance' else 'hardening',_kind,_title,_severity,'CM-6','Review the named configuration and apply the approved policy.',dependencies=DEPENDENCIES.get(_id,[_kind]))
    def _evaluate(item,index,check_id=_id):
        return EVALUATORS[check_id](item,index)
    _evaluate.__name__='check_'+_id.replace('.','_')
    if _category=='compliance': CHECKS[-1]=replace(CHECKS[-1],category='compliance')

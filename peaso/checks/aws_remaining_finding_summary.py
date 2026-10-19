"""Brief observations from 250 reviewed AWS predicates; raw evidence is untouched."""
from .aws_remaining_clarity_reviewed import ROWS


def _integer(value):
    return type(value) is int


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'aws' or finding.get('status') != 'FAIL':
        return None
    cid=finding.get('check_id');row=ROWS.get(cid);evidence=finding.get('evidence')
    if row is None or not isinstance(evidence, dict):
        return None
    if cid=='aws.ec2.restrict_internet_ingress':
        entries=evidence.get('internet_ingress')
        if isinstance(entries,list) and entries:
            rules=[]
            for entry in entries[:3]:
                if not isinstance(entry,dict):continue
                protocol=entry.get('protocol');start=entry.get('from_port');end=entry.get('to_port')
                if protocol in {'tcp','6','udp','17'} and _integer(start) and _integer(end) and 0<=start<=end<=65535:
                    port=str(start) if start==end else f'{start}–{end}'
                    rules.append(('tcp' if protocol in {'tcp','6'} else 'udp')+'/'+port)
                elif protocol=='-1':rules.append('all protocols')
            if rules:
                suffix=' Additional broad ingress rules are recorded.' if len(entries)>3 else ''
                return 'The security group allows Internet ingress to '+', '.join(dict.fromkeys(rules))+'.'+suffix
    numeric={
        'aws.b.acm.expiry_thirty_days':('remaining_calendar_days','The certificate expires in {value} calendar days.'),
        'aws.b.acm.rsa_minimum_2048':('rsa_bits','The certificate declares a {value}-bit RSA key.'),
        'aws.iam.password_minimum_length':('configured','The account password policy requires only {value} characters.'),
        'aws.iam.password_reuse_prevention':('configured','The account policy prevents reuse of {value} prior passwords; this profile requires 24.'),
        'aws.cb.kinesis.retention_at_least_168h':('retention_hours','Kinesis retention is {value} hours; this profile requires at least 168.'),
        'aws.cb.kinesis.retention_exactly_168h':('retention_hours','Kinesis retention is {value} hours; this profile prefers exactly 168.'),
        'aws.c2b.appstream.max_user_duration_under_10h':('max_user_duration_seconds','AppStream maximum session duration is {value} seconds; this profile requires under 36,000.'),
        'aws.c2b.appstream.disconnect_timeout_5m':('disconnect_timeout_seconds','AppStream disconnect timeout is {value} seconds; this profile allows at most 300.'),
        'aws.c2b.appstream.idle_disconnect_10m':('idle_disconnect_timeout_seconds','AppStream idle timeout is {value} seconds; this profile requires 1–600.'),
        'aws.c2b.documentdb.backup_retention_7':('backup_retention_period','DocumentDB backup retention is {value} days; this profile requires at least seven.'),
        'aws.c2b.elasticache.rg_backup_retention_7':('snapshot_retention_limit','ElastiCache snapshot retention is {value} days; this profile requires at least seven.'),
        'aws.c2b.elasticache.rg_backup_retention_15':('snapshot_retention_limit','ElastiCache snapshot retention is {value} days; this profile requires at least 15.'),
        'aws.c2b.backup.recovery_point_retention_35':('delete_after_days','The recovery point declares deletion after {value} days; this profile requires at least 35.'),
        'aws.b.cognito.password_minimum_fourteen':('minimum_length','The user-pool policy permits {value}-character passwords; this profile requires at least 14.'),
        'aws.b.cognito.temporary_password_seven_days':('declared_validity_days','Temporary passwords are valid for {value} days; this profile allows at most seven.'),
    }
    if cid in numeric:
        key,text=numeric[cid];value=evidence.get(key)
        invalid = {
            'aws.b.acm.expiry_thirty_days': lambda v:v<30,
            'aws.b.acm.rsa_minimum_2048': lambda v:0<v<2048,
            'aws.iam.password_minimum_length': lambda v:0<=v<14,
            'aws.iam.password_reuse_prevention': lambda v:v>=0 and v!=24,
            'aws.cb.kinesis.retention_at_least_168h':lambda v:0<=v<168,
            'aws.cb.kinesis.retention_exactly_168h':lambda v:v>=0 and v!=168,
            'aws.c2b.appstream.max_user_duration_under_10h':lambda v:v>=36000,
            'aws.c2b.appstream.disconnect_timeout_5m':lambda v:v>300,
            'aws.c2b.appstream.idle_disconnect_10m':lambda v:v==0 or v>600,
            'aws.c2b.documentdb.backup_retention_7':lambda v:0<=v<7,
            'aws.c2b.elasticache.rg_backup_retention_7':lambda v:0<=v<7,
            'aws.c2b.elasticache.rg_backup_retention_15':lambda v:0<=v<15,
            'aws.c2b.backup.recovery_point_retention_35':lambda v:0<=v<35,
            'aws.b.cognito.password_minimum_fourteen':lambda v:0<=v<14,
            'aws.b.cognito.temporary_password_seven_days':lambda v:v>7,
        }
        if _integer(value) and invalid[cid](value):
            if cid=='aws.b.acm.expiry_thirty_days' and value<0:
                return f'The certificate expired {-value} calendar days before the snapshot date.'
            return text.format(value=value)
    if cid=='aws.b.redshift.kms_key_declared':
        if evidence.get('encrypted') is False:return 'The Redshift cluster declares storage encryption disabled.'
        if evidence.get('encrypted') is True and evidence.get('kms_key_id') is None:
            return 'The encrypted Redshift cluster has no KMS key reference in the complete native inventory.'
    if cid=='aws.c2b.backup.plan_rules_retention_35':
        short=evidence.get('short_retention_rules')
        if isinstance(short,list) and short:
            days=[x['delete_after_days'] for x in short if isinstance(x,dict) and _integer(x.get('delete_after_days')) and 0<=x['delete_after_days']<35]
            if days:return f'{len(days)} backup-plan rules declare retention below 35 days (shortest: {min(days)} days).'
    if cid=='aws.c2b.drs.region_has_job':
        counts=evidence.get('replication_states')
        if isinstance(counts,dict):
            parts=[f'{counts[state]} {state.lower()}' for state in ['STOPPED','STALLED','DISCONNECTED'] if _integer(counts.get(state)) and counts[state]>0]
            if parts:return 'DRS source replication reports '+', '.join(parts)+'.'
    if cid=='aws.cb.workspaces.private_subnet_with_nat_vpc' and evidence.get('workspace_subnet_public') is True:
        return 'The WorkSpace subnet has a default Internet-gateway route; this profile requires a private subnet.'
    if cid=='aws.cb.sqs.cmk_encryption':
        if evidence.get('kms_master_key_id')=='alias/aws/sqs':return 'The queue declares the AWS-managed SQS KMS alias; this profile prefers a customer-managed key.'
    return None

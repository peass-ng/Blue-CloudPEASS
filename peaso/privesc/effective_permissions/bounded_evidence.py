"""Stricter attestation boundary for newly modeled terminal resource effects."""
import json
import re
from pathlib import Path
CONTRACT=json.loads(Path(__file__).resolve().parents[1].joinpath('bounded_effects.json').read_text())


def valid(technique, fact, source, resource, scope):
    spec=CONTRACT.get(technique)
    if spec is None:return True
    if not isinstance(fact,dict) or fact.get('TechniqueId')!=technique or fact.get('EffectType')!='bounded_resource_operation':return False
    if fact.get('Status')!='verified' or fact.get('VerifiedPreconditions')is not True:return False
    if not isinstance(fact.get('EvidenceRef'),str) or not fact['EvidenceRef'].strip():return False
    conditions=fact.get('VerifiedConditionIds')
    if not isinstance(conditions,list) or any(not isinstance(c,str)for c in conditions) or sorted(conditions)!=spec['conditions']:return False
    if not isinstance(resource,str) or '*'in resource or '?'in resource:return False
    provider=spec['provider']
    if fact.get('TargetKind')!=provider+'_verified_authority' or fact.get('TargetId')!=resource:return False
    if provider=='aws':
        account=str(scope).split('/')[0]
        return (fact.get('SourceArn')==source and fact.get('TargetAccount')==account
                and bool(re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:'+re.escape(account)+r':.+',resource)))
    if fact.get('SourceId')!=source or fact.get('TargetScope')!=scope:return False
    if provider=='azure':return resource.casefold().startswith(str(scope).casefold().rstrip('/')+'/') and '/providers/'in resource.casefold()
    return resource.startswith(str(scope).rstrip('/')+'/')

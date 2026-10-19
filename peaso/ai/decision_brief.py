"""Build a complete decision catalog, rather than a shortlist of raw previews."""
import hashlib
import json
from collections import Counter, defaultdict

SECTIONS = ('findings', 'least_privilege', 'privesc', 'iam', 'network')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest()


def catalog(db):
    from .briefing import encode, RISK
    db.executescript('''
        CREATE TABLE case_members(case_domain TEXT,case_id TEXT,domain TEXT,id TEXT,
                                 PRIMARY KEY(case_domain,case_id,domain,id));
        CREATE INDEX case_member_source ON case_members(domain,id);
        CREATE TABLE case_anchors(case_domain TEXT,case_id TEXT,domain TEXT,id TEXT,
                                 PRIMARY KEY(case_domain,case_id,domain,id));
        CREATE INDEX case_anchor_source ON case_anchors(domain,id);
    ''')
    cases = {}

    def observed(value):
        if not isinstance(value, dict):
            return value if len(encode(value)) <= 300 else {'detail_required': True}
        sample = {}
        for key, item in value.items():
            if key.startswith('_') or key in ('source', 'resource_id', 'native_resource_ref') or len(encode(item)) > 100:
                continue
            candidate = dict(sample, **{key: item})
            if len(encode(candidate)) <= 350:
                sample = candidate
            if len(sample) == 3:
                break
        return sample or {'detail_required': True}

    def add(section, key, signal, state, severity, member, facts, scopes=()):
        ident = fingerprint([section, key])[:20]
        case = cases.setdefault((section, ident), {'id': ident, 'signal': signal, 'state': state,
            'severity': severity, 'count': 0, 'facts': facts, 'example': {'domain': member[0], 'id': member[1]},
            'unit': {'findings': 'findings', 'least_privilege': 'suggestions', 'privesc': 'edges', 'iam': 'iam_records', 'network': 'rule_candidates'}[section],
            '_scopes': set(), '_variants': set(), '_counter': Counter(), '_members': set(),
            '_sources': set(), '_targets': set(), '_exposed': set(), '_exposure_states': set()})
        case['_members'].add(member)
        case['_scopes'].update(scope for scope in scopes if isinstance(scope, str))
        if RISK.get(severity, 4) < RISK.get(case['severity'], 4):
            case['severity'] = severity
            case['example'] = {'domain': member[0], 'id': member[1]}
        return case

    def rows(domain):
        for ident, summary, detail, rank in db.execute('SELECT id,summary,detail,risk FROM records WHERE domain=? AND candidate=1 ORDER BY risk,id', (domain,)):
            yield ident, json.loads(summary), json.loads(detail), rank

    def rows_in(*domains):
        for domain in domains:
            for row in rows(domain):
                yield domain, *row

    for ident, summary, detail, _ in rows('finding_groups'):
        members = db.execute('SELECT finding_id FROM members WHERE group_id=?', (ident,)).fetchall()
        case = add('findings', ident, f"{summary.get('check_id')}: {summary.get('title')}", summary['verdict'],
                   summary['severity'], ('findings', summary['example_finding_id']),
                   {key: summary[key] for key in ('category', 'resource_count', 'scope_count', 'scope_sample', 'evidence_variant_count')})
        case['facts']['observed_sample'] = observed(summary.get('evidence_sample', {}))
        case['_members'] = {('findings', row[0]) for row in members}
        case['count'] = len(members)
        # The signal and its state represent every member; avoid repeating the
        # same large evidence and remediation prose on the account-wide pass.

    for ident, summary, detail, _ in rows('least_privilege'):
        for suggestion in detail.get('suggestions', []):
            confidence = suggestion.get('confidence', 'unknown')
            kind = suggestion.get('kind', 'access')
            source = suggestion.get('source', 'collected evidence')
            key = (kind, confidence, source)
            case = add('least_privilege', key,
                f"{'Review provider-recommended reductions to' if confidence == 'provider_recommendation' else 'Review declared'} {kind}{'' if kind == 'access' else ' access'}",
                confidence, detail.get('severity', 'info'), ('least_privilege', ident),
                {'kind': kind, 'source': source, 'values_sample': [], 'replacement_sample': []}, detail.get('scopes', []))
            case['count'] += 1
            case['_counter']['principals:' + ident] = 1
            if detail.get('exposures'):
                case['_exposed'].add(ident)
                case['_exposure_states'].update(str(item.get('state', 'unknown')) for item in detail['exposures'])
            for field, value in (('values_sample', suggestion.get('value')), ('replacement_sample', suggestion.get('replacement'))):
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item and item not in case['facts'][field] and len(case['facts'][field]) < 3:
                        case['facts'][field].append(str(item))
            case['_variants'].add(fingerprint(suggestion))
        if not detail.get('suggestions') and detail.get('exposures'):
            # Exposure without a removal recommendation still influences the
            # ordering; never silently hide an exposed privileged principal.
            case = add('least_privilege', ('exposure_only',), 'Review exposed identities', 'exposure_context',
                       detail.get('severity', 'info'), ('least_privilege', ident),
                       {'exposure_sample': detail['exposures'][:1]}, detail.get('scopes', []))
            case['count'] += 1
            case['unit'] = 'identities'

    target_sizes = dict(db.execute("SELECT id,COALESCE(json_extract(detail,'$.underlying_count'),1) FROM records WHERE domain='privesc_nodes'"))
    finding_severities = dict(db.execute("SELECT id,json_extract(summary,'$.severity') FROM records WHERE domain='findings'"))
    for ident, summary, detail, _ in rows('privesc_edges'):
        techniques = tuple(sorted(detail.get('techniques', [])))
        state = detail.get('confidence', 'unknown')
        details = detail.get('technique_details', [])
        confidence_signature = tuple(sorted((item.get('id', ''), item.get('confidence', 'unknown')) for item in details))
        levels = [item['severity'] for item in details if item.get('severity')]
        levels.extend(finding_severities[value] for value in detail.get('findings', []) if finding_severities.get(value))
        severity = min(levels, key=lambda value: RISK.get(value, 4), default='unknown')
        case = add('privesc', (techniques, state, confidence_signature), ' / '.join(techniques) or 'Privilege-escalation relationship',
                   state, severity, ('privesc_edges', ident), {'conditions_sample': [], 'mitigation_sample': [],
                       'technique_confidences': sorted({item.get('confidence', 'unknown') for item in details}),
                       'outcomes': [], 'capabilities_sample': [], 'outcome_inferred': False, 'largest_target_group': 0})
        case['count'] += 1
        case['_sources'].add(detail.get('source'))
        case['_targets'].add(detail.get('target'))
        case['facts']['largest_target_group'] = max(case['facts']['largest_target_group'], target_sizes.get(detail.get('target'), 0))
        for item in details:
            outcome = item.get('outcome')
            if outcome and outcome not in case['facts']['outcomes']:
                case['facts']['outcomes'].append(outcome)
            case['facts']['outcome_inferred'] |= bool(item.get('outcome_inferred'))
            for capability in item.get('grants', []):
                if capability not in case['facts']['capabilities_sample'] and len(case['facts']['capabilities_sample']) < 3:
                    case['facts']['capabilities_sample'].append(capability)
            for field, values in (('conditions_sample', item.get('conditions', [])), ('mitigation_sample', [item.get('mitigation')])):
                for value in values:
                    if value and value not in case['facts'][field] and len(case['facts'][field]) < 3:
                        text = str(value)
                        case['facts'][field].append(text if len(text) <= 150 else text[:150] + '… [see original]')
        case['_variants'].add(fingerprint(details))

    for source_domain, ident, summary, detail, _ in rows_in('iam_nodes', 'iam_edges'):
        card = detail.get('card') or {}
        grants = card.get('grant_summary') or {}
        annotations = tuple(sorted({item.get('type', 'unspecified') for item in detail.get('risk_annotations', [])}))
        state = card.get('effective_access', 'unknown')
        severity_counts = grants.get('by_severity') or {}
        severity = min((value for value, count in severity_counts.items() if count), key=lambda value: RISK.get(value, 4),
                       default='high' if grants.get('high_risk_allowed') else 'unknown')
        case = add('iam', (annotations, state, bool(grants.get('high_risk_allowed'))),
                   'Review ' + (', '.join(annotations) or 'risk-marked IAM records'), state, severity, (source_domain, ident),
                   {'high_risk_grants': 0, 'grant_severity_counts': {}, 'restrictions_present': 0, 'exposure_records': 0,
                    'permission_sample': [], 'usage_is_not_unused_access': True}, [detail.get('scope')])
        case['count'] += 1
        case['facts']['high_risk_grants'] += grants.get('high_risk_allowed', 0)
        case['facts']['restrictions_present'] += bool(card.get('restrictions'))
        case['facts']['exposure_records'] += bool(detail.get('exposures'))
        for value, count in severity_counts.items():
            case['facts']['grant_severity_counts'][value] = case['facts']['grant_severity_counts'].get(value, 0) + count
        for grant in sorted(card.get('source_grants', []), key=lambda row: RISK.get(row.get('severity'), 4)):
            if not grant.get('allowed_declaration'):
                continue
            native = grant.get('native_grant')
            values = ([('permission', native)] if isinstance(native, str) else
                      [(key, native[key]) for key in ('Action', 'NotAction', 'role', 'actions', 'dataActions', 'verbs', 'resources') if key in native]
                      if isinstance(native, dict) else [])
            for field, value in values:
                for permission in value if isinstance(value, list) else [value]:
                    sample = {'field': field, 'value': permission}
                    if sample not in case['facts']['permission_sample'] and len(case['facts']['permission_sample']) < 3:
                        case['facts']['permission_sample'].append(sample)
        case['_variants'].add(fingerprint(card))

    for ident, summary, detail, _ in rows('network_edges'):
        evidence = detail.get('evidence') or {}
        rule = evidence.get('native_rule') or {}
        # Preserve differences in protocol, ports and sources. Unknown provider
        # shapes use the whole rule as the key instead of collapsing unlike rules.
        keys = ('IpProtocol', 'FromPort', 'ToPort', 'IpRanges', 'Ipv6Ranges', 'UserIdGroupPairs', 'PrefixListIds',
                'direction', 'allowed', 'denied', 'sourceRanges', 'destinationRanges',
                'priority', 'disabled', 'sourceTags', 'sourceServiceAccounts', 'targetTags', 'targetServiceAccounts',
                'protocol', 'sourceAddressPrefix', 'sourceAddressPrefixes', 'sourceApplicationSecurityGroups',
                'destinationAddressPrefix', 'destinationAddressPrefixes', 'destinationApplicationSecurityGroups',
                'destinationPortRange', 'destinationPortRanges', 'sourcePortRange', 'sourcePortRanges', 'access')
        core = {key: rule[key] for key in keys if key in rule} if isinstance(rule, dict) else rule
        if not core:
            core = rule
        state = evidence.get('reachability', 'unknown')
        key = (detail.get('type'), detail.get('layer'), state, core)
        case = add('network', key, 'Review public rule candidate', state, detail.get('severity', 'unknown'), ('network_edges', ident),
                   {'rule': core, 'uncertainty': evidence.get('uncertainty'), 'layer': detail.get('layer')})
        case['count'] += 1
        case['_variants'].add(fingerprint(rule))

    for ident, summary, detail, _ in rows('network_nodes'):
        state = (detail.get('evidence') or {}).get('reachability', 'unknown')
        annotations = detail.get('risk_annotations', [])
        case = add('network', ('node', detail.get('type'), annotations, state), 'Review risk-marked network records',
                   state, detail.get('severity', 'unknown'), ('network_nodes', ident),
                   {'record_type': detail.get('type'), 'risk_annotations': annotations}, [detail.get('scope')])
        case['count'] += 1
        case['unit'] = 'network_records'

    # A common referenced resource/identity is a useful correlation cue. This
    # joins at most two explicit-reference hops, never an inferred access path.
    for (section, ident), case in cases.items():
        domain = 'decision_' + section
        db.executemany('INSERT INTO case_members VALUES(?,?,?,?)',
                       ((domain, ident, source_domain, source_id) for source_domain, source_id in case['_members']))
    db.execute('INSERT OR IGNORE INTO case_anchors SELECT * FROM case_members')
    db.execute('''INSERT OR IGNORE INTO case_anchors
        SELECT m.case_domain,m.case_id,l.b_domain,l.b_id FROM case_members m
        JOIN links l ON l.a_domain=m.domain AND l.a_id=m.id''')
    db.execute('''INSERT OR IGNORE INTO case_anchors
        SELECT m.case_domain,m.case_id,l.a_domain,l.a_id FROM case_members m
        JOIN links l ON l.b_domain=m.domain AND l.b_id=m.id''')
    sections = {section: [] for section in SECTIONS}
    for (section, ident), case in cases.items():
        domain = 'decision_' + section
        related = db.execute('''SELECT b.case_domain,COUNT(DISTINCT b.case_id) FROM case_anchors a
            JOIN case_anchors b ON a.domain=b.domain AND a.id=b.id
            WHERE a.case_domain=? AND a.case_id=? AND b.case_domain!=?
            GROUP BY b.case_domain''', (domain, ident, domain)).fetchall()
        case['related'] = {name.removeprefix('decision_'): count for name, count in related}
        if case['_scopes']:
            case['facts'].update(scope_count=len(case['_scopes']), scope_sample=sorted(case['_scopes'])[:3])
        if case['_variants']:
            case['facts']['detail_variants'] = len(case['_variants'])
        if section == 'least_privilege' and case['_counter']:
            case['facts']['principal_count'] = len(case['_counter'])
            case['facts']['exposed_principals'] = len(case['_exposed'])
            case['facts']['exposure_states'] = sorted(case['_exposure_states'])
        if section == 'privesc':
            case['facts']['source_count'] = len(case['_sources'])
            case['facts']['target_count'] = len(case['_targets'])
        for key in list(case):
            if key.startswith('_'):
                case.pop(key)
        # Keep the initial catalog concise. Exact rule/source text remains under
        # the example and members; explicit markers make compression visible.
        for key, value in list(case['facts'].items()):
            if len(encode(value)) > 400:
                case['facts'][key] = {'detail_required': True}
        db.execute('INSERT INTO records VALUES(?,?,?,?,?,?)',
                   (domain, ident, encode(case), encode(case), RISK.get(case['severity'], 4), 1))
        sections[section].append(case)
    for values in sections.values():
        values.sort(key=lambda row: (RISK.get(row['severity'], 4), -sum(row['related'].values()), row['id']))
    return sections

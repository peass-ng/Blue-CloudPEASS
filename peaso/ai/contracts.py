"""Strict output contracts plus cross-reference checks beyond JSON Schema."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Review(Strict):
    finding_id: str
    verdict: Literal['PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY']
    reason: str = Field(max_length=500, description='Must be empty for FAIL; otherwise explain the verdict and any likely check error in at most 500 characters.')

    @model_validator(mode='after')
    def reason_matches_verdict(self):
        if self.verdict == 'FAIL' and self.reason != '':
            raise ValueError('Confirmed FAIL must have an empty reason')
        if self.verdict != 'FAIL' and not self.reason.strip():
            raise ValueError('Other verdicts must explain the result')
        return self


class Reviews(Strict):
    items: list[Review]


class Action(Strict):
    rank: int = Field(ge=1, le=15)
    title: str = Field(min_length=1, max_length=300)
    resource_ids: list[str]
    finding_ids: list[str]
    rationale: str = Field(min_length=1, max_length=1000)
    steps: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(min_length=1, max_length=5)
    verification: str = Field(min_length=1, max_length=700)


class Recommendations(Strict):
    actions: list[Action] = Field(max_length=15)
    limitations: list[str]


class NetworkEvidence(Strict):
    summary: str = Field(min_length=1, max_length=1000)
    resource_ids: list[str] = Field(min_length=1, max_length=50)
    graph_refs: list[str] = Field(max_length=50)
    observations: list[Annotated[str, Field(min_length=1, max_length=1000)]] = Field(min_length=1, max_length=10)
    limitations: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(max_length=10)


class NetworkFinding(Strict):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=1000)
    rationale: str = Field(min_length=1, max_length=1000)
    resource_id: str
    severity: Literal['critical', 'high', 'medium', 'low', 'info']
    status: Literal['FAIL', 'MANUAL', 'UNKNOWN']
    evidence: NetworkEvidence
    remediation: str = Field(min_length=1, max_length=2000)
    verification: str = Field(min_length=1, max_length=1000)


class NetworkReview(Strict):
    explanation: str = Field(min_length=1, max_length=1000)
    findings: list[NetworkFinding] = Field(max_length=100)
    limitations: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(max_length=20)


def validate_network(data, platform):
    """Bind generated findings to supplied native resources and graph records."""
    from peaso.analysis.common import stable_id
    value = NetworkReview.model_validate(data).model_dump()
    resources = {row['id']: row for row in platform['inventory']}
    graph = platform['report'].get('graphs', {}).get('network') or {}
    graph_ids = {row['id'] for kind in ('nodes', 'edges') for row in graph.get(kind, [])}
    seen = set()
    for row in value['findings']:
        evidence = row['evidence']
        resource = resources.get(row['resource_id'])
        if (not resource or row['resource_id'] not in evidence['resource_ids']
                or not set(evidence['resource_ids']) <= resources.keys()
                or not set(evidence['graph_refs']) <= graph_ids):
            raise ValueError('unknown_network_reference')
        key = (row['resource_id'], row['title'].strip().casefold())
        if key in seen:
            raise ValueError('duplicate_network_finding')
        seen.add(key)
        ident = stable_id('ai.network', *key)
        row.update(id=ident, check_id='ai.network.' + ident.split(':')[1], category='network',
                   provider=resource['provider'], scope=resource['scope'], service=resource.get('service') or 'network',
                   frameworks=[], finding_type='network', native_resource_id=resource.get('native_id', resource['id']))
        evidence['source'] = 'ai_network_review'
        row['evidence_summary'] = evidence['summary']
    return value


def validate_reviews(data, findings):
    value = Reviews.model_validate(data).model_dump()
    expected = {row['id'] for row in findings}
    ids = [row['finding_id'] for row in value['items']]
    if len(ids) != len(set(ids)) or set(ids) != expected:
        raise ValueError('review_coverage_mismatch')
    return value


def validate_actions(data, report, reviews):
    value = Recommendations.model_validate(data).model_dump()
    actions = value['actions']
    if [a['rank'] for a in actions] != list(range(1, len(actions) + 1)):
        raise ValueError('action_rank_mismatch')
    findings = {row['id'] for row in report['findings'] if row.get('status') == 'FAIL'
                or (row.get('category') == 'network' and row.get('status') in ('MANUAL', 'UNKNOWN'))}
    resources = {row['id'] for row in report.get('resources', [])}
    rejected = {r['finding_id'] for r in reviews if r['verdict'] != 'FAIL'}
    titles = set()
    for action in actions:
        title = action['title'].strip().casefold()
        if title in titles:
            raise ValueError('invalid_action')
        titles.add(title)
        if not set(action['finding_ids']) <= findings - rejected or not set(action['resource_ids']) <= resources:
            raise ValueError('unknown_action_reference')
        if not action['finding_ids'] and not action['resource_ids']:
            raise ValueError('action_reference_missing')
    return value

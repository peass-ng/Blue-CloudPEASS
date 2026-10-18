"""Versioned, hash-guarded native CloudTrail management selector description.

The compiled description pack remains immutable. These checks have no signed
new-check proposal, so this overlay makes no signed-spec claim.
"""
from copy import deepcopy
import hashlib
import json

VERSION = "cloudtrail-management-description-overlay-v2"
SOURCE_RELATIONSHIP = "bounded native selector-configuration evaluation, not proof of event delivery or regional coverage"
OFFICIAL_REFERENCES = [
    "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html",
]
ROWS = {'aws.cloudtrail.management_events': {'base_row_sha256': '851e408acb96e31b553001a6f335bd0126c67aa19b8f42362818bfb0f4a0055b',
                                      'fields': {'description': 'Evaluates captured basic or '
                                                                'supported advanced management '
                                                                'selectors for one CloudTrail '
                                                                'trail. Proved read/write coverage '
                                                                'is PASS; supported incomplete '
                                                                'coverage is FAIL; unreadable or '
                                                                'unresolved selectors are UNKNOWN. '
                                                                'This is selector configuration '
                                                                'evidence, not logging status, '
                                                                'delivery, regional completeness, '
                                                                'or observed event coverage.',
                                                 'evaluated': ['cloudtrail.TrailARN matched to '
                                                               'native GetEventSelectors TrailARN',
                                                               'cloudtrail.EventSelectors.EventSelectors[].IncludeManagementEvents',
                                                               'cloudtrail.EventSelectors.EventSelectors[].ReadWriteType',
                                                               'cloudtrail.EventSelectors.EventSelectors[].ExcludeManagementEventSources',
                                                               'cloudtrail.EventSelectors.AdvancedEventSelectors'],
                                                 'fail_when': 'FAIL when readable supported '
                                                              'selectors establish that full '
                                                              'management coverage is absent; '
                                                              'unsupported, malformed, or denied '
                                                              'selector evidence is UNKNOWN unless '
                                                              'a separate selector independently '
                                                              'proves full coverage.',
                                                 'not_applicable_when': None,
                                                 'pass_when': 'PASS when a basic selector includes '
                                                              'all management events with no '
                                                              'excluded management sources, or '
                                                              'when the union of advanced '
                                                              'management selectors proves read '
                                                              'and write coverage across all '
                                                              'management source domains, '
                                                              'including complementary supported '
                                                              'source exclusions.'}}}

def _row_sha256(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def description(check_id, original):
    """Apply only to an exact original compiled row; reject pack drift."""
    correction = ROWS.get(check_id)
    if correction is None:
        return deepcopy(original)
    if not isinstance(original, dict) or _row_sha256(original) != correction["base_row_sha256"]:
        raise ValueError("CloudTrail original description row changed: " + check_id)
    value = deepcopy(original)
    value.update(deepcopy(correction["fields"]))
    value["description_correction"] = {"version": VERSION,
        "base_row_sha256": correction["base_row_sha256"],
        "source_relationship": SOURCE_RELATIONSHIP,
        "official_references": list(OFFICIAL_REFERENCES)}
    return value


def validate_rows(checks):
    """Materializer gate for the original CloudTrail description row."""
    for check_id in ROWS:
        description(check_id, checks.get(check_id))

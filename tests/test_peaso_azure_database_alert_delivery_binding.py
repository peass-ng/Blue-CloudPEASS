"""External backup alert trigger and receiver-delivery boundaries."""
from copy import deepcopy

from peaso.checks import evaluate_check
from tests.test_peaso_azure_wave_backup_native_alert import CID, SCOPE, SERVICE, GROUP, _facts, _proof

CAPTURE = '2026-10-12T00:00:00Z'
EVENT_AT = '2026-10-05T00:00:00Z'
WINDOW_END = '2026-10-05T00:10:00Z'
RECEIVER = 'operations@example.test'


def observed():
    index = _facts([_proof('one')])
    index['context']['created_at'] = CAPTURE
    metadata = index['context']['metadata']
    metadata.update(credential_context_id='capture-1', customer_context_id='customer-1')
    metadata['compliance_policy']['sw33']['backupAlerts'].update(
        windowStart='2026-10-01T00:00:00Z', windowEnd='2026-10-10T00:00:00Z',
        approvedActionGroupIds=[GROUP], approvedReceiverIds=[RECEIVER],
        triggerSourceId='trigger-reader', deliverySourceId='receiver-reader',
        authorizedObservationDocumentIds=['approved-read-1', 'approved-read-2'])
    proof = index['collections']['database_backup_alert_evidence'][0]['items'][0]
    proof['_provenance'] = {'scope': SCOPE, 'credential_context_id': 'capture-1',
        'customer_context_id': 'customer-1', 'capturedAt': CAPTURE,
        'readOnly': True, 'authorizationDocumentId': 'approved-read-1'}
    for name, signal in proof['signals'].items():
        event = 'event-' + name
        common = {'scope': SCOPE, 'credential_context_id': 'capture-1',
                  'customer_context_id': 'customer-1', 'capturedAt': CAPTURE}
        signal['triggerObservation'] = {**common, 'serviceId': SERVICE, 'signal': name,
            'eventId': event, 'eventAt': EVENT_AT, 'sourceId': 'trigger-reader',
            'observer': 'source-observer', 'authorizationDocumentId': 'approved-read-1',
            'readOnly': True}
        signal['deliveryObservation'] = {**common, 'serviceId': SERVICE, 'signal': name,
            'eventId': event, 'sourceId': 'receiver-reader',
            'observer': 'receiver-observer', 'authorizationDocumentId': 'approved-read-2',
            'readOnly': True, 'complete': True, 'windowStart': EVENT_AT,
            'windowEnd': WINDOW_END, 'deliveries': [{'serviceId': SERVICE,
                'signal': name, 'eventId': event, 'actionGroupId': GROUP,
                'receiverId': RECEIVER, 'alertLogId': 'delivered-' + name,
                'deliveredAt': '2026-10-05T00:05:00Z'}]}
    return index


def proof_of(index):
    return index['collections']['database_backup_alert_evidence'][0]['items'][0]


def status(index):
    return evaluate_check(CID, {}, index)[0]


def test_bare_pass_labels_do_not_prove_trigger_or_receiver_delivery():
    assert status(_facts([_proof('one')])) == 'UNKNOWN'


def test_complete_independent_trigger_and_receiver_observations_pass():
    assert status(observed()) == 'PASS'


def test_foreign_capture_credential_is_unknown():
    index = observed(); proof_of(index)['_provenance']['credential_context_id'] = 'other'
    assert status(index) == 'UNKNOWN'


def test_foreign_customer_is_unknown():
    index = observed(); proof_of(index)['signals']['disabled']['triggerObservation']['customer_context_id'] = 'other'
    assert status(index) == 'UNKNOWN'


def test_foreign_trigger_service_is_unknown():
    index = observed(); proof_of(index)['signals']['disabled']['triggerObservation']['serviceId'] = SERVICE + '-other'
    assert status(index) == 'UNKNOWN'


def test_wrong_signal_identity_is_unknown():
    index = observed(); proof_of(index)['signals']['paused']['deliveryObservation']['signal'] = 'disabled'
    assert status(index) == 'UNKNOWN'


def test_same_trigger_and_receiver_source_is_unknown():
    index = observed()
    index['context']['metadata']['compliance_policy']['sw33']['backupAlerts']['deliverySourceId'] = 'trigger-reader'
    assert status(index) == 'UNKNOWN'


def test_incomplete_receiver_window_is_unknown():
    index = observed(); proof_of(index)['signals']['disabled']['deliveryObservation']['windowEnd'] = '2026-10-05T00:09:59Z'
    assert status(index) == 'UNKNOWN'


def test_complete_receiver_search_with_no_delivery_fails():
    index = observed(); proof_of(index)['signals']['disabled']['deliveryObservation']['deliveries'] = []
    assert status(index) == 'FAIL'


def test_complete_receiver_search_with_late_delivery_fails():
    index = observed()
    proof_of(index)['signals']['disabled']['deliveryObservation']['deliveries'][0]['deliveredAt'] = '2026-10-05T00:11:00Z'
    assert status(index) == 'FAIL'


def test_delivery_to_unapproved_receiver_fails():
    index = observed()
    proof_of(index)['signals']['disabled']['deliveryObservation']['deliveries'][0]['receiverId'] = 'other@example.test'
    assert status(index) == 'FAIL'


def test_future_trigger_cannot_pass():
    index = observed(); proof_of(index)['signals']['disabled']['triggerObservation']['eventAt'] = '2026-10-13T00:00:00Z'
    assert status(index) == 'UNKNOWN'

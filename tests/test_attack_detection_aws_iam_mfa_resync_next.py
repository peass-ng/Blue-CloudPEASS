"""Successful IAM MFA resynchronization from CloudTrail's null-response shape."""
from copy import deepcopy
from peaso.attack_detection import Rule,detect_aws_events

ACCOUNT='222233334444'
RULE=Rule(id='mfa',title='IAM MFA resync',level='medium',description='mfa',
          technique_id='aws-iam-mfa-device-resynchronized',product='aws',selection={
              'event.source':'iam.amazonaws.com','event.name':'ResyncMFADevice',
              'event.outcome':'success','request.iam_mfa_resync_observed':True})
ENROLL=Rule(id='enroll',title='IAM MFA enroll',level='low',description='enroll',
          technique_id='aws-iam-mfa-device-enrolled',product='aws',selection={
              'event.source':'iam.amazonaws.com','event.name':'EnableMFADevice',
              'event.outcome':'success','request.iam_mfa_enrolled':True})
DEACTIVATE=Rule(id='deactivate',title='IAM MFA deactivate',level='medium',description='deactivate',
          technique_id='aws-iam-mfa-device-deactivated',product='aws',selection={
              'event.source':'iam.amazonaws.com','event.name':'DeactivateMFADevice',
              'event.outcome':'success','request.iam_mfa_deactivated':True})


def event():
    return {'eventSource':'iam.amazonaws.com','eventName':'ResyncMFADevice','eventCategory':'Management',
            'eventType':'AwsApiCall','managementEvent':True,'readOnly':False,
            'awsRegion':'us-east-1','recipientAccountId':ACCOUNT,
            'requestParameters':{'userName':'example-mfa-user','serialNumber':f'arn:aws:iam::{ACCOUNT}:mfa/example-mfa-device'},
            'responseElements':None,'eventID':'lab-resync'}


def hits(record):
    return [x.technique_id for x in detect_aws_events([record],[RULE,ENROLL,DEACTIVATE])]


def test_success_and_negative_controls():
    record=event()
    assert hits(record)==['aws-iam-mfa-device-resynchronized']
    for variant in ('denied','foreign_serial','missing_user','read_only','bad_serial'):
        item=deepcopy(record)
        if variant=='denied':item['errorCode']='InvalidAuthenticationCode'
        if variant=='foreign_serial':item['requestParameters']['serialNumber']=item['requestParameters']['serialNumber'].replace(ACCOUNT,'999999999999')
        if variant=='missing_user':item['requestParameters'].pop('userName')
        if variant=='read_only':item['readOnly']=True
        if variant=='bad_serial':item['requestParameters']['serialNumber']='not a valid serial!'
        assert hits(item)==[],variant


def test_hardware_serial_is_supported():
    record=event()
    record['requestParameters']['serialNumber']='ABCD12345678'
    assert hits(record)==['aws-iam-mfa-device-resynchronized']


def test_enrollment_and_deactivation_live_shapes():
    for name,expected in [('EnableMFADevice','aws-iam-mfa-device-enrolled'),
                          ('DeactivateMFADevice','aws-iam-mfa-device-deactivated')]:
        item=event()
        item['eventName']=name
        assert hits(item)==[expected]
        for variant in ('error','foreign_serial','read_only','missing_user'):
            altered=deepcopy(item)
            if variant=='error':altered['errorCode']='AccessDenied'
            if variant=='foreign_serial':altered['requestParameters']['serialNumber']=altered['requestParameters']['serialNumber'].replace(ACCOUNT,'999999999999')
            if variant=='read_only':altered['readOnly']=True
            if variant=='missing_user':altered['requestParameters'].pop('userName')
            assert hits(altered)==[],variant

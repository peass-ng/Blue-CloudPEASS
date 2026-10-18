"""SSM inventory read management events, projected before shared request caching."""
from datetime import timedelta
import json
import re
from .aws_kms_enclave_native import _time, _object

KIND = 'ssm_inventory_read_event'
SPECS = {KIND: ('cloudtrail', 'lookup_events', 'Events')}
NATIVE_IDS = {KIND: 'EventId'}
READ_ACTIONS = set()  # Existing cloudtrail:LookupEvents grant.
OPERATIONS = {'GetInventory', 'ListInventoryEntries'}
REFERENCE = 'https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html'


def is_inventory_query(attributes):
    return (isinstance(attributes, list) and len(attributes) == 1
            and isinstance(attributes[0], dict)
            and set(attributes[0]) == {'AttributeKey', 'AttributeValue'}
            and attributes[0].get('AttributeKey') == 'EventName'
            and attributes[0].get('AttributeValue') in OPERATIONS)


def project(response, expected_operation):
    from .aws import ReadFailure
    try:
        if expected_operation not in OPERATIONS or not isinstance(response, dict) or not isinstance(response.get('Events'), list):
            raise ValueError('undeclared inventory event page')
        rows = []
        for event in response['Events']:
            if not isinstance(event, dict) or not isinstance(event.get('CloudTrailEvent'), str):
                raise ValueError('event body missing')
            payload = json.loads(event['CloudTrailEvent'], object_pairs_hook=_object)
            if not isinstance(payload, dict):
                raise ValueError('event body malformed')
            ident, name, when = event.get('EventId'), event.get('EventName'), event.get('EventTime')
            account, region = payload.get('recipientAccountId'), payload.get('awsRegion')
            if (not isinstance(ident, str) or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', ident)
                    or payload.get('eventID') != ident or name != expected_operation or payload.get('eventName') != name
                    or payload.get('eventSource') != 'ssm.amazonaws.com' or event.get('EventSource') != 'ssm.amazonaws.com'
                    or payload.get('eventType') != 'AwsApiCall' or payload.get('eventCategory') != 'Management'
                    or payload.get('managementEvent') is not True or payload.get('readOnly') is not True
                    or not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account)
                    or not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', region)
                    or not hasattr(when, 'astimezone') or when.tzinfo is None or _time(payload.get('eventTime')) != when):
                raise ValueError('event identity or management classification differs')
            identity = payload.get('userIdentity')
            actor = identity.get('arn') if isinstance(identity, dict) else None
            if not isinstance(actor, str) or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:[^:]+:[^:]*:[0-9]{12}:[^\s]+', actor):
                raise ValueError('event actor ARN unresolved')
            code = payload.get('errorCode')
            if ('errorCode' in payload and (not isinstance(code, str) or not code)) or ('errorMessage' in payload and not code):
                raise ValueError('event success state ambiguous')
            rows.append({'EventId': ident, 'EventName': name, 'EventSource': 'ssm.amazonaws.com',
                         'EventTime': when.isoformat(), 'AccountId': account, 'Region': region,
                         'userIdentity': {'arn': actor}, 'success': not bool(code)})
        result = {'Events': rows}
        if 'NextToken' in response:
            if not isinstance(response['NextToken'], str) or not response['NextToken']:
                raise ValueError('event cursor malformed')
            result['NextToken'] = response['NextToken']
        return result
    except (ValueError, TypeError, AttributeError):
        raise ReadFailure('malformed', 'ssm_inventory_event_metadata_invalid') from None


def events(requests, session, region, account):
    from .aws import ReadResult
    end = requests.observed_at
    start = end - timedelta(minutes=requests.activity_minutes)
    rows, seen = [], set()
    for name in sorted(OPERATIONS):
        read = requests.pages(session, 'cloudtrail', region, 'lookup_events', 'Events',
                              LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': name}],
                              StartTime=start, EndTime=end)
        if read.status not in ('collected', 'empty'):
            return ReadResult([], read.status, read.error or {'code': 'ssm_inventory_history_incomplete'})
        for row in read.items:
            try:
                valid = (row.get('AccountId') == account and row.get('Region') == region
                         and row.get('EventName') == name and row.get('EventId') not in seen
                         and start <= _time(row.get('EventTime')) <= end)
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                return ReadResult([], 'malformed', {'code': 'ssm_inventory_event_scope_or_window_mismatch'})
            seen.add(row['EventId'])
            rows.append({**row, '_provenance': {'source_operation': 'cloudtrail:LookupEvents',
                         'read_only': True, 'reference': REFERENCE, 'window_start': start.isoformat(),
                         'window_end': end.isoformat(), 'boundary': 'Complete returned management-event pages in this observed window only; no older history, delivery guarantee or effective IAM authorization claim'}})
    return ReadResult(rows, 'collected' if rows else 'empty')


FETCHERS = {KIND: events}


def approved_readers(options):
    """Owner intent only: exact observed actor ARNs, never event observations."""
    parameters = options.get('compliance_parameters')
    if not isinstance(parameters, dict) or 'approved_inventory_reader_arns' not in parameters:
        return None
    values = parameters['approved_inventory_reader_arns']
    if (not isinstance(values, list) or not 1 <= len(values) <= 256
            or any(not isinstance(v, str) or len(v) > 2048
                   or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:(?:iam|sts)::[0-9]{12}:[^\s]+', v) for v in values)
            or len(set(values)) != len(values)):
        raise ValueError('approved inventory readers must be unique bounded principal ARNs')
    return list(values)

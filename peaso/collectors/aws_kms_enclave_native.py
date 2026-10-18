"""Opt-in KMS Nitro enclave PCR metadata from CloudTrail management event history.

The raw event, identity, access keys, requests and responses never enter a cache
or snapshot. This does not decrypt data or attest that an enclave is running.
"""
from datetime import datetime,timedelta,timezone
import json,re
SPECS={'cloudtrail_event':('cloudtrail','lookup_events','Events')}
NATIVE_IDS={'cloudtrail_event':'EventId'}
READ_ACTIONS=set()  # Existing exact cloudtrail:LookupEvents grant and shared pacing.
OPERATIONS={'Decrypt','DeriveSharedSecret','GenerateDataKey','GenerateDataKeyPair','GenerateRandom'}
REFERENCE='https://docs.aws.amazon.com/kms/latest/developerguide/ct-nitro-enclave.html'

def _time(value):
 if not isinstance(value,str):raise ValueError('event time missing')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None or parsed.utcoffset()is None:raise ValueError('event time timezone missing')
 return parsed.astimezone(timezone.utc)
def _object(pairs):
 out={}
 for key,value in pairs:
  if key in out:raise ValueError('ambiguous duplicate event key')
  out[key]=value
 return out

def is_enclave_query(attributes):
 return (isinstance(attributes,list)and len(attributes)==1 and isinstance(attributes[0],dict)and set(attributes[0])=={'AttributeKey','AttributeValue'}and attributes[0].get('AttributeKey')=='EventName'and attributes[0].get('AttributeValue')in OPERATIONS)

def project(response, expected_operation):
 """Called at the SDK boundary, before Request's single-flight Future is set."""
 from .aws import ReadFailure
 try:
  if expected_operation not in OPERATIONS:raise ValueError('undeclared enclave query')
  if not isinstance(response,dict)or not isinstance(response.get('Events'),list):raise ValueError('event page unavailable')
  rows=[]
  for event in response['Events']:
   if not isinstance(event,dict)or not isinstance(event.get('CloudTrailEvent'),str):raise ValueError('event body missing')
   payload=json.loads(event['CloudTrailEvent'],object_pairs_hook=_object)
   if not isinstance(payload,dict):raise ValueError('event body malformed')
   ident=event.get('EventId');name=event.get('EventName');when=event.get('EventTime');account=payload.get('recipientAccountId');region=payload.get('awsRegion')
   if not isinstance(ident,str)or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',ident)or payload.get('eventID')!=ident or payload.get('eventName')!=name or payload.get('eventSource')!='kms.amazonaws.com'or event.get('EventSource','kms.amazonaws.com')!='kms.amazonaws.com'or payload.get('eventType')!='AwsApiCall'or not isinstance(account,str)or not re.fullmatch(r'[0-9]{12}',account)or not isinstance(region,str)or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+',region)or not isinstance(when,datetime)or when.tzinfo is None or _time(payload.get('eventTime'))!=when.astimezone(timezone.utc):raise ValueError('event identity mismatch')
   if name!=expected_operation:raise ValueError('event query mismatch')
   additional=payload.get('additionalEventData',{})
   if not isinstance(additional,dict):raise ValueError('additional event data malformed')
   if 'recipient'not in additional:continue
   recipient=additional['recipient']
   if not isinstance(recipient,dict):raise ValueError('recipient metadata malformed')
   module=recipient.get('attestationDocumentModuleId')
   if isinstance(module,str)and re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})-tpm[0-9a-f]{8,32}',module)and any(k.startswith('attestationDocumentNitroTPMPCR')for k in recipient):continue
   if not isinstance(module,str)or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})-enc[0-9a-f]{8,32}',module):raise ValueError('enclave module metadata unavailable')
   pcrs={'PCR0':recipient.get('attestationDocumentEnclaveImageDigest')}
   for key,value in recipient.items():
    if key.startswith('attestationDocumentEnclavePCR'):
     index=key.removeprefix('attestationDocumentEnclavePCR')
     if index not in('0','1','2','3','4','8'):raise ValueError('unrecognized enclave PCR')
     if index=='0'and value!=pcrs['PCR0']:raise ValueError('conflicting PCR0 metadata')
     pcrs['PCR'+index]=value
   if any(not isinstance(v,str)or not re.fullmatch(r'[0-9a-fA-F]{96}',v)for v in pcrs.values()):raise ValueError('PCR SHA384 metadata malformed')
   rows.append({'EventId':ident,'EventName':name,'EventSource':'kms.amazonaws.com','EventTime':when.isoformat(),'AccountId':account,'Region':region,'IsEnclaveAttestation':True,'AttestationPcrs':pcrs})
  result={'Events':rows}
  if 'NextToken'in response:
   if not isinstance(response['NextToken'],str)or not response['NextToken']:raise ValueError('event cursor malformed')
   result['NextToken']=response['NextToken']
  return result
 except (ValueError,TypeError,AttributeError):raise ReadFailure('malformed','kms_enclave_metadata_invalid')from None

def events(requests,session,region,account):
 from .aws import ReadResult
 end=requests.observed_at;start=end-timedelta(minutes=requests.activity_minutes);rows=[];seen=set()
 for name in sorted(OPERATIONS):
  read=requests.pages(session,'cloudtrail',region,'lookup_events','Events',LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':name}],StartTime=start,EndTime=end)
  if read.status not in('collected','empty'):return ReadResult([],read.status,(read.error or{'code':'enclave_history_incomplete'}))
  for row in read.items:
   try:valid=(isinstance(row,dict)and row.get('AccountId')==account and row.get('Region')==region and row.get('EventName')==name and row.get('EventId')not in seen and start<=_time(row.get('EventTime'))<=end)
   except (TypeError,ValueError):valid=False
   if not valid:return ReadResult([],'malformed',{'code':'kms_enclave_scope_or_window_mismatch'})
   seen.add(row['EventId']);rows.append({**row,'_provenance':{'source_operation':'cloudtrail:LookupEvents','read_only':True,'reference':REFERENCE,'window_start':start.isoformat(),'window_end':end.isoformat(),'boundary':'Observed Nitro enclave PCR metadata only; no attestation verification, secret read or complete historical-delivery assurance'}})
 return ReadResult(rows,'collected'if rows else'empty')
FETCHERS={'cloudtrail_event':events}

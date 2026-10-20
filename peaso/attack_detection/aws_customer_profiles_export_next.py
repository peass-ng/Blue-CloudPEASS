"""Seven Customer Profiles export, upload and segment access observations.

Raw profile IDs, CSV contents, segment expressions, snapshot destinations and
role ARNs are deliberately omitted from projected events.
"""
from collections.abc import Mapping
import re
from typing import Any
from uuid import UUID

SOURCE="profile.amazonaws.com"
FLAGS={"CreateSegmentSnapshot":"segment_snapshot_requested",
       "GetSegmentSnapshot":"segment_snapshot_status_read",
       "StartUploadJob":"upload_job_started",
       "StopUploadJob":"upload_job_stopped",
       "GetSegmentMembership":"segment_membership_accessed",
       "CreateSegmentEstimate":"segment_estimate_requested",
       "GetSegmentEstimate":"segment_estimate_accessed"}
READ_ONLY={"GetSegmentSnapshot","GetSegmentEstimate"}
DOMAIN=re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
REGION=re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
HEX32=re.compile(r"[a-f0-9]{32}\Z")
HEX64=re.compile(r"[a-f0-9]{64}\Z")


def field(obj: Mapping[str,Any],name:str)->Any:
    return obj.get(name,obj.get(name[0].upper()+name[1:]))


def normalize(record:Mapping[str,Any])->dict[str,Any]|None:
    name=record.get("eventName")
    if (record.get("eventSource")!=SOURCE or name not in FLAGS
            or record.get("eventCategory")!="Management"
            or record.get("eventType")!="AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in READ_ONLY)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account,region=record.get("recipientAccountId"),record.get("awsRegion")
    request,identity=record.get("requestParameters"),record.get("userIdentity")
    if (not isinstance(account,str) or not re.fullmatch(r"[0-9]{12}",account)
            or not isinstance(region,str) or not REGION.fullmatch(region)
            or not isinstance(request,Mapping) or not isinstance(identity,Mapping)
            or identity.get("accountId")!=account):return None
    actor=identity.get("arn")
    if not isinstance(actor,str) or not actor.startswith((f"arn:aws:iam::{account}:",f"arn:aws:sts::{account}:")):return None
    try:UUID(record.get("eventID"))
    except (ValueError,TypeError,AttributeError):return None
    domain=field(request,"domainName")
    if not isinstance(domain,str) or not DOMAIN.fullmatch(domain):return None
    response=record.get("responseElements")
    if response is not None and not isinstance(response,Mapping):return None
    response=response or {}
    target=f"arn:aws:profile:{region}:{account}:domains/{domain}"
    if name in {"CreateSegmentSnapshot","GetSegmentSnapshot","GetSegmentMembership"}:
        segment=field(request,"segmentDefinitionName")
        if not isinstance(segment,str) or not DOMAIN.fullmatch(segment):return None
        target+="/segment-definitions/"+segment
    if name=="CreateSegmentSnapshot":
        role,dest=field(request,"roleArn"),field(request,"destinationUri")
        sid=field(response,"snapshotId")
        if (field(request,"dataFormat") not in {"CSV","JSONL","ORC"}
                or not isinstance(role,str) or not re.fullmatch(
                    rf"arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@/-]+",role)
                or not isinstance(dest,str) or not re.fullmatch(r"s3://[a-z0-9.-]{3,63}/.{0,200}",dest)
                or not isinstance(sid,str) or not HEX32.fullmatch(sid)):
            return None
    elif name=="GetSegmentSnapshot":
        sid=field(request,"snapshotId")
        if not isinstance(sid,str) or not HEX32.fullmatch(sid):return None
    elif name in {"StartUploadJob","StopUploadJob"}:
        jid=field(request,"jobId")
        if not isinstance(jid,str) or not HEX32.fullmatch(jid):return None
        target+="/upload-jobs/"+jid
    elif name=="GetSegmentMembership":
        profiles=field(request,"profileIds")
        if (not isinstance(profiles,list) or not 1<=len(profiles)<=100
                or any(not isinstance(p,str) or not HEX32.fullmatch(p) for p in profiles)):
            return None
        # CloudTrail labels this read-like API readOnly=false and redacts its response.
    elif name=="CreateSegmentEstimate":
        query,sql=field(request,"segmentQuery"),field(request,"segmentSqlQuery")
        estimate=field(response,"estimateId")
        if (not (isinstance(query,Mapping) or isinstance(sql,str))
                or not isinstance(estimate,str) or not HEX64.fullmatch(estimate)):
            return None
    else:
        estimate=field(request,"estimateId")
        if not isinstance(estimate,str) or not HEX64.fullmatch(estimate):return None
    return {"cloud.provider":"aws","event.source":SOURCE,"event.name":name,
            "event.outcome":"success","event.id":record["eventID"],
            "event.time":record.get("eventTime"),"account.id":account,
            "actor.id":actor,"cloud.region":region,"target.id":target,
            "request.customer_profiles_"+FLAGS[name]:True}

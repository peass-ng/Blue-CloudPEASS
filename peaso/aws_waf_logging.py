"""Documented WAF log destination ARN families; S3 has no Region/account fields."""
import re

def valid_destination_arn(value, *, classic=False):
 if not isinstance(value,str)or not 1<=len(value)<=2048:return False
 prefix=r'arn:aws(?:-[a-z0-9-]+)?:'
 regional=r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+:[0-9]{12}:'
 if re.fullmatch(prefix+r'firehose:'+regional+r'deliverystream/[A-Za-z0-9_.-]{1,64}',value):return True
 if classic:return False
 if re.fullmatch(prefix+r'logs:'+regional+r'log-group:[A-Za-z0-9_./#-]{1,512}(?::\*)?',value):return True
 match=re.fullmatch(prefix+r's3:::([^/]+)(?:/[^\x00-\x1f\x7f]*)?',value)
 if not match:return False
 bucket=match.group(1)
 return bool(len(bucket)<=63 and re.fullmatch(r'aws-waf-logs-[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',bucket)and'..'not in bucket)

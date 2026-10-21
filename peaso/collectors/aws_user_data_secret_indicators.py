"""Inspect EC2 user data in memory; retain categories, never literal values.

These are bounded high-confidence indicators, not exhaustive secret discovery.
The caller validates the native response identity, base64 and 16 KiB limit.
"""

from peaso.secret_evidence import scan_with_source
import re

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_ACCESS = re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")
_SECRET = re.compile(r'''(?i)(?:aws_secret_access_key|awsSecretAccessKey|secretAccessKey)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])''')
_PASSWORD = re.compile(r'''(?im)\b(?:[a-z0-9_]*password|[a-z0-9_]*passwd)["']?\s*[:=]\s*(["'])([^\r\n"']{8,256})\1''')


def project(text, instance_id):
    from peaso.secret_evidence import legacy_text
    legacy_text(text, instance_id)
    categories = []
    if _PRIVATE_KEY.search(text):
        categories.append("private_key")
    if _ACCESS.search(text) and _SECRET.search(text):
        categories.append("cloud_credential")
    for match in _PASSWORD.finditer(text):
        value = match.group(2)
        # Template expressions, documentation placeholders and interpolated
        # values are not literal credential witnesses.
        if (not any(marker in value for marker in ("$", "{{", "}}", "<", ">", "\\")) and
                not value.lower().startswith(("example", "your_", "replace_", "placeholder")) and
                re.search(r"[A-Za-z]", value) and re.search(r"[0-9!@#%^&*]", value)):
            categories.append("password_assignment")
            break
    return {"InstanceId": instance_id, "collection_status": "collected", "Present": bool(text),
            "HighConfidenceSecretPresent": bool(categories), "MatchedCategories": sorted(categories)}


def scan_selected_content(projected, text):
    """Only a named, opted-in caller invokes external offline detectors."""
    from peaso.secret_scanning import scan_content
    outcome = scan_with_source(scan_content, text.encode('utf-8'), 'ec2/user-data', source={'resource_id': projected['InstanceId'], 'path': 'ec2/user-data'})
    projected['ContentScan'] = outcome
    return projected

"""Offline contract for the CSPM document and API response header bindings."""
import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
OWNED_ARTIFACT_SOURCE = "https://${aws_s3_bucket.artifacts.bucket}.s3.amazonaws.com/artifacts/"


def block(source, opening):
    match = re.search(opening + r"\s*\{", source)
    if not match:
        raise AssertionError("Missing Terraform block: " + opening)
    start = match.end()
    depth, quoted, escaped = 1, False, False
    for position in range(start, len(source)):
        char = source[position]
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "{":
            depth += 1
        elif not quoted and char == "}":
            depth -= 1
            if depth == 0:
                return source[start:position]
    raise AssertionError("Unclosed Terraform block")


def directives(value):
    result = {}
    for raw in value.split(";"):
        words = raw.strip().split()
        if words:
            if words[0] in result:
                raise AssertionError("Duplicate CSP directive: " + words[0])
            result[words[0]] = words[1:]
    return result


class HostedCspHeaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tf = (ROOT / "infra/aws/frontend.tf").read_text()
        cls.security = block(cls.tf, r'resource "aws_cloudfront_response_headers_policy" "security"')
        cls.distribution = block(cls.tf, r'resource "aws_cloudfront_distribution" "cspm"')
        cls.csp_block = block(cls.security, "content_security_policy")
        match = re.search(r'content_security_policy\s*=\s*"([^"\n]+)"', cls.csp_block)
        if not match:
            raise AssertionError("CSP must be one literal reviewable policy")
        cls.csp = directives(match.group(1))

    def test_enforcement_and_execution_boundaries(self):
        self.assertRegex(self.csp_block, r"override\s*=\s*true")
        self.assertEqual(self.csp["default-src"], ["'self'"])
        self.assertEqual(self.csp["script-src"], ["'self'"])
        for forbidden in ["'unsafe-eval'", "'wasm-unsafe-eval'", "*"]:
            self.assertNotIn(forbidden, [v for values in self.csp.values() for v in values])

    def test_document_and_embed_restrictions(self):
        for name, values in {"object-src": ["'none'"], "base-uri": ["'self'"],
                             "form-action": ["'self'"], "frame-ancestors": ["'none'"],
                             "upgrade-insecure-requests": []}.items():
            self.assertEqual(self.csp[name], values)

    def test_only_owned_artifact_downloads_extend_connect(self):
        # API JSON envelopes can contain a direct private S3 URL. The browser
        # fetches it with credentials omitted, before creating a download blob.
        self.assertEqual(self.csp["connect-src"], ["'self'", OWNED_ARTIFACT_SOURCE])
        self.assertNotIn("https:", self.csp["connect-src"])
        self.assertNotIn("https://tools.hacktricks.wiki", self.csp["connect-src"])
        self.assertNotIn("https://*.amazonaws.com", self.csp["connect-src"])

    def test_layout_worker_and_style_compatibility(self):
        self.assertEqual(self.csp["worker-src"], ["'self'", "blob:"])
        self.assertEqual(self.csp["style-src"], ["'self'", "'unsafe-inline'"])
        self.assertEqual(self.csp["img-src"], ["'self'", "data:", "blob:"])
        self.assertEqual(self.csp["font-src"], ["'self'", "data:"])

    def test_same_policy_bound_to_frontend_and_api(self):
        default = block(self.distribution, "default_cache_behavior")
        ordered = block(self.distribution, "ordered_cache_behavior")
        binding = r"response_headers_policy_id\s*=\s*aws_cloudfront_response_headers_policy.security.id"
        self.assertRegex(default, binding)
        self.assertRegex(ordered, binding)
        self.assertRegex(ordered, r'path_pattern\s*=\s*"/api/\*"')
        self.assertEqual(len(re.findall(r"ordered_cache_behavior\s*\{", self.distribution)), 1)
        self.assertRegex(ordered, r"cache_policy_id\s*=\s*data.aws_cloudfront_cache_policy.api.id")
        self.assertRegex(ordered, r"origin_request_policy_id\s*=\s*data.aws_cloudfront_origin_request_policy.api.id")
        self.assertRegex(ordered, r'viewer_protocol_policy\s*=\s*"https-only"')

    def test_existing_security_headers_remain_enabled(self):
        content_type = block(self.security, "content_type_options")
        frame = block(self.security, "frame_options")
        hsts = block(self.security, "strict_transport_security")
        referrer = block(self.security, "referrer_policy")
        for value in [content_type, frame, hsts, referrer]:
            self.assertRegex(value, r"override\s*=\s*true")
        self.assertRegex(frame, r'frame_option\s*=\s*"DENY"')
        self.assertRegex(hsts, r"access_control_max_age_sec\s*=\s*31536000")
        self.assertRegex(hsts, r"include_subdomains\s*=\s*true")
        self.assertRegex(referrer, r'referrer_policy\s*=\s*"strict-origin-when-cross-origin"')


if __name__ == "__main__":
    unittest.main()

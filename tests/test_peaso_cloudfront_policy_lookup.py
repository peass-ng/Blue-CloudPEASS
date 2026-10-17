"""Offline regression for the CloudFront API managed-policy lookup and routing."""
from pathlib import Path
import re
import unittest


FRONTEND = Path(__file__).resolve().parents[1] / "infra/aws/frontend.tf"


class CloudFrontPolicyLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FRONTEND.read_text()

    def block(self, name, indent="  "):
        matches = re.findall(
            rf"^{indent}{name} \{{\n(.*?)^{indent}\}}", self.source, re.M | re.S
        )
        self.assertEqual(len(matches), 1, f"Expected one {name} block")
        return matches[0]

    def assert_setting(self, block, name, value):
        self.assertRegex(block, rf"(?m)^\s*{name}\s*=\s*{re.escape(value)}\s*$")

    def test_api_resolves_exact_managed_policy_name_instead_of_uuid(self):
        lookup = self.block('data "aws_cloudfront_cache_policy" "api"', indent="")
        self.assert_setting(lookup, "name", '"Managed-CachingDisabled"')
        self.assert_setting(self.block("ordered_cache_behavior"), "cache_policy_id",
                            "data.aws_cloudfront_cache_policy.api.id")
        self.assertNotIn("413f160e-6fd7-4b54-9aac-74d34941d972", self.source)
        self.assertNotRegex(self.source, r'"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}"')

    def test_api_keeps_authenticated_forwarding_and_write_methods(self):
        api = self.block("ordered_cache_behavior")
        expected = {
            "path_pattern": '"/api/*"',
            "target_origin_id": '"api"',
            "viewer_protocol_policy": '"https-only"',
            "allowed_methods": '["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]',
            "cached_methods": '["GET", "HEAD"]',
            "origin_request_policy_id": "data.aws_cloudfront_origin_request_policy.api.id",
            "compress": "true",
        }
        for name, value in expected.items():
            with self.subTest(setting=name):
                self.assert_setting(api, name, value)
        lookup = self.block('data "aws_cloudfront_origin_request_policy" "api"', indent="")
        self.assert_setting(lookup, "name", '"Managed-AllViewerExceptHostHeader"')

    def test_frontend_retains_caching_and_security_headers(self):
        frontend = self.block("default_cache_behavior")
        self.assert_setting(frontend, "cache_policy_id", "data.aws_cloudfront_cache_policy.frontend.id")
        lookup = self.block('data "aws_cloudfront_cache_policy" "frontend"', indent="")
        self.assert_setting(lookup, "name", '"Managed-CachingOptimized"')
        self.assert_setting(frontend, "target_origin_id", '"frontend"')
        self.assert_setting(frontend, "response_headers_policy_id",
                            "aws_cloudfront_response_headers_policy.security.id")
        self.assert_setting(frontend, "viewer_protocol_policy", '"redirect-to-https"')

    def test_private_s3_origin_and_tls_remain_enforced(self):
        oac = self.block('resource "aws_cloudfront_origin_access_control" "frontend"', indent="")
        self.assert_setting(oac, "origin_access_control_origin_type", '"s3"')
        self.assert_setting(oac, "signing_behavior", '"always"')
        self.assert_setting(oac, "signing_protocol", '"sigv4"')
        self.assert_setting(self.source, "origin_access_control_id",
                            "aws_cloudfront_origin_access_control.frontend.id")
        self.assert_setting(self.source, "origin_protocol_policy", '"https-only"')
        self.assert_setting(self.source, "origin_ssl_protocols", '["TLSv1.2"]')
        self.assert_setting(self.block("viewer_certificate"), "minimum_protocol_version",
                            '"TLSv1.2_2021"')


if __name__ == "__main__":
    unittest.main()

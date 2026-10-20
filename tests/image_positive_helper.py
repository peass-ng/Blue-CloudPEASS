"""Real image modules and existing native fixture builders."""
from portable_fixture import load_fixture
from peaso import secret_scanning as scanning
from peaso.collectors import gcp_image_secret_indicators as projection
from peaso.checks import gcp_image_secret_review_20261019 as check

fixtures = load_fixture("test_gcp_image_secret_review_20261019.py")

def positive(payload, path, timeout):
    return [(fixtures.TOKEN, "fixture-rule", 1)] if fixtures.TOKEN.encode() in payload else []

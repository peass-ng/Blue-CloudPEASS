"""Exact pure URL/bounds subset of the reviewed isolated ARM reader."""
import re
from urllib.parse import parse_qsl, urlsplit

HOST = "management.azure.com"
VERSION = "2024-11-01"
SITE_RE = re.compile(r"^/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/resourceGroups/([^/]+)/providers/Microsoft\.Web/sites/([^/]+)$", re.I)
MAX_PAGE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 4_000_000
MAX_PAGES = 8

def _url(path):
    return "https://" + HOST + path + "?api-version=" + VERSION


def _valid_url(url, path, *, continuation):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        return False
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != HOST or parsed.path != path or parsed.fragment or parsed.username or parsed.password:
        return False
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    if sum(k == "api-version" and v == VERSION for k, v in pairs) != 1 or any(k == "api-version" and v != VERSION for k, v in pairs):
        return False
    if not continuation and pairs != [("api-version", VERSION)]:
        return False
    return True

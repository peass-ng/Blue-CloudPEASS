"""Bounded read-only provider adapters. No evaluator has access to these clients."""
from __future__ import annotations
import json
from datetime import date, datetime
from itertools import count
import time
from urllib.parse import urlencode, urlsplit, quote
from peaso.snapshot import canonical, digest, make_snapshot, resource_id

# Types are stable across the wire; payloads retain their provider-native fields.
TYPES = {
    "aws": ["iam_user", "iam_group", "iam_role", "iam_policy", "bucket", "vpc", "subnet", "security_group", "instance", "route_table"],
    "gcp": ["iam_policy", "bucket", "network", "subnetwork", "firewall", "instance"],
    "azure": ["role_assignment", "role_definition", "storage_account", "vnet", "nsg", "nic", "vm"],
    "k8s": ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "pod", "service", "networkpolicy", "namespace"],
}


def _json(value):
    return json.loads(json.dumps(value, default=lambda x: x.isoformat() if isinstance(x, (datetime, date)) else str(x)))


def _error_status(exc):
    code = str(getattr(exc, "code", ""))
    response = getattr(exc, "response", {})
    if isinstance(response, dict):
        code = str(response.get("Error", {}).get("Code", code))
    text = str(exc).lower()
    if isinstance(exc, (TimeoutError,)) or "timeout" in text or "timed out" in text:
        return "timeout", {"kind": type(exc).__name__, "code": code or "read_timeout"}
    if isinstance(exc, ValueError):
        return "malformed", {"kind": type(exc).__name__, "code": "malformed_response"}
    denied = any(x in (code + " " + text).lower() for x in ("403", "401", "accessdenied", "unauthorized", "forbidden", "permission_denied"))
    return "denied" if denied else "unknown", {"kind": type(exc).__name__, "code": code or ("permission_denied" if denied else "read_failed")}


class Budget:
    def __init__(self, options):
        self.progress_callback = options.get("_progress_callback")
        def optional_limit(name):
            value = options.get(name)
            if value is None:
                return None
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(name + " must be a positive integer or omitted")
            return value
        self.max_pages = optional_limit("max_pages")
        self.max_items = optional_limit("max_resources")
        self.max_calls = optional_limit("max_calls")
        self.intentional_limits = {name: options[name] for name in ("max_pages", "max_resources", "max_calls") if options.get(name) is not None}
        self.cancel_event = options.get("cancel_event")
        self.deadline = options.get("deadline")
        self.calls = 0

    def call(self, operation, *args, **kwargs):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RuntimeError("collection_cancelled")
        if self.deadline is not None and time.time() >= self.deadline:
            raise TimeoutError("explicit collection deadline exceeded")
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise RuntimeError("collection call budget exhausted")
        self.calls += 1
        return operation(*args, **kwargs)


def _bound(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class Collector:
    def __init__(self, provider, scopes, options):
        self.provider, self.scopes = provider, scopes
        self.budget = Budget(options)
        inventories = options.get("inventories", TYPES[provider])
        if not isinstance(inventories, list) or any(x not in TYPES[provider] for x in inventories):
            raise ValueError("inventories must be a list of supported resource types")
        self.wanted = set(inventories)
        self.collections = []
        self.total_items = 0
        self.progress_callback = options.get("_progress_callback")

    def collect(self, kind, scope, service, fetch):
        if kind not in self.wanted:
            return
        from peaso.progress import emit_progress
        emit_progress(self.progress_callback, phase="collecting", provider=self.provider, scope=scope,
                      completed=len(self.collections), total=None, resources=self.total_items, dynamic_total=True)
        items = {}
        status, error = "collected", None
        try:
            pages = iter(fetch())
            for page_index, page in enumerate(pages):
                if self.budget.max_pages is not None and page_index >= self.budget.max_pages:
                    status, error = "partial", {"code": "page_limit"}
                    break
                if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                    status, error = "partial" if items else "malformed", {"code": "malformed_response"}
                    break
                for item in page:
                    rid = resource_id(self.provider, kind, scope, item)
                    if rid in items:
                        continue
                    if self.budget.max_items is not None and self.total_items >= self.budget.max_items:
                        status, error = "partial", {"code": "resource_limit"}
                        break
                    items[rid] = _json(item)
                    self.total_items += 1
                if status == "partial":
                    break
        except Exception as exc:
            unavailable, error = _error_status(exc)
            status = "partial" if items else unavailable
        if not items and status == "collected":
            status = "empty"
        envelope = {"type": kind, "scope": scope, "service": service, "status": status, "items": list(items.values())}
        if error:
            envelope["error"] = error
        self.collections.append(envelope)
        emit_progress(self.progress_callback, phase="collecting", provider=self.provider, scope=scope,
                      completed=len(self.collections), total=None, resources=self.total_items, dynamic_total=True)

    def fail_remaining(self, exc):
        status, error = _error_status(exc)
        existing = {(c["type"], c["scope"]) for c in self.collections}
        for scope in self.scopes:
            for kind in sorted(self.wanted):
                if (kind, scope) not in existing:
                    self.collections.append({"type": kind, "scope": scope, "service": kind, "status": status, "items": [], "error": error})

    def finish(self):
        return make_snapshot(self.provider, self.scopes, self.collections,
            metadata={"collection": "read-only", "calls": self.budget.calls, "max_calls": self.budget.max_calls,
                      "max_pages": self.budget.max_pages, "max_resources": self.budget.max_items, "intentional_limits": self.budget.intentional_limits,
                      "omitted_inventories": sorted(set(TYPES[self.provider]) - self.wanted)})


def _aws_pages(collector, client, operation, key, **kwargs):
    # SDK manual pagination imposes the same total budget as all other providers.
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[operation])
    input_members = model.input_shape.members if model.input_shape else {}
    token, seen = None, set()
    for _ in (count() if collector.budget.max_pages is None else range(collector.budget.max_pages)):
        arguments = dict(kwargs)
        if "MaxResults" in input_members:
            arguments["MaxResults"] = 100 if collector.budget.max_items is None else min(100, collector.budget.max_items)
        if token:
            arguments["Marker" if "Marker" in input_members else "NextToken"] = token
        result = collector.budget.call(getattr(client, operation), **arguments)
        batch = result.get(key)
        if not isinstance(batch, list):
            raise ValueError("malformed AWS list response")
        yield batch
        token = result.get("Marker") or result.get("NextToken") or result.get("ContinuationToken")
        if not token:
            return
        if token in seen:
            raise ValueError("repeated pagination token")
        seen.add(token)
    raise RuntimeError("page budget exhausted")


def _http_pages(collector, url, read, *, key="items", next_key="nextPageToken", query=None, token_query="pageToken", transform=None):
    origin = urlsplit(url)
    seen, current = set(), url
    for _ in (count() if collector.budget.max_pages is None else range(collector.budget.max_pages)):
        # Do not send bearer tokens to a different host supplied by a nextLink.
        parsed = urlsplit(current)
        if parsed.scheme != "https" or parsed.netloc != origin.netloc:
            raise ValueError("unsafe pagination origin")
        response = collector.budget.call(read, current)
        if not isinstance(response, dict):
            raise ValueError("malformed JSON response")
        items = response.get(key, [])
        if transform:
            items = transform(items)
        if not isinstance(items, list):
            raise ValueError("malformed list response")
        yield items
        token = response.get(next_key) or (response.get("metadata") or {}).get("continue")
        if not token:
            return
        if token in seen:
            raise ValueError("repeated pagination token")
        seen.add(token)
        if next_key == "nextLink":
            current = token
        else:
            separator = "&" if "?" in url else "?"
            current = url + separator + urlencode({token_query: token})
    raise RuntimeError("page budget exhausted")


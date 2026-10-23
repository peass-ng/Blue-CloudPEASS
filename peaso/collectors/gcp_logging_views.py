"""Read existing Cloud Logging views and their IAM policies."""

import re

from .gcp import ReadError


def collection_pages(collector, scope):
    """List all bucket locations, then exact views and their policies."""
    root = "https://logging.googleapis.com/v2/"
    seen_buckets = set()
    seen_views = set()
    for buckets, bucket_request in collector.pages(
            root + scope + "/locations/-/buckets", scope, key="buckets"):
        yield [], bucket_request
        for bucket in buckets:
            name = bucket.get("name")
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(scope) + r"/locations/[a-z0-9-]+/buckets/[A-Za-z0-9_.-]+", name)
                    or name in seen_buckets):
                raise ReadError("malformed", "logging_view_bucket_identity_unbound")
            seen_buckets.add(name)
            for views, view_request in collector.pages(root + name + "/views", scope, key="views"):
                rows = []
                for view in views:
                    view_name = view.get("name")
                    if (not isinstance(view_name, str) or not re.fullmatch(
                            re.escape(name) + r"/views/[A-Za-z0-9_-]+", view_name)
                            or view_name in seen_views):
                        raise ReadError("malformed", "logging_view_identity_unbound")
                    seen_views.add(view_name)
                    rows.append(view)
                def policy(view):
                    return collector.hydrate(
                        view, "iamPolicy", root + view["name"] + ":getIamPolicy", scope,
                        method="POST", body={"options": {"requestedPolicyVersion": 3}})
                yield collector.parallel(policy, rows), view_request

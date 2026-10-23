"""Small hosted Kubernetes preflight transport; no generated SDK in Lambda.

The collector's existing origin/path/method guard still governs every request.
Only public TLS endpoints and embedded customer credentials are accepted.
"""
import base64
import json
from pathlib import Path
import ssl
import tempfile
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import urllib3

from peaso.collectors.k8s import _BoundedPool, _public_server, hosted_auth

MAX_RESPONSE = 2 * 1024 * 1024


class AccessReadError(Exception):
    def __init__(self, status):
        super().__init__("Kubernetes access check failed")
        self.status = status


class _Response:
    def __init__(self, response):
        self.response = response
        self._data = None

    @property
    def data(self):
        if self._data is None:
            self._data = self.response.read(MAX_RESPONSE + 1)
            if len(self._data) > MAX_RESPONSE:
                raise ValueError("Kubernetes access response exceeds the limit")
        return self._data

    def read(self):
        return self.data

    def close(self):
        self.response.close()

    def release_conn(self):
        self.response.release_conn()


def _pem(value):
    return value.encode() if value.startswith("-----BEGIN") else base64.b64decode(value, validate=True)


class HostedAccessApi:
    def __init__(self, auth):
        selected = hosted_auth(auth)
        origin = urlsplit(selected["server"])
        pinned, hostname = _public_server(selected["server"])
        destination = urlsplit(pinned)
        hostname = selected.get("tls_server_name") or hostname
        ca = selected.get("ca_cert_data")
        context = ssl.create_default_context(cadata=_pem(ca).decode("ascii") if ca else None)
        self.temporary = None
        try:
            if selected.get("client_cert_data") or selected.get("client_key_data"):
                if not selected.get("client_cert_data") or not selected.get("client_key_data"):
                    raise ValueError("Client certificate and key must be supplied together")
                self.temporary = tempfile.TemporaryDirectory(prefix="peaso-k8s-access-")
                paths = []
                for key in ("client_cert_data", "client_key_data"):
                    path = Path(self.temporary.name) / key
                    with path.open("xb") as stream:
                        path.chmod(0o600)
                        stream.write(_pem(selected[key]))
                    paths.append(str(path))
                context.load_cert_chain(*paths)
            self.pool = urllib3.HTTPSConnectionPool(destination.hostname, port=destination.port or 443,
                ssl_context=context, assert_hostname=hostname, server_hostname=hostname,
                maxsize=8, block=True, timeout=urllib3.Timeout(connect=5, read=15))
        except Exception:
            if self.temporary:
                self.temporary.cleanup()
            raise
        self.base = pinned.rstrip("/")
        self.headers = {"Host": origin.netloc, "Accept": "application/json"}
        if selected.get("token"):
            self.headers["Authorization"] = "Bearer " + selected["token"]
        self.rest_client = SimpleNamespace(pool_manager=_BoundedPool(self.pool, pinned))
        self.api_client = self

    def call_api(self, path, method, *, query_params=None, body=None, **kwargs):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Access checks require an API-relative path")
        url = self.base + path
        if query_params:
            url += ("&" if "?" in path else "?") + urlencode(query_params)
        headers = dict(self.headers)
        raw = None
        if body is not None:
            raw = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        response = self.rest_client.pool_manager.request(method, url, headers=headers, body=raw,
            preload_content=False)
        if not 200 <= response.status < 300:
            status = response.status
            response.close()
            response.release_conn()
            raise AccessReadError(status)
        return _Response(response)

    def close(self):
        self.pool.close()
        if self.temporary:
            self.temporary.cleanup()

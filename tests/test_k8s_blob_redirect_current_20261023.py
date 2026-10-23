"""MCR blob redirect boundaries and final-byte verification."""
import hashlib
from io import BytesIO
import unittest

from peaso.collectors.k8s_selected_registry_image_20261021 import (
    Incomplete, RegistryReader, _blob_redirect,
)


class Response:
    def __init__(self, status, body=b'', location=None):
        self.status = status
        self.data = BytesIO(body)
        self.headers = {'Content-Length': str(len(body)), 'Content-Encoding': 'identity'}
        if location is not None:
            self.headers['Location'] = location

    def read(self, count):
        return self.data.read(count)

    def close(self):
        pass


class Connection:
    def close(self):
        pass


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.body = b'owned registry blob fixture'
        self.digest = 'sha256:' + hashlib.sha256(self.body).hexdigest()
        self.location = 'https://westeurope.data.mcr.microsoft.com/owned/blob?signature=private'

    def reader(self, wire, **kwargs):
        return RegistryReader('mcr.microsoft.com', 'oss/kubernetes/pause', lambda: None,
                              open_https=wire, **kwargs)

    def test_blob_follows_provider_cdn_without_forwarding_credentials_or_persisting_query(self):
        calls = []
        def wire(host, path, headers, timeout):
            calls.append((host, path, dict(headers)))
            return Connection(), Response(307, location=self.location) if len(calls) == 1 else Response(200, self.body)
        reader = self.reader(wire, authorization='Bearer private-registry-token')
        self.assertEqual(reader.get('blobs', self.digest, 1024, size=len(self.body)), self.body)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0], 'westeurope.data.mcr.microsoft.com')
        self.assertEqual(calls[1][1], '/owned/blob?signature=private')
        self.assertIn('Authorization', calls[0][2])
        self.assertNotIn('Authorization', calls[1][2])
        self.assertNotIn('Cookie', calls[1][2])
        self.assertEqual(reader.calls, 2)
        self.assertEqual(reader.receipts[0]['bytes'], len(self.body))
        self.assertNotIn('signature', str(reader.receipts))

    def test_manifest_redirect_is_rejected(self):
        reader = self.reader(lambda *_: (Connection(), Response(307, location=self.location)))
        with self.assertRaisesRegex(Incomplete, 'redirect_unsupported'):
            reader.get('manifests', self.digest, 1024)

    def test_foreign_or_malformed_blob_redirects_are_rejected(self):
        for location in (
            'http://westeurope.data.mcr.microsoft.com/blob',
            'https://169.254.169.254/blob',
            'https://storage.googleapis.com/blob',
            'https://westeurope.data.mcr.microsoft.com:8443/blob',
            'https://user:pass@westeurope.data.mcr.microsoft.com/blob',
            'https://westeurope.data.mcr.microsoft.com/blob#fragment',
            'https://westeurope.data.mcr.microsoft.com\\@evil.example/blob',
        ):
            with self.subTest(location=location), self.assertRaises(Incomplete):
                _blob_redirect('mcr.microsoft.com', location)

    def test_redirect_hop_bound_and_digest_verification(self):
        calls = []
        def loop(host, path, headers, timeout):
            calls.append(host)
            return Connection(), Response(307, location=self.location)
        with self.assertRaisesRegex(Incomplete, 'redirect_unsupported'):
            self.reader(loop).get('blobs', self.digest, 1024)
        self.assertEqual(len(calls), 3)

        def changed(host, path, headers, timeout):
            return Connection(), Response(307, location=self.location) if host == 'mcr.microsoft.com' else Response(200, b'changed')
        with self.assertRaisesRegex(Incomplete, 'registry_truncated_or_digest'):
            self.reader(changed).get('blobs', self.digest, 1024)


if __name__ == '__main__':
    unittest.main()

"""Task-private HTTP model relay. Real model auth never enters the agent container."""
import base64
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time
import sys

PORT = 8765
MAX_REQUEST = 16 * 1024 * 1024
UPSTREAM = 'https://chatgpt.com/backend-api'


def placeholder(account_id):
    """A relay capability in JWT shape; it is not an OpenAI access credential."""
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return '.'.join([encode({'alg': 'none'}), encode({'exp': int(time.time()) + 3600,
        'https://api.openai.com/auth': {'chatgpt_account_id': account_id}}), secrets.token_urlsafe(32)])


def serve(config, *, server_class=ThreadingHTTPServer):
    from .auth import claims
    token = config['token']
    account = (claims(token).get('https://api.openai.com/auth') or {}).get('chatgpt_account_id')
    if not isinstance(account, str) or not account:
        raise ValueError('invalid_model_identity')
    capability = placeholder(account)
    public = {key: config[key] for key in ('stage', 'timeout')}
    public['relay_token'] = capability
    duration = max(1, min(1800, config['timeout'], config.get('expires_at', time.time() + config['timeout']) - time.time()))
    public['timeout'] = max(1, int(duration))
    deadline = time.monotonic() + duration
    lock = threading.Lock()
    state = {'calls': 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass  # Paths, errors and headers may contain secrets.

        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def reply(self, status, data):
            raw = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == '/bootstrap':
                return self.reply(200, public)
            if self.path == '/input' and self.authorized():
                return self.input_bundle()
            self.forward()

        def do_POST(self):
            if self.path == '/result' and self.authorized():
                lengths = self.headers.get_all('Content-Length', [])
                if (len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 9
                        or int(lengths[0]) > 8_000_000 or self.headers.get('Transfer-Encoding')):
                    return self.reply(413, {'error': 'result_limit'})
                try:
                    from .task_runtime import transfer
                    body = self.rfile.read(int(lengths[0]))
                    json.loads(body)
                    transfer('PUT', config['output_url'], body=body, limit=1024)
                    return self.reply(200, {'stored': True})
                except Exception:
                    return self.reply(502, {'error': 'result_transfer_failed'})
            self.forward()

        def authorized(self):
            return (time.monotonic() < deadline and
                    hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + capability))

        def input_bundle(self):
            import requests
            from .fargate import MAX_INPUT
            try:
                with requests.Session() as session:
                    session.trust_env = False
                    with session.get(config['input_url'], stream=True, allow_redirects=False, timeout=(10, 60)) as response:
                        if response.status_code != 200:
                            return self.reply(502, {'error': 'input_transfer_failed'})
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        total = 0
                        for chunk in response.iter_content(65536):
                            total += len(chunk)
                            if total > MAX_INPUT or time.monotonic() >= deadline:
                                break
                            self.wfile.write(chunk)
                        self.close_connection = True
            except Exception:
                self.close_connection = True

        def forward(self):
            from urllib.parse import urlsplit, parse_qs
            parsed = urlsplit(self.path)
            allowed = (self.command == 'POST' and parsed.path in ('/codex/responses', '/codex/responses/compact')
                       and not parsed.query or self.command == 'GET' and parsed.path == '/codex/models'
                       and set(parse_qs(parsed.query)) <= {'client_version'})
            if (not allowed or parsed.scheme or parsed.netloc or parsed.fragment
                    or not self.authorized()):
                return self.reply(403, {'error': 'relay_request_denied'})
            lengths = self.headers.get_all('Content-Length', [])
            if (self.headers.get('Transfer-Encoding') or len(lengths) > 1 or
                    lengths and (not lengths[0].isdigit() or len(lengths[0]) > 9 or int(lengths[0]) > MAX_REQUEST)):
                return self.reply(413, {'error': 'relay_request_limit'})
            body = self.rfile.read(int(lengths[0])) if lengths else b''
            with lock:
                state['calls'] += 1
                if state['calls'] > 128 or time.monotonic() >= deadline:
                    return self.reply(429, {'error': 'relay_budget_exhausted'})
            import requests
            try:
                with requests.Session() as session:
                    session.trust_env = False
                    response = session.request(self.command, UPSTREAM + self.path, data=body or None,
                        headers={'Authorization': 'Bearer ' + token, 'ChatGPT-Account-ID': account,
                            'Content-Type': 'application/json', 'Accept': self.headers.get('Accept', 'text/event-stream'),
                            'Accept-Encoding': 'identity',
                            'OpenAI-Beta': self.headers.get('OpenAI-Beta', 'responses=experimental'),
                            'originator': 'codex_cli_rs',
                            'User-Agent': 'cspm-isolated-codex-relay',
                            **{name: self.headers[name] for name in ('session_id', 'conversation_id',
                                'x-codex-turn-state', 'x-codex-beta-features') if self.headers.get(name)}},
                        stream=True, allow_redirects=False, timeout=(10, min(120, max(1, deadline - time.monotonic()))))
                    with response:
                        if response.status_code != 200:
                            print('ai_model_upstream_status=' + str(response.status_code), file=sys.stderr, flush=True)
                            # No provider error, redirect header or token-bearing
                            # diagnostics may reach the untrusted shell.
                            return self.reply(502, {'error': 'model_upstream_unavailable'})
                        self.send_response(200)
                        self.send_header('Content-Type', response.headers.get('Content-Type', 'text/event-stream'))
                        for name in ('x-codex-turn-state', 'x-request-id'):
                            if response.headers.get(name):
                                self.send_header(name, response.headers[name])
                        self.send_header('Connection', 'close')
                        self.send_header('Cache-Control', 'no-store')
                        self.end_headers()
                        total = 0
                        for chunk in response.iter_content(chunk_size=4096):
                            total += len(chunk)
                            if total > 32 * 1024 * 1024 or time.monotonic() >= deadline:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        self.close_connection = True
            except Exception:
                self.close_connection = True

    server = server_class(('127.0.0.1', PORT), Handler)
    timer = threading.Timer(max(1, deadline - time.monotonic()), server.shutdown)
    timer.daemon = True
    timer.start()
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        timer.cancel()
        server.server_close()

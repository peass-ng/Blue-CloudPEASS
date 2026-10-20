"""Bound actual ASGI request bytes before routing or JSON/Pydantic parsing."""
from starlette.responses import JSONResponse


class RequestBodyLimit:
    def __init__(self, app, max_bytes=16 * 1024 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        lengths = [v for k, v in scope.get('headers', []) if k.lower() == b'content-length']
        transfer = any(k.lower() == b'transfer-encoding' for k, v in scope.get('headers', []))
        if len(lengths) > 1 or lengths and (transfer or not lengths[0].isdigit()):
            return await JSONResponse({'detail': 'Invalid request length'}, status_code=400)(scope, receive, send)
        # Bound numeric length parsing too; extremely long digits must not raise
        # an uncaught ValueError or consume arbitrary integer conversion work.
        if lengths and (len(lengths[0]) > 16 or int(lengths[0]) > self.max_bytes):
            return await JSONResponse({'detail': 'Request too large'}, status_code=413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            if len(chunk) > self.max_bytes - len(body):
                # Stop receiving immediately; never pass a partial JSON body to
                # the router and never buffer the rest of an oversized upload.
                return await JSONResponse({'detail': 'Request too large'}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get('more_body', False):
                break
        if lengths and len(body) != int(lengths[0]):
            return await JSONResponse({'detail': 'Invalid request length'}, status_code=400)(scope, receive, send)
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()
        return await self.app(scope, bounded_receive, send)

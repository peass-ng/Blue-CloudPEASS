"""Bounded offline text normalization for already base64-decoded EC2 user data.

No command execution, include retrieval, file extraction or network access. MIME
parts and gzip bytes stay transient; only decoded text reaches existing scanners.
"""
import base64
from email import policy
from email.parser import BytesParser
import quopri
import re
import zlib

MAX_INPUT = 16384
MAX_TEXT = 1024 * 1024
MAX_WORK = 4 * MAX_TEXT
MAX_PARTS = 32
MAX_DEPTH = 4
MAX_GZIP_MEMBERS = 8
_HEADER = re.compile(rb'(?im)^(?:mime-version|content-type|content-transfer-encoding):')


def _text(raw):
    value = raw.decode('utf-8-sig')
    if any(ord(char) < 32 and char not in '\t\r\n' for char in value):
        raise ValueError('binary user data unsupported')
    return value


def _inflate(raw, state):
    output = []
    for _ in range(MAX_GZIP_MEMBERS):
        if not raw:
            return b''.join(output)
        if not raw.startswith(b'\x1f\x8b'):
            raise ValueError('invalid gzip tail')
        decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        try:
            expanded = decoder.decompress(raw, MAX_TEXT + 1)
        except zlib.error:
            raise ValueError('malformed gzip user data') from None
        if len(expanded) > MAX_TEXT or not decoder.eof or decoder.unconsumed_tail:
            raise ValueError('gzip expansion incomplete or bounded')
        state['work'] += len(expanded)
        if state['work'] > MAX_WORK or sum(map(len, output)) + len(expanded) > MAX_TEXT:
            raise ValueError('user data expansion bound')
        output.append(expanded)
        raw = decoder.unused_data
    if raw:
        raise ValueError('gzip member bound')
    return b''.join(output)


def decoded_text(raw):
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise ValueError('encoded native user data bound')
    state = {'parts': 0, 'work': 0, 'text': 0}
    values = []

    def add(data):
        value = _text(data)
        state['text'] += len(value.encode('utf-8')) + (1 if values else 0)
        if state['text'] > MAX_TEXT:
            raise ValueError('user data text bound')
        values.append(value)

    def visit(data, depth):
        if depth > MAX_DEPTH:
            raise ValueError('user data nesting bound')
        if data.startswith(b'\x1f\x8b'):
            return visit(_inflate(data, state), depth + 1)
        if (data.startswith((b'PK\x03\x04', b'BZh', b'\xfd7zXZ', b'7z\xbc\xaf', b'Rar!', b'\x28\xb5\x2f\xfd'))
                or data[257:262] == b'ustar'):
            raise ValueError('unsupported user data archive')
        header = re.split(rb'\r?\n\r?\n', data, maxsplit=1)[0]
        first = header.splitlines()[0] if header else b''
        starts_header = bool(re.match(rb'^[!-9;-~]+:', first))
        if not starts_header or not _HEADER.search(header):
            add(data)
            return
        message = BytesParser(policy=policy.default.clone(raise_on_defect=True)).parsebytes(data)
        walk(message, depth)

    def walk(message, depth):
        state['parts'] += 1
        if depth > MAX_DEPTH or state['parts'] > MAX_PARTS or message.defects:
            raise ValueError('MIME user data bound or defect')
        # Header values can themselves contain a secret. Keep original header
        # spellings in the transient detector input; filenames are never used
        # as paths for file extraction or passed to an external program.
        for name, value in message.raw_items():
            if len(message.get_all(name, [])) != 1:
                raise ValueError('duplicate MIME header')
            add((name + ': ' + value).encode('utf-8'))
        if message.is_multipart():
            if message.get_content_maintype() != 'multipart':
                raise ValueError('unsupported MIME message attachment')
            if message.preamble:
                add(message.preamble.encode('utf-8'))
            for part in message.iter_parts():
                walk(part, depth + 1)
            if message.epilogue:
                add(message.epilogue.encode('utf-8'))
            return
        charset = message.get_content_charset('utf-8').lower()
        if charset not in ('utf-8', 'utf8', 'us-ascii', 'ascii'):
            raise ValueError('unsupported MIME charset')
        transfer = message.get('Content-Transfer-Encoding', '8bit').lower().strip()
        payload = message.get_payload(decode=False)
        if type(payload) is not str:
            raise ValueError('unsupported MIME payload')
        if transfer == 'base64':
            compact = re.sub(rb'[ \t\r\n]', b'', payload.encode('ascii'))
            content = base64.b64decode(compact, validate=True)
        elif transfer == 'quoted-printable':
            if re.search(r'=(?![0-9a-fA-F]{2}|\r?\n)', payload):
                raise ValueError('malformed MIME quoted printable')
            content = quopri.decodestring(payload.encode('ascii'))
        elif transfer in ('7bit', '8bit', 'binary'):
            content = message.get_payload(decode=True)
        else:
            raise ValueError('unsupported MIME transfer encoding')
        if type(content) is not bytes:
            raise ValueError('unsupported MIME body')
        if len(content) > MAX_TEXT:
            raise ValueError('MIME payload bound')
        visit(content, depth + 1)

    visit(raw, 0)
    if len(values) == 1:
        return values[0]
    return '\n'.join(values)

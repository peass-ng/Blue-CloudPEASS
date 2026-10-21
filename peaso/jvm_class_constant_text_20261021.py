"""Bounded JVM constant-pool text extraction; no bytecode loading or execution.

Only CONSTANT_Utf8 entries are inspected. Encrypted/computed strings, method
bodies, custom attributes and runtime values are outside this extraction. The
caller must retain partial coverage even when every supported constant is read.
JVMS25 sections4.1/4.4/4.4.7 define the byte layout and modified UTF-8 encoding.
"""
MAX_CLASS_BYTES = 1048576
MAX_CONSTANTS = 8192
MAX_TEXT_BYTES = 1048576


def _modified_utf8(raw):
    # Modified UTF-8 uses C0 80 for NUL and UTF-16 surrogate pairs for astral
    # characters. Overlong encodings and four-byte UTF-8 are not valid here.
    if b'\x00' in raw:
        raise ValueError('unsupported_class_encoding')
    pos = 0
    units = bytearray()
    while pos < len(raw):
        first = raw[pos]
        if 1 <= first <= 0x7f:
            value, size = first, 1
        elif 0xc0 <= first <= 0xdf and pos + 1 < len(raw) and raw[pos + 1] & 0xc0 == 0x80:
            value = ((first & 0x1f) << 6) | (raw[pos + 1] & 0x3f)
            if value < 0x80 and not (first == 0xc0 and raw[pos + 1] == 0x80):
                raise ValueError('unsupported_class_encoding')
            size = 2
        elif 0xe0 <= first <= 0xef and pos + 2 < len(raw) and all(b & 0xc0 == 0x80 for b in raw[pos + 1:pos + 3]):
            value = ((first & 0x0f) << 12) | ((raw[pos + 1] & 0x3f) << 6) | (raw[pos + 2] & 0x3f)
            if value < 0x800:
                raise ValueError('unsupported_class_encoding')
            size = 3
        else:
            raise ValueError('unsupported_class_encoding')
        units.extend(value.to_bytes(2, 'big'))
        pos += size
    value = units.decode('utf-16-be', errors='strict')
    # Keep token boundaries when a constant contains control characters.
    return ''.join(c if ord(c) >= 32 and ord(c) != 127 or c in '\t\n\r' else '\n' for c in value).encode('utf-8')


def extract_constant_text(payload):
    """Return UTF-8 constant entries; ValueError means no usable extraction.

    This validates pool framing, supported tags, wide slots and text encoding.
    It is deliberately not a JVM verifier and does not certify the class body.
    """
    if type(payload) is not bytes or not 24 <= len(payload) <= MAX_CLASS_BYTES or payload[:4] != b'\xca\xfe\xba\xbe':
        raise ValueError('unsupported_class_header')
    minor, major, count = (int.from_bytes(payload[n:n + 2], 'big') for n in (4, 6, 8))
    if not 45 <= major <= 69 or major >= 56 and minor not in (0, 65535) or not 2 <= count <= MAX_CONSTANTS:
        raise ValueError('unsupported_class_version_or_bound')
    # (payload bytes, constant-pool slots); tag1 is variable-length text.
    widths = {3: (4, 1), 4: (4, 1), 5: (8, 2), 6: (8, 2),
              7: (2, 1), 8: (2, 1), 9: (4, 1), 10: (4, 1),
              11: (4, 1), 12: (4, 1), 15: (3, 1), 16: (2, 1),
              17: (4, 1), 18: (4, 1), 19: (2, 1), 20: (2, 1)}
    offset, index, total, texts = 10, 1, 0, []
    while index < count:
        if offset >= len(payload):
            raise ValueError('truncated_class_pool')
        tag = payload[offset]
        offset += 1
        if tag == 1:
            if offset + 2 > len(payload):
                raise ValueError('truncated_class_text')
            size = int.from_bytes(payload[offset:offset + 2], 'big')
            offset += 2
            if offset + size > len(payload):
                raise ValueError('truncated_class_text')
            text = _modified_utf8(payload[offset:offset + size])
            total += len(text) + 1
            if total > MAX_TEXT_BYTES:
                raise ValueError('class_text_bound')
            texts.append(text)
            slots = 1
        else:
            if tag not in widths:
                raise ValueError('unsupported_class_tag')
            size, slots = widths[tag]
            if index + slots > count:
                raise ValueError('invalid_class_wide_slot')
        offset += size
        if offset > len(payload):
            raise ValueError('truncated_class_pool')
        index += slots
    # At least the fixed header and empty interface/field/method/attribute counts
    # follow the pool. Variable class-body contents are deliberately uninspected.
    if offset + 14 > len(payload) or not texts:
        raise ValueError('truncated_or_textless_class')
    return b'\n'.join(texts)

"""Bounded gzip expansion without reserving the full limit per audit object."""
import gzip
import io
import zlib


class ExpansionLimitError(ValueError):
    pass


def read_gzip(data, limit):
    if type(limit) is not int or limit < 0:
        raise ValueError('Invalid expansion limit')
    # The C decoder bounds its growing output without BufferedReader's large
    # up-front allocation. Most CloudTrail objects contain one gzip member.
    # Keep GzipFile authoritative for multiple members, unusual headers and
    # errors, including its existing trailer/error semantics.
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        expanded = decoder.decompress(data, limit + 1)
        if len(expanded) > limit:
            raise ExpansionLimitError()
        if decoder.eof and not decoder.unused_data.strip(b'\0'):
            return expanded
    except zlib.error:
        pass
    # Release the speculative output and unused compressed tail before the
    # compatibility path allocates its bounded buffers. Never emit partial data.
    decoder = expanded = None
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        # A short buffered read reaches EOF and validates the gzip trailer.
        # Larger objects grow one bounded chunk at a time. The final extra
        # byte distinguishes an exact-limit object from an oversized one.
        # ISIZE is only an allocation hint, never an accepted length: it may
        # describe just the last gzip member or be corrupt. Clamp it, then
        # continue to EOF regardless and let gzip validate every member.
        hint = int.from_bytes(data[-4:], 'little') + 1
        first_read = min(1024 * 1024, limit + 1, max(64 * 1024, hint))
        expanded = stream.read(first_read)
        if len(expanded) > limit:
            raise ExpansionLimitError()
        if len(expanded) == first_read:
            expanded = bytearray(expanded)
            while True:
                remaining = limit - len(expanded)
                chunk = stream.read(min(1024 * 1024, remaining + 1))
                if len(chunk) > remaining:
                    raise ExpansionLimitError()
                if not chunk:
                    break
                expanded.extend(chunk)
    return expanded

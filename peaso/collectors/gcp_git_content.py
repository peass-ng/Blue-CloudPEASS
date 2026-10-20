"""Offline SHA-1 PACK decoder for explicitly selected immutable Git files.

No transport, credentials, object database, filesystem or Git execution. Raw bytes
are deliberately excluded from repr. This is selected-file coverage only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import re
import time
import zlib
from typing import Callable, Sequence

MAX_WIRE = 8 * 1024 * 1024
MAX_OBJECT = 1024 * 1024
MAX_INFLATED = 16 * 1024 * 1024
MAX_OBJECTS = 4096
MAX_DELTA_DEPTH = 32
MAX_TREE_DEPTH = 32
MAX_FILES = 8
MAX_FILE = 256 * 1024
MAX_SELECTED = 2 * 1024 * 1024
MAX_PATH = 1024
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PERSON = re.compile(rb"[^\x00-\x1f\x7f<>]+ <[^\x00-\x1f\x7f<>]*> -?[0-9]+ [+-][0-9]{4}\Z")


class GitContentError(ValueError):
    """Static reason only; never accepts provider/object content."""
    def __init__(self) -> None:
        super().__init__("git_content_rejected")


@dataclass(frozen=True)
class SelectedGitFile:
    path: str = field(repr=False)
    object_sha: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class GitContentResult:
    commit_sha: str
    files: tuple[SelectedGitFile, ...] = field(repr=False)
    object_count: int
    inflated_bytes: int
    wire_bytes: int
    selected_bytes: int


@dataclass(repr=False)
class _Object:
    offset: int
    kind: int
    data: bytes
    base: int | bytes | None = None
    depth: int = 0
    oid: bytes | None = None


class _Budget:
    def __init__(self, cancelled: Callable[[], bool] | None, deadline: float | None):
        self.total = 0
        self.cancelled = cancelled
        self.deadline = deadline

    def check(self) -> None:
        try:
            stopped = self.cancelled is not None and bool(self.cancelled())
        except Exception:
            raise GitContentError() from None
        if stopped or (self.deadline is not None and time.monotonic() >= self.deadline):
            raise GitContentError()

    def reserve(self, size: int) -> None:
        self.check()
        if size < 0 or size > MAX_OBJECT or self.total + size > MAX_INFLATED:
            raise GitContentError()
        self.total += size


def validate_selection(commit_sha: str, paths: Sequence[str]) -> tuple[str, ...]:
    """Validate before fetching; paths are exact UTF-8 relative POSIX names."""
    if not isinstance(commit_sha, str) or not _SHA.fullmatch(commit_sha):
        raise GitContentError()
    if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= MAX_FILES:
        raise GitContentError()
    seen = set()
    for path in paths:
        if not isinstance(path, str) or len(path) > MAX_PATH:
            raise GitContentError()
        try:
            encoded = path.encode("utf-8")
        except UnicodeError:
            raise GitContentError() from None
        if (not encoded or len(encoded) > MAX_PATH or b"\\" in encoded
                or any(c < 32 or c == 127 for c in encoded)
                or any(p in ("", ".", "..", ".git") for p in path.split("/"))
                or len(path.split("/")) > MAX_TREE_DEPTH or path in seen):
            raise GitContentError()
        seen.add(path)
    return tuple(paths)


def _varint(data: bytes, pos: int, limit: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 28, 7):
        if pos >= len(data):
            raise GitContentError()
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if value > limit:
            raise GitContentError()
        if not byte & 128:
            return value, pos
    raise GitContentError()


def _inflate(wire: bytes, pos: int, end: int, size: int, budget: _Budget) -> tuple[bytes, int]:
    budget.reserve(size)
    decoder = zlib.decompressobj()
    chunks = []
    length = 0
    try:
        while not decoder.eof:
            budget.check()
            if pos >= end:
                raise GitContentError()
            chunk = memoryview(wire)[pos:min(pos + 65536, end)]
            # A bounded scratch byte detects a lying size. Its allowance is
            # checked against the aggregate ceiling before asking zlib for it.
            remaining = size - length
            allowance = remaining + (budget.total < MAX_INFLATED)
            if not allowance:
                raise GitContentError()
            part = decoder.decompress(chunk, min(65536, allowance))
            # At EOF zlib can expose the same remainder in both attributes.
            remainder = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
            used = len(chunk) - len(remainder)
            pos += used
            length += len(part)
            if length > size or (used == 0 and not part and not decoder.eof):
                raise GitContentError()
            chunks.append(part)
        if length != size:
            raise GitContentError()
        return b"".join(chunks), pos
    except zlib.error:
        raise GitContentError() from None


def _delta(base: bytes, instructions: bytes, budget: _Budget) -> bytes:
    source_size, pos = _varint(instructions, 0, MAX_OBJECT)
    size, pos = _varint(instructions, pos, MAX_OBJECT)
    if source_size != len(base):
        raise GitContentError()
    budget.reserve(size)
    result = bytearray()
    while pos < len(instructions):
        budget.check()
        opcode = instructions[pos]
        pos += 1
        if opcode & 128:
            offset = count = 0
            for bit in range(7):
                if opcode & (1 << bit):
                    if pos >= len(instructions):
                        raise GitContentError()
                    value = instructions[pos]
                    pos += 1
                    if bit < 4:
                        offset |= value << (8 * bit)
                    else:
                        count |= value << (8 * (bit - 4))
            count = count or 65536
            if offset + count > len(base) or len(result) + count > size:
                raise GitContentError()
            result.extend(memoryview(base)[offset:offset + count])
        else:
            count = opcode
            if not count or pos + count > len(instructions) or len(result) + count > size:
                raise GitContentError()
            result.extend(memoryview(instructions)[pos:pos + count])
            pos += count
    if len(result) != size:
        raise GitContentError()
    return bytes(result)


def _identity(kind: int, data: bytes) -> bytes:
    names = {1: b"commit", 2: b"tree", 3: b"blob"}
    digest = hashlib.sha1(names[kind] + b" " + str(len(data)).encode("ascii") + b"\0")
    digest.update(data)
    return digest.digest()


def _tree(data: bytes, budget: _Budget) -> dict[bytes, tuple[bytes, bytes]]:
    entries = {}
    pos = 0
    previous = None
    while pos < len(data):
        budget.check()
        space = data.find(b" ", pos, pos + 8)
        nul = data.find(b"\0", space + 1, space + 2 + MAX_PATH) if space >= 0 else -1
        if space < 0 or nul < 0 or nul + 21 > len(data):
            raise GitContentError()
        mode, name = data[pos:space], data[space + 1:nul]
        if (mode not in (b"40000", b"100644", b"100755", b"120000", b"160000")
                or not name or name in (b".", b"..", b".git") or b"/" in name
                or b"\\" in name or any(c < 32 or c == 127 for c in name) or name in entries):
            raise GitContentError()
        order = name + (b"/" if mode == b"40000" else b"\0")
        if previous is not None and order <= previous:
            raise GitContentError()
        previous = order
        identity = data[nul + 1:nul + 21]
        if identity == b"\0" * 20:
            raise GitContentError()
        entries[name] = (mode, identity)
        pos = nul + 21
    return entries


def _commit(data: bytes, budget: _Budget) -> bytes:
    split = data.find(b"\n\n")
    if split < 0 or b"\0" in data:
        raise GitContentError()
    lines = data[:split].split(b"\n")
    if not lines or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]):
        raise GitContentError()
    if lines[0][5:] == b"0" * 40:
        raise GitContentError()
    author = committer = False
    parents = set()
    last_key = b"tree"
    for line in lines[1:]:
        budget.check()
        if line.startswith(b" "):
            if last_key in (b"tree", b"parent", b"author", b"committer"):
                raise GitContentError()
            continue
        key, sep, value = line.partition(b" ")
        if not sep or not re.fullmatch(rb"[a-zA-Z][a-zA-Z0-9-]*", key) or not value:
            raise GitContentError()
        if key == b"tree":
            raise GitContentError()
        if key == b"parent" and (author or committer or not re.fullmatch(rb"[0-9a-f]{40}", value)):
            raise GitContentError()
        if key == b"parent":
            if value == b"0" * 40 or value in parents:
                raise GitContentError()
            parents.add(value)
        if key == b"author":
            if author or committer or not _PERSON.fullmatch(value):
                raise GitContentError()
            author = True
        if key == b"committer":
            if not author or committer or not _PERSON.fullmatch(value):
                raise GitContentError()
            committer = True
        last_key = key
    if not author or not committer:
        raise GitContentError()
    return bytes.fromhex(lines[0][5:].decode("ascii"))


def decode_selected_files(pack: bytes, commit_sha: str, paths: Sequence[str], *,
                          cancelled: Callable[[], bool] | None = None,
                          deadline: float | None = None) -> GitContentResult:
    """Decode raw PACK v2/v3 (SHA-1), returning only exact selected regular files.

    ``deadline`` uses time.monotonic(). Transport must strip pkt-line/sideband
    framing and impose its own streaming wire cap before calling this function.
    All objects, including unused bases, count toward limits. No thin packs/tags.
    """
    selection = validate_selection(commit_sha, paths)
    try:
        invalid_deadline = deadline is not None and (
            not isinstance(deadline, (int, float)) or not math.isfinite(deadline)
        )
    except (OverflowError, TypeError, ValueError):
        raise GitContentError() from None
    if invalid_deadline or (cancelled is not None and not callable(cancelled)):
        raise GitContentError()
    budget = _Budget(cancelled, deadline)
    budget.check()
    if (not isinstance(pack, bytes) or not 32 <= len(pack) <= MAX_WIRE
            or pack[:4] != b"PACK" or int.from_bytes(pack[4:8], "big") not in (2, 3)):
        raise GitContentError()
    count = int.from_bytes(pack[8:12], "big")
    if not 1 <= count <= MAX_OBJECTS:
        raise GitContentError()
    end = len(pack) - 20
    if hashlib.sha1(memoryview(pack)[:end]).digest() != pack[end:]:
        raise GitContentError()
    objects = []
    offsets = {}
    pos = 12
    for _ in range(count):
        budget.check()
        start = pos
        if pos >= end:
            raise GitContentError()
        byte = pack[pos]
        pos += 1
        kind, size = (byte >> 4) & 7, byte & 15
        shift = 4
        while byte & 128:
            if pos >= end or shift > 25:
                raise GitContentError()
            byte = pack[pos]
            pos += 1
            size |= (byte & 127) << shift
            shift += 7
            if size > MAX_OBJECT:
                raise GitContentError()
        if kind not in (1, 2, 3, 6, 7) or size > MAX_OBJECT:
            raise GitContentError()
        base = None
        if kind == 6:
            if pos >= end:
                raise GitContentError()
            byte = pack[pos]
            pos += 1
            distance = byte & 127
            for _ in range(4):
                if not byte & 128:
                    break
                if pos >= end:
                    raise GitContentError()
                byte = pack[pos]
                pos += 1
                distance = ((distance + 1) << 7) | (byte & 127)
                if distance > start:
                    raise GitContentError()
            if byte & 128 or not distance or start - distance not in offsets:
                raise GitContentError()
            base = start - distance
        elif kind == 7:
            if pos + 20 > end:
                raise GitContentError()
            base = pack[pos:pos + 20]
            pos += 20
        data, pos = _inflate(pack, pos, end, size, budget)
        obj = _Object(start, kind, data, base)
        objects.append(obj)
        offsets[start] = obj
    if pos != end:
        raise GitContentError()
    identities = {}
    unresolved = objects[:]
    while unresolved:
        remaining = []
        for obj in unresolved:
            budget.check()
            if obj.kind in (6, 7):
                base = offsets.get(obj.base) if isinstance(obj.base, int) else identities.get(obj.base)
                if base is None or base.oid is None:
                    remaining.append(obj)
                    continue
                if base.depth >= MAX_DELTA_DEPTH:
                    raise GitContentError()
                obj.data = _delta(base.data, obj.data, budget)
                obj.kind, obj.depth = base.kind, base.depth + 1
            obj.oid = _identity(obj.kind, obj.data)
            if obj.oid in identities:
                raise GitContentError()
            identities[obj.oid] = obj
            # Validate even unselected commits/trees, without retaining parsed trees.
            if obj.kind == 1:
                _commit(obj.data, budget)
            elif obj.kind == 2:
                _tree(obj.data, budget)
        if len(remaining) == len(unresolved):
            raise GitContentError()  # absent external base or dependency cycle
        unresolved = remaining
    commit = identities.get(bytes.fromhex(commit_sha))
    if commit is None or commit.kind != 1:
        raise GitContentError()
    root = _commit(commit.data, budget)
    selected = []
    total = 0
    for path in selection:
        current = root
        components = path.encode("utf-8").split(b"/")
        visited = set()
        for index, component in enumerate(components):
            budget.check()
            tree = identities.get(current)
            if tree is None or tree.kind != 2 or current in visited:
                raise GitContentError()
            visited.add(current)
            entry = _tree(tree.data, budget).get(component)
            if entry is None:
                raise GitContentError()
            mode, current = entry
            if index < len(components) - 1:
                if mode != b"40000":
                    raise GitContentError()
            else:
                blob = identities.get(current)
                if mode not in (b"100644", b"100755") or blob is None or blob.kind != 3:
                    raise GitContentError()
                if len(blob.data) > MAX_FILE or total + len(blob.data) > MAX_SELECTED:
                    raise GitContentError()
                if blob.data.startswith(b"version https://git-lfs.github.com/spec/"):
                    raise GitContentError()
                total += len(blob.data)
                selected.append(SelectedGitFile(path, current.hex(), blob.data))
    budget.check()
    return GitContentResult(commit_sha, tuple(selected), count, budget.total, len(pack), total)

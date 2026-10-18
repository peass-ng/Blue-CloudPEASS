"""Source ZIP rewriting preserves bytes and fails without replacing bad inputs."""
import hashlib
import stat
import struct
import zipfile
import zlib

import pytest

from scripts.peaso_source_archive import optimize_source_archive

LIMITS = dict(max_members=20, max_member_bytes=200000, max_uncompressed_bytes=400000)


def package(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data, compresslevel=9)


def test_recompression_preserves_unicode_empty_binary_and_release_bytes(tmp_path):
    path = tmp_path / "source.zip"
    files = {"release.json": b'{"source_version":"example"}', "empty": b"",
             "docs/seguridad-\u00f1.md": ("seguridad \u2713\n" * 3000).encode(),
             "binary.dat": bytes(range(256)) * 150}
    files["peaso/rulepacks/check_descriptions.json"] = b'{"description":"' + b"signed input unchanged " * 1000 + b'"}'
    package(path, files)
    before = path.stat().st_size
    receipt = optimize_source_archive(path, **LIMITS)
    assert path.stat().st_size <= before
    assert receipt["file_bytes_verified_unchanged"] and receipt["saved_bytes"] >= 0
    with zipfile.ZipFile(path) as archive:
        assert {name: archive.read(name) for name in archive.namelist()} == files
        assert all(info.compress_type == 8 and not info.flag_bits & 1 for info in archive.infolist())
        if receipt["applied"]:
            assert all(stat.S_ISREG(info.external_attr >> 16) for info in archive.infolist())
    assert not list(tmp_path.glob("*.deflate-*"))


@pytest.mark.parametrize("name", ["../escape", "/absolute", "windows\\escape", "C:/escape"])
def test_unsafe_member_names_never_replace_source(tmp_path, name):
    path = tmp_path / "source.zip"
    package(path, {name: b"data"})
    original = path.read_bytes()
    with pytest.raises(ValueError, match="invalid source archive member"):
        optimize_source_archive(path, **LIMITS)
    assert path.read_bytes() == original


def test_symlink_and_expansion_bounds_reject_without_overwrite(tmp_path):
    path = tmp_path / "source.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    info.compress_type = 8
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, "target")
    original = path.read_bytes()
    with pytest.raises(ValueError):
        optimize_source_archive(path, **LIMITS)
    assert path.read_bytes() == original
    package(path, {"file": b"x" * 100})
    original = path.read_bytes()
    with pytest.raises(ValueError):
        optimize_source_archive(path, **{**LIMITS, "max_uncompressed_bytes": 99})
    assert path.read_bytes() == original


def test_corrupt_crc_or_deflate_stream_leaves_original_and_no_temporary_file(tmp_path):
    path = tmp_path / "source.zip"
    package(path, {"file": b"native source integrity " * 1000})
    raw = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack("<HH", raw[26:30])
    raw[30 + name_length + extra_length + 2] ^= 0x7F
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises((zipfile.BadZipFile, zlib.error, ValueError)):
        optimize_source_archive(path, **LIMITS)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert not list(tmp_path.glob("*.deflate-*"))

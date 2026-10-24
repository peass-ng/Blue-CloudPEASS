"""Lossless bounded transport of large priority SQLite contexts."""
import gzip
import io
import sqlite3
import sys
import tarfile
import pytest
from peaso.ai import briefing, fargate, runner, task_runtime


def database(root):
    path = root / 'context.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE evidence(id INTEGER PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO evidence VALUES(?,?)', [(i, 'full fact ' * 200) for i in range(30)])
    return path


def test_lossless_bytes_queries_and_bounded_archive(tmp_path, monkeypatch):
    path = database(tmp_path); original = path.read_bytes()
    monkeypatch.setattr(briefing, 'CONTEXT_COMPRESS_THRESHOLD', 1)
    briefing.compress_context(tmp_path)
    packed = tmp_path / 'context.sqlite.gz'
    assert not path.exists() and packed.stat().st_mode & 0o777 == 0o600
    assert gzip.decompress(packed.read_bytes()) == original
    # Retain the transport limit; a large uncompressed database need not enter it.
    assert fargate.MAX_INPUT == 256 * 1024 * 1024
    monkeypatch.setattr(fargate, 'MAX_INPUT', packed.stat().st_size + 4096)
    assert len(original) > fargate.MAX_INPUT
    archive = fargate.pack_workspace(tmp_path)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        assert tar.getnames() == ['context.sqlite.gz']
    agent_root = tmp_path / 'agent'
    agent_root.mkdir()
    monkeypatch.setattr(task_runtime, 'MAX_INPUT', fargate.MAX_INPUT)
    task_runtime.unpack(archive, agent_root)
    briefing.materialize_context(agent_root)
    assert (agent_root / 'context.sqlite').read_bytes() == original
    briefing.materialize_context(tmp_path)
    assert path.read_bytes() == original and not packed.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT COUNT(*),MIN(id),MAX(id) FROM evidence').fetchone() == (30,0,29)
        assert db.execute('SELECT value FROM evidence WHERE id=17').fetchone()[0] == 'full fact ' * 200


def test_small_context_remains_unchanged(tmp_path):
    path=database(tmp_path);original=path.read_bytes()
    briefing.compress_context(tmp_path);briefing.materialize_context(tmp_path)
    assert path.read_bytes()==original and not (tmp_path/'context.sqlite.gz').exists()


@pytest.mark.parametrize('payload', [b'not gzip', gzip.compress(b'not sqlite'), gzip.compress(b''), gzip.compress(b'SQLite format 3\x00'+b'x'*64)[:-4]])
def test_invalid_payload_never_leaves_partial_database(tmp_path,payload):
    packed=tmp_path/'context.sqlite.gz';packed.write_bytes(payload)
    with pytest.raises((ValueError,OSError,EOFError)):
        briefing.materialize_context(tmp_path)
    assert not (tmp_path/'context.sqlite').exists() and packed.read_bytes()==payload


def test_expansion_limit_cleanup(tmp_path,monkeypatch):
    path=database(tmp_path);payload=gzip.compress(path.read_bytes());path.unlink()
    packed=tmp_path/'context.sqlite.gz';packed.write_bytes(payload)
    monkeypatch.setattr(briefing,'MAX_CONTEXT_BYTES',32)
    with pytest.raises(ValueError,match='too_large'):
        briefing.materialize_context(tmp_path)
    assert not path.exists() and packed.exists()


def test_source_size_limit_keeps_original(tmp_path,monkeypatch):
    path=database(tmp_path);original=path.read_bytes()
    monkeypatch.setattr(briefing,'MAX_CONTEXT_BYTES',len(original)-1)
    with pytest.raises(ValueError,match='too_large'):
        briefing.compress_context(tmp_path)
    assert path.read_bytes()==original and not (tmp_path/'context.sqlite.gz').exists()


@pytest.mark.parametrize('symlink',[False,True])
def test_existing_output_is_never_overwritten(tmp_path,symlink):
    original=database(tmp_path).read_bytes();(tmp_path/'context.sqlite').unlink()
    packed=tmp_path/'context.sqlite.gz';packed.write_bytes(gzip.compress(original))
    target=tmp_path/'external';target.write_bytes(b'keep')
    output=tmp_path/'context.sqlite'
    if symlink:output.symlink_to(target)
    else:output.write_bytes(b'keep')
    with pytest.raises(FileExistsError):briefing.materialize_context(tmp_path)
    assert output.read_bytes()==b'keep' and target.read_bytes()==b'keep' and packed.exists()


def test_packed_symlink_is_rejected(tmp_path):
    target=tmp_path/'external';target.write_bytes(gzip.compress(b'SQLite format 3\x00data'))
    (tmp_path/'context.sqlite.gz').symlink_to(target)
    with pytest.raises(ValueError,match='invalid_briefing'):
        briefing.materialize_context(tmp_path)
    assert not (tmp_path/'context.sqlite').exists() and target.exists()


def test_source_symlink_is_rejected(tmp_path):
    target=tmp_path/'external';target.write_bytes(b'keep')
    (tmp_path/'context.sqlite').symlink_to(target)
    with pytest.raises(ValueError,match='invalid_briefing'):
        briefing.compress_context(tmp_path)
    assert target.read_bytes()==b'keep' and not (tmp_path/'context.sqlite.gz').exists()


def test_existing_packed_file_is_preserved(tmp_path,monkeypatch):
    path=database(tmp_path);original=path.read_bytes();packed=tmp_path/'context.sqlite.gz';packed.write_bytes(b'keep')
    monkeypatch.setattr(briefing,'CONTEXT_COMPRESS_THRESHOLD',1)
    with pytest.raises(FileExistsError):briefing.compress_context(tmp_path)
    assert path.read_bytes()==original and packed.read_bytes()==b'keep'


def test_invalid_context_rejected_before_agent_import(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);monkeypatch.setattr(sys,'argv',['runner','priorities'])
    (tmp_path/'context.sqlite.gz').write_bytes(b'bad')
    with pytest.raises(gzip.BadGzipFile):runner.main()
    assert not (tmp_path/'context.sqlite').exists()

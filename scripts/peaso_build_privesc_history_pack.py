from pathlib import Path
import base64,gzip,hashlib,json,struct,sys,zipfile
root=Path(__file__).resolve().parents[1];out=root/'peaso/privesc/catalog_versions/runtime-history-v1.zip';p=root/'peaso/privesc/catalog_versions'
import ast
sys.path.insert(0,str(root))
from peaso.privesc import versioned_catalog as catalog
SOURCE=root/'peaso/privesc/versioned_catalog.py'
def declarations():
    tree = ast.parse(SOURCE.read_bytes())
    result = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        calls = [node for node in ast.walk(function)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == '_verified_archived_current']
        for call in calls:
            if len(call.args) != 7 or call.keywords:
                raise ValueError('archived reader signature changed')
            def arg(node):
                if isinstance(node, ast.Name):
                    return getattr(catalog, node.id)
                return ast.literal_eval(node)
            result.append(tuple(arg(node) for node in call.args))
    result.append((catalog.PRIOR_SOURCE_MANIFEST, catalog.PRIOR_CATALOG_ARCHIVE, catalog.PRIOR_CURRENT_MANIFEST, catalog.PRIOR_CATALOG_ARCHIVE_SHA256, None, 1234, 2847))
    return result

def main():
    sha=lambda b:hashlib.sha256(b).hexdigest()
    blocks={};records={};manifests={}
    pins={row[1].name:row for row in declarations()}
    assert set(pins)=={a.name for a in p.glob('*.tar.gz')}
    for a in sorted(p.glob('*.tar.gz')):
     c=a.read_bytes()
     if sha(c)!=pins[a.name][3]:raise ValueError('original archive pin changed: '+a.name)
     raw=gzip.decompress(c)
     assert len(raw)%512==0 and c[:3]==b'\x1f\x8b\x08'
     flags=c[3];pos=10
     if flags&4:
      n=int.from_bytes(c[pos:pos+2],'little');pos+=2+n
     if flags&8:pos=c.index(0,pos)+1
     if flags&16:pos=c.index(0,pos)+1
     if flags&2:pos+=2
     assert pos<len(c)-8
     refs=[]
     for i in range(0,len(raw),512):
      b=raw[i:i+512];h=sha(b)
      if blocks.setdefault(h,b)!=b:raise ValueError('block digest collision')
      refs.append(h)
     manifest=pins[a.name][0]
     if not manifest.is_file() or sha(manifest.read_bytes())!=pins[a.name][2]:
      raise ValueError('original manifest pin changed: '+manifest.name)
     m=manifest.read_bytes()
     if manifest.name in manifests and manifests[manifest.name]!=m:raise ValueError('manifest name collision')
     manifests[manifest.name]=m
     records[a.name]=dict(archive_sha256=sha(c),manifest_name=manifest.name,manifest_sha256=sha(m),header=base64.b64encode(c[:pos]).decode(),trailer=base64.b64encode(c[-8:]).decode(),tar_size=len(raw),refs=refs)
    keys=sorted(blocks)
    if len(keys)>65536:raise ValueError('too many unique blocks')
    number={h:i for i,h in enumerate(keys)}
    block_stream=b''.join(blocks[h] for h in keys)
    references=bytearray();manifest_stream=bytearray()
    # Serialize block references without changing their order.
    for name,row in records.items():
     refs=row.pop('refs');row['reference_offset']=len(references);row['reference_count']=len(refs)
     references.extend(struct.pack('<'+'H'*len(refs),*(number[h] for h in refs)))
    for name in sorted(manifests):
     m=manifests[name];offset=len(manifest_stream);manifest_stream.extend(m)
     for row in records.values():
      if row['manifest_name']==name:
       row['manifest_offset']=offset;row['manifest_size']=len(m)
    index=dict(schema='privesc-exact-history-v1',block_sha256=keys,versions=records)
    with zipfile.ZipFile(out,'w') as z:
     for name,b in [('index.json',json.dumps(index,sort_keys=True,separators=(',',':')).encode()),('blocks.bin',block_stream),('references.bin',references),('manifests.bin',manifest_stream)]:
      zi=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));zi.compress_type=zipfile.ZIP_DEFLATED;z.writestr(zi,b,compresslevel=9)
    digest=sha(out.read_bytes())
    import re
    source=SOURCE.read_bytes()
    source,n=re.subn(rb'(?m)^RUNTIME_HISTORY_SHA256 = "[0-9a-f]{64}"$',b'RUNTIME_HISTORY_SHA256 = "'+digest.encode()+b'"',source)
    assert n==1
    SOURCE.write_bytes(source)
    print(json.dumps(dict(size=out.stat().st_size,sha256=digest,archives=len(records),blocks=len(blocks),refs=len(references)//2,manifest_bytes=len(manifest_stream))))


def materialize():
    """Restore original public history files from a source ZIP on pinned Linux."""
    restored = 0
    for manifest, archive, manifest_sha, archive_sha, *_ in declarations():
        manifest_bytes, archive_bytes = catalog._history_original_pair(
            manifest, archive, manifest_sha, archive_sha)
        for path, raw in ((manifest, manifest_bytes), (archive, archive_bytes)):
            if path.is_symlink():
                raise ValueError('history destination is a symlink: ' + path.name)
            if path.exists():
                if path.read_bytes() != raw:
                    raise ValueError('existing history bytes differ: ' + path.name)
            else:
                path.write_bytes(raw)
                path.chmod(0o644)
                restored += 1
    print(json.dumps({'restored_files': restored, 'verified_versions': len(declarations())}))


if __name__ == '__main__':
    if sys.argv[1:] == ['--materialize']:
        materialize()
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit('usage: peaso_build_privesc_history_pack.py [--materialize]')

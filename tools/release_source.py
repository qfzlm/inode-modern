#!/usr/bin/env python3
"""Build source exclusively from the audited Git candidate list."""
from pathlib import Path
import gzip
import io
import tarfile
from public_audit import ROOT,candidates,audit

VERSION='0.2.0~beta.1'
files=candidates()
errors=audit(files)
if errors: raise SystemExit(repr(errors))
out=ROOT/'dist';out.mkdir(exist_ok=True)
archive=out/f'inode-modern-{VERSION}.tar.gz'
with archive.open('wb') as raw, gzip.GzipFile(fileobj=raw,mode='wb',mtime=0,filename='') as zipped, tarfile.open(fileobj=zipped,mode='w') as t:
    for name in files:
        data=(ROOT/name).read_bytes()
        item=tarfile.TarInfo(f'inode-modern-{VERSION}/{name}')
        item.size=len(data);item.mode=0o755 if name.endswith('.sh') else 0o644
        item.uid=item.gid=0;item.uname=item.gname='root';item.mtime=0
        t.addfile(item,io.BytesIO(data))
print(archive)

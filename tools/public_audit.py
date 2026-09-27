#!/usr/bin/env python3
"""Audit the exact Git candidate set; never print secret values."""
from pathlib import Path
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def candidates():
    raw = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT)
    return sorted(set(raw.decode().strip('\0').split('\0')) - {''})

def audit(paths):
    failures = []
    token = re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16})')
    for name in paths:
        p=ROOT/name
        if p.is_symlink() or not p.is_file(): failures.append((name,'non-regular file')); continue
        if any(part in ('artifacts','build','dist','.od','.impeccable','__pycache__','frontend-snapshots','rollback') for part in p.relative_to(ROOT).parts): failures.append((name,'private/generated directory'))
        data=p.read_bytes()
        if len(data)>512*1024 or data.startswith((b'\x7fELF',b'PK\x03\x04',b'\x1f\x8b')): failures.append((name,'binary/archive/oversized file'))
        try: text=data.decode('utf-8')
        except UnicodeDecodeError: failures.append((name,'non-text payload'));continue
        if token.search(text): failures.append((name,'secret signature'))
        if re.search(r'/ho' + r'me/(?!example(?:/|\b)|test(?:/|\b)|u(?:/|\b))[^/\s\"\']+|10\.51\.(?:128|144|163)\.',text): failures.append((name,'machine-specific path/address'))
        if p.name in ('AuthenMngService','iNodeMon','iNodeClient'): failures.append((name,'vendor payload'))
    return failures

if __name__ == '__main__':
    files=candidates(); failures=audit(files)
    print(json.dumps({'files':len(files),'failures':failures},indent=2))
    raise SystemExit(bool(failures))

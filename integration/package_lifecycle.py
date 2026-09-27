#!/usr/bin/python3
"""RPM final erase: stop the fault domain before removing its dedicated guard."""
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from integration.firewall import teardown_guard
except ImportError:
    from firewall import teardown_guard


def remove():
    for name in ('inode-modern-backend.service','inode-modern-firewall.service'):
        subprocess.run(['systemctl','disable','--now',name],check=True,timeout=120)
    root = Path('/sys/fs/cgroup/system.slice/inode-modern-backend.service')
    if root.exists():
        for p in root.rglob('cgroup.procs'):
            if p.read_text().strip(): raise RuntimeError('服务 cgroup 仍有进程，拒绝移除保护规则')
    teardown_guard()

if __name__ == '__main__':
    if sys.argv[1:] != ['--remove']: raise SystemExit(2)
    remove()

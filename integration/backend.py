#!/usr/bin/python3
"""Supervise pinned vendor generation pair and unprivileged control broker.

Root supervisor handles only lifecycle, private mount namespace, and runtime
process invariants. It never parses client business requests or credentials.
"""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat as stat_module
import socket
import subprocess
import sys
import time

# Isolated Python excludes the script directory; this directory is root-owned at install.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from integration.firewall import verify_firewall
    from integration.identities import check_identities, resolve_identities
    from integration.invariants import (
        ProcessSnapshot,
        parse_snapshot,
        verify_invariants,
    )
    from tools.vendor_generation import (
        CURRENT_SYMLINK,
        VENDOR_BASE,
        GenerationError,
        get_active_generation,
        verify_generation,
    )
except ImportError:
    from firewall import verify_firewall
    from identities import check_identities, resolve_identities
    from invariants import (
        ProcessSnapshot,
        parse_snapshot,
        verify_invariants,
    )
    from vendor_generation import (
        CURRENT_SYMLINK,
        VENDOR_BASE,
        GenerationError,
        get_active_generation,
        verify_generation,
    )

CONFIG = Path('/etc/inode-modern/backend.json')
VENDOR_CONFIG = Path('/etc/iNode/inodesys.conf')
NAMES = ('AuthenMngService', 'iNodeMon')
BROKER_SCRIPT = Path(__file__).resolve().with_name('broker.py')

MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 262144

EVENTS = ('ProcessEapSuccess', 'ProcessEapFail', 'Dot_Success', 'Dot_PktFail', 'SendLogoffPkt')
EVENT_RE = re.compile(rb'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*\[[^\]\r\n]+\]\s*\[[^\]\r\n]+\]\s*\[([A-Za-z_]+)\]')


class BackendError(RuntimeError):
    pass


def resolve_generation(explicit: Path | None = None) -> Path:
    """Resolve and pin canonical vendor generation, verifying checksum manifest."""
    if explicit:
        gen_path = Path(explicit).resolve(strict=True)
    elif CURRENT_SYMLINK.is_symlink():
        gen_path = CURRENT_SYMLINK.resolve(strict=True)
    elif CONFIG.is_file():
        cfg = json.loads(CONFIG.read_text())
        gen_path = Path(cfg['vendor_directory']).resolve(strict=True)
    elif VENDOR_CONFIG.is_file():
        entries = [line.split('=', 1)[1].strip() for line in VENDOR_CONFIG.read_text().splitlines()
                   if line.startswith('INSTALL_DIR=')]
        if len(entries) != 1:
            raise BackendError('vendor INSTALL_DIR in /etc/iNode/inodesys.conf is missing or ambiguous')
        gen_path = Path(entries[0]).resolve(strict=True)
    else:
        raise BackendError('cannot resolve active vendor generation')

    if gen_path.parent != VENDOR_BASE or not re.fullmatch(r"gen-[0-9]{4,}", gen_path.name):
        raise BackendError("vendor generation is outside trusted generation store")

    for req in NAMES:
        path = gen_path / req
        if not path.is_file() or not os.access(path, os.X_OK):
            raise BackendError(f'required vendor executable is missing: {path}')
        with path.open('rb') as src:
            if src.read(4) != b'\x7fELF':
                raise BackendError(f'vendor executable is not ELF: {path}')

    if not all((gen_path / name).is_dir() for name in ('libs/std', 'libs')):
        raise BackendError(f'required vendor library directories missing in {gen_path}')

    try:
        verify_generation(gen_path)
    except GenerationError as exc:
        raise BackendError(f'vendor generation integrity verification failed: {exc}') from None
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(gen_path)):
        raise BackendError('unsafe vendor generation path')

    return gen_path


def vendor_directory(explicit=None, vendor_config=VENDOR_CONFIG) -> Path:
    # This is data, never source the vendor shell-style file.
    entries = [line.split('=', 1)[1].strip() for line in vendor_config.read_text().splitlines()
               if line.startswith('INSTALL_DIR=')]
    if len(entries) != 1:
        raise BackendError('vendor INSTALL_DIR is missing or ambiguous')
    directory = Path(explicit or entries[0])
    # iNodeMon itself builds a shell command; do not accept shell metacharacters.
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(directory)) or '..' in directory.parts:
        raise BackendError('vendor directory must be an absolute path without spaces or shell characters')
    directory = directory.resolve()
    if directory != Path(entries[0]).resolve():
        raise BackendError('vendor directory differs from /etc/iNode/inodesys.conf')
    for name in NAMES:
        path = directory / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise BackendError('required vendor executable is missing')
        with path.open('rb') as source:
            if source.read(4) != b'\x7fELF':
                raise BackendError('vendor executable is not ELF')
    if not all((directory / name).is_dir() for name in ('libs/std', 'libs')):
        raise BackendError('required vendor library directories are missing')
    return directory


def processes(proc: Path = Path('/proc')) -> list[tuple[int, Path, str]]:
    """Return only executable identities; never read cmdline or environment."""
    result = []
    for path in proc.iterdir():
        if not path.name.isdigit():
            continue
        try:
            name = (path / 'comm').read_text().strip()
            if name not in ('AuthenMngServic', 'AuthenMngService', 'iNodeMon', 'iNodeClient'):
                continue
            exe = (path / 'exe').resolve(strict=True)
            group = (path / 'cgroup').read_text().strip()
            result.append((int(path.name), exe, group))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def notify(message: str) -> None:
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0' + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
            channel.sendto(message.encode(), address)


def emit(event: str) -> None:
    print(event, flush=True)


class EventReader:
    """Tail fixed function labels only. Never forward vendor stdout or log lines."""
    def __init__(self, directory: Path):
        self.directory = directory
        self.positions = {}
        if self.directory.is_dir():
            self.read(initial=True)

    def read(self, initial: bool = False) -> list[str]:
        found = []
        if not self.directory.is_dir():
            return found
        for path in self.directory.glob('*'):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                stat = path.stat()
                old_inode, offset = self.positions.get(path.name, (stat.st_ino, stat.st_size if initial else 0))
                if old_inode != stat.st_ino or offset > stat.st_size:
                    offset = 0
                if stat.st_size - offset > 262144:
                    self.positions[path.name] = (stat.st_ino, stat.st_size)
                    continue
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as source:
                    opened = os.fstat(source.fileno())
                    if not stat_module.S_ISREG(opened.st_mode) or opened.st_ino != stat.st_ino:
                        continue
                    source.seek(offset)
                    data = source.read(262144)
                end = data.rfind(b'\n') + 1
                self.positions[path.name] = (stat.st_ino, offset + end)
                for line in data[:end].splitlines():
                    match = EVENT_RE.match(line)
                    if match and match[1].decode('ascii') in EVENTS:
                        found.append(match[1].decode('ascii'))
            except OSError:
                continue
        return sorted(set(found))


class Supervisor:
    def __init__(self, pinned_gen: Path, proc_path: Path = Path('/proc')):
        self.pinned_gen = pinned_gen
        self.directory = pinned_gen
        self.proc_path = proc_path
        self.group = (proc_path / 'self/cgroup').read_text().strip() if (proc_path / 'self/cgroup').is_file() else ''
        self.stopping = False
        self.children: list[subprocess.Popen] = []
        self.broker_pid = None
        self.vendor_env = {
            'PATH': '/usr/sbin:/usr/bin',
            'LANG': 'C.UTF-8',
            'LD_LIBRARY_PATH': f'{pinned_gen}/libs/std:{pinned_gen}/libs'
        }

    def owned(self, name: str) -> list[int]:
        return [pid for pid, exe, group in processes(self.proc_path)
                if exe == self.pinned_gen / name and group == self.group]

    def preflight(self) -> None:
        if any(exe.name in (*NAMES, 'iNodeClient') for _, exe, _ in processes(self.proc_path)):
            raise BackendError('external vendor process exists; stop it or use the explicit migration command')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(('0.0.0.0', 50001))
            except OSError:
                raise BackendError('backend UDP port 50001 is already occupied') from None

    def setup_namespace(self) -> None:
        """Create private mount namespace and bind vendor-ipc to /tmp/iNode."""
        roles = resolve_identities()
        # 1. Setup host paths
        ctrl_dir = Path('/run/inode-modern')
        ctrl_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chown(ctrl_dir, *roles['inode-modern-broker'])
        os.chmod(ctrl_dir, 0o755)

        priv_dir = Path('/run/inode-modern-private')
        priv_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(priv_dir, 0o700)

        ipc_dir = priv_dir / 'vendor-ipc'
        ipc_dir.mkdir(parents=True, exist_ok=True, mode=0o777)
        os.chmod(ipc_dir, 0o777)

        log_dir = priv_dir / 'log'
        log_dir.mkdir(exist_ok=True, mode=0o700)
        os.chown(log_dir, *roles['inode-modern-engine'])
        os.chmod(log_dir, 0o700)

        # Mount failures must abort before any vendor process is launched.
        if os.geteuid() != 0:
            raise BackendError('private namespace requires root')
        libc = ctypes.CDLL(None, use_errno=True)
        def mount(source, target, fs=None, flags=0, data=None):
            if libc.mount(source, target, fs, flags, data) != 0:
                raise BackendError('private runtime mount failed')
        os.unshare(os.CLONE_NEWNS)
        mount(None, b'/', flags=MS_REC | MS_PRIVATE)
        # Overlay /tmp first: never create/use the host-global /tmp/iNode.
        mount(b'tmpfs', b'/tmp', b'tmpfs', flags=2 | 4 | 8, data=b'mode=1777')
        Path('/tmp/iNode').mkdir(mode=0o777)
        mount(os.fsencode(ipc_dir), b'/tmp/iNode', flags=MS_BIND)
        log_target = self.pinned_gen / 'log'
        if log_target.is_symlink() or not log_target.is_dir() or any(log_target.iterdir()):
            raise BackendError('generation log mountpoint must be an empty real directory')
        mount(os.fsencode(log_dir), os.fsencode(log_target), flags=MS_BIND)
        # Writable mounts contain only state and cannot execute code or create devices.
        mount(None, os.fsencode(log_target), flags=MS_BIND | 32 | 2 | 4 | 8)
        mount(None, b'/tmp/iNode', flags=MS_BIND | 32 | 2 | 4 | 8)
        # Shadow the config directory; never create/chown a host Vendor lock file.
        etc_dir = priv_dir / 'etc-iNode'
        etc_dir.mkdir(exist_ok=True, mode=0o700)
        pinned_config = etc_dir / 'inodesys.conf'
        pinned_config.write_text(f'INSTALL_DIR={self.pinned_gen}\n')
        pinned_config.chmod(0o444)
        lock = etc_dir / 'inode_mon_lock'
        lock.touch(exist_ok=False)
        os.chown(lock, *roles['inode-modern-mon'])
        lock.chmod(0o600)
        etc_dir.chmod(0o555)
        mount(os.fsencode(etc_dir), os.fsencode(VENDOR_CONFIG.parent), flags=MS_BIND)
        mount(None, os.fsencode(VENDOR_CONFIG.parent), flags=MS_BIND | 32 | 2 | 4 | 8)

    def command(self, name: str, *args) -> subprocess.Popen:
        """Launch processes with strictly contained privileges via setpriv."""
        roles = resolve_identities()
        if name == 'AuthenMngService':
            cmd = [
                'setpriv',
                '--reuid', str(roles['inode-modern-engine'][0]),
                '--regid', str(roles['inode-modern-engine'][1]),
                '--clear-groups',
                '--bounding-set=-all,+net_raw,+net_admin',
                '--inh-caps=-all,+net_raw,+net_admin',
                '--ambient-caps=-all,+net_raw,+net_admin',
                '--no-new-privs',
                str(self.pinned_gen / name),
                *args,
            ]
            env = self.vendor_env
            cwd = self.pinned_gen
        elif name == 'iNodeMon':
            cmd = [
                'setpriv',
                '--reuid', str(roles['inode-modern-mon'][0]),
                '--regid', str(roles['inode-modern-mon'][1]),
                '--clear-groups',
                '--bounding-set=-all',
                '--inh-caps=-all',
                '--ambient-caps=-all',
                '--no-new-privs',
                str(self.pinned_gen / name),
                *args,
            ]
            env = self.vendor_env
            cwd = self.pinned_gen
        elif name == 'broker':
            broker_path = BROKER_SCRIPT
            if not broker_path.is_file():
                raise BackendError('installed broker is missing')
            cmd = [
                'setpriv',
                '--reuid', str(roles['inode-modern-broker'][0]),
                '--regid', str(roles['inode-modern-broker'][1]),
                '--clear-groups',
                '--bounding-set=-all',
                '--inh-caps=-all',
                '--ambient-caps=-all',
                '--no-new-privs',
                '/usr/bin/python3', '-I', '-B', '-u', str(broker_path),
                *args,
            ]
            env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'}
            cwd = broker_path.parent
        else:
            raise BackendError(f'unknown process name {name}')

        child = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.children.append(child)
        if name == "broker":
            self.broker_pid = child.pid
        return child

    def reap(self) -> None:
        self.children = [child for child in self.children if child.poll() is None]

    def scan_invariants(self) -> tuple[bool, str]:
        snapshots = []
        for path in self.proc_path.iterdir():
            if not path.name.isdigit():
                continue
            snap = parse_snapshot(int(path.name), proc_path=self.proc_path)
            if snap:
                snapshots.append(snap)
        return verify_invariants(snapshots, self.pinned_gen, self.group, proc_path=self.proc_path, broker_pid=self.broker_pid)

    def wait_for(self, predicate, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.reap()
            if predicate():
                return True
            time.sleep(0.2)
        return bool(predicate())

    def stop_one(self, name: str) -> None:
        emit(f'stopping {name}')
        try:
            self.command(name, '-k')
        except Exception:
            pass
        self.wait_for(lambda: not any(p.canonical_exe.name == name for p in self._get_current_procs()), 5.0)

    def _get_current_procs(self) -> list[ProcessSnapshot]:
        res = []
        for path in self.proc_path.iterdir():
            if path.name.isdigit():
                snap = parse_snapshot(int(path.name), proc_path=self.proc_path)
                if snap and snap.cgroup == self.group:
                    res.append(snap)
        return res

    def stop(self) -> None:
        # Prevent watchdog resurrection: stop Mon first, then Engine
        self.stop_one('iNodeMon')
        self.stop_one('AuthenMngService')
        for child in self.children:
            if child.poll() is None:
                try:
                    child.terminate()
                except OSError:
                    pass
        self.reap()
        emit('backend stopped')

    def run(self) -> None:
        check_identities()
        verify_firewall(require_membership=True)
        self.preflight()
        self.setup_namespace()
        log_dir = Path('/run/inode-modern-private/log')
        reader = EventReader(log_dir)

        try:
            emit('starting AuthenMngService')
            self.command('AuthenMngService')
            if not self.wait_for(lambda: self.stopping or any(
                p.canonical_exe == self.pinned_gen / 'AuthenMngService' for p in self._get_current_procs()
            ), 10.0):
                raise BackendError('engine failed to start in time')

            emit('starting iNodeMon')
            self.command('iNodeMon')
            if not self.wait_for(lambda: self.stopping or any(
                p.canonical_exe == self.pinned_gen / 'iNodeMon' for p in self._get_current_procs()
            ), 10.0):
                raise BackendError('watchdog failed to start in time')

            emit('starting broker')
            self.command('broker')

            # Wait for invariants to settle
            if not self.wait_for(lambda: self.stopping or self.scan_invariants()[0], 10.0):
                ok, reason = self.scan_invariants()
                raise BackendError(f'runtime invariants failed to establish: {reason}')

            verify_firewall(require_membership=True)
            notify('READY=1\nSTATUS=Vendor pair running with strict Candidate A privilege model')
            emit('backend steady state reached')

            while not self.stopping:
                self.reap()
                verify_firewall(require_membership=True)
                ok, reason = self.scan_invariants()
                if not ok:
                    # Invariant violation: zero grace period, fail closed immediately
                    raise BackendError(f'runtime invariant violation: {reason}')

                for event in reader.read(initial=False):
                    emit(f'vendor event {event}')

                time.sleep(0.5)

        except BaseException:
            # Exit immediately; systemd destroys the entire fault domain.
            notify('STOPPING=1')
            raise
        else:
            notify('STOPPING=1')
            self.stop()


def main() -> int:
    if os.geteuid() != 0:
        emit('backend supervisor requires root')
        return 1
    try:
        pinned_gen = resolve_generation()
        emit(f'pinned vendor generation: {pinned_gen}')
        supervisor = Supervisor(pinned_gen)
        signal.signal(signal.SIGTERM, lambda *_: setattr(supervisor, 'stopping', True))
        signal.signal(signal.SIGINT, lambda *_: setattr(supervisor, 'stopping', True))

        lock_path = Path('/run/inode-modern-private/backend.lock')
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            supervisor.run()
        return 0
    except BackendError as exc:
        emit(f'FATAL: {exc}')
    except Exception as exc:
        emit(f'UNEXPECTED ERROR: {exc}')
    return 1


if __name__ == '__main__':
    sys.exit(main())

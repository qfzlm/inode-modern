"""Durable legacy snapshot for the permanent installer; no service operations.

Only fixed system targets and one explicitly named user's managed frontend are
restored. The root-private bundle is write-once, verified before any overwrite.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat

BACKUP = Path('/var/lib/inode-modern/rollback/legacy-production')
DISTRIBUTION_DROPIN = Path('/usr/lib/systemd/system/service.d/10-timeout-abort.conf')
SYSTEM_TARGETS = (
    Path('/etc/systemd/system/inode-modern-backend.service'),
    Path('/etc/systemd/system/inode-modern-firewall.service'),
    Path('/usr/local/libexec/inode-modern'),
    Path('/etc/inode-modern/backend.json'),
    Path('/usr/local/share/doc/inode-modern'),
)
FRONTEND_NAMES = (
    'share/inode-modern', 'bin/inode-modern', 'bin/inode-modern-gui',
    'share/applications/org.inode_modern.Client.desktop',
    'share/icons/hicolor/scalable/apps/org.inode_modern.Client.svg',
)


class BundleError(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def user_info(name):
    user = pwd.getpwnam(name)
    if user.pw_uid < 1000 or not Path(user.pw_dir).is_absolute():
        raise BundleError('frontend user must be a regular user with an absolute home')
    return dict(name=name, uid=user.pw_uid, gid=user.pw_gid, home=user.pw_dir)


def distribution_dropins(value):
    """Accept only Fedora's observed global stop-timeout default, never overrides."""
    if not isinstance(value, str):
        raise BundleError('missing effective unit drop-in information')
    if not value:
        return {}
    if value != str(DISTRIBUTION_DROPIN):
        raise BundleError('unknown systemd drop-in requires explicit review: ' + value)
    no_links(DISTRIBUTION_DROPIN)
    for item in (DISTRIBUTION_DROPIN, *DISTRIBUTION_DROPIN.parents):
        st = item.stat()
        if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
            raise BundleError('untrusted distribution drop-in')
    data = DISTRIBUTION_DROPIN.read_bytes()
    lines = [line.strip() for line in data.decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if lines != ['[Service]', 'TimeoutStopFailureMode=abort']:
        raise BundleError('distribution stop-timeout policy changed')
    return {str(DISTRIBUTION_DROPIN): digest(data)}


def targets(user):
    prefix = Path(user['home']) / '.local'
    return [*SYSTEM_TARGETS, *(prefix / name for name in FRONTEND_NAMES)]


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise BundleError(f'symlink in rollback target: {item}')


def volatile_bytecode(name):
    path = Path(name)
    return '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo')


def inventory(path, blobs=None, *, ignore_bytecode=False):
    """No symlinks, hardlinks or special files; record absent targets explicitly."""
    no_links(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return []
    result = []
    def visit(item):
        if ignore_bytecode and volatile_bytecode(item.relative_to(path)):
            return
        before = item.lstat()
        row = dict(name=str(item.relative_to(path)), mode=stat.S_IMODE(before.st_mode),
                   uid=before.st_uid, gid=before.st_gid)
        if stat.S_ISDIR(before.st_mode):
            row['kind'] = 'directory'
            result.append(row)
            for child in sorted(item.iterdir()):
                visit(child)
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                stream_stat = os.fstat(stream.fileno())
                if (stream_stat.st_dev, stream_stat.st_ino) != (before.st_dev, before.st_ino):
                    raise BundleError('backup source replaced')
                data = stream.read()
            row.update(kind='file', sha256=digest(data))
            if blobs is not None:
                blobs[row['sha256']] = data
            result.append(row)
        else:
            raise BundleError(f'unsupported backup entry: {item}')
        after = item.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise BundleError(f'backup source changed: {item}')
    visit(path)
    return result


def private_store(path):
    # Ancestors must be root-owned and not writable by other users.
    no_links(path)
    for item in (path, *path.parents):
        if item.exists():
            st = item.stat()
            if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
                raise BundleError(f'untrusted backup location: {item}')
    if path.exists() and stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise BundleError('backup directory must have mode 0700')


def durable_write(path, data):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_entry(item):
    st = item.lstat()
    if (st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o077
            or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode))
            or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1)):
        raise BundleError(f'unsafe rollback bundle entry: {item}')


def verify(path=None):
    path = BACKUP if path is None else path
    private_store(path)
    for item in path.rglob('*'):
        private_entry(item)
    raw = (path / 'manifest.json').read_bytes()
    if digest(raw) != (path / 'manifest.sha256').read_text().strip():
        raise BundleError('rollback manifest checksum mismatch')
    manifest = json.loads(raw)
    if manifest['format'] != 1 or user_info(manifest['user']['name']) != manifest['user']:
        raise BundleError('rollback user identity changed')
    if manifest['backend_enabled'] not in ('enabled', 'disabled'):
        raise BundleError('unsupported legacy enablement state')
    if distribution_dropins(' '.join(manifest['unit_dropins'])) != manifest['unit_dropins']:
        raise BundleError('preserved distribution drop-in changed')
    expected = targets(manifest['user'])
    if [row['target'] for row in manifest['entries']] != list(map(str, expected)):
        raise BundleError('rollback target list mismatch')
    blobs = {}
    for entry in manifest['entries']:
        names = set()
        for row in entry['tree']:
            name = Path(row['name'])
            if name.is_absolute() or '..' in name.parts or str(name) != row['name'] or row['name'] in names:
                raise BundleError('invalid rollback relative path')
            if row['name'] != '.' and str(name.parent) not in names:
                raise BundleError('missing rollback parent')
            if row['kind'] not in ('file', 'directory') or not 0 <= row['mode'] <= 0o7777:
                raise BundleError('invalid rollback entry')
            names.add(row['name'])
            if row['kind'] == 'file':
                sha = row['sha256']
                if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
                    raise BundleError('invalid rollback digest')
                data = (path / 'blobs' / sha).read_bytes()
                if digest(data) != sha:
                    raise BundleError('rollback payload checksum mismatch')
                blobs[sha] = data
    actual = {str(p.relative_to(path / 'recovery')): digest(p.read_bytes())
              for p in (path / 'recovery').rglob('*') if p.is_file()}
    if actual != manifest['recovery'] or 'install_backend.py' not in actual:
        raise BundleError('rollback recovery tool checksum mismatch')
    return manifest, blobs


def unchanged(manifest):
    for entry in manifest['entries']:
        preserved = [row for row in entry['tree'] if not volatile_bytecode(row['name'])]
        if inventory(Path(entry['target']), ignore_bytecode=True) != preserved:
            raise BundleError(f'legacy source differs from preserved bundle: {entry["target"]}')


def create(user_name, enabled, recovery_files, unit_dropins=None):
    user = user_info(user_name)
    unit_dropins = {} if unit_dropins is None else unit_dropins
    if BACKUP.exists():
        manifest, _ = verify()
        if (manifest['user'] != user or manifest['backend_enabled'] != enabled
                or manifest['unit_dropins'] != unit_dropins):
            raise BundleError('existing rollback bundle belongs to another baseline')
        unchanged(manifest)
        return BACKUP
    private_store(BACKUP.parent)
    BACKUP.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = BACKUP.with_name(BACKUP.name + '.incomplete')
    staging.mkdir(mode=0o700)  # never overwrite incomplete or preserved evidence
    (staging / 'blobs').mkdir(mode=0o700)
    (staging / 'recovery').mkdir(mode=0o700)
    blobs = {}
    entries = [dict(target=str(path), tree=inventory(path, blobs, ignore_bytecode=True))
               for path in targets(user)]
    for sha, data in blobs.items():
        durable_write(staging / 'blobs' / sha, data)
    recovery = {}
    for name, source in recovery_files.items():
        dest = staging / 'recovery' / name
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = source.read_bytes()
        durable_write(dest, data)
        recovery[name] = digest(data)
    manifest = dict(format=1, user=user, backend_enabled=enabled, unit_dropins=unit_dropins,
                    entries=entries, recovery=recovery)
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    durable_write(staging / 'manifest.json', raw)
    durable_write(staging / 'manifest.sha256', (digest(raw) + '\n').encode())
    verify(staging)
    unchanged(manifest)
    for directory in sorted((p for p in staging.rglob('*') if p.is_dir()), reverse=True):
        sync_directory(directory)
    sync_directory(staging)
    staging.rename(BACKUP)
    sync_directory(BACKUP.parent)
    verify()
    return BACKUP


def restore_entry(entry, blobs):
    path = Path(entry['target'])
    # Validate the entire destination before deleting only this recorded target.
    inventory(path)
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)
    for row in entry['tree']:
        dest = path / row['name']
        if row['kind'] == 'directory':
            dest.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            durable_write(dest, blobs[row['sha256']])
    for row in reversed(entry['tree']):
        dest = path / row['name']
        os.chown(dest, row['uid'], row['gid'])
        dest.chmod(row['mode'])
    if inventory(path) != entry['tree']:
        raise BundleError(f'restored target failed verification: {path}')


def restore_system(manifest, blobs):
    for entry in manifest['entries'][:len(SYSTEM_TARGETS)]:
        restore_entry(entry, blobs)


def restore_frontend(manifest, blobs):
    # Root never writes into user-controlled directories. Child inherits verified
    # bytes in memory, then drops all root credentials before touching the home.
    user = manifest['user']
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups(user['name'], user['gid'])
            os.setgid(user['gid'])
            os.setuid(user['uid'])
            for entry in manifest['entries'][len(SYSTEM_TARGETS):]:
                restore_entry(entry, blobs)
        except BaseException as exc:
            os.write(2, f'frontend restore failed: {exc}\n'.encode())
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if status != 0:
        raise BundleError('legacy backend restored; frontend restoration failed')

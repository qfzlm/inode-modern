#!/usr/bin/python3
"""Install/remove iNode Modern's system integration, never vendor files.

Run explicitly as root for system installation. GUI never invokes this tool.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent
sys.path.insert(0, str(HERE))
# Source and installed layouts both work under -I, independently of cwd/PYTHONPATH.
if HERE.name == 'integration' and (SOURCE / 'tools/vendor_generation.py').is_file():
    sys.path.insert(0, str(SOURCE))
from identities import check_identities, resolve_identities, IdentityError
import rollback_bundle
from firewall import guard_present, teardown_guard, FirewallError

APP_ID = 'org.inode_modern.Backend'
SERVICE = 'inode-modern-backend.service'
FIREWALL_SERVICE = 'inode-modern-firewall.service'
UNIT = Path('/etc/systemd/system') / SERVICE
FIREWALL_UNIT = Path('/etc/systemd/system') / FIREWALL_SERVICE
LIBEXEC = Path('/usr/local/libexec/inode-modern')
CONFIG_DIR = Path('/etc/inode-modern')
DOC_DIR = Path('/usr/local/share/doc/inode-modern')
MARKER = LIBEXEC / '.inode-modern-install'

spec = importlib.util.spec_from_file_location('inode_backend', HERE / 'backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)

spec_vg = importlib.util.spec_from_file_location('vendor_generation', (HERE / 'vendor_generation.py') if (HERE / 'vendor_generation.py').is_file() else SOURCE / 'tools/vendor_generation.py')
vendor_generation = importlib.util.module_from_spec(spec_vg)
spec_vg.loader.exec_module(vendor_generation)


def run(*args, check=True, capture_output=False):
    return subprocess.run(args, check=check, capture_output=capture_output, text=True,
                          timeout=120, env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'})


def unit_state(name):
    result = run('systemctl', 'show', name,
                 '--property=LoadState,ActiveState,MainPID,ControlGroup,UnitFileState,FragmentPath,DropInPaths',
                 capture_output=True)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if not {'LoadState', 'ActiveState', 'MainPID', 'ControlGroup'}.issubset(values):
        raise backend.BackendError('incomplete systemctl unit state')
    return values


def stop_firewall(disable=False):
    state = unit_state(FIREWALL_SERVICE)
    if state['LoadState'] == 'not-found':
        if state['ActiveState'] != 'inactive' or state['MainPID'] != '0':
            raise backend.BackendError('missing firewall unit has unexpected runtime state')
        return
    if state['LoadState'] != 'loaded':
        raise backend.BackendError('firewall unit cannot be safely stopped: ' + state['LoadState'])
    if disable:
        run('systemctl', 'disable', '--now', FIREWALL_SERVICE)
    else:
        run('systemctl', 'stop', FIREWALL_SERVICE)


def cgroup_members(root=Path('/sys/fs/cgroup/system.slice') / SERVICE):
    try:
        root.stat()
    except FileNotFoundError:
        return []
    members = []
    def visit(group):
        members.extend((group / 'cgroup.procs').read_text().split())
        # scandir propagates unreadable descendants; Path.rglob can suppress them.
        with os.scandir(group) as children:
            for child in children:
                if child.is_dir(follow_symlinks=False):
                    visit(Path(child.path))
    visit(root)
    return members


def verify_quiescent(proc=Path('/proc')):
    state = unit_state(SERVICE)
    if (state['ActiveState'] not in ('inactive', 'failed') or state['MainPID'] != '0'
            or state['ControlGroup'] not in ('', '/system.slice/' + SERVICE)
            or cgroup_members()):
        raise backend.BackendError('Candidate service/cgroup has not stopped')
    for process in proc.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            status = (process / 'status').read_text()
            uid_line = next((line for line in status.splitlines() if line.startswith('Uid:')), '')
            uids = {int(value) for value in uid_line.split()[1:]}
            if len(uid_line.split()) != 5:
                raise backend.BackendError('incomplete process identity: ' + process.name)
            cmd = (process / 'cmdline').read_bytes().split(b'\0')
            group = (process / 'cgroup').read_text()
            try:
                exe = os.readlink(process / 'exe')
            except FileNotFoundError:
                exe = ''  # kernel threads/zombies still checked by uid/cgroup below
            if (uids & {uid for uid, _ in resolve_identities(allow_missing=True).values()} or '/system.slice/' + SERVICE in group
                    or Path(exe.removesuffix(' (deleted)')).name in backend.NAMES
                    or str(vendor_generation.VENDOR_BASE) + '/' in exe
                    or any(os.fsencode(LIBEXEC / name) in cmd for name in ('backend.py', 'broker.py'))):
                raise backend.BackendError('residual Candidate/vendor process: ' + process.name)
        except (FileNotFoundError, ProcessLookupError):
            if process.exists():
                raise backend.BackendError('cannot verify exiting process: ' + process.name)
    for protocol in ('udp', 'udp6'):
        for line in (proc / 'net' / protocol).read_text().splitlines()[1:]:
            if int(line.split()[1].rsplit(':', 1)[1], 16) in (50000, 50001, 50002):
                raise backend.BackendError('legacy UDP ports are still occupied')


def stop_candidate(expected_dropins=None):
    state = unit_state(SERVICE)
    if state['LoadState'] == 'not-found' and state['ActiveState'] == 'inactive' and state['MainPID'] == '0':
        verify_quiescent()
        return
    dropins = rollback_bundle.distribution_dropins(state.get('DropInPaths'))
    if expected_dropins is not None and dropins != expected_dropins:
        raise backend.BackendError('effective unit drop-ins changed since legacy backup')
    if (state['LoadState'] != 'loaded'
            or state.get('FragmentPath') != str(UNIT)
            or state['ControlGroup'] not in ('', '/system.slice/' + SERVICE)):
        raise backend.BackendError('unexpected backend unit/cgroup identity')
    try:
        run('systemctl', 'stop', SERVICE)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Stop timeout/failure is reported, never silently treated as a clean stop.
        print('Backend stop failed; forcing Candidate fault-domain termination.', file=sys.stderr)
        run('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', SERVICE)
        run('systemctl', 'stop', SERVICE)
    if cgroup_members():
        run('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', SERVICE)
        deadline = time.monotonic() + 5
        while cgroup_members() and time.monotonic() < deadline:
            time.sleep(0.1)
    verify_quiescent()


def recovery_files():
    result = {name: HERE / name for name in (
        'backend.py', 'broker.py', 'invariants.py', 'identities.py', 'firewall.py',
        'install_backend.py', 'rollback_bundle.py')}
    result['vendor_generation.py'] = (HERE / 'vendor_generation.py' if (HERE / 'vendor_generation.py').is_file()
                                      else SOURCE / 'tools/vendor_generation.py')
    package = HERE / 'inode_modern' if (HERE / 'inode_modern').is_dir() else SOURCE / 'inode_modern'
    result.update({'inode_modern/' + name: package / name for name in ('__init__.py', 'protocol.py', 'validator.py')})
    return result


def prepare_backup(frontend_user):
    if not frontend_user:
        raise backend.BackendError('--frontend-user is required to preserve the legacy GUI/CLI')
    if not managed() or not UNIT.is_file() or not (LIBEXEC / 'backend.py').is_file():
        raise backend.BackendError('a managed known-good legacy backend is required')
    config = json.loads((CONFIG_DIR / 'backend.json').read_text())
    if ('source_directory' in config or FIREWALL_SERVICE in UNIT.read_text()
            or Path(config['vendor_directory']).is_relative_to(vendor_generation.VENDOR_BASE)):
        raise backend.BackendError('refusing to replace the legacy backup with a Candidate installation')
    user = rollback_bundle.user_info(frontend_user)
    prefix = Path(user['home']) / '.local'
    if (prefix / 'share/inode-modern/.inode-modern-install').read_text() != 'org.inode_modern.Client':
        raise backend.BackendError('managed legacy frontend is required')
    for name in rollback_bundle.FRONTEND_NAMES:
        if not (prefix / name).exists():
            raise backend.BackendError('incomplete legacy frontend: ' + name)
    for target in (LIBEXEC, CONFIG_DIR, DOC_DIR, UNIT, FIREWALL_UNIT):
        vendor_generation.validate_destination(target, recursive=True)
    state = unit_state(SERVICE)
    dropins = rollback_bundle.distribution_dropins(state.get('DropInPaths'))
    if (state['LoadState'] != 'loaded' or state.get('FragmentPath') != str(UNIT)
            or state.get('UnitFileState') not in ('enabled', 'disabled')):
        raise backend.BackendError('legacy unit overrides or enablement require explicit review')
    # Do not carry stale overrides into Candidate or legacy restoration.
    for name in (SERVICE, FIREWALL_SERVICE):
        for base in ('/etc/systemd/system', '/run/systemd/system'):
            dropin_dir = Path(base) / (name + '.d')
            if dropin_dir.exists() and any(dropin_dir.iterdir()):
                raise backend.BackendError('unit drop-ins require explicit review: ' + str(dropin_dir))
    path = rollback_bundle.create(frontend_user, state['UnitFileState'], recovery_files(), dropins)
    print('Verified legacy rollback bundle: ' + str(path), flush=True)
    print('Recovery: sudo python3 -I ' + str(path / 'recovery/install_backend.py') + ' --rollback', flush=True)
    return path


def rollback():
    manifest, blobs = rollback_bundle.verify()
    # All restoration destinations must be trusted before stopping anything.
    for target in rollback_bundle.SYSTEM_TARGETS:
        vendor_generation.validate_destination(target, recursive=True)
    stop_candidate(expected_dropins=manifest['unit_dropins'])
    stop_firewall(disable=True)
    teardown_guard()
    verify_quiescent()
    rollback_bundle.restore_system(manifest, blobs)
    run('restorecon', '-R', str(LIBEXEC), str(CONFIG_DIR), str(DOC_DIR), str(UNIT))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable' if manifest['backend_enabled'] == 'enabled' else 'disable', SERVICE)
    teardown_guard()  # final guard gate immediately before legacy start
    run('systemctl', 'start', SERVICE)
    rollback_bundle.restore_frontend(manifest, blobs)
    print('Legacy backend and frontend restored. OPERATOR_REQUIRED: reopen the legacy GUI, '
          'reconnect, verify authentication/readiness and wired Internet; service start is not authentication.')


def unit_text(directory=None):
    text = (HERE / (SERVICE + '.in')).read_text()
    if directory is not None:
        text = text.replace('@VENDOR_DIRECTORY@', str(directory))
    return text


def hashes(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob('*') if path.is_file() and
            (path.name in (*backend.NAMES, 'iNodeClient') or 'libs' in path.relative_to(directory).parts)}


def managed():
    return MARKER.is_file() and MARKER.read_text() == APP_ID


def migrate(directory):
    found = backend.processes()
    if any(exe.name == 'iNodeClient' for _, exe, _ in found):
        raise backend.BackendError('close the old GTK2 GUI before migration')
    if any(exe.name in backend.NAMES and exe.parent != directory for _, exe, _ in found):
        raise backend.BackendError('another vendor installation is running; migration refused')
    class ExistingPair(backend.Supervisor):
        def owned(self, name):
            return [pid for pid, exe, _ in backend.processes() if exe == directory / name]
    # Explicit administrator-only migration. Normal service never adopts external PIDs.
    ExistingPair(directory).stop()


def uninstall():
    if not managed():
        raise backend.BackendError('no managed backend installation found')
    stop_candidate()
    run('systemctl', 'disable', SERVICE)
    stop_firewall(disable=True)
    teardown_guard()
    UNIT.unlink(missing_ok=True)
    FIREWALL_UNIT.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    # Only our recorded file set, never recursive removal of vendor or /etc/iNode.
    for file in (CONFIG_DIR / 'backend.json', DOC_DIR / 'phase4-integration.md',
                 LIBEXEC / 'backend.py', LIBEXEC / 'broker.py', LIBEXEC / 'invariants.py',
                 LIBEXEC / 'vendor_generation.py', LIBEXEC / 'firewall_guard.sh',
                 LIBEXEC / 'identities.py', LIBEXEC / 'firewall.py',
                 LIBEXEC / 'install_backend.py', LIBEXEC / 'rollback_bundle.py', MARKER):
        file.unlink(missing_ok=True)
    package = LIBEXEC / 'inode_modern'
    for name in ('__init__.py', 'protocol.py', 'validator.py'):
        (package / name).unlink(missing_ok=True)
    if package.is_dir():
        package.rmdir()
    cache = LIBEXEC / '__pycache__'
    if cache.is_dir() and not cache.is_symlink():
        for file in cache.glob('*.pyc'):
            file.unlink(missing_ok=True)
        try:
            cache.rmdir()
        except OSError:
            pass
    for directory in (CONFIG_DIR, DOC_DIR, LIBEXEC):
        try:
            directory.rmdir()
        except OSError:
            pass
    print('Removed backend integration and Candidate nft guard. Vendor and rollback bundle retained. '
          '--uninstall does not restore legacy production; use the bundle recovery tool --rollback.')


def install(directory, take_over=False, frontend_user=None):
    # Complete read-only preflight before accounts, writes, migration or service stop.
    for target in (LIBEXEC, CONFIG_DIR, DOC_DIR, UNIT, FIREWALL_UNIT):
        vendor_generation.validate_destination(target, recursive=True)
    vendor_generation.validate_destination(vendor_generation.VENDOR_BASE)
    vendor_generation.validate_destination(vendor_generation.CURRENT_SYMLINK.parent)
    missing_roles = check_identities(allow_missing=True)
    for target in (LIBEXEC, CONFIG_DIR, DOC_DIR, UNIT, FIREWALL_UNIT):
        if target.exists() and not managed():
            raise backend.BackendError('installation target already exists and is not managed')
    selector = vendor_generation.CURRENT_SYMLINK
    if selector.is_symlink() or selector.exists():
        vendor_generation.check_root_owned(selector)
        active_gen = vendor_generation.get_active_generation()  # corruption never means reinstall
    else:
        active_gen = None
    before = hashes(directory)
    # This permanent cutover requires a known-good managed legacy installation.
    # Publish and verify its complete bundle before accounts, stop or overwrite.
    prepare_backup(frontend_user)
    for source in (*recovery_files().values(), HERE / (SERVICE + '.in'),
                   HERE / FIREWALL_SERVICE, SOURCE / 'tools/firewall_guard.sh',
                   SOURCE / 'docs/phase4-integration.md'):
        if not source.is_file():
            raise backend.BackendError('missing installation source: ' + str(source))
    fw_state = unit_state(FIREWALL_SERVICE)
    if fw_state['LoadState'] not in ('loaded', 'not-found'):
        raise backend.BackendError('unexpected firewall unit state')
    rollback_bundle.distribution_dropins(fw_state.get('DropInPaths'))
    # Collision preflight completed for ALL roles before creating any identity.
    for name in missing_roles:
        run('systemd-sysusers', '--inline', f'u {name} - "iNode Modern service" / /usr/sbin/nologin')
    check_identities()
    if managed():
        run('systemctl', 'stop', SERVICE)  # known old backend stop must succeed
        stop_firewall()
    existing = [exe for _, exe, _ in backend.processes() if exe.name in (*backend.NAMES, 'iNodeClient')]
    if existing:
        if not take_over:
            raise backend.BackendError('vendor processes already running; use --migrate once to stop the manual pair')
        migrate(directory)

    if active_gen is None:
        gen_dir = vendor_generation.import_generation(directory)
        vendor_generation.activate_generation(gen_dir)
    target_vendor = vendor_generation.CURRENT_SYMLINK

    for target in (LIBEXEC, CONFIG_DIR, DOC_DIR):
        target.mkdir(parents=True, exist_ok=True, mode=0o755)

    # Install daemon / supervisor / broker / tools into LIBEXEC
    for name in ('backend.py', 'broker.py', 'invariants.py', 'identities.py', 'firewall.py',
                 'install_backend.py', 'rollback_bundle.py'):
        shutil.copyfile(HERE / name, LIBEXEC / name)
        (LIBEXEC / name).chmod(0o644)

    package = LIBEXEC / 'inode_modern'
    package.mkdir(exist_ok=True, mode=0o755)
    for name in ('__init__.py', 'protocol.py', 'validator.py'):
        shutil.copyfile(SOURCE / 'inode_modern' / name, package / name)
        (package / name).chmod(0o644)

    shutil.copyfile(SOURCE / 'tools/vendor_generation.py', LIBEXEC / 'vendor_generation.py')
    (LIBEXEC / 'vendor_generation.py').chmod(0o644)

    shutil.copyfile(SOURCE / 'tools/firewall_guard.sh', LIBEXEC / 'firewall_guard.sh')
    (LIBEXEC / 'firewall_guard.sh').chmod(0o755)

    shutil.copyfile(SOURCE / 'docs/phase4-integration.md', DOC_DIR / 'phase4-integration.md')
    MARKER.write_text(APP_ID)
    (CONFIG_DIR / 'backend.json').write_text(json.dumps({
        'vendor_directory': str(target_vendor),
        'source_directory': str(directory),
    }, indent=2) + '\n')

    # Install systemd units
    FIREWALL_UNIT.write_text((HERE / FIREWALL_SERVICE).read_text())
    FIREWALL_UNIT.chmod(0o644)
    UNIT.write_text(unit_text(target_vendor))
    UNIT.chmod(0o644)

    for file in (UNIT, FIREWALL_UNIT, MARKER, CONFIG_DIR / 'backend.json', DOC_DIR / 'phase4-integration.md'):
        file.chmod(0o644)

    # Restore policy-defined labels on our own newly installed paths only.
    run('restorecon', '-R', str(LIBEXEC), str(CONFIG_DIR), str(DOC_DIR), str(UNIT), str(FIREWALL_UNIT))
    run('systemd-analyze', 'verify', str(FIREWALL_UNIT), str(UNIT))
    if guard_present():
        raise FirewallError('Candidate nft guard already exists; installation refused')
    # Enable may reload the manager: finish every reload before creating the table.
    run('systemctl', 'enable', FIREWALL_SERVICE)
    run('systemctl', 'enable', SERVICE)
    run('systemctl', 'daemon-reload')
    # No enable or manager reload after this point: NFTSet must add only the live cgroup.
    run('systemctl', 'start', FIREWALL_SERVICE)
    run(str(LIBEXEC / 'firewall_guard.sh'), 'check')
    run('systemctl', 'start', SERVICE)
    if hashes(directory) != before:
        raise backend.BackendError('vendor content changed during installation; inspect before continuing')
    print('Backend installed and enabled; vendor hashes unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-dir', type=Path, help='default: existing /etc/iNode/inodesys.conf')
    parser.add_argument('--migrate', action='store_true', help='stop the existing manual vendor pair before installation')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--uninstall', action='store_true')
    actions.add_argument('--rollback', action='store_true', help='restore the verified permanent legacy bundle')
    actions.add_argument('--prepare-backup', action='store_true', help='preserve legacy production without stopping it')
    actions.add_argument('--verify-backup', action='store_true', help='verify the root-private rollback bundle')
    actions.add_argument('--check', action='store_true', help='read-only installation discovery, no root required')
    parser.add_argument('--frontend-user', help='normal user whose ~/.local legacy frontend must be preserved')
    args = parser.parse_args()
    try:
        if args.check:
            print(json.dumps({'vendor_directory': str(backend.vendor_directory(args.vendor_dir)),
                              'system_integration_installed': managed()}, indent=2))
        elif os.geteuid() != 0:
            raise backend.BackendError('system installation requires administrator authorization')
        elif args.verify_backup:
            rollback_bundle.verify()
            print('Verified legacy rollback bundle: ' + str(rollback_bundle.BACKUP))
        else:
            # One permanent installer/rollback transaction at a time.
            rollback_bundle.private_store(rollback_bundle.BACKUP.parent)
            rollback_bundle.BACKUP.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            lock_fd = os.open(rollback_bundle.BACKUP.parent / '.lock',
                              os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            with os.fdopen(lock_fd, 'r+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.prepare_backup:
                    prepare_backup(args.frontend_user)
                elif args.rollback:
                    rollback()
                elif args.uninstall:
                    uninstall()
                else:
                    install(backend.vendor_directory(args.vendor_dir), args.migrate, args.frontend_user)
        return 0
    except (backend.BackendError, IdentityError, vendor_generation.GenerationError,
            rollback_bundle.BundleError, FirewallError) as exc:
        print(str(exc), file=sys.stderr)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Installer operation failed: ' + str(exc), file=sys.stderr)
    print('No automatic restart/rollback was attempted. Preserved rollback location: '
          + str(rollback_bundle.BACKUP) + '; use its recovery/install_backend.py --rollback '
          'after correcting the reported gate failure. --uninstall is not rollback.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())

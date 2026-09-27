"""Offline permanent-cutover regression tests. All service/nft mutations mocked."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from integration import install_backend as installer
from tests.test_release_blockers import ruleset

bundle = installer.rollback_bundle
firewall = sys.modules[installer.teardown_guard.__module__]
ROOT = Path(__file__).resolve().parents[1]


class GuardReloadModel:
    """Offline model of the observed reload/NFTSet interaction, not systemd emulation."""
    def __init__(self):
        self.elements = None
        self.stale = '123456'
        self.live = firewall.SERVICE_CGROUP.lstrip('/')

    def validate(self, require_live=False):
        document = ruleset()
        for record in document['nftables']:
            if 'set' in record:
                record['set']['elem'] = list(self.elements)
        firewall.validate_ruleset(document, cgroup_id=789012 if require_live else None)

    def run(self, *args, **kwargs):
        if args[0] != 'systemctl':
            if args[-1] == 'check':
                self.validate()
            return
        operation = args[1]
        # enable includes an implicit manager reload before --now starts the unit.
        if operation in ('enable', 'daemon-reload') and self.elements is not None:
            if self.stale not in self.elements:
                self.elements.append(self.stale)
        if operation == 'start' or (operation == 'enable' and '--now' in args):
            if args[-1] == installer.FIREWALL_SERVICE:
                if self.elements is None:
                    self.elements = []
            elif args[-1] == installer.SERVICE:
                self.elements.append(self.live)
                self.validate(require_live=True)


class GuardOrderingTests(unittest.TestCase):
    def test_ruleset_membership_shapes(self):
        model = GuardReloadModel()
        for elements, valid in (([], True), ([model.live], True),
                                ([model.stale, model.live], False), ([model.stale], False)):
            with self.subTest(elements=elements):
                model.elements = elements
                if valid:
                    model.validate()
                else:
                    with self.assertRaises(firewall.FirewallError):
                        model.validate()

    def test_old_sequence_materializes_stale_member_and_fails(self):
        model = GuardReloadModel()
        model.run('systemctl', 'daemon-reload')
        model.run('systemctl', 'enable', '--now', installer.FIREWALL_SERVICE)
        with self.assertRaises(firewall.FirewallError):
            model.run('systemctl', 'enable', '--now', installer.SERVICE)
        self.assertEqual(model.elements, [model.stale, model.live])
        model.elements.remove(model.live)  # failed backend exits; orphan remains
        with self.assertRaises(firewall.FirewallError):
            model.validate()

    def test_generated_units_pass_systemd_analyze_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            backend_unit = units / installer.SERVICE
            firewall_unit = units / installer.FIREWALL_SERVICE
            backend_unit.write_text(installer.unit_text(installer.vendor_generation.CURRENT_SYMLINK))
            firewall_unit.write_text((installer.HERE / installer.FIREWALL_SERVICE).read_text())
            self.assertIn('NFTSet=cgroup:inet:inode_modern_guard:allowed_cgroups', backend_unit.read_text())
            # Verify exact unit contents in an offline root, independent of the
            # rolled-back host payload and unrelated host units. Nothing executes.
            for name in ('sysinit', 'basic', 'shutdown', 'local-fs', 'network', 'network-pre', 'multi-user'):
                (units / (name + '.target')).write_text('[Unit]\nDescription=Offline fixture\n')
            for source, destination in ((ROOT / 'tools/firewall_guard.sh',
                                         root / 'usr/local/libexec/inode-modern/firewall_guard.sh'),
                                        (Path(sys.executable), root / 'usr/bin/python3')):
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                destination.chmod(0o755)
            result = subprocess.run(['systemd-analyze', '--root=' + str(root), 'verify',
                                     '/etc/systemd/system/' + installer.FIREWALL_SERVICE,
                                     '/etc/systemd/system/' + installer.SERVICE],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def state(load='loaded'):
    return dict(LoadState=load, ActiveState='inactive', MainPID='0', ControlGroup='',
                UnitFileState='enabled', FragmentPath=str(installer.UNIT), DropInPaths='')


class EntryPointTests(unittest.TestCase):
    def test_real_isolated_script_check_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            for folder in ('integration', 'inode_modern'):
                shutil.copytree(ROOT / folder, source / folder, ignore=shutil.ignore_patterns('__pycache__'))
            (source / 'tools').mkdir()
            shutil.copyfile(ROOT / 'tools/vendor_generation.py', source / 'tools/vendor_generation.py')
            vendor = root / 'vendor'
            (vendor / 'libs/std').mkdir(parents=True)
            for name in installer.backend.NAMES:
                (vendor / name).write_bytes(b'\x7fELFsynthetic')
                (vendor / name).chmod(0o755)
            config = root / 'inodesys.conf'
            config.write_text('INSTALL_DIR=' + str(vendor) + '\n')
            backend = source / 'integration/backend.py'
            backend.write_text(backend.read_text().replace(
                "VENDOR_CONFIG = Path('/etc/iNode/inodesys.conf')", f'VENDOR_CONFIG = Path({str(config)!r})'))
            poison = root / 'poison'
            poison.mkdir()
            (poison / 'firewall.py').write_text("raise RuntimeError('ambient path was used')")
            for env in ({'PATH': os.environ['PATH']}, {'PATH': os.environ['PATH'], 'PYTHONPATH': str(poison)}):
                result = subprocess.run([sys.executable, '-I', str(source / 'integration/install_backend.py'), '--check'],
                                        cwd=poison, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['vendor_directory'], str(vendor))


class StopTests(unittest.TestCase):
    def test_missing_firewall_is_skipped_and_backend_stop_stays_checked(self):
        with patch.object(installer, 'unit_state', return_value=state('not-found')), \
                patch.object(installer, 'run') as run:
            installer.stop_firewall()
            run.assert_not_called()

    def test_loaded_firewall_stop_failure_is_not_hidden(self):
        with patch.object(installer, 'unit_state', return_value=state()), \
                patch.object(installer, 'run', side_effect=subprocess.CalledProcessError(1, 'systemctl')):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.stop_firewall()

    def test_bad_load_or_missing_but_active_is_rejected(self):
        for values in (state('error'), state('masked'), state('not-found') | {'ActiveState': 'active'}):
            with patch.object(installer, 'unit_state', return_value=values), patch.object(installer, 'run') as run:
                with self.assertRaises(installer.backend.BackendError):
                    installer.stop_firewall()
                run.assert_not_called()

    def test_query_errors_are_not_missing_units(self):
        with patch.object(installer, 'run', side_effect=subprocess.CalledProcessError(1, 'systemctl')):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.stop_firewall()

    def test_candidate_override_is_rejected_before_stop(self):
        with patch.object(installer, 'unit_state', return_value=state() | {'DropInPaths': '/run/override.conf'}), \
                patch.object(installer, 'run') as run:
            with self.assertRaises(bundle.BundleError):
                installer.stop_candidate()
            run.assert_not_called()

    def test_stop_failure_forces_group_kill_then_checked_stop_and_verification(self):
        with patch.object(installer, 'unit_state', return_value=state()), \
                patch.object(installer, 'cgroup_members', return_value=[]), \
                patch.object(installer, 'verify_quiescent') as verify, \
                patch.object(installer, 'run', side_effect=[subprocess.CalledProcessError(1, 'stop'), None, None]) as run:
            installer.stop_candidate()
        self.assertEqual([call.args for call in run.call_args_list], [
            ('systemctl', 'stop', installer.SERVICE),
            ('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', installer.SERVICE),
            ('systemctl', 'stop', installer.SERVICE)])
        verify.assert_called_once()


class BundlePermissionTests(unittest.TestCase):
    def test_only_observed_distribution_dropin_is_accepted_and_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '10-timeout-abort.conf'
            data = b'# Fedora default\n[Service]\nTimeoutStopFailureMode=abort\n'
            path.write_bytes(data)
            trusted = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100644)
            with patch.object(bundle, 'DISTRIBUTION_DROPIN', path), patch.object(bundle, 'no_links'), \
                    patch.object(Path, 'stat', return_value=trusted):
                self.assertEqual(bundle.distribution_dropins(str(path)), {str(path): hashlib.sha256(data).hexdigest()})
                path.write_text('[Service]\nExecStart=/unknown\n')
                with self.assertRaises(bundle.BundleError):
                    bundle.distribution_dropins(str(path))
        with self.assertRaises(bundle.BundleError):
            bundle.distribution_dropins('/etc/systemd/system/service.d/unknown.conf')

    def test_bundle_entry_owner_modes_links_and_specials_fail_closed(self):
        valid = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        item = Mock()
        item.lstat.return_value = SimpleNamespace(**valid)
        bundle.private_entry(item)
        for changes in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFREG | 0o644},
                        {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFIFO | 0o600}, {'st_nlink': 2}):
            item.lstat.return_value = SimpleNamespace(**(valid | changes))
            with self.assertRaises(bundle.BundleError):
                bundle.private_entry(item)


class NftTeardownTests(unittest.TestCase):
    def listing(self, present=False):
        tables = [{'table': {'family': 'ip', 'name': 'unrelated'}}]
        if present:
            tables.append({'table': {'family': 'inet', 'name': 'inode_modern_guard'}})
        return SimpleNamespace(stdout=json.dumps({'nftables': tables}))

    def test_delete_then_repeat_absent_only_deletes_owned_table_once(self):
        results = [self.listing(True), SimpleNamespace(), self.listing(), self.listing(), self.listing()]
        with patch.object(firewall.subprocess, 'run', side_effect=results) as run:
            firewall.teardown_guard()
            firewall.teardown_guard()
        deletions = [call.args[0] for call in run.call_args_list if 'delete' in call.args[0]]
        self.assertEqual(deletions, [['/usr/sbin/nft', 'delete', 'table', 'inet', 'inode_modern_guard']])

    def test_table_remaining_or_reappearing_is_error(self):
        for results in ([self.listing(True), SimpleNamespace(), self.listing(True)],
                        [self.listing(), self.listing(True)]):
            with patch.object(firewall.subprocess, 'run', side_effect=results):
                with self.assertRaises(firewall.FirewallError):
                    firewall.teardown_guard()

    def test_query_parse_delete_and_postcheck_failures_are_errors(self):
        failure = subprocess.CalledProcessError(1, 'nft')
        for results in ([failure], [SimpleNamespace(stdout='bad')],
                        [SimpleNamespace(stdout='{}')], [self.listing(True), failure],
                        [self.listing(True), SimpleNamespace(), failure]):
            with patch.object(firewall.subprocess, 'run', side_effect=results):
                with self.assertRaises(firewall.FirewallError):
                    firewall.teardown_guard()


class BytecodeComparisonTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'module.py'
        self.source.write_text('source')
        (self.root / 'config.json').write_text('config')
        (self.root / 'launcher').write_text('launcher')
        self.cache = self.root / '__pycache__'
        self.cache.mkdir()
        (self.cache / 'module.cpython-314.pyc').write_bytes(b'old cache')
        (self.cache / 'nested').mkdir()
        (self.cache / 'nested/anything').write_text('volatile subtree')
        (self.root / 'module.pyc').write_bytes(b'old adjacent cache')
        (self.root / 'module.pyo').write_bytes(b'old optimized cache')
        # Historical manifests recorded these entries, including directory metadata.
        self.manifest = {'entries': [{'target': str(self.root), 'tree': bundle.inventory(self.root)}]}

    def test_changed_bytecode_passes(self):
        for path in (self.cache / 'module.cpython-314.pyc', self.root / 'module.pyc', self.root / 'module.pyo'):
            path.write_bytes(b'regenerated')
        (self.cache / 'nested/anything').write_text('changed')
        self.cache.chmod(0o700)
        bundle.unchanged(self.manifest)

    def test_missing_bytecode_passes(self):
        shutil.rmtree(self.cache)
        (self.root / 'module.pyc').unlink()
        (self.root / 'module.pyo').unlink()
        bundle.unchanged(self.manifest)

    def test_new_bytecode_and_cache_subtree_pass(self):
        (self.root / 'new.pyc').write_bytes(b'new')
        (self.root / 'new.pyo').write_bytes(b'new')
        (self.cache / '__pycache__').mkdir()
        (self.cache / '__pycache__/new.data').write_bytes(b'new')
        bundle.unchanged(self.manifest)

    def test_changed_source_fails(self):
        self.source.write_text('changed source')
        with self.assertRaises(bundle.BundleError):
            bundle.unchanged(self.manifest)

    def test_missing_source_fails(self):
        self.source.unlink()
        with self.assertRaises(bundle.BundleError):
            bundle.unchanged(self.manifest)

    def test_unexpected_nonvolatile_files_fail(self):
        for name in ('extra.txt', 'module.pyc.backup', 'module.pyo.txt', '__pycache__backup'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text('unexpected')
                with self.assertRaises(bundle.BundleError):
                    bundle.unchanged(self.manifest)
                path.unlink()

    def test_changed_launcher_and_config_fail(self):
        for name in ('launcher', 'config.json'):
            with self.subTest(name=name):
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(b'changed')
                with self.assertRaises(bundle.BundleError):
                    bundle.unchanged(self.manifest)
                path.write_bytes(before)

    def test_nonvolatile_mode_and_ownership_remain_strict(self):
        self.source.chmod(self.source.stat().st_mode ^ 0o100)
        with self.assertRaises(bundle.BundleError):
            bundle.unchanged(self.manifest)
        self.source.chmod(self.source.stat().st_mode ^ 0o100)
        for name in ('.', 'module.py'):
            row = next(row for row in self.manifest['entries'][0]['tree'] if row['name'] == name)
            for field in ('uid', 'gid', 'mode'):
                with self.subTest(name=name, field=field):
                    row[field] += 1
                    with self.assertRaises(bundle.BundleError):
                        bundle.unchanged(self.manifest)
                    row[field] -= 1


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.system = tuple(self.root / name for name in ('backend.service', 'firewall.service', 'payload', 'backend.json', 'docs'))
        self.system[0].write_text('legacy unit')
        self.system[2].mkdir()
        (self.system[2] / 'backend.py').write_text('legacy backend')
        (self.system[2] / '.inode-modern-install').write_text(installer.APP_ID)
        self.system[3].write_text('{"vendor_directory":"/legacy"}')
        self.system[4].mkdir()
        (self.system[4] / 'phase4-integration.md').write_text('legacy docs')
        self.user = dict(name='fixture', uid=os.getuid(), gid=os.getgid(), home=str(self.root / 'home'))
        self.backup = self.root / 'backup/legacy-production'
        for name in bundle.FRONTEND_NAMES:
            path = Path(self.user['home']) / '.local' / name
            if name == 'share/inode-modern':
                path.mkdir(parents=True)
                (path / 'legacy.py').write_text('legacy frontend')
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('legacy launcher')
        for attr, value in (('BACKUP', self.backup), ('SYSTEM_TARGETS', self.system)):
            self.stack.enter_context(patch.object(bundle, attr, value))
        self.stack.enter_context(patch.object(bundle, 'user_info', return_value=self.user))
        # Only privilege/ownership gates mocked; real file copying, hashes, restore.
        self.stack.enter_context(patch.object(bundle, 'private_store'))
        self.stack.enter_context(patch.object(bundle, 'private_entry'))

    def create(self):
        return bundle.create('fixture', 'enabled', installer.recovery_files())

    def test_old_bundle_with_bytecode_is_reused_without_rewriting(self):
        cache = self.system[2] / '__pycache__'
        cache.mkdir()
        bytecode = cache / 'backend.cpython-314.pyc'
        bytecode.write_bytes(b'old bytecode')
        # Produce an authentic format-1 bundle with the historical inventory policy.
        with patch.object(bundle, 'volatile_bytecode', return_value=False):
            self.create()
        before = bundle.inventory(self.backup)
        manifest, blobs = bundle.verify()
        self.assertTrue(any(row['name'].endswith('.pyc') for row in manifest['entries'][2]['tree']))
        bytecode.write_bytes(b'regenerated bytecode')
        self.assertEqual(self.create(), self.backup)
        bundle.unchanged(manifest)
        self.assertEqual(bundle.inventory(self.backup), before)
        # Historical restore and its strict verification still work unmodified.
        bundle.restore_system(manifest, blobs)
        self.assertEqual(bytecode.read_bytes(), b'old bytecode')

    def test_new_bundle_omits_bytecode_and_accepts_new_cache(self):
        cache = self.system[2] / '__pycache__'
        cache.mkdir()
        (cache / 'arbitrary.data').write_bytes(b'cache contents')
        (self.system[2] / 'backend.pyc').write_bytes(b'pyc contents')
        (self.system[2] / 'backend.pyo').write_bytes(b'pyo contents')
        self.create()
        manifest, blobs = bundle.verify()
        for entry in manifest['entries']:
            self.assertFalse(any(bundle.volatile_bytecode(row['name']) for row in entry['tree']))
        for data in (b'cache contents', b'pyc contents', b'pyo contents'):
            self.assertNotIn(bundle.digest(data), blobs)
        shutil.rmtree(cache)
        bundle.restore_system(manifest, blobs)
        cache.mkdir()
        (cache / 'new.pyc').write_bytes(b'new cache')
        bundle.unchanged(manifest)

    def test_real_prepare_preserves_effective_dropin_map_in_bundle(self):
        marker = Path(self.user['home']) / '.local/share/inode-modern/.inode-modern-install'
        marker.write_text('org.inode_modern.Client')
        with patch.multiple(installer, UNIT=self.system[0], FIREWALL_UNIT=self.system[1],
                            LIBEXEC=self.system[2], CONFIG_DIR=self.root, DOC_DIR=self.system[4],
                            MARKER=self.system[2] / '.inode-modern-install'), \
                patch.object(installer.vendor_generation, 'validate_destination'), \
                patch.object(installer, 'unit_state', side_effect=lambda name: state()):
            self.assertEqual(installer.prepare_backup('fixture'), self.backup)
        manifest, _ = bundle.verify()
        self.assertEqual(manifest['unit_dropins'], {})

    def test_roundtrip_complete_payload_modes_absence_and_frontend(self):
        self.create()
        manifest, blobs = bundle.verify()
        before = (self.backup / 'manifest.json').read_bytes()
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.backup.rglob('*') if p.is_file()))
        (self.system[2] / 'backend.py').write_text('candidate')
        (self.system[2] / 'broker.py').write_text('candidate-only')
        self.system[1].write_text('candidate firewall')
        bundle.restore_system(manifest, blobs)
        for entry in manifest['entries'][len(self.system):]:
            path = Path(entry['target'])
            if path.is_file():
                path.write_text('candidate frontend')
            bundle.restore_entry(entry, blobs)
        bundle.unchanged(manifest)
        self.assertFalse(self.system[1].exists())
        self.assertFalse((self.system[2] / 'broker.py').exists())
        self.assertEqual(before, (self.backup / 'manifest.json').read_bytes())
        self.assertEqual(self.create(), self.backup)  # reuse never replaces it

    def test_corruption_and_changed_baseline_fail_closed(self):
        self.create()
        manifest, _ = bundle.verify()
        (self.system[2] / 'backend.py').write_text('different production')
        with self.assertRaises(bundle.BundleError):
            self.create()
        blob = next((self.backup / 'blobs').iterdir())
        blob.write_bytes(b'corrupt')
        with self.assertRaises(bundle.BundleError):
            bundle.verify()
        self.assertEqual((self.system[2] / 'backend.py').read_text(), 'different production')

    def test_creation_failure_never_publishes_or_changes_sources(self):
        before = [bundle.inventory(p) for p in self.system]
        with patch.object(bundle, 'durable_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.create()
        self.assertFalse(self.backup.exists())
        self.assertEqual(before, [bundle.inventory(p) for p in self.system])

    def test_verification_failure_never_publishes(self):
        with patch.object(bundle, 'verify', side_effect=bundle.BundleError('checksum')):
            with self.assertRaises(bundle.BundleError):
                self.create()
        self.assertFalse(self.backup.exists())

    def test_source_and_destination_symlinks_fail_closed(self):
        (self.system[2] / 'link').symlink_to('/etc/passwd')
        with self.assertRaises(bundle.BundleError):
            self.create()

    def test_recovery_is_independent_of_source_and_run_staging(self):
        self.create()
        result = subprocess.run([sys.executable, '-I', str(self.backup / 'recovery/install_backend.py'), '--help'],
                                cwd='/', env={'PATH': '/usr/bin'}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--rollback', result.stdout)

    def test_frontend_child_drops_privileges_before_restore(self):
        self.create()
        manifest, blobs = bundle.verify()
        events = []
        with patch.object(bundle.os, 'fork', return_value=0), \
                patch.object(bundle.os, 'initgroups', side_effect=lambda *a: events.append('groups')), \
                patch.object(bundle.os, 'setgid', side_effect=lambda *a: events.append('gid')), \
                patch.object(bundle.os, 'setuid', side_effect=lambda *a: events.append('uid')), \
                patch.object(bundle, 'restore_entry', side_effect=lambda *a: events.append('restore')), \
                patch.object(bundle.os, '_exit', side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                bundle.restore_frontend(manifest, blobs)
        self.assertEqual(events[:4], ['groups', 'gid', 'uid', 'restore'])

    def install_context(self, stack, events, fail_stop=False):
        stack.enter_context(patch.object(installer, 'guard_present',
                                        side_effect=lambda: events.append('guard-absent') or False))
        stack.enter_context(patch.multiple(installer, UNIT=self.system[0], FIREWALL_UNIT=self.system[1],
                            LIBEXEC=self.system[2], CONFIG_DIR=self.root, DOC_DIR=self.system[4],
                            MARKER=self.system[2] / '.inode-modern-install'))
        stack.enter_context(patch.object(installer, 'check_identities', return_value=[]))
        stack.enter_context(patch.object(installer, 'hashes', return_value={}))
        stack.enter_context(patch.object(installer.backend, 'processes', return_value=[]))
        stack.enter_context(patch.object(installer.vendor_generation, 'validate_destination'))
        stack.enter_context(patch.object(installer.vendor_generation, 'CURRENT_SYMLINK', self.root / 'selector'))
        stack.enter_context(patch.object(installer.vendor_generation, 'import_generation', return_value=self.root / 'generation'))
        stack.enter_context(patch.object(installer.vendor_generation, 'activate_generation'))
        stack.enter_context(patch.object(installer, 'unit_state', side_effect=lambda name: state('not-found') if name == installer.FIREWALL_SERVICE else state()))
        def backup(*args):
            result = self.create()
            events.append('verified-backup')
            return result
        stack.enter_context(patch.object(installer, 'prepare_backup', side_effect=backup))
        def run(*args, **kwargs):
            events.append(args)
            if args == ('systemctl', 'stop', installer.SERVICE):
                bundle.verify()
                self.assertEqual((self.system[2] / 'backend.py').read_text(), 'legacy backend')
                self.assertNotIn('check', kwargs)  # run's checked default
                if fail_stop:
                    raise subprocess.CalledProcessError(1, args)
        stack.enter_context(patch.object(installer, 'run', side_effect=run))

    def test_first_permanent_install_missing_firewall_and_sandbox_rollback(self):
        events = []
        with ExitStack() as stack:
            self.install_context(stack, events)
            installer.install(Path('/fixture'), frontend_user='fixture')
        self.assertEqual(events[0], 'verified-backup')
        self.assertIn(('systemctl', 'stop', installer.SERVICE), events)
        self.assertNotIn(('systemctl', 'stop', installer.FIREWALL_SERVICE), events)
        self.assertEqual((self.system[2] / 'backend.py').read_bytes(), (ROOT / 'integration/backend.py').read_bytes())
        manifest, blobs = bundle.verify()
        bundle.restore_system(manifest, blobs)
        bundle.unchanged(manifest)
        self.assertFalse(self.system[1].exists())

    def test_old_backend_stop_failure_prevents_overwrite(self):
        events = []
        with ExitStack() as stack:
            self.install_context(stack, events, fail_stop=True)
            with self.assertRaises(subprocess.CalledProcessError):
                installer.install(Path('/fixture'), frontend_user='fixture')
        manifest, _ = bundle.verify()
        bundle.unchanged(manifest)
        self.assertFalse(self.system[1].exists())

    def test_install_order_and_new_sequence_live_membership(self):
        events = []
        model = GuardReloadModel()
        with ExitStack() as stack:
            self.install_context(stack, events)
            original_run = installer.run
            def run(*args, **kwargs):
                original_run(*args, **kwargs)
                model.run(*args, **kwargs)
            stack.enter_context(patch.object(installer, 'run', side_effect=run))
            installer.install(Path('/fixture'), frontend_user='fixture')
            verify = ('systemd-analyze', 'verify', str(installer.FIREWALL_UNIT), str(installer.UNIT))
            self.assertEqual(events[events.index(verify):], [
                verify, 'guard-absent',
                ('systemctl', 'enable', installer.FIREWALL_SERVICE),
                ('systemctl', 'enable', installer.SERVICE),
                ('systemctl', 'daemon-reload'),
                ('systemctl', 'start', installer.FIREWALL_SERVICE),
                (str(installer.LIBEXEC / 'firewall_guard.sh'), 'check'),
                ('systemctl', 'start', installer.SERVICE)])
        self.assertEqual(model.elements, [model.live])
        model.validate(require_live=True)

    def test_existing_or_unknown_guard_aborts_before_enable_reload_or_start(self):
        for result in (True, firewall.FirewallError('inventory failed')):
            events = []
            with self.subTest(result=result), ExitStack() as stack:
                self.install_context(stack, events)
                stack.enter_context(patch.object(installer, 'guard_present', side_effect=[result]))
                teardown = stack.enter_context(patch.object(installer, 'teardown_guard'))
                with self.assertRaises(firewall.FirewallError):
                    installer.install(Path('/fixture'), frontend_user='fixture')
                teardown.assert_not_called()
            self.assertFalse(any(isinstance(event, tuple) and event[0] == 'systemctl'
                                 and event[1] in ('enable', 'daemon-reload', 'start') for event in events))
            manifest, blobs = bundle.verify()
            bundle.restore_system(manifest, blobs)

    def test_fresh_guard_check_failure_prevents_backend_start(self):
        events = []
        with ExitStack() as stack:
            self.install_context(stack, events)
            original_run = installer.run
            def run(*args, **kwargs):
                original_run(*args, **kwargs)
                if args == (str(installer.LIBEXEC / 'firewall_guard.sh'), 'check'):
                    raise subprocess.CalledProcessError(1, args)
            stack.enter_context(patch.object(installer, 'run', side_effect=run))
            with self.assertRaises(subprocess.CalledProcessError):
                installer.install(Path('/fixture'), frontend_user='fixture')
        self.assertNotIn(('systemctl', 'start', installer.SERVICE), events)


class TransactionTests(unittest.TestCase):
    def test_backup_failure_precedes_any_stop_or_account_mutation(self):
        with patch.object(installer.vendor_generation, 'validate_destination'), \
                patch.object(installer.vendor_generation, 'CURRENT_SYMLINK', Path('/not-existing-fixture-selector')), \
                patch.object(installer, 'check_identities', return_value=[]), \
                patch.object(installer, 'managed', return_value=True), \
                patch.object(installer, 'hashes', return_value={}), \
                patch.object(installer, 'prepare_backup', side_effect=bundle.BundleError('failed')), \
                patch.object(installer, 'run') as run:
            with self.assertRaises(bundle.BundleError):
                installer.install(Path('/fixture'), frontend_user='fixture')
            run.assert_not_called()

    def rollback_context(self, stack, events):
        stack.enter_context(patch.object(bundle, 'verify', return_value=({'backend_enabled': 'enabled', 'unit_dropins': {}}, {})))
        stack.enter_context(patch.object(installer.vendor_generation, 'validate_destination'))
        for name in ('stop_candidate', 'stop_firewall', 'teardown_guard', 'verify_quiescent'):
            stack.enter_context(patch.object(installer, name, side_effect=lambda *a, n=name, **k: events.append(n)))
        for name in ('restore_system', 'restore_frontend'):
            stack.enter_context(patch.object(bundle, name, side_effect=lambda *a, n=name: events.append(n)))
        stack.enter_context(patch.object(installer, 'run', side_effect=lambda *a, **k: events.append(a)))

    def test_rollback_order_and_final_nft_gate_before_old_start(self):
        events = []
        with ExitStack() as stack:
            self.rollback_context(stack, events)
            installer.rollback()
        self.assertEqual(events[:5], ['stop_candidate', 'stop_firewall', 'teardown_guard', 'verify_quiescent', 'restore_system'])
        start = events.index(('systemctl', 'start', installer.SERVICE))
        self.assertEqual(events[start - 1], 'teardown_guard')
        self.assertLess(events.index(('systemctl', 'daemon-reload')), start)
        self.assertEqual(events[-1], 'restore_frontend')

    def test_failures_before_start_never_restart_legacy(self):
        for module, name in ((bundle, 'verify'), (installer, 'stop_candidate'), (installer, 'stop_firewall'),
                             (installer, 'teardown_guard'), (installer, 'verify_quiescent'), (bundle, 'restore_system')):
            events = []
            with ExitStack() as stack:
                self.rollback_context(stack, events)
                stack.enter_context(patch.object(module, name, side_effect=RuntimeError('gate failure')))
                with self.assertRaises(RuntimeError):
                    installer.rollback()
            self.assertNotIn(('systemctl', 'start', installer.SERVICE), events)

    def test_uninstall_teardown_failure_keeps_installed_files(self):
        with patch.object(installer, 'managed', return_value=True), patch.object(installer, 'stop_candidate'), \
                patch.object(installer, 'stop_firewall'), patch.object(installer, 'run'), \
                patch.object(installer, 'teardown_guard', side_effect=firewall.FirewallError('remaining')), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaises(firewall.FirewallError):
                installer.uninstall()
            unlink.assert_not_called()


class QuiescenceTests(unittest.TestCase):
    def test_ports_residual_roles_and_unreadable_process_are_gates(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(installer, 'unit_state', return_value=state()), \
                patch.object(installer, 'cgroup_members', return_value=[]):
            proc = Path(tmp)
            (proc / 'net').mkdir()
            for name in ('udp', 'udp6'):
                (proc / 'net' / name).write_text('header\n')
            installer.verify_quiescent(proc)
            (proc / 'net/udp').write_text('header\n0: 00000000:C351 rest\n')
            with self.assertRaises(installer.backend.BackendError):
                installer.verify_quiescent(proc)
            (proc / 'net/udp').write_text('header\n')
            process = proc / '999999'
            process.mkdir()
            (process / 'status').write_text('Uid:\t10001\t10001\t10001\t10001\n')
            (process / 'cmdline').write_bytes(b'vendor\0')
            (process / 'cgroup').write_text('0::/elsewhere')
            with self.assertRaises(installer.backend.BackendError):
                installer.verify_quiescent(proc)
            (process / 'status').unlink()
            with self.assertRaises(installer.backend.BackendError):
                installer.verify_quiescent(proc)

    def test_missing_cgroup_procs_is_not_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                installer.cgroup_members(Path(tmp))

    def test_descendant_cgroup_members_and_unreadable_tree_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'cgroup.procs').write_text('')
            (root / 'child').mkdir()
            (root / 'child/cgroup.procs').write_text('123\n')
            self.assertEqual(installer.cgroup_members(root), ['123'])
            with patch.object(installer.os, 'scandir', side_effect=PermissionError('unreadable')):
                with self.assertRaises(PermissionError):
                    installer.cgroup_members(root)


if __name__ == '__main__':
    unittest.main()


# These tests model process snapshots independently of the host account database.
def setUpModule():
    import sys
    from tests.identity_fixture import start_role_fixture
    global _role_patches
    _role_patches = start_role_fixture(sys.modules[__name__])


def tearDownModule():
    for mock in reversed(_role_patches):
        mock.stop()

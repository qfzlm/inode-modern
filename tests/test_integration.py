import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.install_desktop import install, uninstall

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend', ROOT / 'integration/backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
spec = importlib.util.spec_from_file_location('installer', ROOT / 'integration/install_backend.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class IntegrationTests(unittest.TestCase):
    def test_discovery_is_data_not_shell_and_must_match_vendor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'inodesys.conf'
            config.write_text('INSTALL_DIR=' + str(root) + '\n')
            for name in backend.NAMES:
                (root / name).write_bytes(b'\x7fELFsynthetic')
                (root / name).chmod(0o755)
            (root / 'libs/std').mkdir(parents=True)
            self.assertEqual(backend.vendor_directory(vendor_config=config), root)
            with self.assertRaises(backend.BackendError):
                backend.vendor_directory('/tmp/elsewhere', config)
            config.write_text('INSTALL_DIR=/tmp/$(touch-injected)\n')
            with self.assertRaises(backend.BackendError):
                backend.vendor_directory(vendor_config=config)
            self.assertFalse((root / 'touch-injected').exists())

    def test_journal_only_emits_whitelisted_new_function_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'vendor.log'
            prefix = b'[2026-09-06 12:00:00] [x] [y] '
            log.write_bytes(prefix + b'[ProcessEapSuccess] old\n')
            reader = backend.EventReader(root)
            with log.open('ab') as f:
                f.write(prefix + b'[Payload] password=synthetic-secret ProcessEapSuccess\n')
                f.write(prefix + b'[SendLogoffPkt] synthetic-secret\n')
                f.write(prefix + b'[ProcessEapSuccess] synthetic-secret')
            self.assertEqual(reader.read(), ['SendLogoffPkt'])
            with log.open('ab') as f:
                f.write(b'\n')
            result = reader.read()
            self.assertEqual(result, ['ProcessEapSuccess'])
            self.assertNotIn('synthetic-secret', repr(result))
            self.assertEqual(reader.read(), [])

    def test_log_rotation_and_large_payload_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'a.log'
            log.write_bytes(b'old\n')
            reader = backend.EventReader(root)
            log.unlink()
            log.write_bytes(b'[2026-09-06 12:00:00] [x] [y] [Dot_Success] text\n')
            self.assertEqual(reader.read(), ['Dot_Success'])
            with log.open('ab') as f:
                f.write(b'x' * 300000)
            self.assertEqual(reader.read(), [])

    def test_owned_processes_require_exact_executable_and_cgroup(self):
        supervisor = backend.Supervisor(Path('/vendor'))
        data = [(1, Path('/vendor/AuthenMngService'), supervisor.group),
                (2, Path('/vendor/AuthenMngService'), 'external'),
                (3, Path('/elsewhere/AuthenMngService'), supervisor.group)]
        with patch.object(backend, 'processes', return_value=data):
            self.assertEqual(supervisor.owned('AuthenMngService'), [1])
            with self.assertRaises(backend.BackendError):
                supervisor.preflight()

    def test_normal_stop_orders_watchdog_before_engine(self):
        supervisor = backend.Supervisor(Path('/vendor'))
        with patch.object(supervisor, 'stop_one') as stop, patch.object(backend, 'emit'):
            supervisor.stop()
        self.assertEqual([call.args[0] for call in stop.call_args_list], ['iNodeMon', 'AuthenMngService'])

    def test_private_libraries_only_in_vendor_child_environment(self):
        supervisor = backend.Supervisor(Path('/vendor'))
        with patch.dict(os.environ, {'LD_PRELOAD': 'untrusted', 'PASSWORD': 'synthetic-secret'}), \
             patch.object(backend.subprocess, 'Popen') as spawn:
            supervisor.command('AuthenMngService')
        kwargs = spawn.call_args.kwargs
        self.assertEqual(kwargs['env']['LD_LIBRARY_PATH'], '/vendor/libs/std:/vendor/libs')
        self.assertNotIn('LD_PRELOAD', kwargs['env'])
        self.assertNotIn('PASSWORD', kwargs['env'])
        self.assertEqual(kwargs['stdout'], backend.subprocess.DEVNULL)

    def test_unit_has_bounded_group_lifecycle_and_boot_dependency(self):
        unit = installer.unit_text(Path('/home/example/iNodeClient'))
        for field in ('Type=notify', 'NotifyAccess=main', 'KillMode=mixed', 'Restart=on-failure',
                      'TimeoutStopSec=40', 'StartLimitBurst=3', 'WantedBy=multi-user.target',
                      'RequiresMountsFor=/home/example/iNodeClient', 'LimitCORE=0',
                      'Requires=inode-modern-firewall.service',
                      'NFTSet=cgroup:inet:inode_modern_guard:allowed_cgroups',
                      'RuntimeDirectory=inode-modern inode-modern-private'):
            self.assertIn(field, unit)
        for forbidden in ('LD_LIBRARY_PATH', '50002', 'setenforce', 'chcon', 'install_64', 'User=zhxhjg'):
            self.assertNotIn(forbidden, unit)

    def test_frontend_install_uninstall_roundtrip_without_source_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            install(prefix)
            self.assertTrue((prefix / 'bin/inode-modern').exists())
            self.assertTrue((prefix / 'share/inode-modern/install_desktop.py').exists())
            (prefix / 'unrelated-file').write_text('preserve')
            uninstall(prefix)
            self.assertEqual([p.name for p in prefix.iterdir() if p.is_file()], ['unrelated-file'])
            self.assertFalse((prefix / 'share/inode-modern').exists())

    def test_uninstall_does_not_delete_modified_or_unrelated_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            install(prefix)
            launcher = prefix / 'bin/inode-modern'
            launcher.write_text('user changed this')
            with self.assertRaises(RuntimeError):
                uninstall(prefix)
            self.assertTrue(launcher.exists())

    def test_system_uninstall_removes_own_bytecode_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lib, config, doc = (root / name for name in ('libexec', 'config', 'doc'))
            for directory in (lib, config, doc):
                directory.mkdir()
            (lib / '.inode-modern-install').write_text(installer.APP_ID)
            (lib / '__pycache__').mkdir()
            (lib / '__pycache__/backend.cpython-314.pyc').write_bytes(b'synthetic cache')
            unit = root / 'unit.service'
            unit.write_text('synthetic')
            fw_unit = root / 'fw_unit.service'
            fw_unit.write_text('synthetic')
            with patch.multiple(installer, LIBEXEC=lib, CONFIG_DIR=config, DOC_DIR=doc,
                                MARKER=lib / '.inode-modern-install', UNIT=unit, FIREWALL_UNIT=fw_unit), \
                 patch.object(installer, 'run'), patch.object(installer, 'stop_candidate'), \
                 patch.object(installer, 'stop_firewall'), patch.object(installer, 'teardown_guard'):
                installer.uninstall()
            self.assertFalse(lib.exists())
            self.assertFalse(unit.exists())
            self.assertFalse(fw_unit.exists())

    def test_distribution_file_list_contains_no_vendor_files(self):
        own = list((ROOT / 'inode_modern').rglob('*.py')) + list((ROOT / 'integration').glob('*'))
        self.assertTrue(own)
        for file in own:
            if file.is_file():
                self.assertNotEqual(file.read_bytes()[:4], b'\x7fELF')
                self.assertNotIn('.so', file.name)


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

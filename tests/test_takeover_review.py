"""Offline regression coverage for Candidate A takeover findings."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from inode_modern.client import Client, ClientError
from inode_modern.protocol import Message, TLV, connect_request
from integration import backend, broker, invariants
from tools import vendor_generation as vg

ROOT = Path(__file__).resolve().parents[1]


class TakeoverTests(unittest.TestCase):
    def test_missing_refused_and_denied_uds_never_open_udp(self):
        for error in (FileNotFoundError(), ConnectionRefusedError(), PermissionError()):
            with self.subTest(error=type(error).__name__):
                sock = Mock()
                sock.connect.side_effect = error
                with patch('inode_modern.client.socket.socket', return_value=sock) as factory:
                    with self.assertRaises(ClientError):
                        with Client():
                            pass
                    factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.sendto.assert_not_called()

    def test_repeated_uds_rpc_and_no_ack_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = broker.ControlBroker(Path(tmp) / 'control.sock', frontend_addr=('127.0.0.1', 0))
            seen = []
            def exchange(message, **kwargs):
                seen.append((message.kind, kwargs.get('wait_response', True)))
                if not kwargs.get('wait_response', True):
                    return None
                return Message(8, (TLV(14, b'\0\0\0\1'),))
            with patch.object(control, '_exchange_udp', side_effect=exchange), \
                 patch('integration.broker.validate_interface_name', return_value='eth0'):
                control.start()
                thread = threading.Thread(target=control.run, daemon=True)
                # start() is already complete; avoid rebinding in run().
                with patch.object(control, 'start'):
                    thread.start()
                    try:
                        with Client(control_socket=control.socket_path) as client:
                            self.assertEqual(client.status().kind, 8)
                            client.send(connect_request('synthetic', 'synthetic-secret', 'eth0'))
                            client.send(Message(3))
                            self.assertEqual(client.status().kind, 8)
                    finally:
                        control.running = False
                        thread.join(2)
                        control.close()
                self.assertFalse(thread.is_alive())
            self.assertEqual(seen, [(7, True), (1, False), (3, False), (7, True)])

    def test_broker_fixed_frontend_and_ephemeral_response_source(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as daemon, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reply, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            daemon.bind(('127.0.0.1', 0))
            daemon.settimeout(2)
            reserve.bind(('127.0.0.1', 0))
            frontend = reserve.getsockname()
            reserve.close()
            control = broker.ControlBroker(daemon_addr=daemon.getsockname(), frontend_addr=frontend)
            observed = []
            def serve():
                _, peer = daemon.recvfrom(65535)
                observed.append(peer)
                reply.sendto(b'invalid', frontend)
                reply.sendto(Message(11).encode(), frontend)
                reply.sendto(Message(8).encode(), frontend)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            self.assertEqual(control._exchange_udp(Message(7), timeout=1), Message(8))
            thread.join(2)
            self.assertEqual(observed, [frontend])

    def test_redacted_metadata_does_not_become_numeric_zero(self):
        client = Client()
        with patch.object(client, '_uds_rpc', return_value={
            'ok': True, 'status': {'fields': [{'type': 14, 'value_length': 1}]}
        }):
            self.assertFalse(any('value' in f for f in client.status().safe_summary()['fields']))

    def test_broker_does_not_reflect_request_secrets(self):
        control = broker.ControlBroker()
        for req in ([], {'action': 'synthetic-secret'},
                    {'action': 'connect', 'username': 'a', 'password': 'b', 'interface': 'synthetic-secret;'}):
            self.assertNotIn('synthetic-secret', json.dumps(control.dispatch_request(req, 1000)))

    def test_exact_capability_launch_arguments(self):
        supervisor = backend.Supervisor(Path('/opt/inode-modern/vendor/gen-0001'))
        with patch('integration.backend.subprocess.Popen') as spawn, patch.object(Path, 'is_file', return_value=True):
            for name, caps in [('AuthenMngService', '-all,+net_raw,+net_admin'),
                               ('iNodeMon', '-all'), ('broker', '-all')]:
                supervisor.command(name)
                self.assertIn('--bounding-set=' + caps, spawn.call_args.args[0])
                self.assertIn('--no-new-privs', spawn.call_args.args[0])
                self.assertNotIn('LD_PRELOAD', spawn.call_args.kwargs['env'])

    def test_missing_manifest_cannot_bypass_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = Path(tmp) / 'gen-0001'
            (gen / 'libs/std').mkdir(parents=True)
            for name in backend.NAMES:
                (gen / name).write_bytes(b'\x7fELFsynthetic')
                (gen / name).chmod(0o555)
            with patch.object(backend, 'VENDOR_BASE', Path(tmp)), \
                 patch.object(backend, 'verify_generation', side_effect=vg.GenerationError('missing')) as verify:
                with self.assertRaises(backend.BackendError):
                    backend.resolve_generation(gen)
                verify.assert_called_once_with(gen)

    def test_untrusted_owner_rejected(self):
        st = Mock(st_uid=1000, st_gid=0, st_mode=0o100444)
        with patch.object(Path, 'lstat', return_value=st):
            with self.assertRaises(vg.GenerationError):
                vg.check_root_owned(Path('/synthetic'))

    def test_manifest_coverage_traversal_and_external_links_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(vg, 'check_root_owned'):
            gen = Path(tmp)
            data = gen / 'data'
            data.write_text('synthetic')
            manifest = gen / vg.MANIFEST_NAME
            manifest.write_text('')
            with self.assertRaises(vg.GenerationError):
                vg.verify_generation(gen)
            manifest.write_text('0' * 64 + '  ../outside\n')
            with self.assertRaises(vg.GenerationError):
                vg.verify_generation(gen)
            manifest.write_text(vg.compute_sha256(data) + '  data\n')
            (gen / 'escape').symlink_to('/etc/passwd')
            with self.assertRaises(vg.GenerationError):
                vg.verify_generation(gen)

    def test_import_rejects_hardlinks_and_generation_name_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'src'
            source.mkdir()
            for name in vg.REQUIRED_BINARIES:
                (source / name).write_bytes(b'\x7fELFsynthetic')
            (source / 'libs').mkdir()
            for name in ('../escape', '/tmp/escape'):
                with self.assertRaises(vg.GenerationError):
                    vg.import_generation(source, Path(tmp) / 'target', name)
            os.link(source / 'iNodeMon', Path(tmp) / 'outside')
            with self.assertRaises(vg.GenerationError):
                vg.import_generation(source, Path(tmp) / 'target', 'gen-0001')
            self.assertFalse((Path(tmp) / 'target').exists())

    def snapshots(self):
        gen = Path('/opt/inode-modern/vendor/gen-0001')
        group = '0::/system.slice/inode-modern-backend.service'
        def snap(pid, name, uid, caps):
            return invariants.ProcessSnapshot(pid, name, gen / name, group,
                (uid,) * 4, (uid,) * 4, (), caps, caps, caps, caps, caps, 1)
        engine = snap(1, 'AuthenMngService', 10001, 0x3000)
        mon = snap(2, 'iNodeMon', 10002, 0)
        control = replace(snap(3, 'python3', 10000, 0), canonical_exe=Path('/usr/bin/python3').resolve())
        return gen, group, engine, mon, control

    def test_invariants_reject_missing_broker_extra_mon_and_capability_drift(self):
        gen, group, engine, mon, control = self.snapshots()
        with patch.object(invariants, 'verify_socket_ownership', return_value=True):
            self.assertTrue(invariants.verify_invariants([engine, mon, control], gen, group, broker_pid=3)[0])
            bad_sets = [[engine, mon], [engine, mon, control, replace(mon, pid=4, uids=(0,) * 4)],
                        [replace(engine, cap_bnd=0xffff), mon, control],
                        [replace(engine, cap_amb=0), mon, control],
                        [engine, mon, replace(control, cap_bnd=1)],
                        [engine, mon, replace(control, no_new_privs=0)]]
            for snapshots in bad_sets:
                self.assertFalse(invariants.verify_invariants(snapshots, gen, group, broker_pid=3)[0])

    def test_socket_ownership_requires_all_listeners(self):
        with patch.object(invariants, 'get_listening_udp_inodes', return_value={'1', '2'}), \
             patch.object(invariants, 'get_process_socket_inodes', return_value={'1'}):
            self.assertFalse(invariants.verify_socket_ownership(1, 50001))

    def test_mount_failure_aborts_namespace_setup(self):
        supervisor = backend.Supervisor(Path('/opt/inode-modern/vendor/gen-0001'))
        libc = Mock()
        libc.mount.return_value = -1
        with patch.object(Path, 'mkdir'), patch('integration.backend.os.chown'), \
             patch('integration.backend.os.chmod'), patch('integration.backend.os.geteuid', return_value=0), \
             patch('integration.backend.os.unshare'), patch('integration.backend.ctypes.CDLL', return_value=libc):
            with self.assertRaises(backend.BackendError):
                supervisor.setup_namespace()
            self.assertEqual(libc.mount.call_count, 1)

    def test_invariant_failure_skips_graceful_stop(self):
        supervisor = backend.Supervisor(Path('/opt/inode-modern/vendor/gen-0001'))
        with patch.object(supervisor, 'preflight'), patch.object(supervisor, 'setup_namespace'), \
             patch.object(supervisor, 'command'), patch.object(supervisor, 'wait_for', return_value=True), \
             patch.object(supervisor, 'scan_invariants', return_value=(False, 'synthetic')), \
             patch.object(supervisor, 'stop') as stop, patch.object(backend, 'notify'), \
             patch.object(backend, 'emit'), patch.object(backend, 'EventReader'), \
             patch.object(backend, 'check_identities'), patch.object(backend, 'verify_firewall'):
            with self.assertRaises(backend.BackendError):
                supervisor.run()
            stop.assert_not_called()

    def test_installed_layout_imports_under_isolated_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp)
            for name in ('backend.py', 'broker.py', 'invariants.py', 'identities.py', 'firewall.py',
                         'install_backend.py', 'rollback_bundle.py'):
                shutil.copyfile(ROOT / 'integration' / name, lib / name)
            shutil.copyfile(ROOT / 'tools/vendor_generation.py', lib / 'vendor_generation.py')
            (lib / 'inode_modern').mkdir()
            for name in ('__init__.py', 'protocol.py', 'validator.py'):
                shutil.copyfile(ROOT / 'inode_modern' / name, lib / 'inode_modern' / name)
            result = subprocess.run([sys.executable, '-I', '-B', str(lib / 'install_backend.py'), '--help'],
                                    capture_output=True, text=True, cwd='/')
            self.assertEqual(result.returncode, 0, result.stderr)
            code = 'import sys; sys.path.insert(0, sys.argv[1]); import broker, backend'
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(lib)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_peer_credentials_reject_system_uid_before_dispatch(self):
        control = broker.ControlBroker()
        left, right = socket.socketpair()
        with right, patch.object(broker, 'get_peer_credentials', return_value=(123, 42, 42)), \
             patch.object(control, 'dispatch_request') as dispatch:
            control.handle_client(left)
            self.assertFalse(json.loads(right.recv(4096))['ok'])
            dispatch.assert_not_called()

    def test_guard_sources_preserve_dynamic_set_and_protect_reply_port(self):
        script = (ROOT / 'tools/firewall_guard.sh').read_text()
        init = script.split('init_guard() {', 1)[1].split('cleanup_guard()', 1)[0]
        self.assertNotIn('delete table', init)
        self.assertNotIn('flush set', init)
        self.assertIn('{ 50000, 50001, 50002 }', init)
        self.assertIn('socket cgroupv2 level 2 @allowed_cgroups accept', init)
        fw_unit = (ROOT / 'integration/inode-modern-firewall.service').read_text()
        self.assertNotIn('ExecStop=', fw_unit)
        unit = (ROOT / 'integration/inode-modern-backend.service.in').read_text()
        self.assertIn('BindsTo=inode-modern-firewall.service', unit)
        self.assertIn('RuntimeDirectoryMode=0700', unit)
        self.assertIn('PrivateTmp=yes', unit)

    def test_event_reader_rejects_symlink_swap_at_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'vendor.log'
            log.write_bytes(b'old\n')
            reader = backend.EventReader(root)
            with log.open('ab') as stream:
                stream.write(b'new\n')
            with patch.object(backend.os, 'open', side_effect=OSError('synthetic race')) as opened:
                self.assertEqual(reader.read(), [])
                flags = opened.call_args.args[1]
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)


# These tests model process snapshots independently of the host account database.
def setUpModule():
    import sys
    from tests.identity_fixture import start_role_fixture
    global _role_patches
    _role_patches = start_role_fixture(sys.modules[__name__])


def tearDownModule():
    for mock in reversed(_role_patches):
        mock.stop()

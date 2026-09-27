import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integration.invariants import (
    ProcessSnapshot,
    verify_invariants,
    parse_status_field,
    parse_snapshot,
    EXPECTED_CAPS_ENGINE,
)


class TestRuntimeInvariants(unittest.TestCase):
    def setUp(self):
        roles = {f"inode-modern-{r}": (n, n) for r, n in (("broker",10000),("engine",10001),("mon",10002))}
        mock = patch("integration.invariants.resolve_identities", return_value=roles)
        mock.start(); self.addCleanup(mock.stop)
        self.pinned_gen = Path("/opt/inode-modern/vendor/gen-0001")
        self.cgroup = "0::/system.slice/inode-modern-backend.service"

    def _make_mock_proc(self, tmp_path: Path, engine_pid=100, mon_pid=200):
        # Create /proc/net/udp
        net_dir = tmp_path / "net"
        net_dir.mkdir(parents=True)
        # Port 50001 (C351) has inode 11111, Port 50002 (C352) has inode 22222
        udp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:C351 00000000:0000 07 00000000:00000000 00:00000000 00000000 10001        0 11111 2 0000000000000000 0\n"
            "   1: 00000000:C352 00000000:0000 07 00000000:00000000 00:00000000 00000000 10002        0 22222 2 0000000000000000 0\n"
        )
        (net_dir / "udp").write_text(udp_content)

        # Create engine fd dir
        eng_fd = tmp_path / str(engine_pid) / "fd"
        eng_fd.mkdir(parents=True)
        (eng_fd / "3").symlink_to("socket:[11111]")

        # Create mon fd dir
        mon_fd = tmp_path / str(mon_pid) / "fd"
        mon_fd.mkdir(parents=True)
        (mon_fd / "4").symlink_to("socket:[22222]")

    def test_valid_invariants(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp)
            self._make_mock_proc(proc_path)

            engine = ProcessSnapshot(
                pid=100,
                name="AuthenMngService",
                canonical_exe=self.pinned_gen / "AuthenMngService",
                cgroup=self.cgroup,
                uids=(10001, 10001, 10001, 10001),
                gids=(10001, 10001, 10001, 10001),
                groups=(),
                cap_inh=EXPECTED_CAPS_ENGINE,
                cap_prm=EXPECTED_CAPS_ENGINE,
                cap_eff=EXPECTED_CAPS_ENGINE,
                cap_bnd=EXPECTED_CAPS_ENGINE,
                cap_amb=EXPECTED_CAPS_ENGINE,
                no_new_privs=1,
            )

            mon = ProcessSnapshot(
                pid=200,
                name="iNodeMon",
                canonical_exe=self.pinned_gen / "iNodeMon",
                cgroup=self.cgroup,
                uids=(10002, 10002, 10002, 10002),
                gids=(10002, 10002, 10002, 10002),
                groups=(),
                cap_inh=0,
                cap_prm=0,
                cap_eff=0,
                cap_bnd=0,
                cap_amb=0,
                no_new_privs=1,
            )

            broker = ProcessSnapshot(300, 'python3', Path('/usr/bin/python3').resolve(),
                                     self.cgroup, (10000,) * 4, (10000,) * 4, (),
                                     0, 0, 0, 0, 0, 1)
            ok, reason = verify_invariants([engine, mon, broker], self.pinned_gen, self.cgroup,
                                           proc_path=proc_path, broker_pid=300)
            self.assertTrue(ok)
            self.assertEqual(reason, "OK")

    def test_rogue_engine_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp)
            self._make_mock_proc(proc_path)

            # iNodeMon self-respawned an engine with UID 10002 and zero caps
            rogue_engine = ProcessSnapshot(
                pid=101,
                name="AuthenMngService",
                canonical_exe=self.pinned_gen / "AuthenMngService",
                cgroup=self.cgroup,
                uids=(10002, 10002, 10002, 10002),
                gids=(10002, 10002, 10002, 10002),
                groups=(),
                cap_inh=0,
                cap_prm=0,
                cap_eff=0,
                cap_bnd=0,
                cap_amb=0,
                no_new_privs=1,
            )

            mon = ProcessSnapshot(
                pid=200,
                name="iNodeMon",
                canonical_exe=self.pinned_gen / "iNodeMon",
                cgroup=self.cgroup,
                uids=(10002, 10002, 10002, 10002),
                gids=(10002, 10002, 10002, 10002),
                groups=(),
                cap_inh=0,
                cap_prm=0,
                cap_eff=0,
                cap_bnd=0,
                cap_amb=0,
                no_new_privs=1,
            )

            ok, reason = verify_invariants([rogue_engine, mon], self.pinned_gen, self.cgroup, proc_path=proc_path)
            self.assertFalse(ok)
            self.assertIn("Rogue Engine detected", reason)

    def test_engine_excessive_capabilities_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp)
            self._make_mock_proc(proc_path)

            engine = ProcessSnapshot(
                pid=100,
                name="AuthenMngService",
                canonical_exe=self.pinned_gen / "AuthenMngService",
                cgroup=self.cgroup,
                uids=(10001, 10001, 10001, 10001),
                gids=(10001, 10001, 10001, 10001),
                groups=(),
                cap_inh=0x7ffffff,
                cap_prm=0x7ffffff,
                cap_eff=0x7ffffff,
                cap_bnd=0x7ffffff,
                cap_amb=0x7ffffff,
                no_new_privs=1,
            )

            mon = ProcessSnapshot(
                pid=200,
                name="iNodeMon",
                canonical_exe=self.pinned_gen / "iNodeMon",
                cgroup=self.cgroup,
                uids=(10002, 10002, 10002, 10002),
                gids=(10002, 10002, 10002, 10002),
                groups=(),
                cap_inh=0,
                cap_prm=0,
                cap_eff=0,
                cap_bnd=0,
                cap_amb=0,
                no_new_privs=1,
            )

            broker = ProcessSnapshot(300, 'python3', Path('/usr/bin/python3').resolve(),
                                     self.cgroup, (10000,) * 4, (10000,) * 4, (),
                                     0, 0, 0, 0, 0, 1)
            ok, reason = verify_invariants([engine, mon, broker], self.pinned_gen, self.cgroup,
                                           proc_path=proc_path, broker_pid=300)
            self.assertFalse(ok)
            self.assertIn("Rogue Engine detected", reason)

    def test_missing_watchdog_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp)
            self._make_mock_proc(proc_path)

            engine = ProcessSnapshot(
                pid=100,
                name="AuthenMngService",
                canonical_exe=self.pinned_gen / "AuthenMngService",
                cgroup=self.cgroup,
                uids=(10001, 10001, 10001, 10001),
                gids=(10001, 10001, 10001, 10001),
                groups=(),
                cap_inh=EXPECTED_CAPS_ENGINE,
                cap_prm=EXPECTED_CAPS_ENGINE,
                cap_eff=EXPECTED_CAPS_ENGINE,
                cap_bnd=EXPECTED_CAPS_ENGINE,
                cap_amb=EXPECTED_CAPS_ENGINE,
                no_new_privs=1,
            )

            ok, reason = verify_invariants([engine], self.pinned_gen, self.cgroup, proc_path=proc_path)
            self.assertFalse(ok)
            self.assertIn("Expected exactly 1 Mon, found 0", reason)

    def test_socket_ownership_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_path = Path(tmp)
            self._make_mock_proc(proc_path)
            # Break engine's socket fd
            (proc_path / "100/fd/3").unlink()

            engine = ProcessSnapshot(
                pid=100,
                name="AuthenMngService",
                canonical_exe=self.pinned_gen / "AuthenMngService",
                cgroup=self.cgroup,
                uids=(10001, 10001, 10001, 10001),
                gids=(10001, 10001, 10001, 10001),
                groups=(),
                cap_inh=EXPECTED_CAPS_ENGINE,
                cap_prm=EXPECTED_CAPS_ENGINE,
                cap_eff=EXPECTED_CAPS_ENGINE,
                cap_bnd=EXPECTED_CAPS_ENGINE,
                cap_amb=EXPECTED_CAPS_ENGINE,
                no_new_privs=1,
            )
            mon = ProcessSnapshot(
                pid=200,
                name="iNodeMon",
                canonical_exe=self.pinned_gen / "iNodeMon",
                cgroup=self.cgroup,
                uids=(10002, 10002, 10002, 10002),
                gids=(10002, 10002, 10002, 10002),
                groups=(),
                cap_inh=0,
                cap_prm=0,
                cap_eff=0,
                cap_bnd=0,
                cap_amb=0,
                no_new_privs=1,
            )

            broker = ProcessSnapshot(300, 'python3', Path('/usr/bin/python3').resolve(),
                                     self.cgroup, (10000,) * 4, (10000,) * 4, (),
                                     0, 0, 0, 0, 0, 1)
            ok, reason = verify_invariants([engine, mon, broker], self.pinned_gen, self.cgroup,
                                           proc_path=proc_path, broker_pid=300)
            self.assertFalse(ok)
            self.assertIn("does not own UDP port 50001", reason)


if __name__ == "__main__":
    unittest.main()

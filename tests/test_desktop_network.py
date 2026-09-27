from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from inode_modern.desktop.network import activate_existing_dhcp, wired_interfaces
from tools.install_desktop import install


class NetworkTests(unittest.TestCase):
    def test_only_physical_wired_interfaces_are_listed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("enp5s0", "wlp3s0", "veth0", "lo"):
                path = root / name
                path.mkdir()
                (path / "type").write_text("1")
                (path / "carrier").write_text("1")
                if name in ("enp5s0", "wlp3s0"):
                    (path / "device").mkdir()
                if name == "wlp3s0":
                    (path / "wireless").mkdir()
            with patch("inode_modern.desktop.network.ipv4_address", return_value="10.0.0.2"):
                interfaces = wired_interfaces(root)
            self.assertEqual([item.name for item in interfaces], ["enp5s0"])

    @patch("socket.if_nametoindex", return_value=1)
    def test_dhcp_only_activates_exact_existing_profile(self, _):
        with patch("inode_modern.desktop.network._nmcli", side_effect=["id1:ethernet\nid2:wifi\n", "enp5s0\nauto\n", ""]) as nm:
            activate_existing_dhcp("enp5s0")
        self.assertEqual(nm.call_args.args, ("--wait", "12", "connection", "up", "uuid", "id1", "ifname", "enp5s0"))

    @patch("socket.if_nametoindex", return_value=1)
    def test_dhcp_does_not_activate_another_8021x_stack(self, _):
        with patch("inode_modern.desktop.network._nmcli", side_effect=["id1:ethernet\n", "enp5s0\nauto\npeap\n"]) as nm:
            with self.assertRaises(RuntimeError):
                activate_existing_dhcp("enp5s0")
            self.assertEqual(nm.call_count, 2)

    def test_menu_install_contains_only_our_app(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "prefix with spaces"
            launcher, desktop, icon, app = install(prefix)
            self.assertTrue(launcher.stat().st_mode & 0o111)
            self.assertIn("Terminal=false", desktop.read_text())
            self.assertIn(f'Exec="{launcher}"', desktop.read_text())
            self.assertTrue((app / "inode_modern/protocol.py").exists())
            self.assertTrue(icon.exists())
            self.assertFalse(list(app.rglob("AuthenMngService")))
            self.assertFalse(list(app.rglob("*.so*")))


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from inode_modern.validator import validate_interface_name, ValidationError


class TestInterfaceValidator(unittest.TestCase):
    def test_valid_host_interface(self):
        if Path("/sys/class/net/enp5s0").exists():
            self.assertEqual(validate_interface_name("enp5s0"), "enp5s0")

    def test_reject_loopback(self):
        if Path("/sys/class/net/lo").exists():
            with self.assertRaises(ValidationError) as ctx:
                validate_interface_name("lo")
            self.assertIn("not an Ethernet device", str(ctx.exception))

    def test_syntax_rejection(self):
        bad_names = [
            "enp5s0; id",
            "enp5s0$(whoami)",
            "enp5s0`id`",
            "enp5s0\nrm -rf /",
            "eth0\" ;",
            "eth0' ;",
            "",
            "a" * 16,
            "foo bar",
            "../enp5s0",
            "/dev/null",
            "enp5s0&",
            "enp5s0|cat",
        ]
        for name in bad_names:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError) as ctx:
                    validate_interface_name(name)
                self.assertIn("invalid interface name syntax", str(ctx.exception))

    def test_nonexistent_interface(self):
        with self.assertRaises(ValidationError) as ctx:
            validate_interface_name("nonexist99")
        self.assertIn("no valid kernel ifindex", str(ctx.exception))

    def test_mocked_device_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = Path(tmp)
            eth_dir = sysfs / "eth0"
            eth_dir.mkdir(parents=True)
            (eth_dir / "type").write_text("1\n")

            wlan_dir = sysfs / "wlan0"
            wlan_dir.mkdir(parents=True)
            (wlan_dir / "type").write_text("801\n")  # ARPHRD_IEEE80211

            def mock_ifindex(name):
                if name in ("eth0", "wlan0"):
                    return 42
                raise OSError("No such device")

            self.assertEqual(
                validate_interface_name("eth0", sysfs_root=sysfs, ifindex_func=mock_ifindex),
                "eth0"
            )

            with self.assertRaises(ValidationError) as ctx:
                validate_interface_name("wlan0", sysfs_root=sysfs, ifindex_func=mock_ifindex)
            self.assertIn("not an Ethernet device", str(ctx.exception))


if __name__ == '__main__':
    unittest.main()

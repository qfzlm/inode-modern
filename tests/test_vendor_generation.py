import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools.vendor_generation import (
    GenerationError,
    import_generation,
    verify_generation,
    activate_generation,
    get_active_generation,
    compute_sha256,
)


class TestVendorGeneration(unittest.TestCase):
    def setUp(self):
        # Synthetic trees belong to the test user; ownership rejection has separate coverage.
        owner = patch("tools.vendor_generation.check_root_owned")
        owner.start()
        self.addCleanup(owner.stop)
        destination = patch("tools.vendor_generation._trusted_stat")
        destination.start()
        self.addCleanup(destination.stop)
        self.tmp_dir = tempfile.mkdtemp()
        self.base = Path(self.tmp_dir)
        self.source = self.base / "source_tree"
        self.source.mkdir()

        # Populate synthetic vendor files
        (self.source / "AuthenMngService").write_bytes(b"\x7fELFfake_authen")
        (self.source / "iNodeMon").write_bytes(b"\x7fELFfake_mon")
        (self.source / "renew.ps").write_text("#!/bin/sh\necho renew\n")
        (self.source / "addRun.sh").write_text("#!/bin/sh\necho add\n")
        (self.source / "delRun.sh").write_text("#!/bin/sh\necho del\n")
        (self.source / "enablecards.ps").write_text("#!/bin/sh\necho enable\n")

        libs = self.source / "libs"
        libs.mkdir()
        (libs / "libtest.so").write_bytes(b"\x7fELFfake_lib")
        std = libs / "std"
        std.mkdir()
        (std / "libstd.so").write_bytes(b"\x7fELFfake_std")

        config = self.source / "config.ini"
        config.write_text("[section]\nkey=val\n")

        self.vendor_target = self.base / "vendor"
        self.current_link = self.base / "current"
        self.sysconf = self.base / "inodesys.conf"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_import_and_verify(self):
        gen_path = import_generation(self.source, target_base=self.vendor_target, gen_name="gen-0001")
        self.assertTrue(gen_path.is_dir())
        self.assertEqual(gen_path.name, "gen-0001")

        manifest = verify_generation(gen_path)
        self.assertIn("AuthenMngService", manifest)
        self.assertIn("libs/libtest.so", manifest)
        self.assertIn("config.ini", manifest)

        # Permissions check: executables 0555, config 0444
        auth_mode = (gen_path / "AuthenMngService").stat().st_mode & 0o777
        self.assertEqual(auth_mode, 0o555)
        conf_mode = (gen_path / "config.ini").stat().st_mode & 0o777
        self.assertEqual(conf_mode, 0o444)

    def test_symlink_escape_rejection(self):
        # Create external file
        outside = self.base / "outside.txt"
        outside.write_text("secret")

        # Create symlink pointing outside
        evil_link = self.source / "evil_link"
        evil_link.symlink_to(outside)

        with self.assertRaises(GenerationError) as ctx:
            import_generation(self.source, target_base=self.vendor_target, gen_name="gen-0002")
        self.assertIn("Symlink escape detected", str(ctx.exception))

    def test_tamper_detection(self):
        gen_path = import_generation(self.source, target_base=self.vendor_target, gen_name="gen-0001")
        verify_generation(gen_path)

        # Tamper with file
        target_file = gen_path / "AuthenMngService"
        target_file.chmod(0o755)
        target_file.write_bytes(b"\x7fELFcorrupted")

        with self.assertRaises(GenerationError) as ctx:
            verify_generation(gen_path)
        self.assertIn("Checksum mismatch", str(ctx.exception))

    def test_permission_tamper_detection(self):
        gen_path = import_generation(self.source, target_base=self.vendor_target, gen_name="gen-0001")
        verify_generation(gen_path)

        # Make file group-writable
        target_file = gen_path / "config.ini"
        target_file.chmod(0o664)

        with self.assertRaises(GenerationError) as ctx:
            verify_generation(gen_path)
        self.assertIn("File permissions too permissive", str(ctx.exception))

    def test_activate_and_get_active(self):
        gen_path = import_generation(self.source, target_base=self.vendor_target, gen_name="gen-0001")
        activate_generation(gen_path, current_link=self.current_link, sysconf=self.sysconf)

        active = get_active_generation(current_link=self.current_link)
        self.assertEqual(active, gen_path.resolve())

        # Check sysconf content
        self.assertFalse(self.sysconf.exists())


if __name__ == "__main__":
    unittest.main()

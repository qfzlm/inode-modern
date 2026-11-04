import os
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HAS_QT = importlib.util.find_spec("PySide6") is not None
if HAS_QT:
    from PySide6.QtCore import QSettings
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication, QLineEdit, QLabel
    from inode_modern.desktop.preferences import Preferences, Wallet, StorageError
    from inode_modern.desktop.worker import Worker, LoginRequest
    from inode_modern.desktop.window import Window
    from inode_modern.desktop.window_opendesign import Window as OpenDesignWindow
    from inode_modern.desktop.network import WiredInterface
from inode_modern.protocol import Message, TLV
from tools.install_desktop import install, APP_ID


class MemoryWallet:
    value = None
    def write(self, username, password):
        self.value = {"username": username, "password": password}
    def read(self):
        return self.value
    def delete(self):
        self.value = None


@unittest.skipUnless(HAS_QT, "GUI optional dependency PySide6 is not installed")
class PreferencesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(["preferences-test"])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "gui.ini")
        self.wallet = MemoryWallet()
        self.prefs = Preferences(self.path, self.wallet)

    def test_save_restore_update_and_delete_without_plaintext_config(self):
        self.prefs.submitted("student@ct", "private-value", True)
        restored = Preferences(self.path, self.wallet).load()
        self.prefs.restore_secret(restored)
        self.assertEqual((restored.username, restored.password, restored.remember), ("student@ct", "private-value", True))
        self.assertNotIn("private-value", Path(self.path).read_text())
        self.prefs.submitted("second@ct", "changed-value", True)
        self.assertEqual(self.wallet.value["password"], "changed-value")
        self.assertEqual(self.prefs.load().username, "second@ct")
        self.prefs.set_remember(False)
        self.assertIsNone(self.wallet.value)
        self.assertFalse(self.prefs.load().remember)

    def test_migration_retains_only_public_settings_and_is_idempotent(self):
        settings = QSettings(self.path, QSettings.Format.IniFormat)
        settings.setValue("username", "student@ct")
        settings.setValue("password", "legacy-plaintext")
        settings.setValue("internal", 12)
        settings.sync()
        self.assertEqual(self.prefs.load().username, "student@ct")
        migrated = Path(self.path).read_bytes()
        self.prefs.load()
        self.assertEqual(Path(self.path).read_bytes(), migrated)
        self.assertNotIn(b"legacy-plaintext", migrated)
        self.assertNotIn(b"internal", migrated)
        self.assertIsNone(self.wallet.value)

    def test_missing_wallet_fails_closed_and_failed_delete_retries_on_start(self):
        self.prefs.submitted("student@ct", "private-value", True)
        with patch.object(self.wallet, "delete", side_effect=StorageError("无法安全保存密码")):
            with self.assertRaises(StorageError):
                self.prefs.set_remember(False)
        restored = self.prefs.load()
        self.prefs.restore_secret(restored)
        self.assertIsNone(self.wallet.value)
        self.assertEqual(restored.password, "")
        with patch.object(self.wallet, "write", side_effect=StorageError("无法安全保存密码")):
            with self.assertRaises(StorageError):
                self.prefs.submitted("student@ct", "another-private-value", True)
        self.assertNotIn("private-value", Path(self.path).read_text())

    def test_account_mismatch_never_prefills_other_accounts_secret(self):
        self.prefs.submitted("student@ct", "private-value", True)
        self.prefs.save_config("different@ct", True)
        restored = self.prefs.load()
        self.prefs.restore_secret(restored)
        self.assertEqual(restored.password, "")

    def test_gui_restores_masked_credentials_and_remember_available_online(self):
        self.prefs.submitted("student@ct", "private-value", True)
        saved = self.prefs.load()
        self.prefs.restore_secret(saved)
        window = Window()
        self.addCleanup(window.deleteLater)
        window.restore_credentials(saved)
        self.assertEqual(window.password.echoMode(), QLineEdit.EchoMode.Password)
        self.assertEqual(window.password.text(), "private-value")
        self.assertEqual(saved.password, "")
        window.update_state({"phase": "online"})
        window.show()
        self.app.processEvents()
        self.assertTrue(window.remember.isVisible())
        self.assertTrue(window.remember.isEnabled())
        labels = [item.text() for item in window.findChildren(QLabel)]
        self.assertFalse(any("状态值" in value or value == "网络地址" for value in labels))
        self.assertFalse(window.windowIcon().isNull())

    def test_worker_only_persists_after_successful_submission(self):
        class Client:
            fail = False
            def status(self):
                return Message(8, (TLV(14, (1).to_bytes(4, "big")), TLV(21, bytes(4))))
            def send(self, message):
                if self.fail:
                    raise OSError()
        worker = Worker(preferences=self.prefs)
        worker.client = Client()
        notices = []
        worker.notice.connect(notices.append)
        with patch("inode_modern.desktop.worker.wired_interfaces", return_value=[WiredInterface("enp5s0", True, "")]):
            worker.client.fail = True
            worker.connect_account(LoginRequest("student@ct", "private-value", "enp5s0", True))
            self.assertIsNone(self.wallet.value)
            worker.client.fail = False
            request = LoginRequest("student@ct", "private-value", "enp5s0", True)
            worker.connect_account(request)
            self.assertEqual(self.wallet.value["password"], "private-value")
            self.assertEqual(request.password, "")
        self.assertNotIn("private-value", repr(notices))

    def test_disconnect_restores_saved_password_for_repeated_reconnects(self):
        class Client:
            state = 2
            def status(self):
                return Message(8, (TLV(14, self.state.to_bytes(4, "big")), TLV(21, bytes(4))))
            def send(self, message):
                self.state = 1 if message.kind == 3 else 2

        self.prefs.submitted("student@ct", "private-value", True)
        for window_class in (Window, OpenDesignWindow):
            with self.subTest(window=window_class.__module__):
                window = window_class()
                self.addCleanup(window.deleteLater)
                worker = Worker(preferences=self.prefs)
                worker.client = Client()
                worker.credentials_restored.connect(window.restore_credentials)
                worker.changed.connect(window.update_state)
                worker.command_finished.connect(window.command_finished)
                window.disconnect_requested.connect(worker.disconnect_account)
                window.login.connect(worker.connect_account)
                saved = self.prefs.load()
                self.prefs.restore_secret(saved)
                window.restore_credentials(saved)
                with patch("inode_modern.desktop.worker.wired_interfaces",
                           return_value=[WiredInterface("enp5s0", True, "")]):
                    worker.poll()
                    for _ in range(2):
                        window.disconnect_button.click()
                        worker.poll()
                        self.assertEqual(window.snapshot["phase"], "offline")
                        self.assertEqual(window.password.text(), "private-value")
                        self.assertTrue(window.remember.isChecked())
                        window.connect_button.click()
                        self.assertEqual(window.password.text(), "")
                        worker.poll()
                        self.assertEqual(window.snapshot["phase"], "online")
                self.assertEqual(self.wallet.value["password"], "private-value")

    def test_disconnect_without_remember_does_not_restore_or_read_wallet(self):
        self.prefs.submitted("student@ct", "private-value", True)
        self.prefs.set_remember(False)
        worker = Worker(preferences=self.prefs)
        restored = []
        worker.credentials_restored.connect(restored.append)
        with patch.object(self.wallet, "read") as read:
            worker.disconnect_account()
        read.assert_not_called()
        self.assertEqual(restored, [])

    def test_disconnect_wallet_error_still_finishes_without_exposing_secret(self):
        self.prefs.submitted("student@ct", "private-value", True)
        worker = Worker(preferences=self.prefs)
        notices, finished = [], []
        worker.notice.connect(notices.append)
        worker.command_finished.connect(lambda: finished.append(True))
        with patch.object(self.wallet, "read", side_effect=StorageError("无法安全保存密码")):
            worker.disconnect_account()
        self.assertIn("无法安全保存密码", notices)
        self.assertEqual(finished, [True])
        self.assertNotIn("private-value", repr(notices))

    @unittest.skipUnless(importlib.util.find_spec("dbus"), "GUI dbus-python dependency is not installed")
    def test_wallet_denial_and_nonzero_results_are_errors(self):
        wallet = Wallet()
        with patch.object(wallet, "call", side_effect=["kdewallet", -1]):
            with self.assertRaises(StorageError):
                wallet.open()
        with patch.object(wallet, "open", return_value=1), patch.object(wallet, "call", side_effect=[True, -1]):
            with self.assertRaises(StorageError):
                wallet.write("u", "p")
        with patch.object(wallet, "call", side_effect=["kdewallet", False, 1, -1]):
            with self.assertRaises(StorageError):
                wallet.delete()

    def test_installed_icon_and_desktop_id_match_packaged_resource(self):
        prefix = Path(self.tmp.name) / "install"
        launcher, desktop, icon, app_dir = install(prefix)
        source = Path("inode_modern/desktop/inode-modern.svg").read_bytes()
        self.assertEqual(icon.relative_to(prefix).as_posix(), f"share/icons/hicolor/scalable/apps/{APP_ID}.svg")
        self.assertEqual(icon.read_bytes(), source)
        self.assertEqual((app_dir / "inode_modern/desktop/inode-modern.svg").read_bytes(), source)
        self.assertEqual(desktop.stem, APP_ID)
        self.assertIn(f"Icon={APP_ID}\n", desktop.read_text())
        self.assertIn(str(launcher), desktop.read_text())
        self.assertFalse(QIcon(str(icon)).isNull())


if __name__ == "__main__":
    unittest.main()

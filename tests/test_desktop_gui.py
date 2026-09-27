import importlib.util
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
import unittest
from unittest.mock import patch

HAS_QT = importlib.util.find_spec("PySide6") is not None
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if HAS_QT:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLineEdit
    from inode_modern.desktop.app import build_window
    from inode_modern.desktop.network import WiredInterface
    from inode_modern.desktop.window import Window
    from inode_modern.desktop.worker import LoginRequest, Worker
from inode_modern.client import ClientError, StatusTimeout
from inode_modern.protocol import Message, TLV, connect_request
from tests.test_desktop_state import status


@unittest.skipUnless(HAS_QT, "GUI optional dependency PySide6 is not installed")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(["inode-gui-tests"])
        cls.app.setQuitOnLastWindowClosed(False)

    def window(self):
        window = Window()
        self.addCleanup(window.deleteLater)
        window.update_state({"phase": "offline", "detail": "ready", "state": 1, "result": 0,
                             "can_connect": True, "can_disconnect": False, "responsive": True,
                             "interface": "enp5s0", "interfaces": [{"name": "enp5s0", "carrier": True, "ipv4": ""}]})
        window.show()
        self.app.processEvents()
        return window

    def test_login_masks_clears_password_and_blocks_duplicate_clicks(self):
        window = self.window()
        requests = []
        window.login.connect(requests.append)
        window.username.setText("synthetic@ct")
        window.password.setText("synthetic-secret")
        self.assertEqual(window.password.echoMode(), QLineEdit.EchoMode.Password)
        QTest.mouseClick(window.connect_button, Qt.MouseButton.LeftButton)
        QTest.mouseClick(window.connect_button, Qt.MouseButton.LeftButton)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].password, "synthetic-secret")
        self.assertEqual(window.password.text(), "")
        self.assertNotIn("synthetic-secret", repr(requests[0]))

    def test_suffix_only_never_leaves_the_gui(self):
        window = self.window()
        requests = []
        window.login.connect(requests.append)
        window.username.setText("@ct")
        window.password.setText("synthetic")
        window.connect_account()
        self.assertFalse(requests)
        self.assertTrue(window.notice.isVisible())

    def test_close_clears_inputs_without_implicit_logoff(self):
        window = self.window()
        disconnects, closes = [], []
        window.disconnect_requested.connect(lambda: disconnects.append(True))
        window.close_requested.connect(lambda: closes.append(True))
        window.password.setText("synthetic-secret")
        window.username.setText("synthetic@ct")
        window.close()
        self.assertFalse(disconnects)
        self.assertEqual(closes, [True])
        self.assertEqual(window.password.text(), "")
        self.assertEqual(window.username.text(), "")

    def test_unknown_status_cannot_enable_connect_or_claim_success(self):
        window = self.window()
        window.update_state({**window.snapshot, "phase": "unknown", "can_connect": False,
                             "can_disconnect": True, "state": 998})
        self.assertFalse(window.connect_button.isEnabled())
        self.assertTrue(window.disconnect_button.isEnabled())
        self.assertEqual(window.status_title.text(), "状态待确认")

    def test_worker_reuses_core_codec_and_drops_credentials_on_send_failure(self):
        class FakeClient:
            def status(self):
                return Message(8, (TLV(14, b"\0\0\0\1"), TLV(21, b"\0\0\0\0")))

            def send(self, message):
                self.packet = message.encode()
                raise ClientError("synthetic-secret")

        worker = Worker()
        worker.client = FakeClient()
        emitted, notices = [], []
        worker.changed.connect(emitted.append)
        worker.notice.connect(notices.append)
        request = LoginRequest("synthetic@ct", "synthetic-secret", "enp5s0")
        with patch("inode_modern.desktop.worker.wired_interfaces", return_value=[WiredInterface("enp5s0", True, "")]):
            worker.connect_account(request)
        self.assertEqual(worker.client.packet, connect_request("synthetic@ct", "synthetic-secret").encode())
        self.assertEqual(request.password, "")
        self.assertEqual(request.username, "")
        self.assertNotIn("synthetic-secret", repr(emitted) + repr(notices))

    def test_service_recovery_refreshes_stale_gui_state(self):
        class FakeClient:
            responsive = False

            def status(self):
                if not self.responsive:
                    raise StatusTimeout("timeout")
                return Message(8, (TLV(14, b"\0\0\0\1"), TLV(21, b"\0\0\0\0")))

        worker = Worker()
        worker.client = FakeClient()
        with patch("inode_modern.desktop.worker.wired_interfaces", return_value=[]):
            worker.poll()
            self.assertEqual(worker.model.phase, "unavailable")
            worker.client.responsive = True
            worker.poll()
        self.assertEqual(worker.model.phase, "offline")

    def test_shutdown_cancels_unsent_credentials(self):
        worker = Worker()
        worker.stop_requested.set()
        request = LoginRequest("synthetic@ct", "synthetic-secret", "enp5s0")
        worker.connect_account(request)
        self.assertEqual(request.password, "")
        self.assertEqual(request.username, "")

    def test_close_exits_real_application_event_loop(self):
        script = textwrap.dedent("""
            from PySide6.QtCore import QTimer
            from PySide6.QtWidgets import QApplication
            from inode_modern.desktop.app import build_window
            from inode_modern.desktop.worker import Worker
            from inode_modern.protocol import Message, TLV
            class Client:
                def __init__(self, **kwargs): pass
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def status(self):
                    return Message(8, (TLV(14, (1).to_bytes(4, 'big')), TLV(21, bytes(4))))
                def send(self, message):
                    raise AssertionError('closing must not send Logoff')
            app = QApplication(['close-lifecycle-test'])
            app.setQuitOnLastWindowClosed(False)
            window, worker, thread = build_window(app, Worker(Client))
            window.show()
            thread.start()
            QTimer.singleShot(150, window.close)
            QTimer.singleShot(2000, lambda: app.exit(91))
            result = app.exec()
            assert not thread.isRunning()
            assert result == 0, 'the window vetoed application quit after the worker stopped'
        """)
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_worker_thread_real_udp_and_gui_responsiveness(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.05)
        stop = threading.Event()
        kinds, errors = [], []
        def serve():
            state = 1
            try:
                while not stop.is_set():
                    try:
                        raw, peer = server.recvfrom(65535)
                    except TimeoutError:
                        continue
                    message = Message.decode(raw)
                    kinds.append(message.kind)
                    if message.kind == 1:
                        state = 2
                    elif message.kind == 3:
                        state = 1
                    elif message.kind == 7:
                        time.sleep(0.12)
                        server.sendto(Message(8, (TLV(14, state.to_bytes(4, "big")), TLV(21, b"\0\0\0\0"))).encode(), peer)
            except BaseException as exc:
                errors.append(exc)
        daemon = threading.Thread(target=serve, daemon=True)
        daemon.start()
        def until(predicate, timeout=5):
            deadline = time.monotonic() + timeout
            while not predicate() and time.monotonic() < deadline:
                QTest.qWait(10)
            self.assertTrue(predicate())
        try:
            with patch("inode_modern.client.FRONTEND", ("127.0.0.1", 0)), \
                 patch("inode_modern.client.DAEMON", server.getsockname()), \
                 patch("inode_modern.desktop.worker.wired_interfaces", return_value=[WiredInterface("enp5s0", True, "")]):
                from inode_modern.client import Client
                window, worker, thread = build_window(self.app, Worker(
                    lambda **kwargs: Client(legacy_udp=True, **kwargs)))
                pulses = []
                timer = QTimer()
                timer.setInterval(20)
                timer.timeout.connect(lambda: pulses.append(True))
                timer.start()
                try:
                    window.show()
                    thread.start()
                    until(lambda: window.snapshot.get("phase") == "offline")
                    self.assertGreaterEqual(len(pulses), 3)
                    window.username.setText("synthetic@ct")
                    window.password.setText("synthetic-secret")
                    QTest.mouseClick(window.connect_button, Qt.MouseButton.LeftButton)
                    until(lambda: window.snapshot.get("phase") == "online")
                    QTest.mouseClick(window.disconnect_button, Qt.MouseButton.LeftButton)
                    until(lambda: window.snapshot.get("phase") == "offline")
                    self.assertEqual(kinds.count(1), 1)
                    self.assertEqual(kinds.count(3), 1)
                finally:
                    window.close()
                    until(lambda: not thread.isRunning())
                    timer.stop()
                    window.deleteLater()
                self.assertEqual(kinds.count(3), 1)  # Closing did not send another Logoff.
        finally:
            stop.set()
            daemon.join(1)
            server.close()
        self.assertFalse(errors)


if __name__ == "__main__":
    unittest.main()

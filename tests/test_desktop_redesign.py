"""Presentation regressions and an isolated GUI -> UDS Broker action loop."""

import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HAS_QT = importlib.util.find_spec("PySide6") is not None
if HAS_QT:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from inode_modern.client import Client
    from inode_modern.desktop.app import build_window
    from inode_modern.desktop.network import WiredInterface
    from inode_modern.desktop.visuals import Colors, contrast
    from inode_modern.desktop.window import Window
    from inode_modern.desktop.worker import Worker
    from inode_modern.protocol import Message, TLV
    from integration.broker import ControlBroker


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class RedesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def make_window(self, **state):
        window = Window()
        self.addCleanup(window.deleteLater)
        window.update_state({"phase": "offline", "can_connect": True,
                             "can_disconnect": False, "interface": "enp5s0",
                             "interfaces": [{"name": "enp5s0", "carrier": True, "ipv4": ""}],
                             **state})
        window.show()
        self.app.processEvents()
        return window

    def test_address_does_not_imply_authenticated(self):
        window = self.make_window(interfaces=[{"name": "enp5s0", "carrier": True, "ipv4": "192.0.2.1"}])
        self.assertEqual(window.facts[2].text(), "已获取")
        self.assertEqual(window.facts[1].text(), "尚未连接")
        self.assertTrue(window.connect_button.isEnabled())

    def test_dhcp_action_requires_online_missing_address_and_no_pending_request(self):
        window = self.make_window(phase="online", can_connect=False, can_disconnect=True)
        calls = []
        window.network_requested.connect(lambda: calls.append(True))
        window.get_network()
        window.get_network()
        self.assertEqual(calls, [True])
        window.command_finished()
        window.update_state({**window.snapshot, "phase": "offline", "can_connect": True})
        window.get_network()
        self.assertEqual(calls, [True])

    def test_missing_interface_blocks_action_and_explains_recovery(self):
        window = self.make_window(interfaces=[])
        self.assertFalse(window.connect_button.isEnabled())
        self.assertIn("接入有线网卡", window.link_badge.text())
        self.assertTrue(window.remember.isVisible())

    def test_long_status_is_plain_text_and_form_survives_poll(self):
        window = self.make_window()
        window.username.setText("synthetic@ct")
        window.password.setText("private-synthetic")
        detail = "<b>服务状态</b> " * 20
        window.update_state({**window.snapshot, "detail": detail})
        self.assertEqual(window.description.textFormat(), Qt.TextFormat.PlainText)
        self.assertEqual(window.username.text(), "synthetic@ct")
        self.assertEqual(window.password.text(), "private-synthetic")

    def test_large_text_controls_reachable_by_scroll(self):
        original = self.app.font()
        enlarged = self.app.font()
        enlarged.setPointSizeF(original.pointSizeF() * 2)
        self.app.setFont(enlarged)
        try:
            window = self.make_window()
            self.assertGreaterEqual(window.context_title.font().pointSizeF(), 30)
            window.resize(700, 540)
            self.app.processEvents()
            scroll = window.centralWidget()
            scroll.ensureWidgetVisible(window.connect_button)
            self.app.processEvents()
            position = window.connect_button.mapTo(scroll.viewport(), window.connect_button.rect().center())
            self.assertTrue(scroll.viewport().rect().contains(position))
        finally:
            self.app.setFont(original)

    def test_palette_text_and_primary_contrast(self):
        for background in ("#ffffff", "#202327"):
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(background))
            c = Colors.from_palette(palette)
            for surface in (c.surface, c.background):
                self.assertGreaterEqual(contrast(c.text, surface), 4.5)
                self.assertGreaterEqual(contrast(c.muted, surface), 4.5)
            self.assertGreaterEqual(max(contrast(c.text, c.accent), contrast(c.surface, c.accent)), 4.5)

    def test_qt_worker_uds_broker_connect_disconnect_and_close(self):
        # Real GUI, Worker, Client and Broker; only the vendor endpoint is synthetic.
        with tempfile.TemporaryDirectory() as tmp:
            broker = ControlBroker(Path(tmp) / "control.sock", frontend_addr=("127.0.0.1", 0))
            state, kinds = [1], []
            def exchange(message, **kwargs):
                kinds.append(message.kind)
                if message.kind == 1:
                    state[0] = 2
                elif message.kind == 3:
                    state[0] = 1
                if kwargs.get("wait_response", True):
                    return Message(8, (TLV(14, state[0].to_bytes(4, "big")), TLV(21, bytes(4))))
                return None
            def until(predicate):
                deadline = time.monotonic() + 5
                while not predicate() and time.monotonic() < deadline:
                    QTest.qWait(10)
                self.assertTrue(predicate())
            with patch.object(broker, "_exchange_udp", side_effect=exchange), \
                 patch("integration.broker.validate_interface_name", return_value="enp5s0"), \
                 patch("inode_modern.desktop.worker.wired_interfaces", return_value=[WiredInterface("enp5s0", True, "")]):
                broker.start()
                server = threading.Thread(target=broker.run, daemon=True)
                with patch.object(broker, "start"):
                    server.start()
                    window, worker, thread = build_window(self.app, Worker(
                        lambda **kwargs: Client(control_socket=broker.socket_path, **kwargs)))
                    try:
                        window.show()
                        thread.start()
                        until(lambda: window.snapshot.get("phase") == "offline")
                        window.username.setText("synthetic@ct")
                        window.password.setText("synthetic-secret")
                        QTest.mouseClick(window.connect_button, Qt.MouseButton.LeftButton)
                        until(lambda: window.snapshot.get("phase") == "online")
                        self.assertEqual(window.password.text(), "")
                        QTest.mouseClick(window.disconnect_button, Qt.MouseButton.LeftButton)
                        until(lambda: window.snapshot.get("phase") == "offline")
                    finally:
                        window.close()
                        until(lambda: not thread.isRunning())
                        window.deleteLater()
                        broker.close()
                        server.join(2)
                self.assertEqual(kinds.count(1), 1)
                self.assertEqual(kinds.count(3), 1)


if __name__ == "__main__":
    unittest.main()

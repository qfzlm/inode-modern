import json
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import time
import unittest

from integration.broker import ControlBroker
from inode_modern.protocol import Message, STATUS_RESPONSE, TLV


class MockVendorEngine:
    def __init__(self, port: int):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                data, addr = self.sock.recvfrom(4096)
                msg = Message.decode(data)
                if msg.kind == 7:  # STATUS_REQUEST
                    reply = Message(STATUS_RESPONSE, (TLV(14, b"\0\0\0\2"),)).encode()
                    self.sock.sendto(reply, addr)
                elif msg.kind == 1:  # CONNECT
                    reply = Message(STATUS_RESPONSE, (TLV(14, b"\0\0\0\0"),)).encode()
                    self.sock.sendto(reply, addr)
                elif msg.kind == 3:  # DISCONNECT
                    reply = Message(STATUS_RESPONSE, (TLV(14, b"\0\0\0\0"),)).encode()
                    self.sock.sendto(reply, addr)
            except (socket.timeout, OSError):
                continue

    def close(self):
        self.running = False
        self.sock.close()
        self.thread.join(timeout=1.0)


class TestControlBroker(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.sock_path = Path(self.tmp_dir) / "test_control.sock"

        # Bind mock engine to an ephemeral UDP port
        find_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        find_sock.bind(("127.0.0.1", 0))
        mock_port = find_sock.getsockname()[1]
        find_sock.close()

        self.mock_engine = MockVendorEngine(mock_port)
        self.broker = ControlBroker(socket_path=self.sock_path, daemon_addr=("127.0.0.1", mock_port), frontend_addr=("127.0.0.1", 0))
        self.broker_thread = threading.Thread(target=self.broker.run, daemon=True)
        self.broker_thread.start()

        # Wait for UDS to appear
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not self.sock_path.exists():
            time.sleep(0.05)

    def tearDown(self):
        self.broker.close()
        self.broker_thread.join(timeout=1.0)
        self.mock_engine.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _rpc(self, payload: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.sock_path))
            client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            raw = client.recv(65536)
            return json.loads(raw.decode("utf-8"))

    def test_status_rpc(self):
        res = self._rpc({"action": "status"})
        self.assertTrue(res.get("ok"))
        self.assertIn("status", res)

    def test_connect_rejection_on_shell_injection(self):
        res = self._rpc({
            "action": "connect",
            "username": "test@ct",
            "password": "secret_password",
            "interface": "enp5s0; id > /tmp/pwned",
        })
        self.assertFalse(res.get("ok"))
        self.assertIn("Interface validation rejected", res.get("error", ""))

    def test_connect_success_on_valid_interface(self):
        if not Path("/sys/class/net/enp5s0").exists():
            self.skipTest("Host has no enp5s0")
        res = self._rpc({
            "action": "connect",
            "username": "test@ct",
            "password": "secret_password",
            "interface": "enp5s0",
        })
        self.assertTrue(res.get("ok"))

    def test_disconnect_rpc(self):
        res = self._rpc({"action": "disconnect"})
        self.assertTrue(res.get("ok"))


if __name__ == "__main__":
    unittest.main()

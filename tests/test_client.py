from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

from inode_modern.client import Client, ClientError, StatusTimeout
from inode_modern.protocol import Message, ProtocolError, TLV, connect_request


class ClientTests(unittest.TestCase):
    def setUp(self):
        # Ephemeral local ports: tests never touch the real daemon or port 50000.
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.settimeout(2)
        self.addCleanup(self.server.close)
        self.patches = [patch("inode_modern.client.FRONTEND", ("127.0.0.1", 0)),
                        patch("inode_modern.client.DAEMON", self.server.getsockname())]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.thread_errors = []

    def server_thread(self, action):
        def run():
            try:
                action()
            except BaseException as exc:
                self.thread_errors.append(exc)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def join(self, thread):
        thread.join(3)
        self.assertFalse(thread.is_alive())
        if self.thread_errors:
            raise self.thread_errors[0]

    def test_status_ignores_malformed_and_routes_async(self):
        events = []
        def daemon():
            data, peer = self.server.recvfrom(65535)
            self.assertEqual(data, bytes.fromhex("1f551f560000000007000000"))
            self.server.sendto(b"invalid sensitive payload", peer)
            self.server.sendto(Message(11, (TLV(99, b"private"),)).encode(), peer)
            self.server.sendto(Message(8, (TLV(14, struct.pack("!I", 987)),)).encode(), peer)
        thread = self.server_thread(daemon)
        with Client(legacy_udp=True, timeout=1, on_event=events.append) as client:
            response = client.status()
        self.join(thread)
        self.assertEqual(response.safe_summary()["fields"][0]["value"], 987)
        self.assertEqual([event.kind for event in events], [11])

    def test_connect_and_disconnect_are_sent_once(self):
        with Client(legacy_udp=True) as client:
            client.send(connect_request("test@ct", "synthetic"))
            self.assertEqual(Message.decode(self.server.recvfrom(65535)[0]).kind, 1)
            client.send(Message(3))
            self.assertEqual(self.server.recvfrom(65535)[0], bytes.fromhex("1f551f560000000003000000"))
            self.server.settimeout(0.05)
            with self.assertRaises(TimeoutError):
                self.server.recvfrom(65535)

    def test_socket_accepts_daemon_ephemeral_source_port(self):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        with Client(legacy_udp=True) as client:
            sender.sendto(Message(8).encode(), client.sock.getsockname())
            self.assertEqual(client.receive(0.5), Message(8))

    def test_socket_rejects_other_source_address(self):
        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        attacker.bind(("127.0.0.2", 0))
        self.addCleanup(attacker.close)
        with Client(legacy_udp=True) as client:
            attacker.sendto(Message(8).encode(), client.sock.getsockname())
            with self.assertRaises(ProtocolError):
                client.receive(0.5)

    def test_timeout_is_bounded_despite_push_traffic(self):
        def daemon():
            _, peer = self.server.recvfrom(65535)
            for _ in range(20):
                self.server.sendto(Message(12).encode(), peer)
                time.sleep(0.01)
        thread = self.server_thread(daemon)
        with Client(legacy_udp=True, timeout=0.08) as client:
            start = time.monotonic()
            with self.assertRaisesRegex(ClientError, "timed out"):
                client.status()
            self.assertLess(time.monotonic() - start, 0.5)
        self.join(thread)

    def test_occupied_frontend_fails_without_reuse(self):
        occupied = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        occupied.bind(("127.0.0.1", 0))
        self.addCleanup(occupied.close)
        with patch("inode_modern.client.FRONTEND", occupied.getsockname()):
            with self.assertRaisesRegex(ClientError, "occupied"):
                with Client(legacy_udp=True):
                    self.fail("must not share a port")

    def test_close_releases_endpoint(self):
        with Client(legacy_udp=True) as client:
            endpoint = client.sock.getsockname()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(endpoint)

    def test_observe_retries_status_timeout_without_resending_action(self):
        statuses, timeouts = [], []
        with Client(legacy_udp=True, timeout=0.03) as client:
            with patch.object(client, "status", side_effect=[StatusTimeout("timeout"), Message(8)]), \
                 patch("inode_modern.client.time.monotonic", side_effect=[0, 0.05, 0.2]):
                client.observe(0.1, 1, statuses.append, lambda: timeouts.append(True))
        self.assertEqual(statuses, [Message(8)])
        self.assertEqual(timeouts, [True])

    def test_observe_does_not_hide_final_timeout(self):
        with Client(legacy_udp=True, timeout=0.03) as client:
            with patch.object(client, "status", side_effect=StatusTimeout("timeout")), \
                 patch("inode_modern.client.time.monotonic", side_effect=[0, 0.2]):
                with self.assertRaises(StatusTimeout):
                    client.observe(0.1, 1, lambda _: None)

    def test_client_via_uds(self):
        import tempfile, json
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "control.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(1)
            self.addCleanup(srv.close)

            def mock_broker():
                try:
                    probe, _ = srv.accept()
                    probe.close()
                    conn, _ = srv.accept()
                    with conn:
                        data = conn.recv(1024)
                        req = json.loads(data.decode("utf-8"))
                        if req.get("action") == "status":
                            resp = {"ok": True, "status": {"fields": [{"type": 14, "value": 2}]}}
                        else:
                            resp = {"ok": True}
                        conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")
                except OSError:
                    pass

            t = threading.Thread(target=mock_broker, daemon=True)
            t.start()

            with Client(timeout=1.0, control_socket=sock_path) as client:
                msg = client.status()
                self.assertEqual(msg.kind, 8)
            t.join(timeout=1.0)


if __name__ == "__main__":
    unittest.main()

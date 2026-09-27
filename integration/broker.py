"""Unprivileged Control Broker.

Runs with ZERO Linux capabilities and non-root UID (inode-modern-broker) inside the
service cgroup. Listens on /run/inode-modern/control.sock, validates interface
names and credentials, enforces SO_PEERCRED policy, constructs Vendor TLV
packets, and communicates with AuthenMngService over 127.0.0.1:50001.
"""
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from inode_modern.protocol import (
    CONNECT,
    DISCONNECT,
    STATUS_REQUEST,
    STATUS_RESPONSE,
    Message,
    ProtocolError,
    connect_request,
)
from inode_modern.validator import ValidationError, validate_interface_name

CONTROL_SOCKET = Path("/run/inode-modern/control.sock")
DAEMON_ADDR = ("127.0.0.1", 50001)


class BrokerError(RuntimeError):
    pass


def get_peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """Retrieve (pid, uid, gid) from Unix Domain Socket via SO_PEERCRED."""
    try:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; };
        cred_bytes = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", cred_bytes)
        return pid, uid, gid
    except OSError as exc:
        raise BrokerError(f"SO_PEERCRED failed: {exc}") from None


class ControlBroker:
    def __init__(self,
                 socket_path: Path = CONTROL_SOCKET,
                 daemon_addr: tuple[str, int] = DAEMON_ADDR,
                 frontend_addr: tuple[str, int] = ("127.0.0.1", 50000)):
        self.socket_path = socket_path
        self.daemon_addr = daemon_addr
        self.frontend_addr = frontend_addr
        self.running = False
        self.server_sock: socket.socket | None = None

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        self.socket_path.chmod(0o666)  # Accessible to authorized local users
        server.listen(16)
        server.setblocking(False)
        self.server_sock = server
        self.running = True

        import threading
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self._stop_handler)
            signal.signal(signal.SIGINT, self._stop_handler)

    def _stop_handler(self, *args):
        self.running = False

    def close(self) -> None:
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
            self.server_sock = None
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

    def run(self) -> None:
        self.start()
        try:
            while self.running:
                sock = self.server_sock
                if sock is None:
                    break
                try:
                    readable, _, _ = select.select([sock], [], [], 0.2)
                except OSError:
                    break
                if not readable or not self.running:
                    continue
                try:
                    conn, _ = sock.accept()
                except OSError:
                    continue

                self.handle_client(conn)
        finally:
            self.close()

    def handle_client(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5.0)
            try:
                pid, uid, gid = get_peer_credentials(conn)
                # Policy: allow local login users (UID >= 1000) or root
                if uid < 1000 and uid != 0:
                    self._send_response(conn, {"ok": False, "error": f"Unauthorized UID {uid}"})
                    return

                # Read request line
                deadline = time.monotonic() + 5.0
                raw_data = b""
                while not raw_data.endswith(b"\n"):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout()
                    conn.settimeout(remaining)
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    raw_data += chunk
                    if len(raw_data) > 65536:
                        self._send_response(conn, {"ok": False, "error": "Request payload too large"})
                        return

                if not raw_data:
                    return

                request = json.loads(raw_data.decode("utf-8"))
                response = self.dispatch_request(request, caller_uid=uid)
                self._send_response(conn, response)

            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_response(conn, {"ok": False, "error": "Invalid JSON format"})
            except socket.timeout:
                self._send_response(conn, {"ok": False, "error": "Request timed out"})
            except Exception as exc:
                self._send_response(conn, {"ok": False, "error": "Internal broker error"})

    def _send_response(self, conn: socket.socket, resp: dict) -> None:
        try:
            payload = json.dumps(resp).encode("utf-8") + b"\n"
            conn.sendall(payload)
        except OSError:
            pass

    def dispatch_request(self, req: dict, caller_uid: int) -> dict:
        if not isinstance(req, dict):
            return {"ok": False, "error": "Invalid request"}
        action = req.get("action")
        if action == "status":
            return self._handle_status()
        elif action == "connect":
            return self._handle_connect(req)
        elif action == "disconnect":
            return self._handle_disconnect()
        else:
            return {"ok": False, "error": "Unknown action"}

    def _exchange_udp(self, msg: Message, timeout: float = 3.0,
                      wait_response: bool = True) -> Message | None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Vendor replies to its fixed frontend port, from an ephemeral source port.
            s.bind(self.frontend_addr)
            s.sendto(msg.encode(), self.daemon_addr)
            if not wait_response:
                return None
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                s.settimeout(remaining)
                try:
                    resp_bytes, peer = s.recvfrom(65535)
                    if peer[0] != self.daemon_addr[0]:
                        continue
                    response = Message.decode(resp_bytes)
                    if response.kind == STATUS_RESPONSE:
                        return response
                except socket.timeout:
                    return None
                except ProtocolError:
                    continue
                except OSError:
                    raise BrokerError("UDP exchange error") from None

    def _handle_status(self) -> dict:
        req = Message(STATUS_REQUEST)
        resp = self._exchange_udp(req, timeout=2.0)
        if resp is None:
            return {"ok": False, "error": "AuthenMngService did not respond to status request"}
        if resp.kind != STATUS_RESPONSE:
            return {"ok": False, "error": "Invalid status response"}
        return {"ok": True, "status": resp.safe_summary()}

    def _handle_disconnect(self) -> dict:
        req = Message(DISCONNECT)
        resp = self._exchange_udp(req, wait_response=False)
        return {"ok": True, "response": resp.safe_summary() if resp else None}

    def _handle_connect(self, req: dict) -> dict:
        username = req.get("username")
        password = req.get("password")
        interface = req.get("interface", "enp5s0")

        if not username or not isinstance(username, str):
            return {"ok": False, "error": "Missing or invalid username"}
        if not password or not isinstance(password, str):
            return {"ok": False, "error": "Missing or invalid password"}

        # Strict validation
        try:
            validate_interface_name(interface)
        except ValidationError as exc:
            return {"ok": False, "error": "Interface validation rejected"}

        try:
            msg = connect_request(username, password, interface)
        except ProtocolError as exc:
            return {"ok": False, "error": f"Protocol validation rejected: {exc}"}

        resp = self._exchange_udp(msg, wait_response=False)
        return {"ok": True, "response": resp.safe_summary() if resp else None}


def main():
    broker = ControlBroker()
    broker.run()


if __name__ == "__main__":
    main()

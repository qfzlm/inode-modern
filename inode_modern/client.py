"""Unified Client transport supporting both Unix Domain Socket Broker and legacy loopback UDP."""

from collections.abc import Callable
import errno
import json
import math
from pathlib import Path
import socket
import struct
import time

from .setup_status import vendor_unconfigured, SETUP_HINT

from .protocol import (
    ASYNC_TYPES,
    CONNECT,
    DISCONNECT,
    Message,
    ProtocolError,
    STATUS_REQUEST,
    STATUS_RESPONSE,
    TLV,
)

FRONTEND = ("127.0.0.1", 50000)
DAEMON = ("127.0.0.1", 50001)
DEFAULT_CONTROL_SOCKET = Path("/run/inode-modern/control.sock")


class ClientError(RuntimeError):
    pass


class StatusTimeout(ClientError):
    pass


class PortOccupied(ClientError):
    pass


class Client:
    def __init__(self, timeout: float = 3.0,
                 on_event: Callable[[Message], None] | None = None,
                 control_socket: Path | None = None, *, legacy_udp: bool = False):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.timeout = timeout
        self.on_event = on_event
        if legacy_udp and control_socket is not None:
            raise ValueError("legacy UDP and control socket are mutually exclusive")
        self.uds_path = None if legacy_udp else (control_socket or DEFAULT_CONTROL_SOCKET)
        self.sock: socket.socket | None = None

    def __enter__(self) -> "Client":
        if self.uds_path == DEFAULT_CONTROL_SOCKET and vendor_unconfigured():
            raise ClientError(SETUP_HINT)
        if self.uds_path is not None:
            # Connect to unprivileged control broker over UDS
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect(str(self.uds_path))
            except OSError as exc:
                sock.close()
                raise ClientError(f"cannot connect to control broker {self.uds_path}: {exc}") from None
            self.sock = sock
            return self

        # Explicit legacy transport only; never selected by broker availability
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(FRONTEND)
        except OSError as exc:
            sock.close()
            if exc.errno == errno.EADDRINUSE:
                raise PortOccupied("127.0.0.1:50000 is occupied; close the old GUI or other frontend") from None
            raise ClientError("cannot open the loopback IPC socket") from None
        self.sock = sock
        return self

    def __exit__(self, *args) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _uds_rpc(self, req: dict) -> dict:
        if self.sock is None:
            raise ClientError("IPC socket is not open")
        # Each broker connection carries exactly one request. Never replay a request.
        self.sock.close()
        self.sock = None
        self.__enter__()
        try:
            payload = json.dumps(req).encode("utf-8") + b"\n"
            self.sock.sendall(payload)
            raw = b""
            deadline = time.monotonic() + self.timeout
            while not raw.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 65536:
                    raise ClientError("broker response too large")
            if not raw.endswith(b"\n"):
                raise ClientError("broker closed connection without complete response")
            result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict):
                raise ClientError("invalid broker response")
            return result
        except socket.timeout:
            raise StatusTimeout("timed out waiting for broker response") from None
        except (ValueError, UnicodeError):
            raise ClientError("invalid broker response") from None
        except OSError:
            raise ClientError("broker communication error") from None

    def send(self, message: Message) -> None:
        if self.sock is None:
            raise ClientError("IPC socket is not open")

        if self.uds_path is not None:
            # Route through broker
            if message.kind == CONNECT:
                username = ""
                password = ""
                interface = "enp5s0"
                for tlv in message.tlvs:
                    if tlv.kind == 1:
                        username = tlv.value.decode("utf-8", errors="replace")
                    elif tlv.kind == 2:
                        password = tlv.value.decode("utf-8", errors="replace")
                    elif tlv.kind == 7:
                        interface = tlv.value.decode("utf-8", errors="replace")
                resp = self._uds_rpc({"action": "connect", "username": username,
                                      "password": password, "interface": interface})
                if not resp.get("ok"):
                    raise ClientError(resp.get("error", "connect failed"))
            elif message.kind == DISCONNECT:
                resp = self._uds_rpc({"action": "disconnect"})
                if not resp.get("ok"):
                    raise ClientError(resp.get("error", "disconnect failed"))
            elif message.kind == STATUS_REQUEST:
                resp = self._uds_rpc({"action": "status"})
                if not resp.get("ok"):
                    raise ClientError(resp.get("error", "status query failed"))
            return

        # Legacy UDP send
        try:
            self.sock.sendto(message.encode(), DAEMON)
        except OSError:
            raise ClientError("IPC send failed; check AuthenMngService") from None

    def receive(self, timeout: float) -> Message:
        if self.sock is None:
            raise ClientError("IPC socket is not open")
        if self.uds_path is not None:
            # UDS returns synchronous RPC responses; receive is not used in UDS mode
            raise NotImplementedError("receive() not applicable in UDS broker mode")

        self.sock.settimeout(timeout)
        try:
            data, peer = self.sock.recvfrom(65535)
        except TimeoutError:
            raise
        except OSError:
            raise ClientError("IPC receive failed; check AuthenMngService") from None
        if peer[0] != "127.0.0.1":
            raise ProtocolError("unexpected IPC source address")
        return Message.decode(data)

    def status(self) -> Message:
        if self.uds_path is not None:
            resp = self._uds_rpc({"action": "status"})
            if not resp.get("ok"):
                raise StatusTimeout(resp.get("error", "status request timed out"))
            # Reconstruct Message from safe_summary fields
            tlvs = []
            for field in resp.get("status", {}).get("fields", []):
                kind = field.get("type", 14)
                if kind not in (14, 21):
                    continue
                if "value" not in field:
                    tlvs.append(TLV(kind, b""))
                    continue
                val = field["value"]
                if isinstance(val, int):
                    tlvs.append(TLV(kind, struct.pack("!I", val)))
                elif isinstance(val, str):
                    tlvs.append(TLV(kind, val.encode("utf-8")))
            return Message(STATUS_RESPONSE, tuple(tlvs))

        # Legacy UDP path
        self.send(Message(STATUS_REQUEST))
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StatusTimeout("timed out waiting for a valid status response")
            try:
                message = self.receive(remaining)
            except TimeoutError:
                raise StatusTimeout("timed out waiting for a valid status response") from None
            except ProtocolError:
                continue
            if message.kind == STATUS_RESPONSE:
                return message
            if message.kind in ASYNC_TYPES and self.on_event is not None:
                self.on_event(message)

    def observe(self, duration: float, interval: float,
                on_status: Callable[[Message], None],
                on_timeout: Callable[[], None] | None = None) -> None:
        if (not math.isfinite(duration) or duration < 0
                or not math.isfinite(interval) or interval <= 0):
            raise ValueError("invalid observation duration or interval")
        deadline = time.monotonic() + duration
        while True:
            try:
                on_status(self.status())
            except StatusTimeout:
                if on_timeout is not None:
                    on_timeout()
                if time.monotonic() >= deadline:
                    raise
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(interval, remaining))

"""The confirmed iNode UDP subset. Unknown values have no inferred meaning."""

from dataclasses import dataclass, field
import re
import struct

PROTO_TYPE = 0x1F55
CONN_ID = 0x1F56
HEADER_SIZE = 12
MAX_DATAGRAM = 65507
CONNECT, DISCONNECT, STATUS_REQUEST, STATUS_RESPONSE = 1, 3, 7, 8
ASYNC_TYPES = (11, 12)

# Preserve both the observed order and the successful SWUFE configuration.
SWUFE_OPTIONS = (
    (16, 1),  # TAKE_VERSION
    (15, 0),  # TAKE_IP: critical for the confirmed campus baseline
    (17, 0),  # REFRESHIP_AFTERCUT
    (18, 0),  # HOLDIP_AFTERCUT
    (22, 1),  # BROADCAST_OFFLINE
    (11, 0),  # DOT1X_TYPE: default PAP path
    (12, 0),  # REFRESH_IPADDR
    (30, 1),  # QUICK_RESUME
    (31, 0),  # REAUTH_TIMES
    (32, 0),  # REAUTH_INTERVAL
    (23, 0),  # ONLINE_STATUS
)


class ProtocolError(ValueError):
    """Messages must never include raw input or payload values."""


@dataclass(frozen=True)
class TLV:
    kind: int
    value: bytes = field(repr=False)

    def encode(self) -> bytes:
        if not 0 <= self.kind <= 255 or len(self.value) > 253:
            raise ProtocolError("invalid TLV type or length")
        return bytes((self.kind, len(self.value) + 2)) + self.value


@dataclass(frozen=True)
class Message:
    kind: int
    tlvs: tuple[TLV, ...] = field(default=(), repr=False)

    def encode(self) -> bytes:
        if not 0 <= self.kind <= 255:
            raise ProtocolError("invalid message type")
        body = b"".join(tlv.encode() for tlv in self.tlvs)
        if len(body) + HEADER_SIZE > MAX_DATAGRAM:
            raise ProtocolError("message exceeds UDP payload limit")
        return (struct.pack("!HHIB", PROTO_TYPE, CONN_ID, 0, self.kind)
                + len(body).to_bytes(3, "big") + body)

    @classmethod
    def decode(cls, data: bytes) -> "Message":
        if len(data) < HEADER_SIZE or len(data) > MAX_DATAGRAM:
            raise ProtocolError("invalid datagram length")
        proto, conn, reserved, kind = struct.unpack("!HHIB", data[:9])
        if (proto, conn, reserved) != (PROTO_TYPE, CONN_ID, 0):
            raise ProtocolError("unexpected IPC header")
        if int.from_bytes(data[9:12], "big") != len(data) - HEADER_SIZE:
            raise ProtocolError("body length mismatch")
        tlvs = []
        offset = HEADER_SIZE
        while offset < len(data):
            if len(data) - offset < 2:
                raise ProtocolError("truncated TLV header")
            tlv_type, length = data[offset:offset + 2]
            if length < 2 or offset + length > len(data):
                raise ProtocolError("invalid TLV length")
            tlvs.append(TLV(tlv_type, data[offset + 2:offset + length]))
            offset += length
        return cls(kind, tuple(tlvs))

    def safe_summary(self) -> dict:
        """Whitelist numeric STATE/RESULT; never print text or packet bytes.

        Preserve duplicates; a malformed known field is metadata, not a number.
        This policy applies equally to async pushes, whose text may be private.
        """
        fields = []
        for tlv in self.tlvs:
            item = {"type": tlv.kind, "value_length": len(tlv.value)}
            if tlv.kind in (14, 21) and len(tlv.value) == 4:
                item["name"] = "STATE" if tlv.kind == 14 else "RESULT"
                item["value"] = int.from_bytes(tlv.value, "big")
            fields.append(item)
        return {"msg_type": self.kind, "fields": fields}


def text_value(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ProtocolError(f"{label}: cannot encode as UTF-8") from None
    if not encoded or len(encoded) > 253 or b"\0" in encoded:
        raise ProtocolError(f"{label}: requires 1..253 UTF-8 bytes without NUL")
    return encoded


def username_value(username: str) -> bytes:
    encoded = text_value(username, "username")
    if "@" in username and any(not part for part in username.split("@")):
        raise ProtocolError("完整用户名需要 @ 前的账号和 @ 后的后缀；不能只输入运营商后缀")
    return encoded


def interface_value(interface: str) -> bytes:
    if not isinstance(interface, str) or not re.fullmatch(r'^[A-Za-z0-9_.-]{1,15}$', interface):
        raise ProtocolError(f"interface: invalid interface name syntax: {interface!r}")
    return text_value(interface, "interface")


def connect_request(username: str, password: str, interface: str = "enp5s0") -> Message:
    # No stripping, suffix rewriting, password normalization, or NUL terminator.
    return Message(CONNECT, (
        TLV(1, username_value(username)),
        TLV(2, text_value(password, "password")),
        TLV(7, interface_value(interface)),
        TLV(29, b""),
        *(TLV(kind, struct.pack("!I", value)) for kind, value in SWUFE_OPTIONS),
    ))

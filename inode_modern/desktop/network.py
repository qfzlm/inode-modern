"""Read physical Ethernet devices and activate an existing DHCP profile only."""

from dataclasses import dataclass
import fcntl
from pathlib import Path
import socket
import struct
import subprocess


@dataclass(frozen=True)
class WiredInterface:
    name: str
    carrier: bool
    ipv4: str


def ipv4_address(name: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            data = fcntl.ioctl(probe, 0x8915, struct.pack("256s", name.encode("ascii")[:15]))
            return socket.inet_ntoa(data[20:24])
    except (OSError, UnicodeError):
        return ""


def wired_interfaces(root: Path = Path("/sys/class/net")) -> list[WiredInterface]:
    interfaces = []
    for path in sorted(root.iterdir()):
        try:
            if not (path / "device").exists() or (path / "wireless").exists():
                continue
            if (path / "type").read_text().strip() != "1":
                continue
            try:
                carrier = (path / "carrier").read_text().strip() == "1"
            except OSError:
                carrier = False
            interfaces.append(WiredInterface(path.name, carrier, ipv4_address(path.name)))
        except OSError:
            continue
    return interfaces


def _nmcli(*args: str, timeout: int = 5) -> str:
    try:
        process = subprocess.run(["nmcli", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("无法访问系统网络管理器。请在系统网络设置中启用有线连接。") from None
    if process.returncode:
        raise RuntimeError("系统未能激活有线连接。请在系统网络设置中检查连接和权限。")
    return process.stdout


def activate_existing_dhcp(interface: str) -> None:
    socket.if_nametoindex(interface)
    candidates = []
    for row in _nmcli("-t", "-f", "UUID,TYPE", "connection", "show").splitlines():
        uuid, _, kind = row.partition(":")
        if kind not in ("ethernet", "802-3-ethernet"):
            continue
        settings = _nmcli("-g", "connection.interface-name,ipv4.method,802-1x.eap",
                          "connection", "show", "uuid", uuid).splitlines()
        if len(settings) >= 2 and settings[0] == interface and settings[1] == "auto" and not any(settings[2:]):
            candidates.append(uuid)
    if len(candidates) != 1:
        raise RuntimeError("未找到唯一的匹配有线 DHCP 连接。请先在系统网络设置中选择或创建连接。")
    _nmcli("--wait", "12", "connection", "up", "uuid", candidates[0], "ifname", interface, timeout=15)

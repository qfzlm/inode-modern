"""Strict network interface validator.

Ensures that network interface names are strictly shell-safe, exist in the kernel,
and correspond to genuine Ethernet devices (ARPHRD_ETHER = 1).
"""
from pathlib import Path
import re
import socket


INTERFACE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,15}$')


class ValidationError(ValueError):
    """Raised when interface or parameter validation fails."""
    pass


def validate_interface_name(name: str,
                            sysfs_root: Path = Path('/sys/class/net'),
                            ifindex_func=socket.if_nametoindex) -> str:
    """Validate network interface name against shell injection, existence, and device type."""
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        raise ValidationError(f"invalid interface name syntax: {name!r}; must match ^[A-Za-z0-9_.-]{{1,15}}$")

    try:
        ifindex_func(name)
    except OSError:
        raise ValidationError(f"interface {name!r} has no valid kernel ifindex") from None

    sys_path = sysfs_root / name
    if not sys_path.is_dir():
        raise ValidationError(f"interface {name!r} does not exist in {sysfs_root}")

    type_path = sys_path / "type"
    try:
        dev_type = int(type_path.read_text().strip())
    except (OSError, ValueError):
        raise ValidationError(f"cannot determine hardware type for interface {name!r}") from None

    if dev_type != 1:  # ARPHRD_ETHER = 1
        raise ValidationError(f"interface {name!r} is not an Ethernet device (type={dev_type}, expected 1)")

    return name

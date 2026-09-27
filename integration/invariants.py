"""Runtime Process Invariant Checker for Candidate A.

Enforces strict credentials, capabilities, cgroup membership, NoNewPrivs,
and UDP socket ownership for Engine (AuthenMngService), Watchdog (iNodeMon),
and Broker (broker.py).
"""
from dataclasses import dataclass
import os
from pathlib import Path


try:
    from integration.identities import resolve_identities, IdentityError
except ImportError:
    from identities import resolve_identities, IdentityError


EXPECTED_CAPS_ENGINE = 0x3000  # CAP_NET_RAW (0x2000) | CAP_NET_ADMIN (0x1000)


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    name: str
    canonical_exe: Path
    cgroup: str
    uids: tuple[int, int, int, int]  # (Real, Effective, Saved, FS)
    gids: tuple[int, int, int, int]  # (Real, Effective, Saved, FS)
    groups: tuple[int, ...]
    cap_inh: int
    cap_prm: int
    cap_eff: int
    cap_bnd: int
    cap_amb: int
    no_new_privs: int


class InvariantViolation(RuntimeError):
    """Raised when any runtime process invariant is broken."""
    pass


def parse_status(text: str) -> dict[str, str]:
    """Parse each status line independently, retaining empty values."""
    fields = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition(':')
        if not separator or not key or key != key.strip() or key in fields:
            raise ValueError('Malformed or duplicate status field')
        fields[key] = value.strip()
    return fields


def parse_status_field(text: str, field_name: str) -> str:
    # Compatibility for callers needing one field; snapshots parse the text once.
    try:
        return parse_status(text)[field_name]
    except KeyError:
        raise ValueError(f'field {field_name} not found in /proc status') from None


def _unsigned(value: str, base: int, bits: int) -> int:
    alphabet = '0123456789' if base == 10 else '0123456789abcdefABCDEF'
    if not value or any(char not in alphabet for char in value):
        raise ValueError('Malformed unsigned status value')
    number = int(value, base)
    if number >= 1 << bits:
        raise ValueError('Status value out of range')
    return number


def parse_snapshot(pid: int, proc_path: Path = Path('/proc')) -> ProcessSnapshot | None:
    pid_dir = proc_path / str(pid)
    try:
        fields = parse_status((pid_dir / 'status').read_text())
        state = fields['State'].split()[0]
        if state not in ('R', 'S', 'D', 'T', 't', 'X', 'x', 'Z', 'I', 'P', 'K', 'W'):
            raise ValueError('Invalid process state')
        if state in ('Z', 'X', 'x'):
            return None
        name = fields['Name']
        if not name:
            raise ValueError('Missing process name')
        uids = tuple(_unsigned(x, 10, 32) for x in fields['Uid'].split())
        gids = tuple(_unsigned(x, 10, 32) for x in fields['Gid'].split())
        if len(uids) != 4 or len(gids) != 4:
            raise ValueError('Expected exactly four UID/GID values')
        groups = tuple(_unsigned(x, 10, 32) for x in fields['Groups'].split())
        caps = [_unsigned(fields[key], 16, 64) for key in
                ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')]
        if fields['NoNewPrivs'] not in ('0', '1'):
            raise ValueError('Invalid NoNewPrivs value')
        exe = (pid_dir / 'exe').resolve(strict=True)
        cgroup = (pid_dir / 'cgroup').read_text().strip()
        if not cgroup:
            raise ValueError('Missing process cgroup')
        return ProcessSnapshot(
            pid=pid, name=name, canonical_exe=exe, cgroup=cgroup,
            uids=uids, gids=gids, groups=groups,
            cap_inh=caps[0], cap_prm=caps[1], cap_eff=caps[2],
            cap_bnd=caps[3], cap_amb=caps[4], no_new_privs=int(fields['NoNewPrivs']),
        )
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, KeyError, IndexError):
        # Exited/zombie processes and malformed or incomplete snapshots fail closed.
        return None


def get_process_socket_inodes(pid: int, proc_path: Path = Path("/proc")) -> set[str]:
    inodes = set()
    fd_dir = proc_path / str(pid) / "fd"
    try:
        for entry in fd_dir.iterdir():
            try:
                target = os.readlink(entry)
                if target.startswith("socket:["):
                    inodes.add(target[8:-1])
            except OSError:
                continue
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return inodes


def get_listening_udp_inodes(port: int, proc_path: Path = Path("/proc")) -> set[str]:
    """Retrieve socket inodes bound to the given UDP port from /proc/net/udp."""
    port_hex = f":{port:04X}"
    inodes = set()
    try:
        lines = (proc_path / "net/udp").read_text().splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) >= 10 and fields[1].endswith(port_hex):
                inodes.add(fields[9])
    except (FileNotFoundError, OSError):
        pass
    return inodes


def verify_socket_ownership(pid: int, port: int, proc_path: Path = Path("/proc")) -> bool:
    listening_inodes = get_listening_udp_inodes(port, proc_path)
    if not listening_inodes:
        return False
    proc_inodes = get_process_socket_inodes(pid, proc_path)
    return listening_inodes <= proc_inodes


def verify_invariants(snapshots: list[ProcessSnapshot],
                      pinned_gen: Path,
                      service_cgroup: str,
                      proc_path: Path = Path("/proc"),
                      broker_pid: int | None = None) -> tuple[bool, str]:
    """Verify all runtime invariants for Engine, Mon, and Broker.

    Returns (True, "OK") or (False, failure_reason).
    """
    try:
        roles = resolve_identities()
    except (IdentityError, KeyError) as exc:
        return False, f"Role identity invalid: {exc}"
    engine_uid, engine_gid = roles['inode-modern-engine']
    mon_uid, mon_gid = roles['inode-modern-mon']
    broker_uid, broker_gid = roles['inode-modern-broker']
    pinned_gen = pinned_gen.resolve()
    expected_engine_exe = pinned_gen / "AuthenMngService"
    expected_mon_exe = pinned_gen / "iNodeMon"

    # Filter by service cgroup
    cgroup_procs = [p for p in snapshots if p.cgroup == service_cgroup]

    # 1. Detect any rogue Engine (e.g. spawned by iNodeMon with wrong UID or capabilities)
    for p in cgroup_procs:
        if p.name in ("AuthenMngServic", "AuthenMngService") or p.canonical_exe.name == "AuthenMngService":
            if p.uids != (engine_uid,) * 4 or p.cap_eff != EXPECTED_CAPS_ENGINE:
                return False, f"Rogue Engine detected: PID {p.pid} UID={p.uids} CapEff={hex(p.cap_eff)}"

    # 2. Check Engine (AuthenMngService)
    engines = [
        p for p in cgroup_procs
        if p.canonical_exe.name == "AuthenMngService" or p.name in ("AuthenMngServic", "AuthenMngService")
    ]
    if len(engines) != 1:
        return False, f"Expected exactly 1 Engine, found {len(engines)}"

    engine = engines[0]
    if engine.canonical_exe != expected_engine_exe:
        return False, "Engine is outside pinned generation"
    if engine.gids != (engine_gid,) * 4:
        return False, f"Engine GID invalid: {engine.gids}"
    if engine.groups not in ((), (engine_gid,)):
        return False, f"Engine supplementary groups invalid: {engine.groups}"
    if engine.cap_eff != EXPECTED_CAPS_ENGINE or engine.cap_inh != EXPECTED_CAPS_ENGINE or engine.cap_prm != EXPECTED_CAPS_ENGINE:
        return False, f"Engine capability mismatch: Eff={hex(engine.cap_eff)} Inh={hex(engine.cap_inh)}"
    if engine.cap_bnd != EXPECTED_CAPS_ENGINE or engine.cap_amb != EXPECTED_CAPS_ENGINE:
        return False, "Engine bounding/ambient capability mismatch"
    if engine.no_new_privs != 1:
        return False, f"Engine NoNewPrivs not set: {engine.no_new_privs}"
    if not verify_socket_ownership(engine.pid, 50001, proc_path):
        return False, f"Engine PID {engine.pid} does not own UDP port 50001"

    # 3. Check Watchdog (iNodeMon)
    mons = [
        p for p in cgroup_procs
        if p.canonical_exe.name == "iNodeMon" or p.name == "iNodeMon"
    ]
    if len(mons) != 1:
        return False, f"Expected exactly 1 Mon, found {len(mons)}"

    mon = mons[0]
    if mon.canonical_exe != expected_mon_exe or mon.uids != (mon_uid,) * 4:
        return False, "Mon identity invalid"
    if mon.gids != (mon_gid,) * 4:
        return False, f"Mon GID invalid: {mon.gids}"
    if mon.groups not in ((), (mon_gid,)):
        return False, f"Mon supplementary groups invalid: {mon.groups}"
    if (mon.cap_eff | mon.cap_inh | mon.cap_prm | mon.cap_bnd | mon.cap_amb) != 0:
        return False, f"Mon capability non-zero: Eff={hex(mon.cap_eff)}"
    if mon.no_new_privs != 1:
        return False, f"Mon NoNewPrivs not set: {mon.no_new_privs}"
    if not verify_socket_ownership(mon.pid, 50002, proc_path):
        return False, f"Mon PID {mon.pid} does not own UDP port 50002"

    brokers = [p for p in cgroup_procs if p.pid == broker_pid]
    if len(brokers) != 1:
        return False, "Broker missing"
    broker = brokers[0]
    if (broker.canonical_exe != Path('/usr/bin/python3').resolve()
            or broker.uids != (broker_uid,) * 4 or broker.gids != (broker_gid,) * 4
            or broker.groups or broker.no_new_privs != 1
            or (broker.cap_inh | broker.cap_prm | broker.cap_eff | broker.cap_bnd | broker.cap_amb)):
        return False, "Broker identity or privilege mismatch"
    return True, "OK"

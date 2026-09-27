"""Fail-closed guard verification and explicit installer-only table teardown."""
import ctypes
import json
import os
import re
from pathlib import Path
import subprocess
import sys

TABLE = 'inode_modern_guard'
SET = 'allowed_cgroups'
SERVICE_CGROUP = '/system.slice/inode-modern-backend.service'
PORTS = {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                   'right': {'set': [50000, 50001, 50002]}}}
EXPECTED_RULES = {
    'input': [[{'match': {'op': '!=', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}},
               PORTS, {'drop': None}]],
    'output': [[PORTS, {'match': {'op': '==', 'left': {'socket': {'key': 'cgroupv2', 'level': 2}},
                                  'right': '@allowed_cgroups'}}, {'accept': None}],
               [PORTS, {'drop': None}]],
}


class FirewallError(RuntimeError):
    pass


def normalize_cgroup_path(value):
    """nft cgroup paths are root-relative, optionally with a leading slash."""
    if (not isinstance(value, str) or not value
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            or '..' in value.split('/')):
        raise ValueError('Invalid cgroup path')
    return '/' + '/'.join(part for part in value.split('/') if part not in ('', '.'))


def validate_members(elements, cgroup_id=None, cgroup_path=SERVICE_CGROUP):
    # This dedicated set authorizes only one service. Initialization may precede
    # population; READY/runtime always require the current membership.
    if not isinstance(elements, list) or len(elements) > 1:
        raise ValueError('Unexpected cgroup members')
    if not elements:
        if cgroup_id is not None:
            raise ValueError('Current cgroup membership missing')
        return
    member = elements[0]
    if type(member) is int and 0 < member < 1 << 64:
        if cgroup_id is not None and member != cgroup_id:
            raise ValueError('Wrong cgroup ID')
    elif isinstance(member, str):
        if normalize_cgroup_path(member) != normalize_cgroup_path(cgroup_path):
            raise ValueError('Wrong cgroup path')
    else:
        raise ValueError('Unknown cgroup member representation')


def validate_ruleset(document, cgroup_id=None, level_rule_handle=None):
    """Match the complete dedicated table, ignoring only nft listing metadata."""
    try:
        records = document['nftables']
        tables, sets, chains = [], [], []
        rules = {'input': [], 'output': []}
        for record in records:
            if len(record) != 1:
                raise ValueError()
            kind, obj = next(iter(record.items()))
            if kind == 'metainfo':
                continue
            if kind not in ('table', 'set', 'chain', 'rule'):
                raise ValueError()
            handle = obj.get('handle')
            obj = {k: v for k, v in obj.items() if k not in ('handle', 'index', 'comment')}
            if obj.get('family') != 'inet':
                raise ValueError()
            if kind == 'table':
                if obj != {'family': 'inet', 'name': TABLE}:
                    raise ValueError()
                tables.append(obj)
                continue
            if obj.get('table') != TABLE:
                raise ValueError()
            if kind == 'set':
                sets.append(obj)
            elif kind == 'chain':
                chains.append(obj)
            else:
                chain = obj.pop('chain')
                if set(obj) != {'family', 'table', 'expr'}:
                    raise ValueError()
                expr = obj['expr']
                # Older libnftables omits socket.level from JSON. Text must prove
                # level 2 on this exact kernel rule handle; absence is not a default.
                if (level_rule_handle is not None and handle == level_rule_handle
                        and chain == 'output' and len(expr) == 3
                        and expr[1].get('match', {}).get('left') == {'socket': {'key': 'cgroupv2'}}):
                    expr = [expr[0], EXPECTED_RULES['output'][0][1], expr[2]] if (
                        expr[1]['match'].get('op') == '=='
                        and expr[1]['match'].get('right') == '@allowed_cgroups'
                        and set(expr[1]['match']) == {'op', 'left', 'right'}) else expr
                rules[chain].append(expr)
        expected_chains = [dict(family='inet', table=TABLE, name=name, type='filter',
                                hook=name, prio=priority, policy='accept')
                           for name, priority in (('input', -10), ('output', 0))]
        if (len(tables) != 1 or len(sets) != 1
                or sorted(chains, key=lambda c: c['name']) != expected_chains
                or rules != EXPECTED_RULES):
            raise ValueError()
        nftset = dict(sets[0])
        elements = nftset.pop('elem', [])
        if nftset != {'family': 'inet', 'table': TABLE, 'name': SET, 'type': 'cgroupsv2'}:
            raise ValueError()
        validate_members(elements, cgroup_id)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise FirewallError('Firewall structure or current cgroup membership mismatch') from None


def current_cgroup_id(proc_file=Path('/proc/self/cgroup'), cgroup_root=Path('/sys/fs/cgroup')):
    # The rule's level 2 is valid only for this explicitly fixed system service path.
    if proc_file.read_text().strip() != '0::' + SERVICE_CGROUP:
        raise FirewallError('Unexpected service cgroup path or cgroup namespace')
    class Handle(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint), ('kind', ctypes.c_int), ('data', ctypes.c_ubyte * 8)]
    handle, mount_id = Handle(8, 0), ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    path = cgroup_root / SERVICE_CGROUP.lstrip('/')
    if libc.name_to_handle_at(-100, os.fsencode(path), ctypes.byref(handle), ctypes.byref(mount_id), 0) != 0:
        raise FirewallError('Cannot determine current kernel cgroup ID')
    if handle.size != 8 or handle.kind != 0xfe:
        raise FirewallError('Unexpected cgroup filesystem handle')
    return int.from_bytes(bytes(handle.data), sys.byteorder)


def verified_level_handle(text):
    matches = re.findall(
        r'^\s*udp dport \{\s*50000,\s*50001,\s*50002\s*\} '
        r'socket cgroupv2 level 2 @allowed_cgroups accept\s+# handle ([0-9]+)\s*$',
        text, re.MULTILINE)
    if len(matches) != 1:
        raise FirewallError('Cannot verify exact cgroupv2 level-2 guard rule')
    return int(matches[0])


def verify_firewall(require_membership=False):
    try:
        cgroup_id = current_cgroup_id() if require_membership else None
        def listing(json_output):
            result = subprocess.run(['/usr/sbin/nft', '-a', '-n', *(['-j'] if json_output else []),
                                     'list', 'table', 'inet', TABLE],
                                    capture_output=True, text=True, check=True, timeout=2,
                                    env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'})
            return result.stdout
        document = json.loads(listing(True))
        handle = verified_level_handle(listing(False))
        validate_ruleset(document, cgroup_id, handle)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise FirewallError('Cannot verify firewall guard') from None


def guard_present():
    """A checked, parsed table inventory distinguishes absence from query failure."""
    try:
        result = subprocess.run(['/usr/sbin/nft', '-j', 'list', 'tables'],
                                capture_output=True, text=True, check=True, timeout=5,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'})
        records = json.loads(result.stdout)['nftables']
        if not isinstance(records, list):
            raise ValueError('invalid nft inventory')
        found = False
        for record in records:
            if set(record) == {'metainfo'}:
                continue
            if set(record) != {'table'} or not isinstance(record['table'], dict):
                raise ValueError('invalid nft table record')
            table = record['table']
            if not isinstance(table['family'], str) or not isinstance(table['name'], str):
                raise ValueError('invalid nft table identity')
            found |= table['family'] == 'inet' and table['name'] == TABLE
        return found
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise FirewallError('Cannot establish Candidate nft table presence') from exc


def teardown_guard():
    """Delete only our table and prove absence, including repeated cleanup calls."""
    if guard_present():
        try:
            subprocess.run(['/usr/sbin/nft', 'delete', 'table', 'inet', TABLE],
                           check=True, timeout=5,
                           env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.SubprocessError) as exc:
            raise FirewallError('Candidate nft table deletion failed') from exc
    if guard_present():
        raise FirewallError('Candidate nft table remains after teardown')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--teardown']:
            teardown_guard()
        else:
            verify_firewall(require_membership='--member' in sys.argv[1:])
    except FirewallError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

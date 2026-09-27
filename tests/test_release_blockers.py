"""Deterministic adversarial/offline tests; no production mounts, accounts or nft changes."""
import copy
import ctypes
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools import vendor_generation as vg
from integration import backend, firewall, identities, install_backend as installer


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.src = self.base / 'source'
        (self.src / 'libs/std').mkdir(parents=True)
        for name in vg.REQUIRED_BINARIES:
            (self.src / name).write_bytes(b'\x7fELFsynthetic')
        (self.src / 'libs/std/lib.so').write_bytes(b'public-library')
        self.target = self.base / 'target'
        trusted = patch.object(vg, '_trusted_stat')
        trusted.start()
        self.addCleanup(trusted.stop)

    def do_import(self):
        return vg.import_generation(self.src, self.target, 'gen-0001')

    def assert_unpublished(self):
        self.assertFalse((self.target / 'gen-0001').exists())
        self.assertEqual(list(self.target.glob('.staging-*')), [])

    def test_replacement_between_stat_and_open_never_follows_link(self):
        outside = self.base / 'private'
        outside.write_bytes(b'secret-never-import')
        outside.chmod(0o600)
        original_open = os.open
        swapped = False
        def attack(name, flags, *args, **kwargs):
            nonlocal swapped
            if name == 'AuthenMngService' and kwargs.get('dir_fd') is not None and not swapped:
                swapped = True
                (self.src / name).unlink()
                (self.src / name).symlink_to(outside)
            return original_open(name, flags, *args, **kwargs)
        with patch.object(vg.os, 'open', side_effect=attack):
            with self.assertRaises((OSError, vg.GenerationError)):
                self.do_import()
        self.assertTrue(swapped)
        self.assertEqual(outside.read_bytes(), b'secret-never-import')
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o600)
        self.assert_unpublished()

    def test_directory_replacement_cannot_redirect_descendant_copy(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'leak').write_bytes(b'not-in-source')
        original_open = os.open
        def attack(name, flags, *args, **kwargs):
            if name == 'libs' and flags & os.O_DIRECTORY and kwargs.get('dir_fd') is not None:
                (self.src / 'libs').rename(self.src / 'old-libs')
                (self.src / 'libs').symlink_to(outside)
            return original_open(name, flags, *args, **kwargs)
        with patch.object(vg.os, 'open', side_effect=attack):
            with self.assertRaises((OSError, vg.GenerationError)):
                self.do_import()
        self.assert_unpublished()

    def test_root_rename_cannot_redirect_pinned_descriptor(self):
        original = vg._copy_source
        def attack(fd, destination, source_root, *args):
            if not args:
                self.src.rename(self.base / 'moved')
                self.src.symlink_to('/etc')
            return original(fd, destination, source_root, *args)
        with patch.object(vg, '_copy_source', side_effect=attack):
            # A pinned root may still produce only the originally opened contents.
            result = self.do_import()
        self.assertEqual((result / 'AuthenMngService').read_bytes(), b'\x7fELFsynthetic')
        self.assertFalse((result / 'passwd').exists())
        for d in result.rglob('*'):
            if d.is_dir(): d.chmod(0o700)
        result.chmod(0o700)

    def test_foreign_private_directory_cannot_be_injected_by_rename(self):
        # Model metadata of an injected root-private directory; no root/chown needed.
        with self.assertRaises(vg.GenerationError):
            vg._source_directory_access(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700), 1000)
        vg._source_directory_access(SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o700), 1000)
        with self.assertRaises(vg.GenerationError):
            vg._source_directory_access(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700), 0)

    def test_hardlink_replacement_and_unreadable_file_are_rejected(self):
        for mode in ('hardlink', 'private'):
            with self.subTest(mode=mode):
                victim = self.src / 'AuthenMngService'
                if mode == 'hardlink':
                    os.link(victim, self.base / 'external-link')
                else:
                    (self.base / 'external-link').unlink()
                    victim.chmod(0o600)
                with self.assertRaises(vg.GenerationError):
                    self.do_import()
                self.assert_unpublished()

    def test_file_mutation_during_copy_aborts(self):
        original_fdopen = os.fdopen
        source_inode = (self.src / 'AuthenMngService').stat().st_ino
        source_path = self.src / "AuthenMngService"
        class MutatingReader:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def read(self, size):
                data = self.stream.read(size)
                if data:
                    source_path.write_bytes(b'changed')
                return data
        def fdopen(fd, *args, **kwargs):
            target = os.fstat(fd).st_ino == source_inode
            stream = original_fdopen(fd, *args, **kwargs)
            return MutatingReader(stream) if target else stream
        with patch.object(vg.os, 'fdopen', side_effect=fdopen):
            with self.assertRaises(vg.GenerationError):
                self.do_import()
        self.assert_unpublished()

    def test_internal_links_are_published_only_after_copy_and_escaping_chain_rejected(self):
        (self.src / 'libs/alias.so').symlink_to(self.src / 'libs/std/lib.so')
        result = self.do_import()
        self.assertEqual((result / 'libs/alias.so').read_bytes(), b'public-library')
        self.assertFalse(os.readlink(result / 'libs/alias.so').startswith('/'))
        for d in result.rglob('*'):
            if d.is_dir(): d.chmod(0o700)
        result.chmod(0o700)
        (self.src / 'libs/alias.so').unlink()
        (self.src / 'libs/alias.so').symlink_to('../../outside')
        with self.assertRaises(vg.GenerationError):
            vg.import_generation(self.src, self.target, 'gen-0002')
        self.assertFalse((self.target / 'gen-0002').exists())

    def test_only_empty_log_mountpoint_is_imported(self):
        (self.src / 'log').mkdir()
        (self.src / 'log/private.log').write_text('synthetic-secret')
        result = self.do_import()
        self.assertEqual(list((result / 'log').iterdir()), [])
        self.assertEqual(stat.S_IMODE((result / 'log').stat().st_mode), 0o555)
        self.assertNotIn('private.log', (result / vg.MANIFEST_NAME).read_text())
        for d in result.rglob('*'):
            if d.is_dir(): d.chmod(0o700)
        result.chmod(0o700)


class DestinationTests(unittest.TestCase):
    def test_owner_group_mode_links_and_specials_rejected(self):
        good = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1)
        vg._trusted_stat(SimpleNamespace(**good))
        for changes in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFDIR | 0o775},
                        {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFIFO | 0o600}, {'st_nlink': 2}):
            with self.subTest(changes=changes), self.assertRaises(vg.GenerationError):
                vg._trusted_stat(SimpleNamespace(**(good | changes)))

    def test_checks_every_ancestor_and_nested_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            leaf = base / 'code/package/module.py'
            leaf.parent.mkdir(parents=True)
            leaf.write_text('synthetic')
            seen = []
            with patch.object(vg, '_trusted_stat', side_effect=lambda st: seen.append(st.st_ino)):
                vg.validate_destination(base / 'code', recursive=True)
            for path in (Path('/'), *base.parents, base, base / 'code', leaf.parent, leaf):
                self.assertIn(path.stat().st_ino, seen)

    def test_symlink_ancestor_nested_leaf_and_dangling_link_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'real').mkdir()
            (base / 'link').symlink_to(base / 'real')
            (base / 'real/dangling').symlink_to(base / 'absent')
            def check(st):
                if stat.S_ISLNK(st.st_mode): raise vg.GenerationError('link')
            with patch.object(vg, '_trusted_stat', side_effect=check):
                for target, recurse in ((base / 'link/new/file', False), (base / 'real', True)):
                    with self.assertRaises(vg.GenerationError):
                        vg.validate_destination(target, recursive=recurse)

    def test_unsafe_install_stops_before_any_mutation(self):
        with patch.object(installer.vendor_generation, 'validate_destination', side_effect=vg.GenerationError('unsafe')), \
             patch.object(installer, 'run') as run, patch.object(installer, 'hashes') as hashes:
            with self.assertRaises(vg.GenerationError):
                installer.install(Path('/synthetic'))
            run.assert_not_called()
            hashes.assert_not_called()

    def test_identity_conflict_stops_before_any_mutation(self):
        with patch.object(installer.vendor_generation, 'validate_destination'), \
             patch.object(installer, 'check_identities', side_effect=identities.IdentityError('collision')), \
             patch.object(installer, 'run') as run, patch.object(installer, 'hashes') as hashes:
            with self.assertRaises(identities.IdentityError):
                installer.install(Path('/synthetic'))
            run.assert_not_called()
            hashes.assert_not_called()


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.users = [pwd.struct_passwd((name, 'x', n, n, '', '/nonexistent', '/usr/bin/nologin'))
                      for n, name in enumerate(identities.ROLES, 10000)]
        self.groups = [grp.struct_group((name, 'x', n, [])) for n, name in enumerate(identities.ROLES, 10000)]
        def lookup(entries, field, value):
            matches = [e for e in entries if getattr(e, field) == value]
            if not matches: raise KeyError(value)
            return matches[0]
        mocks = [patch.object(identities.pwd, 'getpwall', side_effect=lambda: self.users),
                 patch.object(identities.grp, 'getgrall', side_effect=lambda: self.groups),
                 patch.object(identities.pwd, 'getpwnam', side_effect=lambda v: lookup(self.users, 'pw_name', v)),
                 patch.object(identities.pwd, 'getpwuid', side_effect=lambda v: lookup(self.users, 'pw_uid', v)),
                 patch.object(identities.grp, 'getgrnam', side_effect=lambda v: lookup(self.groups, 'gr_name', v)),
                 patch.object(identities.grp, 'getgrgid', side_effect=lambda v: lookup(self.groups, 'gr_gid', v)),
                 patch.object(identities.os, 'getgrouplist', side_effect=lambda name, gid: [gid])]
        for m in mocks:
            m.start(); self.addCleanup(m.stop)

    def test_valid_roles_and_all_missing_preflight(self):
        self.assertEqual(identities.check_identities(), [])
        self.users.clear(); self.groups.clear()
        self.assertEqual(identities.check_identities(True), list(identities.ROLES))
        with self.assertRaises(identities.IdentityError): identities.check_identities()

    def test_duplicate_uid_gid_name_login_and_shared_primary_group(self):
        original_users, original_groups = self.users[:], self.groups[:]
        mutations = [
            lambda: self.users.append(pwd.struct_passwd(('attacker', 'x', 10000, 9, '', '/', '/bin/sh'))),
            lambda: self.groups.append(grp.struct_group(('attacker', 'x', 10001, []))),
            lambda: self.users.append(pwd.struct_passwd(('attacker', 'x', 15000, 10002, '', '/', '/bin/sh'))),
            lambda: self.groups.append(grp.struct_group(('extra', 'x', 20000, ['inode-modern-engine']))),
            lambda: self.users.__setitem__(0, pwd.struct_passwd(('inode-modern-broker', 'x', 10000, 10000, '', '/', '/bin/bash'))),
            lambda: self.groups.__setitem__(0, grp.struct_group(('inode-modern-broker', 'x', 10000, ['attacker']))),
            lambda: self.groups.pop(),
        ]
        for mutation in mutations:
            self.users, self.groups = original_users[:], original_groups[:]
            mutation()
            with self.assertRaises(identities.IdentityError): identities.check_identities(True)

    def test_nss_failure_and_hidden_membership_fail_closed(self):
        with patch.object(identities.os, 'getgrouplist', return_value=[10000, 20000]):
            with self.assertRaises(identities.IdentityError): identities.check_identities()
        self.users.clear(); self.groups.clear()
        with patch.object(identities.pwd, 'getpwnam', return_value=object()):
            with self.assertRaises(identities.IdentityError): identities.check_identities(True)


def ruleset():
    # nft JSON listing shape, independent of the production validator's constants.
    dport = {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                       'right': {'set': [50000, 50001, 50002]}}}
    rows = [{'table': {'family': 'inet', 'name': 'inode_modern_guard', 'handle': 1}},
            {'set': {'family': 'inet', 'table': 'inode_modern_guard', 'name': 'allowed_cgroups',
                     'type': 'cgroupsv2', 'handle': 2, 'elem': [12345]}}]
    for name, priority in (('input', -10), ('output', 0)):
        rows.append({'chain': {'family': 'inet', 'table': 'inode_modern_guard', 'name': name,
                               'type': 'filter', 'hook': name, 'prio': priority, 'policy': 'accept'}})
    expressions = [('input', [{'match': {'op': '!=', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}},
                              dport, {'drop': None}]),
                   ('output', [dport, {'match': {'op': '==', 'left': {'socket': {'key': 'cgroupv2', 'level': 2}},
                                                'right': '@allowed_cgroups'}}, {'accept': None}]),
                   ('output', [dport, {'drop': None}])]
    for chain, expr in expressions:
        rows.append({'rule': {'family': 'inet', 'table': 'inode_modern_guard', 'chain': chain, 'expr': expr}})
    return {'nftables': rows}


class FirewallTests(unittest.TestCase):
    def test_valid_structure_and_exact_current_membership(self):
        firewall.validate_ruleset(ruleset(), 12345)
        data = ruleset(); data['nftables'][1]['set'].pop('elem')
        firewall.validate_ruleset(data)  # infrastructure exists before backend cgroup
        with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(data, 12345)
        for elems in ([23456], [12345, 23456], ['system.slice/backend'], [{'elem': 12345}]):
            data['nftables'][1]['set']['elem'] = elems
            with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(data, 12345)

    def test_member_empty_set_is_allowed_only_before_population(self):
        data = ruleset(); data['nftables'][1]['set']['elem'] = []
        firewall.validate_ruleset(data)
        with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(data, 12345)

    def test_numeric_member_must_match_current_id(self):
        firewall.validate_ruleset(ruleset(), 12345)
        with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(ruleset(), 54321)

    def test_matching_string_path_is_normalized_and_exact(self):
        for path in ('system.slice/inode-modern-backend.service',
                     '/system.slice/inode-modern-backend.service',
                     '//system.slice/./inode-modern-backend.service/'):
            data = ruleset(); data['nftables'][1]['set']['elem'] = [path]
            firewall.validate_ruleset(data)
            firewall.validate_ruleset(data, 12345)

    def test_wrong_or_malformed_string_path_fails_closed(self):
        for path in ('system.slice/other.service', 'system.slice/inode-modern-backend.service/child',
                     'user.slice/system.slice/inode-modern-backend.service',
                     'system.slice/../system.slice/inode-modern-backend.service',
                     '/sys/fs/cgroup/system.slice/inode-modern-backend.service',
                     ' system.slice/inode-modern-backend.service', '', '/', '12345', '0x3039',
                     'system.slice/inode-modern-backend.service\x00'):
            for cgroup_id in (None, 12345):
                data = ruleset(); data['nftables'][1]['set']['elem'] = [path]
                with self.subTest(path=path, current=cgroup_id), self.assertRaises(firewall.FirewallError):
                    firewall.validate_ruleset(data, cgroup_id)

    def test_unknown_member_types_and_invalid_numeric_values_fail_closed(self):
        for member in (True, False, 0, -1, 1 << 64, 12345.0, None, {'elem': 12345}, [], {}):
            data = ruleset(); data['nftables'][1]['set']['elem'] = [member]
            for cgroup_id in (None, 12345):
                with self.subTest(member=member), self.assertRaises(firewall.FirewallError):
                    firewall.validate_ruleset(data, cgroup_id)

    def test_mixed_duplicate_or_unexpected_elements_fail_closed(self):
        path = 'system.slice/inode-modern-backend.service'
        for members in ([12345, path], [path, 'system.slice/other.service'],
                        [12345, 12345], [path, path], [12345, 54321], path, None, {}):
            data = ruleset(); data['nftables'][1]['set']['elem'] = members
            for cgroup_id in (None, 12345):
                with self.subTest(members=members), self.assertRaises(firewall.FirewallError):
                    firewall.validate_ruleset(data, cgroup_id)

    def test_nft_json_without_level_uses_exact_text_handle(self):
        data = ruleset()
        data['nftables'][1]['set']['elem'] = [12345]
        for record in data['nftables']:
            rule = record.get('rule', {})
            if rule.get('chain') == 'output' and len(rule.get('expr', [])) == 3:
                rule['handle'] = 7
                rule['expr'][1]['match']['left']['socket'].pop('level')
        text = 'udp dport { 50000, 50001, 50002 } socket cgroupv2 level 2 @allowed_cgroups accept # handle 7'
        handle = firewall.verified_level_handle(text)
        firewall.validate_ruleset(data, 12345, handle)

    def test_missing_or_modified_table_set_chains_hooks_priorities_rules_rejected(self):
        mutations = [lambda r: r.pop(0), lambda r: r[0]['table'].update(flags=['dormant']),
                     lambda r: r[1]['set'].update(type='integer'),
                     lambda r: r[1]['set'].update(flags=['timeout']),
                     lambda r: r[2]['chain'].update(hook='forward'),
                     lambda r: r[3]['chain'].update(prio=100),
                     lambda r: r[2]['chain'].update(policy='drop'),
                     lambda r: r.pop(), lambda r: r.reverse(),
                     lambda r: r[5]['rule']['expr'][1]['match']['left']['socket'].update(level=1),
                     lambda r: r[6]['rule']['expr'].__setitem__(-1, {'accept': None}),
                     lambda r: r.append(copy.deepcopy(r[-1]))]
        for mutation in mutations:
            data = ruleset(); mutation(data['nftables'])
            with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(data, 12345)

    def test_older_nft_json_requires_matching_text_rule_handle_for_level(self):
        data = ruleset()
        rule = data['nftables'][5]['rule']
        rule['handle'] = 77
        rule['expr'][1]['match']['left']['socket'].pop('level')
        text = 'udp dport { 50000, 50001, 50002 } socket cgroupv2 level 2 @allowed_cgroups accept # handle 77'
        handle = firewall.verified_level_handle(text)
        firewall.validate_ruleset(data, 12345, handle)
        for wrong_handle in (None, 76):
            with self.assertRaises(firewall.FirewallError): firewall.validate_ruleset(data, 12345, wrong_handle)
        with self.assertRaises(firewall.FirewallError): firewall.verified_level_handle(text.replace('level 2', 'level 1'))
        with patch.object(firewall, 'current_cgroup_id', return_value=12345), \
             patch.object(firewall.subprocess, 'run', side_effect=[SimpleNamespace(stdout=json.dumps(data)), SimpleNamespace(stdout=text)]):
            firewall.verify_firewall(require_membership=True)

    def test_json_or_nft_failure_fails_closed(self):
        with patch.object(firewall.subprocess, 'run', return_value=SimpleNamespace(stdout='bad')):
            with self.assertRaises(firewall.FirewallError): firewall.verify_firewall()
        with patch.object(firewall.subprocess, 'run', side_effect=OSError('missing')):
            with self.assertRaises(firewall.FirewallError): firewall.verify_firewall()

    def test_membership_checked_before_vendor_launch(self):
        supervisor = backend.Supervisor(Path('/synthetic'))
        with patch.object(backend, 'check_identities'), \
             patch.object(backend, 'verify_firewall', side_effect=firewall.FirewallError('absent')), \
             patch.object(supervisor, 'setup_namespace') as setup, patch.object(supervisor, 'command') as command:
            with self.assertRaises(firewall.FirewallError): supervisor.run()
            setup.assert_not_called(); command.assert_not_called()

    def test_wrong_service_cgroup_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cgroup'
            for text in ('0::/', '0::/user.slice/attacker', '0::/system.slice/other.service'):
                path.write_text(text)
                with self.assertRaises(firewall.FirewallError): firewall.current_cgroup_id(path)

    def test_kernel_cgroup_handle_is_used_without_inode_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cgroup'
            path.write_text('0::' + firewall.SERVICE_CGROUP)
            libc = Mock()
            def handle_at(fd, name, pointer, mount_id, flags):
                handle = pointer._obj
                handle.kind = 0xfe
                handle.data[:] = (12345).to_bytes(8, firewall.sys.byteorder)
                return 0
            libc.name_to_handle_at.side_effect = handle_at
            with patch.object(firewall.ctypes, 'CDLL', return_value=libc):
                self.assertEqual(firewall.current_cgroup_id(path), 12345)
                libc.name_to_handle_at.side_effect = None
                libc.name_to_handle_at.return_value = -1
                with self.assertRaises(firewall.FirewallError): firewall.current_cgroup_id(path)

    def test_running_service_exits_if_guard_membership_disappears(self):
        supervisor = backend.Supervisor(Path('/synthetic'))
        with patch.object(backend, 'check_identities'), \
             patch.object(backend, 'verify_firewall', side_effect=[None, None, firewall.FirewallError('lost')]), \
             patch.object(supervisor, 'preflight'), patch.object(supervisor, 'setup_namespace'), \
             patch.object(supervisor, 'command'), patch.object(supervisor, 'wait_for', return_value=True), \
             patch.object(supervisor, 'stop') as stop, patch.object(backend, 'notify') as notify, \
             patch.object(backend, 'emit'), patch.object(backend, 'EventReader'):
            with self.assertRaises(firewall.FirewallError): supervisor.run()
            self.assertTrue(any('READY=1' in call.args[0] for call in notify.call_args_list))
            stop.assert_not_called()


class WritableStateTests(unittest.TestCase):
    def test_only_log_ipc_and_mon_lock_are_writable_mounts(self):
        supervisor = backend.Supervisor(Path('/opt/inode-modern/vendor/gen-0001'))
        mounts, ownership, modes, writes = [], [], [], []
        libc = Mock()
        libc.mount.side_effect = lambda src, dst, fs, flags, data: mounts.append((src, dst, flags)) or 0
        with patch.object(Path, 'mkdir'), patch.object(Path, 'chmod', side_effect=lambda mode: modes.append(mode)), \
             patch.object(Path, 'touch'), patch.object(Path, 'write_text', side_effect=lambda data: writes.append(data)), \
             patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'is_dir', return_value=True), \
             patch.object(Path, 'iterdir', return_value=iter(())), patch.object(backend.os, 'unshare'), \
             patch.object(backend.os, 'geteuid', return_value=0), \
             patch.object(backend.os, 'chown', side_effect=lambda p,u,g: ownership.append((str(p),u,g))), \
             patch.object(backend.os, 'chmod'), patch.object(backend.ctypes, 'CDLL', return_value=libc):
            supervisor.setup_namespace()
        binds = [(s,d) for s,d,f in mounts if f == backend.MS_BIND]
        self.assertEqual(binds, [
            (b'/run/inode-modern-private/vendor-ipc', b'/tmp/iNode'),
            (b'/run/inode-modern-private/log', b'/opt/inode-modern/vendor/gen-0001/log'),
            (b'/run/inode-modern-private/etc-iNode', b'/etc/iNode')])
        self.assertIn(('/run/inode-modern-private/log',10001,10001), ownership)
        self.assertIn(('/run/inode-modern-private/etc-iNode/inode_mon_lock',10002,10002), ownership)
        self.assertEqual(writes, ['INSTALL_DIR=/opt/inode-modern/vendor/gen-0001\n'])
        self.assertIn(0o444, modes); self.assertIn(0o555, modes); self.assertIn(0o600, modes)
        self.assertTrue(all(f & 8 and f & 4 and f & 2 for _,_,f in mounts if f & 32))
        self.assertIn((b'tmpfs', b'/tmp', 2 | 4 | 8), mounts)
        unit = (Path(__file__).resolve().parents[1] / 'integration/inode-modern-backend.service.in').read_text()
        self.assertIn('NoExecPaths=/tmp /var/tmp /run/inode-modern-private', unit)


# These tests model process snapshots independently of the host account database.
def setUpModule():
    import sys
    from tests.identity_fixture import start_role_fixture
    global _role_patches
    _role_patches = start_role_fixture(sys.modules[__name__])


def tearDownModule():
    for mock in reversed(_role_patches):
        mock.stop()

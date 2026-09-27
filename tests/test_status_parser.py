"""Line-oriented /proc status parsing and a separately runnable privileged live check."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from integration.invariants import parse_status, parse_status_field, parse_snapshot

STATUS = '''Name:\tAuthenMngServic
State:\tS (sleeping)
Uid:\t10001\t10001\t10001\t10001
Gid:\t10001\t10001\t10001\t10001
Groups:\t
NStgid:\t123
NSpid:\t123
CapInh:\t0000000000003000
CapPrm:\t0000000000003000
CapEff:\t0000000000003000
CapBnd:\t0000000000003000
CapAmb:\t0000000000003000
NoNewPrivs:\t1
'''


class StatusParserTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.proc = Path(temp.name)
        self.task = self.proc / '123'
        self.task.mkdir()
        exe = self.proc / 'AuthenMngService'
        exe.write_bytes(b'synthetic; never executed')
        (self.task / 'exe').symlink_to(exe)
        (self.task / 'cgroup').write_text('0::/system.slice/inode-modern-backend.service\n')

    def snapshot(self, text=STATUS):
        (self.task / 'status').write_text(text)
        return parse_snapshot(123, self.proc)

    def test_empty_groups(self):
        self.assertEqual(self.snapshot().groups, ())

    def test_single_group(self):
        self.assertEqual(self.snapshot(STATUS.replace('Groups:\t\n', 'Groups:\t10001\n')).groups, (10001,))

    def test_multiple_groups(self):
        self.assertEqual(self.snapshot(STATUS.replace('Groups:\t\n', 'Groups:\t10 10001 10002\n')).groups,
                         (10, 10001, 10002))

    def test_whitespace_only_groups(self):
        self.assertEqual(self.snapshot(STATUS.replace('Groups:\t\n', 'Groups:\t  \t \n')).groups, ())

    def test_empty_groups_followed_by_namespace_fields(self):
        fields = parse_status(STATUS)
        self.assertEqual(fields['Groups'], '')
        self.assertEqual(fields['NStgid'], '123')
        self.assertEqual(fields['NSpid'], '123')
        self.assertEqual(parse_status_field(STATUS, 'Groups'), '')
        reversed_ns = STATUS.replace('NStgid:\t123\nNSpid:\t123', 'NSpid:\t123\nNStgid:\t123')
        self.assertEqual(self.snapshot(reversed_ns).groups, ())

    def test_every_required_field_is_read_without_truncation(self):
        s = self.snapshot()
        self.assertEqual(s.uids, (10001,) * 4)
        self.assertEqual(s.gids, (10001,) * 4)
        self.assertEqual((s.cap_inh, s.cap_prm, s.cap_eff, s.cap_bnd, s.cap_amb), (0x3000,) * 5)
        self.assertEqual(s.no_new_privs, 1)
        self.assertEqual(s.canonical_exe, self.proc / 'AuthenMngService')
        self.assertEqual(s.cgroup, '0::/system.slice/inode-modern-backend.service')

    def test_split_on_first_colon_only(self):
        self.assertEqual(parse_status('Name:\tworker:child\nGroups:\t\n')['Name'], 'worker:child')

    def test_all_missing_required_fields_fail_closed(self):
        required = ('Name', 'State', 'Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff',
                    'CapBnd', 'CapAmb', 'NoNewPrivs')
        for key in required:
            with self.subTest(key=key):
                text = '\n'.join(line for line in STATUS.splitlines() if not line.startswith(key + ':'))
                self.assertIsNone(self.snapshot(text))

    def test_malformed_required_values_fail_closed(self):
        cases = {'Name': ('',), 'State': ('', 'Sleeping', '? (invalid)'),
                 'Uid': ('', '10001', '10001 10001 10001', '10001 10001 10001 10001 0',
                         '-1 10001 10001 10001', '4294967296 0 0 0', '1_000 0 0 0'),
                 'Gid': ('', '0 0 0', '0 0 0 0 0', '+0 0 0 0'),
                 'Groups': ('NStgid: 123', '-1', '4294967296', '1_000', '１２'),
                 'NoNewPrivs': ('', '2', '-1', '01', '1 extra')}
        for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
            cases[key] = ('', 'not-hex', '0x3000', '-1', '30_00', '10000000000000000')
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    text = '\n'.join(key + ':\t' + value if line.startswith(key + ':') else line
                                     for line in STATUS.splitlines())
                    self.assertIsNone(self.snapshot(text))

    def test_duplicate_and_malformed_lines_fail_closed(self):
        for extra in ('Uid:\t0 0 0 0\n', 'Groups:\t0\n', 'missing separator\n', ': value\n'):
            with self.subTest(extra=extra):
                self.assertIsNone(self.snapshot(STATUS + extra))

    def test_zombies_and_disappeared_processes_fail_closed(self):
        self.assertIsNone(self.snapshot(STATUS.replace('S (sleeping)', 'Z (zombie)')))
        self.assertIsNone(parse_snapshot(9999, self.proc))
        (self.task / 'exe').unlink()
        self.assertIsNone(self.snapshot())

    def test_empty_cgroup_fails_closed(self):
        (self.task / 'cgroup').write_text('')
        self.assertIsNone(self.snapshot())

    @unittest.skipUnless(os.geteuid() == 0, 'run separately from root-owned staging for live --clear-groups validation')
    def test_real_clear_groups_subprocess_snapshot(self):
        root = str(Path(__file__).resolve().parents[1])
        code = '''import json,os,sys
sys.path.insert(0,sys.argv[1])
from integration.invariants import parse_snapshot
s=parse_snapshot(os.getpid())
assert s is not None and s.groups==()
assert s.uids==(10001,)*4 and s.gids==(10001,)*4 and s.no_new_privs==1
assert (s.cap_inh,s.cap_prm,s.cap_eff,s.cap_bnd,s.cap_amb)==(0x3000,)*5
print(json.dumps({'groups':list(s.groups),'snapshot_present':True,'uid':s.uids[0],'caps':s.cap_eff,'NNP':s.no_new_privs}))
'''
        result = subprocess.run(['/usr/bin/setpriv', '--reuid', '10001', '--regid', '10001',
            '--clear-groups', '--bounding-set=-all,+net_raw,+net_admin',
            '--inh-caps=-all,+net_raw,+net_admin', '--ambient-caps=-all,+net_raw,+net_admin',
            '--no-new-privs', '/usr/bin/python3', '-I', '-B', '-c', code, root],
            check=True, capture_output=True, text=True, timeout=10,
            env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C.UTF-8'})
        self.assertTrue(json.loads(result.stdout)['snapshot_present'])

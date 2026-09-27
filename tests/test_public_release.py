"""Public distribution regressions: no real services, credentials or vendor execution."""
from dataclasses import replace
from pathlib import Path
import tempfile
import pwd
import grp
import unittest
from unittest.mock import patch
from integration import invariants, identities, vendor_setup as setup, package_lifecycle
from inode_modern import setup_status
from inode_modern.client import Client, ClientError
from tests import test_release_blockers as blockers

class DynamicIdentityTests(blockers.IdentityTests):
    def test_arbitrary_uid_and_separate_gid_are_resolved(self):
        self.users = [pwd.struct_passwd((u.pw_name,u.pw_passwd,700+i,800+i,u.pw_gecos,u.pw_dir,u.pw_shell)) for i,u in enumerate(self.users)]
        self.groups = [grp.struct_group((g.gr_name,g.gr_passwd,800+i,g.gr_mem)) for i,g in enumerate(self.groups)]
        self.assertEqual(identities.resolve_identities(),{name:(700+i,800+i) for i,name in enumerate(identities.ROLES)})

class RuntimeRoleTests(unittest.TestCase):
    def test_role_capability_nnp_gates_with_dynamic_ids(self):
        roles={name:(701+i,801+i) for i,name in enumerate(identities.ROLES)}
        gen=Path('/opt/inode-modern/vendor/gen-0001');group='0::/system.slice/inode-modern-backend.service'
        b=invariants.ProcessSnapshot(10,'python3',Path('/usr/bin/python3').resolve(),group,(701,)*4,(801,)*4,(),0,0,0,0,0,1)
        e=invariants.ProcessSnapshot(11,'AuthenMngService',gen/'AuthenMngService',group,(702,)*4,(802,)*4,(),0x3000,0x3000,0x3000,0x3000,0x3000,1)
        m=invariants.ProcessSnapshot(12,'iNodeMon',gen/'iNodeMon',group,(703,)*4,(803,)*4,(),0,0,0,0,0,1)
        with patch.object(invariants,'resolve_identities',return_value=roles), patch.object(invariants,'verify_socket_ownership',return_value=True):
            self.assertTrue(invariants.verify_invariants([e,m,b],gen,group,broker_pid=10)[0])
            for index,original in enumerate((e,m,b)):
                for bad in (replace(original,uids=(999,)*4),replace(original,gids=(999,)*4),replace(original,no_new_privs=0),replace(original,cap_eff=1),replace(original,cap_bnd=0xffff)):
                    snapshots=[e,m,b];snapshots[index]=bad
                    self.assertFalse(invariants.verify_invariants(snapshots,gen,group,broker_pid=10)[0])
        with patch.object(invariants,'resolve_identities',side_effect=identities.IdentityError('missing')):
            self.assertFalse(invariants.verify_invariants([e,m,b],gen,group,broker_pid=10)[0])

class VendorSourceTests(unittest.TestCase):
    def test_only_exact_known_linux64_link(self):
        html=f'<a href="/__local/known.zip">{setup.ARCHIVE_NAME}</a><a href="/32.zip">iNodeClient_Linux32_7.3 (E0538).tar.zip</a>'
        self.assertEqual(setup.parse_download(html),'https://info.swufe.edu.cn/__local/known.zip')
        self.assertEqual(setup.parse_download(html+html),'https://info.swufe.edu.cn/__local/known.zip')

    def test_unknown_changed_ambiguous_page_fails_closed(self):
        for html in ('<html>changed</html>',f'<a href="https://evil.example/a.zip">{setup.ARCHIVE_NAME}</a>',f'<a href="/a.zip">{setup.ARCHIVE_NAME}</a><a href="/b.zip">{setup.ARCHIVE_NAME}</a>'):
            with self.assertRaises(setup.SetupError):setup.parse_download(html)

    def test_redirect_and_url_origin_constraints(self):
        for url in ('http://info.swufe.edu.cn/a','https://evil.example/a','https://info.swufe.edu.cn.evil.example/a','https://x@info.swufe.edu.cn/a','https://info.swufe.edu.cn:444/a'):
            with self.assertRaises(setup.SetupError):setup.official_url(url)

    def test_unknown_hash_never_extracts_or_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'unknown';path.write_bytes(b'unknown archive')
            with patch.object(setup.tarfile,'open') as extract, patch.object(setup.vg,'import_generation') as importing:
                with self.assertRaises(setup.SetupError):setup.extract_archive(path,Path(temp),setup.metadata())
                extract.assert_not_called();importing.assert_not_called()
            with self.assertRaises(setup.SetupError):setup.check_hash(path,'0'*64)

    def test_pinned_library_preparation_and_mismatch(self):
        import hashlib, io, tarfile
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp); base.chmod(0o755)
            source=base/'source'; source.mkdir(); (source/'libs').mkdir()
            archive=source/'libs/linux64_std.tar.gz'
            with tarfile.open(archive,'w:gz') as t:
                member=tarfile.TarInfo('std/libsynthetic.so'); member.size=4
                t.addfile(member,io.BytesIO(b'test'))
            info={'library_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
            work=base/'work';work.mkdir()
            prepared=setup.prepare_source(source,work,info)
            self.assertEqual((prepared/'libs/std/libsynthetic.so').read_bytes(),b'test')
            self.assertFalse((source/'libs/std').exists())
            other=base/'bad';other.mkdir()
            with self.assertRaisesRegex(setup.SetupError,'SHA256'):
                setup.prepare_source(source,other,{'library_archive_sha256':'0'*64})

    def test_pinned_library_traversal_rejected(self):
        import hashlib, io, tarfile
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);base.chmod(0o755)
            source=base/'source';source.mkdir();(source/'libs').mkdir()
            archive=source/'libs/linux64_std.tar.gz'
            with tarfile.open(archive,'w:gz') as t:
                member=tarfile.TarInfo('../escape');member.size=4
                t.addfile(member,io.BytesIO(b'test'))
            with self.assertRaises(setup.SetupError):
                setup.prepare_source(source,base,{'library_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest()})
            self.assertFalse((base/'escape').exists())

    def test_repeated_setup_verifies_without_reimport_or_restart(self):
        from argparse import Namespace
        with patch.object(setup.Path,'exists',return_value=False),patch.object(setup.Path,'is_symlink',return_value=True),patch.object(setup,'check_identities'),patch.object(setup.vg,'get_active_generation',return_value=Path('/synthetic')),patch.object(setup,'verify_supported') as verify,patch.object(setup.vg,'import_generation') as importing,patch.object(setup,'run') as run:
            setup.configure(Namespace(vendor_dir=None,vendor_archive=None))
            verify.assert_called_once();importing.assert_not_called()
            self.assertEqual(run.call_args_list[-1].args,('systemctl','start','inode-modern-backend.service'))
            self.assertFalse(any('restart' in call.args for call in run.call_args_list))

    def test_metadata_has_no_temporary_download_url(self):
        data=setup.metadata()
        self.assertEqual(data['page'],setup.PAGE)
        self.assertEqual(len(data['archive_sha256']),64)
        self.assertNotIn('__local',str(data))

    def test_unknown_manual_generation_rejected(self):
        with patch.object(setup.vg,'verify_generation',return_value={'unknown':'0'*64}):
            with self.assertRaises(setup.SetupError):setup.verify_supported(Path('/synthetic'),setup.metadata())

    def test_failed_verification_cannot_activate_or_start(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as temp:
            args=Namespace(vendor_dir=Path(temp),vendor_archive=None)
            with patch.object(setup.Path,'exists',return_value=False), patch.object(setup.Path,'is_symlink',return_value=False), patch.object(setup,'check_identities'), patch('integration.backend.processes',return_value=[]), patch.object(setup.subprocess,'run') as service, patch.object(setup,'prepare_source',return_value=Path('/synthetic')), patch.object(setup.vg,'import_generation',return_value=Path('/synthetic')), patch.object(setup,'verify_supported',side_effect=setup.SetupError('bad')), patch.object(setup.vg,'activate_generation') as activate, patch.object(setup,'run') as start:
                service.return_value.returncode=3
                with self.assertRaises(setup.SetupError):setup.configure(args)
                activate.assert_not_called();start.assert_not_called()

class PackageBehaviorTests(unittest.TestCase):
    def test_no_vendor_gives_clear_client_message_without_socket(self):
        with patch('inode_modern.client.vendor_unconfigured',return_value=True),patch('inode_modern.client.socket.socket') as sock:
            with self.assertRaisesRegex(ClientError,'尚未配置原厂认证组件'):Client().__enter__()
            sock.assert_not_called()

    def test_units_conditioned_and_supervisor_named_root(self):
        root=Path(__file__).resolve().parents[1]
        for name in ('backend','firewall'):
            text=(root/f'packaging/inode-modern-{name}.service').read_text()
            self.assertIn('ConditionPathIsSymbolicLink=/opt/inode-modern/current',text)
            self.assertIn('User=root',text)
            self.assertNotIn('/usr/local',text)
            for uid in ('10000','10001','10002'):self.assertNotIn(uid,text)

    def test_final_erase_stops_before_guard_cleanup(self):
        events=[]
        with patch.object(package_lifecycle.subprocess,'run',side_effect=lambda *a,**k:events.append('stop')),patch.object(package_lifecycle.Path,'exists',return_value=False),patch.object(package_lifecycle,'teardown_guard',side_effect=lambda:events.append('cleanup')):
            package_lifecycle.remove()
        self.assertEqual(events,['stop','stop','cleanup'])

    def test_failed_stop_keeps_guard(self):
        import subprocess
        with patch.object(package_lifecycle.subprocess,'run',side_effect=subprocess.CalledProcessError(1,'systemctl')),patch.object(package_lifecycle,'teardown_guard') as cleanup:
            with self.assertRaises(subprocess.CalledProcessError):package_lifecycle.remove()
            cleanup.assert_not_called()

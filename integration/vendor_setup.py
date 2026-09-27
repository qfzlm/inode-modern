#!/usr/bin/python3
"""Acquire a pinned official archive and import it without executing vendor installers."""
import argparse
import fcntl
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urljoin, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler
import zipfile

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from tools import vendor_generation as vg
    from integration.identities import check_identities
except ImportError:
    import vendor_generation as vg
    from identities import check_identities

PAGE = 'https://info.swufe.edu.cn/info/1027/2411.htm'
ARCHIVE_NAME = 'iNodeClient_Linux64_7.3 (E0538).tar.zip'
LIMIT = 128 * 1024 * 1024

class SetupError(RuntimeError):
    pass


def metadata():
    from inode_modern import __file__ as package_file
    return json.loads((Path(package_file).parent / 'data/vendor.json').read_text())


def official_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname != 'info.swufe.edu.cn'
            or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
        raise SetupError('下载地址不是西财官方 HTTPS 来源')
    return url


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.href = None; self.text = []; self.matches = set()
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.href = dict(attrs).get('href'); self.text = []
    def handle_data(self, data):
        if self.href is not None: self.text.append(data)
    def handle_endtag(self, tag):
        if tag == 'a':
            if self.href and ' '.join(''.join(self.text).split()) == ARCHIVE_NAME:
                self.matches.add(official_url(urljoin(PAGE, self.href)))
            self.href = None


def parse_download(html):
    links = Links(); links.feed(html)
    if len(links.matches) != 1:
        raise SetupError('官方页面结构或文件名已变化。请打开 ' + PAGE + ' 下载后使用 --vendor-archive 导入；不会猜测链接。')
    return links.matches.pop()


def fetch(url, output, limit=LIMIT):
    official_url(url)
    with build_opener(OfficialRedirects()).open(url, timeout=30) as response, output.open('xb') as dest:
        official_url(response.url)
        count = 0
        while chunk := response.read(65536):
            count += len(chunk)
            if count > limit: raise SetupError('官方响应超过大小限制')
            dest.write(chunk)


def check_hash(path, expected):
    if vg.compute_sha256(path) != expected:
        raise SetupError('SHA256 不匹配：拒绝未知或损坏的原厂版本，未执行或激活任何原厂文件')


def extract_archive(archive, destination, info):
    digest = vg.compute_sha256(archive)
    if digest == info['archive_sha256']:
        with zipfile.ZipFile(archive) as z:
            if z.namelist() != [info['inner_name']] or z.infolist()[0].file_size > LIMIT:
                raise SetupError('原厂压缩包结构不符合已验证版本')
            inner = destination / 'vendor.tar.gz'
            with z.open(info['inner_name']) as src, inner.open('xb') as dst:
                shutil.copyfileobj(src, dst)
        check_hash(inner, info['inner_sha256'])
    elif digest == info['inner_sha256']:
        inner = archive
    else:
        raise SetupError('SHA256 不匹配：拒绝未知原厂版本')
    unpack = destination / 'unpacked'; unpack.mkdir(mode=0o755)
    with tarfile.open(inner, 'r:gz') as t:
        members = t.getmembers(); names = set(); total = 0
        for m in members:
            p = PurePosixPath(m.name)
            if (p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != 'iNodeClient'
                    or m.name in names or not (m.isdir() or m.isfile() or m.issym())):
                raise SetupError('不安全的压缩包成员')
            total += m.size; names.add(m.name)
            if total > 512 * 1024 * 1024: raise SetupError('解压大小超过限制')
        t.extractall(unpack, members=members, filter='data')
    return unpack / 'iNodeClient'


def prepare_source(source, work, info):
    """Copy through the hardened importer; unpack only the pinned compatibility library archive."""
    prepared = work / 'prepared'; prepared.mkdir(mode=0o755)
    fd = vg._open_source_root(source)
    try:
        links = vg._copy_source(fd, prepared, source)
        if not (prepared / 'libs/std').exists():
            libs = os.open('libs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                archive_fd = os.open('linux64_std.tar.gz', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=libs)
                with os.fdopen(archive_fd, 'rb') as src:
                    st = os.fstat(src.fileno())
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not st.st_mode & 0o004 or st.st_size > LIMIT:
                        raise SetupError('不安全的兼容库压缩包')
                    data = src.read(LIMIT + 1)
                if hashlib.sha256(data).hexdigest() != info['library_archive_sha256']:
                    raise SetupError('兼容库 SHA256 不匹配')
            finally:
                os.close(libs)
            archive = work / 'libraries.tar.gz'; archive.write_bytes(data)
            with tarfile.open(archive, 'r:gz') as t:
                members = t.getmembers()
                if sum(m.size for m in members) > 128*1024*1024:
                    raise SetupError('兼容库解压大小超过限制')
                for m in members:
                    path = PurePosixPath(m.name)
                    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'std' or not (m.isdir() or m.isfile() or m.issym()):
                        raise SetupError('不安全的兼容库成员')
                t.extractall(prepared / 'libs', members=members, filter='data')
    finally:
        os.close(fd)
    for relative, target in links:
        link = prepared / relative
        link.symlink_to(os.path.relpath(prepared / target, link.parent))
    for item in prepared.rglob('*'):
        if item.is_symlink(): vg.check_symlink_safety(item, prepared)
        elif item.is_dir(): item.chmod(0o755)
    return prepared


def verify_supported(generation, info):
    actual = vg.verify_generation(generation)
    if actual != info['files_sha256']:
        raise SetupError('目录内容与已验证 Linux64 E0538 版本不一致；拒绝激活')
    links = {str(p.relative_to(generation)): os.readlink(p) for p in generation.rglob('*') if p.is_symlink()}
    if links != info['symlinks']:
        raise SetupError('原厂库符号链接与已验证版本不一致')
    for name in vg.REQUIRED_BINARIES:
        with (generation / name).open('rb') as f: header = f.read(20)
        if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
            raise SetupError('原厂组件不是 Linux x86_64 ELF')


def run(*args):
    return subprocess.run(args, check=True, timeout=120, env={'PATH':'/usr/sbin:/usr/bin','LANG':'C.UTF-8'})


def configure(args):
    info = metadata()
    # Refuse ambiguous legacy installations; never stop a working installation automatically.
    for name in ('inode-modern-backend.service', 'inode-modern-firewall.service'):
        if (Path('/etc/systemd/system') / name).exists():
            raise SetupError('发现本地自定义 systemd unit；请先按迁移文档处理，不会覆盖或停止现有安装')
    check_identities()
    try:
        from integration.backend import processes, NAMES
    except ImportError:
        from backend import processes, NAMES
    if vg.CURRENT_SYMLINK.is_symlink() and not args.vendor_archive and not args.vendor_dir:
        verify_supported(vg.get_active_generation(), info)
    else:
        state = subprocess.run(['systemctl','is-active','--quiet','inode-modern-backend.service'], check=False)
        if state.returncode == 0: raise SetupError('认证服务正在运行；拒绝在线替换原厂组件')
        if any(exe.name in (*NAMES, 'iNodeClient') for _, exe, _ in processes()):
            raise SetupError('发现正在运行的原厂客户端；请先自行关闭，setup 不会终止它')
        if state.returncode not in (3,4): raise SetupError('无法确认认证服务状态')
        with tempfile.TemporaryDirectory(prefix='inode-modern-setup-', dir='/var/tmp') as temp:
            work = Path(temp); work.chmod(0o755)
            if args.vendor_dir:
                source = args.vendor_dir.absolute()
            else:
                archive = args.vendor_archive
                if archive is None:
                    page = work / 'official.html'; fetch(PAGE, page, 2*1024*1024)
                    url = parse_download(page.read_text(encoding='utf-8'))
                    archive = work / 'official.zip'; fetch(url, archive)
                source = extract_archive(archive.absolute(), work, info)
            source = prepare_source(source, work, info)
            generation = vg.import_generation(source)
            verify_supported(generation, info)
            vg.activate_generation(generation)
    # Vendor is verified before any service is enabled. Do not restart an active backend.
    run('systemctl','enable','inode-modern-firewall.service','inode-modern-backend.service')
    run('systemctl','daemon-reload')
    run('systemctl','start','inode-modern-firewall.service')
    run('systemctl','start','inode-modern-backend.service')
    print('原厂组件配置完成。请以普通用户启动 iNode Modern。')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--vendor-archive', type=Path)
    group.add_argument('--vendor-dir', type=Path)
    args = p.parse_args(argv)
    if os.geteuid() != 0: p.error('请使用 sudo inode-modern-setup')
    try:
        lockpath = Path('/run/inode-modern-setup.lock')
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            configure(args)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print('配置失败：' + str(exc) + '\n官方下载页：' + PAGE, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())

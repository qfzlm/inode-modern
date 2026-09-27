"""Trusted Vendor Generation Manager.

Manages root-owned, immutable vendor generations under /opt/inode-modern/vendor/
with SHA-256 Checksum Manifest verification, symlink escape prevention,
and atomic activation/rollback via canonical symlink /opt/inode-modern/current.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import uuid
import posixpath


VENDOR_BASE = Path("/opt/inode-modern/vendor")
CURRENT_SYMLINK = Path("/opt/inode-modern/current")
SYSCONF = Path("/etc/iNode/inodesys.conf")
REQUIRED_BINARIES = ("AuthenMngService", "iNodeMon")
REQUIRED_SCRIPTS = ("addRun.sh", "delRun.sh", "enablecards.ps", "renew.ps")
MANIFEST_NAME = ".manifest.sha256"


class GenerationError(RuntimeError):
    """Raised when generation import, verification, or activation fails."""
    pass


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_symlink_safety(path: Path, tree_root: Path) -> None:
    """Ensure symlink does not escape tree_root."""
    if not path.is_symlink():
        return
    try:
        target = path.resolve(strict=False)
        tree_root_resolved = tree_root.resolve(strict=True)
        if not (target == tree_root_resolved or tree_root_resolved in target.parents):
            raise GenerationError(f"Symlink escape detected: {path} points outside {tree_root}: {target}")
    except (OSError, RuntimeError) as exc:
        raise GenerationError(f"Invalid symlink {path}: {exc}") from None


def check_root_owned(path: Path) -> None:
    st = path.lstat()
    if st.st_uid != 0 or st.st_gid != 0:
        raise GenerationError(f"Generation path is not root:root: {path}")
    if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
        raise GenerationError(f"File permissions too permissive: {path}")


def verify_generation(gen_dir: Path) -> dict[str, str]:
    """Require a complete manifest and a root-owned, non-user-writable tree."""
    gen_dir = gen_dir.resolve(strict=True)
    for parent in (gen_dir, *gen_dir.parents):
        check_root_owned(parent)
    manifest_path = gen_dir / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise GenerationError("Manifest missing or not a regular file")
    expected_hashes = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("  ", 1)
        if (len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0])
                or not parts[1] or Path(parts[1]).is_absolute()
                or '..' in Path(parts[1]).parts or parts[1] in expected_hashes):
            raise GenerationError("Corrupt manifest entry")
        expected_hashes[parts[1]] = parts[0]
    actual_files = set()
    for item in gen_dir.rglob("*"):
        check_root_owned(item)
        st = item.lstat()
        if not item.is_symlink() and st.st_mode & 0o022:
            raise GenerationError("File permissions too permissive")
        if item.is_symlink():
            check_symlink_safety(item, gen_dir)
            if not item.exists():
                raise GenerationError("Dangling generation symlink")
        elif stat.S_ISREG(st.st_mode):
            if st.st_nlink != 1:
                raise GenerationError("Hardlinked generation file")
            if item != manifest_path:
                actual_files.add(str(item.relative_to(gen_dir)))
        elif not stat.S_ISDIR(st.st_mode):
            raise GenerationError("Special file in generation")
    if actual_files != set(expected_hashes):
        raise GenerationError("Manifest does not cover the complete generation")
    for name, digest in expected_hashes.items():
        if compute_sha256(gen_dir / name) != digest:
            raise GenerationError(f"Checksum mismatch for {name}")
    return expected_hashes


def _trusted_stat(st) -> None:
    if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
        raise GenerationError("Attacker-controlled destination owner/mode")
    if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        raise GenerationError("Destination symlink or special file")
    if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
        raise GenerationError("Hardlinked destination")


def validate_destination(path: Path, recursive: bool = False) -> None:
    """Check from / down, before writing; root-owned parents exclude non-root races.

    O_PATH avoids opening attacker FIFOs/devices for IO. Never resolve a link.
    Missing suffixes are safe only after every existing ancestor passed.
    """
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise GenerationError("Destination must be an absolute canonical path")
    def check_children(fd):
        for name in os.listdir(fd):
            child = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                st = os.fstat(child)
                _trusted_stat(st)
                if stat.S_ISDIR(st.st_mode):
                    readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY, dir_fd=child)
                    try:
                        check_children(readable)
                    finally:
                        os.close(readable)
            finally:
                os.close(child)
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        _trusted_stat(os.fstat(fd))
        for name in path.parts[1:]:
            try:
                child = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                return
            os.close(fd)
            fd = child
            _trusted_stat(os.fstat(fd))
        if recursive and stat.S_ISDIR(os.fstat(fd).st_mode):
            readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            try:
                check_children(readable)
            finally:
                os.close(readable)
    finally:
        os.close(fd)


def _open_source_root(path: Path) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise GenerationError("Source must be an absolute path without parent traversal")
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    ancestors = [os.fstat(fd)]
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            ancestors.append(os.fstat(fd))
        source_uid = ancestors[-1].st_uid
        for ancestor in ancestors:
            _source_directory_access(ancestor, source_uid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _source_directory_access(st, source_uid):
    # A rename can inject a root-private directory without using any symlink.
    # Root must not use its DAC override to export data the source owner cannot read.
    public = st.st_mode & 0o005 == 0o005
    owner = source_uid != 0 and st.st_uid == source_uid and st.st_mode & 0o500 == 0o500
    if not (public or owner):
        raise GenerationError("Source directory is not accessible to the unprivileged source owner")


def _version(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _copy_source(fd: int, destination: Path, source_root: Path, rel=Path('.'), links=None, source_uid=None):
    """All source access is relative to pinned descriptors, never rebuilt paths.

    Symlinks are inert until copying finishes. Only public regular files are
    imported: root must not turn an injected unreadable file into public data.
    No source chmod/chown/write is performed. Concurrent changes abort publication.
    """
    if links is None:
        links = []
    directory_before = os.fstat(fd)
    if source_uid is None:
        source_uid = directory_before.st_uid
    _source_directory_access(directory_before, source_uid)
    for name in sorted(os.listdir(fd)):
        relative = rel / name
        if name == MANIFEST_NAME or any(ord(c) < 32 for c in name):
            raise GenerationError("Reserved or unrepresentable source filename")
        if relative.parts[0] in ('log', 'tmp', '.cache'):
            continue
        if Path(name).suffix in ('.zip', '.tar', '.gz', '.bz2', '.xz'):
            continue
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        target = destination / name
        if stat.S_ISLNK(before.st_mode):
            link = os.readlink(name, dir_fd=fd)
            # Lexical translation only. Resolve/validate in root-private staging later.
            if link.startswith('/'):
                try:
                    link = str(Path(link).relative_to(source_root))
                except ValueError:
                    raise GenerationError("Symlink escape detected") from None
            else:
                link = posixpath.join(str(rel), link)
            normalized = posixpath.normpath(link)
            if normalized == '..' or normalized.startswith('../'):
                raise GenerationError("Symlink escape detected")
            links.append((relative, normalized))
        elif stat.S_ISDIR(before.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if _version(os.fstat(child)) != _version(before):
                    raise GenerationError("Source directory replaced")
                target.mkdir(mode=0o700)
                _copy_source(child, target, source_root, relative, links, source_uid)
            finally:
                os.close(child)
        elif stat.S_ISREG(before.st_mode):
            if before.st_nlink != 1 or not before.st_mode & 0o004:
                raise GenerationError("Hardlinked or non-public source file rejected")
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(source, 'rb') as stream:
                if _version(os.fstat(stream.fileno())) != _version(before):
                    raise GenerationError("Source file replaced")
                with target.open('xb') as output:
                    remaining = before.st_size
                    while remaining:
                        chunk = stream.read(min(65536, remaining))
                        if not chunk:
                            raise GenerationError("Source truncated during import")
                        output.write(chunk)
                        remaining -= len(chunk)
                    if stream.read(1) or _version(os.fstat(stream.fileno())) != _version(before):
                        raise GenerationError("Source changed during import")
                target.chmod(0o555 if name in REQUIRED_BINARIES or before.st_mode & 0o111
                             or Path(name).suffix in ('.sh', '.ps', '.so') else 0o444)
        else:
            raise GenerationError("Special source file rejected")
        if _version(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _version(before):
            raise GenerationError("Source entry replaced during import")
    if _version(os.fstat(fd)) != _version(directory_before):
        raise GenerationError("Source directory changed during import")
    return links


def import_generation(source_dir: Path, target_base: Path = VENDOR_BASE,
                      gen_name: str | None = None) -> Path:
    """Copy through pinned FDs into private staging, then publish a hardened tree."""
    source_dir = Path(source_dir).absolute()  # no symlink resolution
    if gen_name is not None and not re.fullmatch(r"gen-[0-9]{4,}", gen_name):
        raise GenerationError("Invalid generation name")
    validate_destination(target_base)
    target_base.mkdir(parents=True, exist_ok=True, mode=0o755)
    if gen_name is None:
        indices = [int(p.name[4:]) for p in target_base.iterdir()
                   if re.fullmatch(r'gen-[0-9]{4,}', p.name)]
        gen_name = f'gen-{max(indices, default=0) + 1:04d}'
    final = target_base / gen_name
    if final.exists() or final.is_symlink():
        raise GenerationError("Target generation already exists")
    staging = target_base / f'.staging-{uuid.uuid4().hex}'
    staging.mkdir(mode=0o700)
    try:
        fd = _open_source_root(source_dir)
        try:
            links = _copy_source(fd, staging, source_dir)
        finally:
            os.close(fd)
        # Links cannot affect the traversal, copy, or chmod of source-derived files.
        for relative, target in links:
            (staging / relative).symlink_to(os.path.relpath(staging / target, (staging / relative).parent))
        for relative, _ in links:
            link = staging / relative
            check_symlink_safety(link, staging)
            if not link.exists():
                raise GenerationError("Dangling source symlink")
        for name in REQUIRED_BINARIES:
            if not (staging / name).is_file() or (staging / name).is_symlink():
                raise GenerationError("Required executable missing or linked")
        if not (staging / 'libs/std').is_dir():
            raise GenerationError("Required library directories missing")
        (staging / 'log').mkdir(mode=0o555)
        entries = []
        for item in sorted(staging.rglob('*')):
            if item.is_file() and not item.is_symlink():
                entries.append(f'{compute_sha256(item)}  {item.relative_to(staging)}\n')
        manifest = staging / MANIFEST_NAME
        manifest.write_text(''.join(entries), encoding='utf-8')
        manifest.chmod(0o444)
        for item in sorted(staging.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if item.is_dir() and not item.is_symlink():
                item.chmod(0o555)
        staging.chmod(0o555)
        # Non-root cannot race publication in the verified destination parent.
        staging.rename(final)
        return final
    except BaseException:
        # Only this invocation's private staging, never the source or published trees.
        for item in staging.rglob('*'):
            if item.is_dir() and not item.is_symlink():
                item.chmod(0o700)
        staging.chmod(0o700)
        shutil.rmtree(staging)
        raise


def activate_generation(gen_dir: Path,
                        current_link: Path = CURRENT_SYMLINK,
                        sysconf: Path = SYSCONF) -> Path:
    """Select the next invocation; running namespaces retain their pinned config."""
    gen_dir = gen_dir.resolve()
    verify_generation(gen_dir)

    validate_destination(current_link.parent)
    if current_link.is_symlink():
        check_root_owned(current_link)
    elif current_link.exists():
        raise GenerationError("Current selector is not a symlink")
    current_link.parent.mkdir(parents=True, exist_ok=True, mode=0o755)

    tmp_link = current_link.parent / f".current.tmp.{uuid.uuid4().hex}"
    tmp_link.symlink_to(gen_dir)
    tmp_link.replace(current_link)


    return current_link.resolve()


def get_active_generation(current_link: Path = CURRENT_SYMLINK) -> Path:
    """Resolve and verify current active pinned generation."""
    if not current_link.is_symlink():
        raise GenerationError(f"Current link does not exist or is not a symlink: {current_link}")
    active = current_link.resolve(strict=True)
    verify_generation(active)
    return active

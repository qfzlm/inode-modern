#!/usr/bin/env python3
"""Install this application's own files into a user prefix. No vendor files."""

import argparse
import hashlib
import os
import json
from pathlib import Path
import shutil
import subprocess

APP_ID = "org.inode_modern.Client"
ROOT = Path(__file__).resolve().parents[1]


def desktop_quote(path: Path) -> str:
    value = str(path).replace("\\", "\\\\\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$").replace("%", "%%")
    return f'"{value}"'


def install(prefix: Path) -> list[Path]:
    prefix = prefix.expanduser().resolve()
    app_dir = prefix / "share/inode-modern"
    marker = app_dir / ".inode-modern-install"
    if app_dir.exists() and (not marker.is_file() or marker.read_text() != APP_ID):
        raise RuntimeError("existing target directory is not managed by inode-modern")
    app_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(APP_ID)
    target = app_dir / "inode_modern"
    shutil.copytree(ROOT / "inode_modern", target, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    launcher = prefix / "bin/inode-modern-gui"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text("#!/usr/bin/python3\nimport sys\nsys.path.insert(0, " + repr(str(app_dir)) + ")\n"
                        "from inode_modern.desktop.app import main\nraise SystemExit(main())\n")
    launcher.chmod(0o755)
    icon = prefix / f"share/icons/hicolor/scalable/apps/{APP_ID}.svg"
    icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "inode_modern/desktop/inode-modern.svg", icon)
    size_icons = []
    for size, suffix in ((size, suffix) for size in (16, 22, 24, 32, 48, 64, 256) for suffix in ("", "@2")):
        sized = prefix / f"share/icons/hicolor/{size}x{size}{suffix}/apps/{APP_ID}.svg"
        sized.parent.mkdir(parents=True, exist_ok=True)
        source = "inode-modern-small.svg" if size <= 24 else "inode-modern.svg"
        shutil.copyfile(ROOT / "inode_modern/desktop" / source, sized)
        size_icons.append(sized)
    desktop = prefix / f"share/applications/{APP_ID}.desktop"
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text("[Desktop Entry]\nType=Application\nName=iNode Modern\n"
                       "GenericName=Campus network authentication\nGenericName[zh_CN]=校园网认证\n"
                       "Comment=Connect to the wired campus network\nComment[zh_CN]=连接有线校园网\n"
                       f"Exec={desktop_quote(launcher)}\nIcon={APP_ID}\n"
                       "Terminal=false\nCategories=Network;\nKeywords=iNode;H3C;802.1X;campus;校园网;\n"
                       "StartupNotify=true\n")
    cli = prefix / "bin/inode-modern"
    if cli.exists() and "inode_modern.cli" not in cli.read_text():
        raise RuntimeError("existing CLI launcher is not managed by inode-modern")
    cli.write_text("#!/usr/bin/python3\nimport sys\nsys.path.insert(0, " + repr(str(app_dir)) + ")\n"
                   "from inode_modern.cli import main\nraise SystemExit(main())\n")
    cli.chmod(0o755)
    shutil.copyfile(Path(__file__), app_dir / "install_desktop.py")
    files = [launcher, desktop, icon, cli, *size_icons]
    (app_dir / "installed-files.json").write_text(json.dumps(
        {str(path.relative_to(prefix)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}, indent=2))
    return [launcher, desktop, icon, app_dir]


def uninstall(prefix: Path) -> list[Path]:
    prefix = prefix.expanduser().resolve()
    app_dir = prefix / "share/inode-modern"
    if not (app_dir / ".inode-modern-install").is_file() or (app_dir / ".inode-modern-install").read_text() != APP_ID:
        raise RuntimeError("no managed desktop installation found")
    allowed = {"bin/inode-modern", "bin/inode-modern-gui", f"share/applications/{APP_ID}.desktop",
               f"share/icons/hicolor/scalable/apps/{APP_ID}.svg"}
    allowed.update(f"share/icons/hicolor/{size}x{size}{suffix}/apps/{APP_ID}.svg"
                   for size in (16, 22, 24, 32, 48, 64, 256) for suffix in ("", "@2"))
    manifest = json.loads((app_dir / "installed-files.json").read_text())
    if not set(manifest).issubset(allowed):
        raise RuntimeError("invalid installation manifest")
    files = [prefix / name for name in manifest]
    for path in files:
        if path.exists() and (path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest[str(path.relative_to(prefix))]):
            raise RuntimeError("installed file was modified; refusing to remove it")
    for path in files:
        path.unlink(missing_ok=True)
    shutil.rmtree(app_dir)
    return files + [app_dir]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local")
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("install the desktop as your normal user, not with sudo")
    if args.uninstall:
        files = uninstall(args.prefix)
        print(json.dumps({"removed": [str(file) for file in files]}, indent=2))
        return
    files = install(args.prefix)
    if shutil.which("desktop-file-validate"):
        subprocess.run(["desktop-file-validate", str(files[1])], check=True)
    print(json.dumps({"installed": [str(file) for file in files]}, indent=2))


if __name__ == "__main__":
    main()

"""Read-only public installation status shared by CLI and GUI."""
from pathlib import Path

SETUP_HINT = ('尚未配置原厂认证组件。请运行 sudo inode-modern-setup；'
              '官方下载页：https://info.swufe.edu.cn/info/1027/2411.htm')

def vendor_unconfigured():
    return (Path('/usr/bin/inode-modern-setup').is_file()
            and not Path('/opt/inode-modern/current').is_symlink())

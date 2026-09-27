"""Optical icon master selection, including desktop high-DPI rendering."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from pathlib import Path
import tempfile
import unittest
from PySide6.QtCore import QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication
from inode_modern.desktop.icons import application_icon, SIZES
from tools.install_desktop import install, uninstall, APP_ID

class IconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_optical_master_at_logical_sizes_and_device_scales(self):
        root = Path(__file__).resolve().parents[1] / 'inode_modern/desktop'
        icon = application_icon()
        for size in SIZES:
            source = root / ('inode-modern-small.svg' if size <= 24 else 'inode-modern.svg')
            for scale in (1., 1.25, 1.5, 2.):
                with self.subTest(size=size, scale=scale):
                    result = icon.pixmap(QSize(size,size), scale)
                    pixels = QSize(round(size*scale),round(size*scale))
                    self.assertEqual(result.size(), pixels)
                    expected = QIcon(str(source)).pixmap(pixels, 1.)
                    actual_image = result.toImage()
                    actual_image.setDevicePixelRatio(1.)
                    self.assertEqual(actual_image, expected.toImage())

    def test_install_and_uninstall_all_icon_variants(self):
        source = Path(__file__).resolve().parents[1] / 'inode_modern/desktop'
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            install(prefix)
            icons = []
            for size in SIZES:
                master = source / ('inode-modern-small.svg' if size <= 24 else 'inode-modern.svg')
                for suffix in ('', '@2'):
                    target = prefix / f'share/icons/hicolor/{size}x{size}{suffix}/apps/{APP_ID}.svg'
                    self.assertEqual(target.read_bytes(), master.read_bytes())
                    icons.append(target)
            uninstall(prefix)
            self.assertTrue(all(not path.exists() for path in icons))

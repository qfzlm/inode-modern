"""Official icon: optical small-size master, selected in logical pixels."""
from pathlib import Path
from PySide6.QtCore import QSize, qVersion
from PySide6.QtGui import QIcon, QIconEngine

SIZES = (16, 22, 24, 32, 48, 64, 256)

class _ApplicationIcon(QIconEngine):
    def clone(self):
        return _ApplicationIcon()

    def availableSizes(self, mode=QIcon.Mode.Normal, state=QIcon.State.Off):
        return [QSize(n, n) for n in SIZES]

    def pixmap(self, size, mode, state):
        return self.scaledPixmap(size, mode, state, 1.0)

    def scaledPixmap(self, size, mode, state, scale):
        # Qt 6.8 changed this argument from device to logical pixels.
        if tuple(map(int, qVersion().split(".")[:2])) < (6, 8):
            size = QSize(round(size.width() / scale), round(size.height() / scale))
        small = max(size.width(), size.height()) <= 24
        name = "inode-modern-small.svg" if small else "inode-modern.svg"
        icon = QIcon(str(Path(__file__).with_name(name)))
        pixels = QSize(round(size.width() * scale), round(size.height() * scale))
        result = icon.pixmap(pixels, 1.0, mode, state)
        result.setDevicePixelRatio(scale)
        return result

    def paint(self, painter, rect, mode, state):
        scale = painter.device().devicePixelRatioF()
        size = rect.size()
        if tuple(map(int, qVersion().split(".")[:2])) < (6, 8):
            size = QSize(round(size.width() * scale), round(size.height() * scale))
        painter.drawPixmap(rect, self.scaledPixmap(size, mode, state, scale))

def application_icon():
    return QIcon(_ApplicationIcon())

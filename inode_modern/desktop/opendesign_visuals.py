"""OpenDesign V2 tokens, converted from the delivered OKLCH values to sRGB."""
from PySide6.QtGui import QPalette

LIGHT = dict(bg='#f6f9fc', surface='#ffffff', fg='#121c23', muted='#5a656d',
             border='#d9dfe3', primary='#15813d', hover='#e1e5ea', rail='#f4f7f9',
             primary_hover='#124317', on_primary='#ffffff', error='#971b17',
             error_bg='#fceeec', warn='#6c4701', warn_bg='#fcf0e0', good='#1d5522',
             focus='#1c5c23', control_border='#77828a')
DARK = dict(bg='#161b20', surface='#1d2227', fg='#e8ebef', muted='#a8afb5',
            border='#383e43', primary='#7fc581', hover='#31363b', rail='#12171b',
            primary_hover='#a5e0a5', on_primary='#0a150b', error='#fba89d',
            error_bg='#38221f', warn='#f1c17f', warn_bg='#322718', good='#92cc93',
            focus='#8bd28d', control_border='#79818a')


def colors(palette):
    return DARK if palette.color(QPalette.ColorRole.Window).lightnessF() < .5 else LIGHT


LIGHT.update(banner='#edf8f1', wave='#dcefe5', ring='#d4f1dc', good_fill='#22a447',
             danger='#d93629', danger_hover='#bd2b21')
DARK.update(banner='#203c30', wave='#294b3b', ring='#2b5740', good_fill='#27994b',
            danger='#b93029', danger_hover='#d13c32')

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QFrame, QWidget


def line_icon(name, color):
    paths = {
        'ethernet': '<path d="M6 13V3h12v10M3 13h18v8H3zM7 17v1m5-1v1m5-1v1M9 6h6"/>',
        'pin': '<path d="M20 10c0 6-8 12-8 12S4 16 4 10a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="2.5"/>',
        'shield': '<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6Z M8 11l3 3 5-5"/>',
        'globe': '<circle cx="12" cy="12" r="10"/><ellipse cx="12" cy="12" rx="4" ry="10"/><path d="M2 12h20M4 6h16M4 18h16"/>',
        'refresh': '<path d="M20 8a9 9 0 1 0 1 8M20 2v6h-6"/>',
        'settings': '<path d="m9 3 1-2h4l1 2 3 2 3 1v4l-2 2 2 3v3l-3 1-3 2-1 2h-4l-1-2-3-2-3-1v-4l2-2-2-3V6l3-1Z"/><circle cx="12" cy="12" r="4"/>',
        'disconnect': '<path d="m3 3 18 18M9 9l-4 8M15 9l4 8"/><circle cx="12" cy="4" r="2.5"/><circle cx="4" cy="20" r="2.5"/><circle cx="20" cy="20" r="2.5"/>',
    }
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{paths[name]}</g></svg>'
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(svg.encode()).render(painter)
    painter.end()
    return QIcon(pixmap)


class StatusBanner(QFrame):
    def set_tone(self, c, phase):
        self.c, self.phase = c, phase
        self.update()

    def paintEvent(self, event):
        if not hasattr(self, 'c'):
            return
        c = self.c
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()), 14, 14)
        p.setClipPath(clip)
        fill = c['error_bg'] if self.phase == 'failed' else c['warn_bg'] if self.phase in ('unknown','unavailable','occupied') else c['banner']
        p.fillRect(self.rect(), QColor(fill))
        if self.phase == 'online':
            path = QPainterPath()
            w, h = self.width(), self.height()
            path.moveTo(w*.65, h)
            path.cubicTo(w*.82, -h*.8, w*.90, h*.1, w*1.1, h*1.2)
            path.closeSubpath()
            p.fillPath(path, QColor(c['wave']))
        p.end()


class StatusEmblem(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(116, 116)
        self.setAccessibleName('连接状态')

    def set_tone(self, c, phase):
        self.c, self.phase = c, phase
        self.update()

    def paintEvent(self, event):
        if not hasattr(self, 'c'):
            return
        c, phase = self.c, self.phase
        online = phase == 'online'
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(c['ring'] if online else c['wave']))
        p.drawEllipse(QRectF(0, 0, 116, 116))
        p.setBrush(QColor(c['good_fill'] if online else c['error'] if phase == 'failed' else c['warn'] if phase in ('unknown','unavailable','occupied') else c['muted']))
        p.drawEllipse(QRectF(12, 12, 92, 92))
        p.setPen(QPen(QColor('#ffffff' if online or c is LIGHT else c['surface']), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        path = QPainterPath()
        if online:
            path.moveTo(39, 58); path.lineTo(53, 72); path.lineTo(78, 44)
        elif phase in ('connecting', 'checking', 'disconnecting'):
            p.drawArc(QRectF(35, 35, 46, 46), 35*16, 280*16)
        elif phase == 'offline':
            p.drawArc(QRectF(36, 37, 44, 44), -55*16, 290*16)
            path.moveTo(58, 32); path.lineTo(58, 53)
        else:
            path.moveTo(58, 36); path.lineTo(58, 61)
            p.drawPoint(58, 77)
        p.drawPath(path)
        p.end()


class StepRail(QFrame):
    def paintEvent(self, event):
        super().paintEvent(event)
        if not hasattr(self, 'dots') or not hasattr(self, 'line_color'):
            return
        p = QPainter(self)
        p.setPen(QPen(QColor(self.line_color), 2))
        for a, b in zip(self.dots, self.dots[1:]):
            start = a.mapTo(self, a.rect().center())
            end = b.mapTo(self, b.rect().center())
            p.drawLine(start, end)
        p.end()

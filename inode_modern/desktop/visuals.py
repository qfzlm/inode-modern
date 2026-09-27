"""Desktop presentation tokens and contrast helpers; no authentication behavior."""

from dataclasses import dataclass

from PySide6.QtGui import QColor, QPalette


def blend(a: QColor, b: QColor, weight: float) -> QColor:
    return QColor(*(round(x * (1 - weight) + y * weight)
                    for x, y in zip(a.getRgb()[:3], b.getRgb()[:3])))


def contrast(a: QColor, b: QColor) -> float:
    def luminance(color):
        channels = [n / 12.92 if n <= .04045 else ((n + .055) / 1.055) ** 2.4
                    for n in color.getRgbF()[:3]]
        return sum(value * weight for value, weight in zip(channels, (.2126, .7152, .0722)))
    low, high = sorted((luminance(a), luminance(b)))
    return (high + .05) / (low + .05)


@dataclass(frozen=True)
class Colors:
    background: QColor
    surface: QColor
    text: QColor
    muted: QColor
    line: QColor
    accent: QColor
    success: QColor
    warning: QColor
    dark: bool

    @classmethod
    def from_palette(cls, palette: QPalette):
        dark = palette.color(QPalette.ColorRole.Window).lightnessF() < .5
        values = (
            ("#1c2924", "#14211c", "#ecf3ee", "#adbbb2", "#62776a", "#97d9b6", "#97d9b6", "#e4bd83")
            if dark else
            ("#eef2ec", "#fafbf7", "#1b3027", "#52645a", "#83968a", "#24684d", "#24684d", "#93601e")
        )
        return cls(*(QColor(value) for value in values), dark)

    @property
    def header(self):
        return QColor("#122c22")

    def header_ink(self, phase):
        if phase == "online":
            return QColor("#9ee1bd")
        if phase in ("failed", "occupied", "unavailable", "unknown"):
            return QColor("#f0cb94")
        return QColor("#f1f6f3")

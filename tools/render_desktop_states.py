#!/usr/bin/env python3
"""Render the actual Qt widgets with synthetic snapshots, without any IPC worker."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPalette, QPixmap
from PySide6.QtWidgets import QApplication

from inode_modern.desktop.window import Window


def snapshots():
    base = {"phase": "offline", "detail": "输入完整账号和密码，即可连接校园网。",
            "state": 1, "result": 0, "can_connect": True, "can_disconnect": False,
            "responsive": True, "interface": "enp5s0",
            "interfaces": [{"name": "enp5s0", "carrier": True, "ipv4": ""}]}
    return {
        "disconnected": base,
        "connecting": {**base, "phase": "connecting", "state": 0, "can_connect": False,
                       "can_disconnect": True, "detail": "正在等待校园网认证结果…"},
        "connected": {**base, "phase": "online", "state": 2, "can_connect": False,
                      "can_disconnect": True, "detail": "校园网认证已通过。",
                      "interfaces": [{"name": "enp5s0", "carrier": True, "ipv4": "10.0.0.24"}]},
        "failure": {**base, "phase": "failed", "state": 6, "can_connect": False,
                    "can_disconnect": True,
                    "detail": "未在 35 秒内确认认证成功。请断开后检查账号、密码和网线，再重试。"},
    }


def dark_palette():
    palette = QPalette()
    for role, color in {
        QPalette.ColorRole.Window: "#202327", QPalette.ColorRole.WindowText: "#edf0f4",
        QPalette.ColorRole.Base: "#25292e", QPalette.ColorRole.AlternateBase: "#2d3238",
        QPalette.ColorRole.Text: "#edf0f4", QPalette.ColorRole.Button: "#30363d",
        QPalette.ColorRole.ButtonText: "#edf0f4", QPalette.ColorRole.Highlight: "#77b5ef",
        QPalette.ColorRole.HighlightedText: "#142331", QPalette.ColorRole.PlaceholderText: "#9da6b1",
    }.items():
        palette.setColor(role, QColor(color))
    return palette


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/visual-refresh/light"))
    parser.add_argument("--dark", action="store_true")
    parser.add_argument("--design", choices=("impeccable", "opendesign"), default="impeccable")
    parser.add_argument("--width", type=int, default=900)
    parser.add_argument("--height", type=int, default=700)
    parser.add_argument("--font-scale", type=float, default=1.0)
    parser.add_argument("--all-states", action="store_true")
    args = parser.parse_args()
    app = QApplication(["inode-visual-review"])
    font = app.font()
    font.setPointSizeF(font.pointSizeF() * args.font_scale)
    app.setFont(font)
    if args.dark:
        app.setPalette(dark_palette())
    args.output.mkdir(parents=True, exist_ok=True)
    pictures = []
    geometry = {}
    window_class = Window
    if args.design == "opendesign":
        from inode_modern.desktop.window_opendesign import Window as window_class
    window = window_class()
    window.resize(args.width, args.height)
    window.show()
    states = snapshots()
    if args.all_states:
        base = states["disconnected"]
        for phase, detail in {
            "checking": "正在检查认证服务…",
            "disconnecting": "正在等待认证服务断开…",
            "unavailable": "认证后台未响应。应用会继续检测。",
            "occupied": "另一个前端正在使用认证接口。请关闭旧 iNode 或正在运行的 CLI。",
            "unknown": "服务返回了尚未确认的状态。可先断开，再重新连接。",
        }.items():
            states[phase] = {**base, "phase": phase, "detail": detail,
                             "can_connect": False, "can_disconnect": phase == "unknown"}
        states["no-interface"] = {**base, "interfaces": []}
        states["no-cable"] = {**base, "interfaces": [{"name": "enp5s0", "carrier": False, "ipv4": ""}]}
        states["no-address"] = {**states["connected"], "interfaces": base["interfaces"]}
        states["wallet-error"] = base
    # No Worker, Client, D-Bus registration, credentials or real authentication.
    for name, snapshot in states.items():
        if name == "failure" and args.design == "opendesign":
            # Reproduce an observed authentication attempt before its timeout.
            window.update_state(states["connecting"])
        window.update_state(snapshot)
        window.notice.hide()
        if name == "wallet-error":
            window.show_notice("无法安全保存密码：系统钱包不可用。请解锁钱包后重试。")
        window.ensurePolished()
        window.layout().activate()
        app.processEvents()
        window.resize(args.width, args.height)
        window.layout().activate()
        app.processEvents()
        picture = window.grab()
        picture.save(str(args.output / f"{name}.png"))
        geometry[name] = [window.width(), window.height()]
        pictures.append((name, picture))

    # Contact sheet preserves the exact rendered content of each window.
    margin, caption, gap = 24, 34, 24
    width = max(size[0] for size in geometry.values())
    height = max(size[1] for size in geometry.values())
    rows = (len(pictures) + 1) // 2
    sheet = QPixmap(2 * width + gap + 2 * margin, rows * (height + caption) + (rows - 1) * gap + 2 * margin)
    sheet.fill(app.palette().color(QPalette.ColorRole.Window))
    painter = QPainter(sheet)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    font = app.font()
    font.setPointSize(11)
    font.setWeight(QFont.Weight.DemiBold)
    painter.setFont(font)
    painter.setPen(app.palette().color(QPalette.ColorRole.WindowText))
    titles = {"disconnected": "未连接", "connecting": "正在认证", "connected": "已连接", "failure": "操作未完成"}
    for index, (name, picture) in enumerate(pictures):
        x = margin + (index % 2) * (width + gap)
        y = margin + (index // 2) * (height + caption + gap)
        painter.drawText(QRectF(x, y, width, caption), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, titles.get(name, name))
        painter.drawPixmap(QRectF(x, y + caption, width, height), picture, QRectF(0, 0, picture.width(), picture.height()))
    painter.end()
    sheet.save(str(args.output / ("all-states.png" if args.all_states else "four-states.png")))
    report = {"platform": app.platformName(), "style": app.style().objectName(),
              "palette": "dark preview" if args.dark else "system", "geometry": geometry,
              "design": args.design, "synthetic_snapshots": True, "authentication_started": False}
    (args.output / "render.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

"""Normal-user desktop entry; D-Bus only exposes window activation."""

import os
from pathlib import Path
from .icons import application_icon
import sys

from PySide6.QtCore import ClassInfo, QThread, Slot
from PySide6.QtDBus import QDBus, QDBusAbstractAdaptor, QDBusConnection, QDBusMessage
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from ..credentials import CredentialError, protect_process
from . import APP_ID, VERSION
from .window_opendesign import Window
from .worker import Worker
from .preferences import Preferences


@ClassInfo({"D-Bus Interface": APP_ID})
class Activation(QDBusAbstractAdaptor):
    @Slot()
    def activate(self):
        window = self.parent()
        window.showNormal()
        window.raise_()
        window.activateWindow()


def build_window(app, worker=None, window_factory=Window):
    window = window_factory()
    worker = worker or Worker()
    thread = QThread(app)
    worker.moveToThread(thread)
    thread.started.connect(worker.start)
    window.login.connect(worker.connect_account)
    window.remember_changed.connect(worker.remember_changed)
    worker.credentials_restored.connect(window.restore_credentials)
    window.disconnect_requested.connect(worker.disconnect_account)
    window.network_requested.connect(worker.activate_network)
    window.refresh_requested.connect(worker.poll)
    window.interface_selected.connect(worker.select_interface)
    worker.changed.connect(window.update_state)
    worker.notice.connect(window.show_notice)
    worker.command_finished.connect(window.command_finished)
    window.close_requested.connect(worker.stop_requested.set)
    window.close_requested.connect(worker.stop)
    worker.finished.connect(thread.quit)
    worker.finished.connect(worker.deleteLater)
    # The window vetoes close events while its worker stops. quit() would send
    # another vetoed close event; exit() finishes the loop after cleanup instead.
    thread.finished.connect(app.exit)
    return window, worker, thread


def main(argv=None, *, window_factory=Window):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--version"]:
        print(f"iNode Modern {VERSION}")
        return 0
    if argv:
        print("参数无效；桌面客户端通过窗口输入凭据。", file=sys.stderr)
        return 2
    try:
        protect_process()
    except (CredentialError, OSError, ValueError):
        print("无法启用凭据保护，桌面客户端未启动。", file=sys.stderr)
        return 1
    # QApplication never receives arbitrary argv (notably any accidental credentials).
    app = QApplication(["inode-modern-gui"])
    app.setApplicationName("iNode Modern")
    app.setApplicationVersion(VERSION)
    app.setOrganizationName("inode-modern")
    app.setDesktopFileName(APP_ID)
    app.setWindowIcon(application_icon())
    app.setQuitOnLastWindowClosed(False)
    if os.geteuid() == 0:
        QMessageBox.critical(None, "iNode Modern", "请以普通用户启动此应用，无需 root 权限。")
        return 1
    bus = QDBusConnection.sessionBus()
    if not bus.isConnected():
        QMessageBox.critical(None, "iNode Modern", "无法连接当前桌面会话，请从 KDE 应用菜单重新启动。")
        return 1
    if not bus.registerService(APP_ID):
        message = QDBusMessage.createMethodCall(APP_ID, "/Client", APP_ID, "activate")
        response = bus.call(message, QDBus.CallMode.Block, 2000)
        if response.type() == QDBusMessage.MessageType.ErrorMessage:
            QMessageBox.warning(None, "iNode Modern", "已有实例正在运行，但暂时无法显示其窗口。")
            return 1
        return 0
    window, worker, thread = build_window(app, Worker(preferences=Preferences()), window_factory=window_factory)
    activation = Activation(window)
    if not bus.registerObject("/Client", window, QDBusConnection.RegisterOption.ExportAdaptors):
        bus.unregisterService(APP_ID)
        QMessageBox.critical(None, "iNode Modern", "无法注册桌面应用实例。")
        return 1
    window.show()
    thread.start()
    result = app.exec()
    worker.stop_requested.set()
    thread.quit()
    thread.wait()
    bus.unregisterObject("/Client")
    bus.unregisterService(APP_ID)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

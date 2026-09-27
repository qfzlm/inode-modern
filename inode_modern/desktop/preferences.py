"""GUI-only preferences and encrypted KWallet storage. Never log secrets."""

from dataclasses import dataclass, field
import json

from PySide6.QtCore import QSettings
from . import APP_ID


class StorageError(Exception):
    pass


@dataclass(repr=False)
class SavedLogin:
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    remember: bool = False

    def clear(self):
        self.username = self.password = ""


class Wallet:
    folder = APP_ID
    key = "gui-login"

    def call(self, method, *args):
        try:
            import dbus
            bus = dbus.SessionBus()
            proxy = bus.get_object("org.kde.kwalletd6", "/modules/kwalletd6")
            interface = dbus.Interface(proxy, "org.kde.KWallet")
            return getattr(interface, method)(*args, timeout=30)
        except Exception:
            raise StorageError("无法安全保存密码，请检查或解锁 KDE Wallet 后重试。") from None

    def open(self):
        try:
            import dbus
        except ImportError:
            raise StorageError("无法安全保存密码：系统缺少 dbus-python。") from None
        name = self.call("networkWallet")
        handle = self.call("open", name, dbus.Int64(0), APP_ID)
        if handle < 0:
            raise StorageError("无法安全保存密码，请解锁 KDE Wallet 后重试。")
        return handle

    def read(self):
        handle = self.open()
        if not self.call("hasEntry", handle, self.folder, self.key, APP_ID):
            return None
        try:
            value = json.loads(str(self.call("readPassword", handle, self.folder, self.key, APP_ID)))
            if not isinstance(value, dict) or not all(isinstance(value.get(k), str) for k in ("username", "password")):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise StorageError("无法安全保存密码：已保存凭据无法读取，请重新输入。") from None

    def write(self, username, password):
        handle = self.open()
        if not self.call("hasFolder", handle, self.folder, APP_ID):
            if not self.call("createFolder", handle, self.folder, APP_ID):
                raise StorageError("无法安全保存密码：无法创建钱包条目。")
        value = json.dumps({"username": username, "password": password}, ensure_ascii=False)
        if self.call("writePassword", handle, self.folder, self.key, value, APP_ID) != 0:
            raise StorageError("无法安全保存密码：钱包写入失败。")

    def delete(self):
        name = self.call("networkWallet")
        if self.call("keyDoesNotExist", name, self.folder, self.key):
            return
        handle = self.open()
        if self.call("removeEntry", handle, self.folder, self.key, APP_ID) != 0:
            raise StorageError("无法安全保存密码：已保存密码未能删除，请解锁 KDE Wallet 后重试。")
        if self.call("hasEntry", handle, self.folder, self.key, APP_ID):
            raise StorageError("无法安全保存密码：已保存密码未能删除。")


class Preferences:
    def __init__(self, filename=None, wallet=None):
        self.filename = filename
        self.wallet = wallet or Wallet()

    def settings(self):
        settings = (QSettings(self.filename, QSettings.Format.IniFormat) if self.filename else
                    QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, "inode-modern", "gui"))
        settings.setFallbacksEnabled(False)
        return settings

    def load(self):
        settings = self.settings()
        username = settings.value("username", "", type=str)
        remember = settings.value("remember_password", False, type=bool)
        # Migrate only this GUI's preferences: retain the explicit allowlist.
        # No legacy plaintext password is ever read or imported into memory.
        if settings.allKeys():
            self.save_config(username, remember)
        return SavedLogin(username, "", remember)

    def save_config(self, username, remember):
        settings = self.settings()
        settings.clear()
        settings.setValue("version", 1)
        settings.setValue("username", username)
        settings.setValue("remember_password", remember)
        settings.sync()
        if settings.status() != QSettings.Status.NoError:
            raise StorageError("无法保存账号设置，请检查用户配置目录权限。")

    def restore_secret(self, saved):
        if saved.remember:
            value = self.wallet.read()
            if value and value["username"] == saved.username:
                saved.password = value["password"]
        elif self.settings().contains("remember_password"):
            self.wallet.delete()  # Retry an earlier failed deletion, never prefill it.

    def set_remember(self, remember):
        settings = self.settings()
        self.save_config(settings.value("username", "", type=str), remember)
        if not remember:
            self.wallet.delete()

    def submitted(self, username, password, remember):
        self.save_config(username, remember)
        if remember:
            self.wallet.write(username, password)
        else:
            self.wallet.delete()

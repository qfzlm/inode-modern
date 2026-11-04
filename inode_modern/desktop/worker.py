"""One worker thread owns the unchanged core Client and serializes every command."""

from dataclasses import dataclass, field
import threading
import time

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from ..setup_status import vendor_unconfigured, SETUP_HINT
from ..client import Client, ClientError, PortOccupied, StatusTimeout
from ..protocol import DISCONNECT, Message, ProtocolError, connect_request
from .network import activate_existing_dhcp, wired_interfaces
from .state import SessionState
from .preferences import StorageError


@dataclass(repr=False)
class LoginRequest:
    username: str = field(repr=False)
    password: str = field(repr=False)
    interface: str
    remember: bool = False

    def clear(self):
        self.username = self.password = ""


class Worker(QObject):
    changed = Signal(object)  # Only state/number/interface metadata; no credentials.
    notice = Signal(str)
    command_finished = Signal()
    finished = Signal()
    credentials_restored = Signal(object)

    def __init__(self, client_factory=Client, preferences=None):
        super().__init__()
        self.preferences = preferences
        self.client_factory = client_factory
        self.client = None
        self.model = SessionState()
        self.timer = None
        self.stop_requested = threading.Event()
        self.interfaces = []
        self.interface = "enp5s0"

    def publish(self):
        snapshot = self.model.snapshot(time.monotonic())
        if snapshot["phase"] == "unavailable" and vendor_unconfigured():
            snapshot["detail"] = SETUP_HINT
        snapshot["interfaces"] = [{"name": item.name, "carrier": item.carrier, "ipv4": item.ipv4}
                                  for item in self.interfaces]
        snapshot["interface"] = self.interface
        self.changed.emit(snapshot)

    def _restore_credentials(self, *, remembered_only=False):
        if self.preferences:
            saved = None
            try:
                saved = self.preferences.load()
                if remembered_only and not saved.remember:
                    return
                self.preferences.restore_secret(saved)
            except StorageError as exc:
                self.notice.emit(str(exc))
            if saved is not None:
                self.credentials_restored.emit(saved)

    @Slot()
    def start(self):
        self._restore_credentials()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        self.poll()

    def _async(self, message):
        # Reuse core's validated input and redaction policy. Never forward payloads.
        self.model.observe(message.safe_summary(), time.monotonic())
        self.publish()

    @Slot()
    def poll(self):
        if self.stop_requested.is_set():
            return
        try:
            self.interfaces = wired_interfaces()
            if self.model.phase != "online" and not self.model.operation and self.interfaces:
                if not any(item.name == self.interface for item in self.interfaces):
                    self.interface = self.interfaces[0].name
            if self.client is None:
                self.client = self.client_factory(timeout=1.0, on_event=self._async)
                try:
                    self.client.__enter__()
                except (OSError, ClientError) as exc:
                    self.client = None
                    self.model.unavailable(time.monotonic(), occupied=isinstance(exc, PortOccupied))
                    self.publish()
                    return
            self.model.observe(self.client.status().safe_summary(), time.monotonic())
        except (StatusTimeout, ClientError, OSError):
            self.model.unavailable(time.monotonic())
        self.model.check_deadline(time.monotonic())
        self.publish()

    @Slot(str)
    def select_interface(self, interface):
        if not self.model.operation and self.model.phase != "online":
            if any(item.name == interface for item in self.interfaces):
                self.interface = interface
        self.publish()

    @Slot(object)
    def connect_account(self, request: LoginRequest):
        packet = None
        try:
            if self.stop_requested.is_set():
                return
            if self.client is None:
                self.notice.emit("认证服务尚未就绪，请等待检测完成。")
                return
            # Recheck the live service before sending credentials; stale UI is insufficient.
            self.model.observe(self.client.status().safe_summary(), time.monotonic())
            if not self.model.snapshot(time.monotonic())["can_connect"]:
                self.notice.emit("当前尚未确认已断开，请等待状态更新或先断开。")
                return
            interfaces = wired_interfaces()
            if not any(item.name == request.interface and item.carrier for item in interfaces):
                self.notice.emit("所选有线网卡不可用或网线未连接。")
                return
            packet = connect_request(request.username, request.password, request.interface)
            if self.stop_requested.is_set():
                return
            self.interface = request.interface
            self.client.send(packet)
            self.model.begin("connect", time.monotonic())
            if self.preferences:
                try:
                    self.preferences.submitted(request.username, request.password, request.remember)
                except StorageError as exc:
                    self.notice.emit(str(exc))
        except ProtocolError:
            self.notice.emit("账号、密码或网卡参数无效。请检查完整账号及输入长度。")
        except (ClientError, OSError):
            self.model.unavailable(time.monotonic())
            self.notice.emit("未能提交连接请求，请检查认证服务后重试。")
        finally:
            request.clear()
            packet = None
            self.publish()
            self.command_finished.emit()

    @Slot(bool)
    def remember_changed(self, remember):
        if self.preferences:
            try:
                self.preferences.set_remember(remember)
            except StorageError as exc:
                self.notice.emit(str(exc))

    @Slot()
    def disconnect_account(self):
        try:
            if self.stop_requested.is_set():
                return
            if self.client is None:
                self.notice.emit("尚未取得认证接口，请等待服务恢复。")
                return
            self.client.send(Message(DISCONNECT))
            self.model.begin("disconnect", time.monotonic())
        except (ClientError, OSError):
            self.notice.emit("断开请求发送失败，请稍后重试。")
        finally:
            if not self.stop_requested.is_set():
                self._restore_credentials(remembered_only=True)
            self.publish()
            self.command_finished.emit()

    @Slot()
    def activate_network(self):
        try:
            if self.stop_requested.is_set() or self.model.phase != "online":
                return
            activate_existing_dhcp(self.interface)
            self.notice.emit("已激活已有有线连接，正在更新网络地址。")
        except RuntimeError as exc:
            self.notice.emit(str(exc))  # Helper raises only fixed, credential-free messages.
        except OSError:
            self.notice.emit("有线网卡当前不可用。")
        finally:
            self.poll()
            self.command_finished.emit()

    @Slot()
    def stop(self):
        self.stop_requested.set()
        if self.timer:
            self.timer.stop()
        if self.client:
            self.client.__exit__(None, None, None)
            self.client = None
        self.finished.emit()

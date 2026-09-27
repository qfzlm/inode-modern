"""Native Qt presentation. Authentication behavior lives in the frozen core."""

from pathlib import Path
from .icons import application_icon

from PySide6.QtCore import QEvent, Qt, Signal, Slot, QSize
from PySide6.QtGui import QAction, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
    QProgressBar, QPushButton, QScrollArea, QSizePolicy, QStackedWidget, QToolButton,
    QVBoxLayout, QWidget,
)

from ..protocol import ProtocolError, text_value, username_value
from .visuals import Colors, blend, contrast
from .worker import LoginRequest

TITLES = {"checking": "正在检测", "offline": "尚未连接", "online": "已连接",
          "connecting": "正在认证", "disconnecting": "正在断开", "failed": "操作未完成",
          "unavailable": "服务未响应", "occupied": "认证接口被占用", "unknown": "状态待确认"}


def label(text="", name="", size=0, weight=QFont.Weight.Normal):
    widget = QLabel(text)
    widget.setObjectName(name)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    font = widget.font()
    if size:
        font.setPointSizeF(size * QApplication.font().pointSizeF() / 9)
    font.setWeight(weight)
    widget.setFont(font)
    return widget


class Window(QMainWindow):
    remember_changed = Signal(bool)
    login = Signal(object)
    disconnect_requested = Signal()
    network_requested = Signal()
    refresh_requested = Signal()
    interface_selected = Signal(str)
    close_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName("inodeWindow")
        self.setWindowTitle("iNode Modern")
        control_font = self.font()
        control_font.setPointSizeF(QApplication.font().pointSizeF() * 10 / 9)
        self.setFont(control_font)
        self.setWindowIcon(application_icon())
        self.resize(900, 700)
        self.setMinimumSize(700, 540)
        self.snapshot = {}
        self.pending = False
        self.closing = False
        self._styled_key = None
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.setCentralWidget(scroll)
        central = QWidget()
        central.setObjectName("page")
        scroll.setWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.hero = QFrame()
        self.hero.setObjectName("hero")
        top = QVBoxLayout(self.hero)
        top.setContentsMargins(32, 22, 32, 24)
        top.setSpacing(18)
        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(self.windowIcon().pixmap(QSize(24, 24)))
        header.addWidget(icon)
        header.addSpacing(6)
        header.addWidget(label("iNode Modern", "brand", 12, QFont.Weight.DemiBold))
        header.addStretch()
        self.refresh = QToolButton()
        self.refresh.setText("刷新状态")
        self.refresh.setToolTip("重新检测认证服务")
        self.refresh.setAccessibleName("重新检测认证服务")
        self.refresh.clicked.connect(self.refresh_requested)
        header.addWidget(self.refresh)
        top.addLayout(header)
        self.status_title = label("正在检测", "statusTitle", 30, QFont.Weight.DemiBold)
        self.status_title.setWordWrap(True)
        top.addWidget(self.status_title)
        self.description = label("正在检查认证服务…", "statusDescription", 11)
        self.description.setWordWrap(True)
        top.addWidget(self.description)
        layout.addWidget(self.hero)

        evidence = QFrame()
        evidence.setObjectName("evidence")
        facts = QHBoxLayout(evidence)
        facts.setContentsMargins(32, 14, 32, 14)
        facts.setSpacing(24)
        self.facts = []
        for title in ("网线", "校园网认证", "网络地址状态"):
            column = QVBoxLayout()
            column.setSpacing(3)
            column.addWidget(label(title, "muted", 9))
            value = label("检测中", "factValue", 11, QFont.Weight.DemiBold)
            value.setWordWrap(True)
            column.addWidget(value)
            facts.addLayout(column, 1)
            self.facts.append(value)
        layout.addWidget(evidence)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("正在等待认证服务响应")
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(3)
        layout.addWidget(self.progress)

        body = QHBoxLayout()
        body.setContentsMargins(32, 26, 32, 24)
        body.setSpacing(32)
        right = QVBoxLayout()
        right.setSpacing(12)
        self.context_title = label("检查连接状态", "contextTitle", 17, QFont.Weight.DemiBold)
        right.addWidget(self.context_title)
        self.pages = QStackedWidget()
        self.pages.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self.signin_page = QWidget()
        form = QVBoxLayout(self.signin_page)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.username = QLineEdit()
        self.username.setObjectName("usernameInput")
        self.username.setAccessibleName("校园网账号")
        self.username.setPlaceholderText("学生账号@ct")
        self.username.setMaxLength(253)
        self.username.setMinimumHeight(42)
        self.username.setClearButtonEnabled(True)
        self.username.setInputMethodHints(Qt.InputMethodHint.ImhNoPredictiveText | Qt.InputMethodHint.ImhNoAutoUppercase)
        account_label = label("校园网账号", "fieldLabel", 10, QFont.Weight.Medium)
        account_label.setBuddy(self.username)
        form.addWidget(account_label)
        form.addWidget(self.username)
        form.addWidget(label("请输入完整账号，保留运营商后缀。", "muted", 9))
        form.addSpacing(8)
        self.password = QLineEdit()
        self.password.setObjectName("passwordInput")
        self.password.setAccessibleName("密码")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setInputMethodHints(Qt.InputMethodHint.ImhHiddenText | Qt.InputMethodHint.ImhSensitiveData
                                         | Qt.InputMethodHint.ImhNoPredictiveText | Qt.InputMethodHint.ImhNoAutoUppercase)
        self.password.setMaxLength(253)
        self.password.setPlaceholderText("输入密码")
        self.password.setMinimumHeight(42)
        password_label = label("密码", "fieldLabel", 10, QFont.Weight.Medium)
        password_label.setBuddy(self.password)
        form.addWidget(password_label)
        form.addWidget(self.password)
        form.addStretch()
        self.password.returnPressed.connect(self.connect_account)
        self.username.returnPressed.connect(self.password.setFocus)
        self.pages.addWidget(self.signin_page)

        self.waiting_page = QWidget()
        waiting = QVBoxLayout(self.waiting_page)
        waiting.setContentsMargins(0, 6, 0, 0)
        waiting.setSpacing(12)
        self.wait_title = label("等待服务响应", "fieldLabel", 12, QFont.Weight.Medium)
        self.wait_title.setWordWrap(True)
        waiting.addWidget(self.wait_title)
        self.wait_hint = label("状态更新后会自动显示结果。", "muted", 11)
        self.wait_hint.setWordWrap(True)
        waiting.addWidget(self.wait_hint)
        waiting.addStretch()
        self.pages.addWidget(self.waiting_page)

        self.connected_page = QWidget()
        summary = QVBoxLayout(self.connected_page)
        summary.setContentsMargins(0, 6, 0, 0)
        summary.setSpacing(12)
        self.network_hint = label("", "fieldLabel", 12, QFont.Weight.Medium)
        self.network_hint.setWordWrap(True)
        summary.addWidget(self.network_hint)
        online_hint = label("认证与网络地址分别显示在上方。实际联网情况请以使用结果为准。", "muted", 10)
        online_hint.setWordWrap(True)
        summary.addWidget(online_hint)
        self.network_button = QPushButton("获取网络地址")
        self.network_button.setProperty("primary", True)
        self.network_button.setMinimumHeight(44)
        self.network_button.setToolTip("激活系统中已有的有线 DHCP 连接")
        self.network_button.clicked.connect(self.get_network)
        summary.addWidget(self.network_button)
        summary.addStretch()
        self.pages.addWidget(self.connected_page)

        self.failure_page = QWidget()
        recovery = QVBoxLayout(self.failure_page)
        recovery.setContentsMargins(0, 6, 0, 0)
        recovery.setSpacing(12)
        self.recovery_title = label("下一步", "fieldLabel", 12, QFont.Weight.Medium)
        self.recovery_hint = label("请先断开，再检查账号与网线。", "muted", 11)
        self.recovery_hint.setWordWrap(True)
        recovery.addWidget(self.recovery_title)
        recovery.addWidget(self.recovery_hint)
        recovery.addStretch()
        self.pages.addWidget(self.failure_page)
        right.addWidget(self.pages, 1)
        self.notice = label("", "notice", 10)
        self.notice.setWordWrap(True)
        self.notice.hide()
        right.addWidget(self.notice)
        self.connect_button = QPushButton("连接校园网")
        self.connect_button.setObjectName("connectButton")
        self.connect_button.setProperty("primary", True)
        self.connect_button.setMinimumHeight(46)
        self.connect_button.setDefault(True)
        self.connect_button.clicked.connect(self.connect_account)
        self.disconnect_button = QPushButton("断开连接")
        self.disconnect_button.setObjectName("disconnectButton")
        self.disconnect_button.setMinimumHeight(46)
        self.disconnect_button.clicked.connect(self.disconnect_account)
        right.addWidget(self.connect_button)
        right.addWidget(self.disconnect_button)
        body.addLayout(right, 3)
        separator = QFrame()
        separator.setObjectName("divider")
        separator.setFixedWidth(1)
        body.addWidget(separator)

        settings = QVBoxLayout()
        settings.setSpacing(10)
        settings.addWidget(label("连接设置", "settingsTitle", 12, QFont.Weight.DemiBold))
        self.interface = QComboBox()
        self.interface.setObjectName("interfaceSelect")
        self.interface.setAccessibleName("有线网卡")
        self.interface.setMinimumHeight(38)
        self.interface.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.interface.setMinimumContentsLength(12)
        self.interface.currentIndexChanged.connect(self.select_interface)
        device_label = label("有线网卡", "muted", 9)
        device_label.setBuddy(self.interface)
        settings.addWidget(device_label)
        settings.addWidget(self.interface)
        self.link_badge = label("检测中", "muted", 9)
        self.link_badge.setWordWrap(True)
        settings.addWidget(self.link_badge)
        settings.addSpacing(16)
        self.remember = QCheckBox("记住密码")
        self.remember.setToolTip("使用 KDE Wallet 安全保存密码；取消勾选会删除已保存密码。")
        self.remember.toggled.connect(self.remember_changed)
        settings.addWidget(self.remember)
        wallet_hint = label("由系统钱包安全保存。\n取消勾选即可删除已保存密码。", "muted", 9)
        wallet_hint.setWordWrap(True)
        settings.addWidget(wallet_hint)
        settings.addStretch()
        body.addLayout(settings, 2)
        layout.addLayout(body, 1)
        footer = label("关闭窗口后，当前认证仍会保留。", "footer", 9)
        footer.setWordWrap(True)
        layout.addWidget(footer)
        action = QAction(self)
        action.setShortcut(QKeySequence.StandardKey.Quit)
        action.triggered.connect(self.close)
        self.addAction(action)
        controls = (self.username, self.password, self.connect_button, self.disconnect_button,
                    self.network_button, self.interface, self.remember, self.refresh)
        for first, second in zip(controls, controls[1:]):
            self.setTabOrder(first, second)
        self.render()

    @Slot(object)
    def update_state(self, snapshot):
        self.snapshot = snapshot
        interfaces = snapshot.get("interfaces", [])
        self.interface.blockSignals(True)
        desired = [(item["name"], item["name"]) for item in interfaces]
        current = [(self.interface.itemText(i), self.interface.itemData(i)) for i in range(self.interface.count())]
        if desired != current:
            self.interface.clear()
            for text, name in desired:
                self.interface.addItem(text, name)
        index = self.interface.findData(snapshot.get("interface", "enp5s0"))
        self.interface.setCurrentIndex(max(0, index) if interfaces else -1)
        self.interface.blockSignals(False)
        self.render()

    def apply_theme(self, phase):
        palette = QApplication.palette()
        c = Colors.from_palette(palette)
        key = (palette.cacheKey(), phase)
        if key == self._styled_key:
            return
        self._styled_key = key
        css = lambda color: color.name()
        accent_text = max((c.text, c.surface), key=lambda color: contrast(color, c.accent)).name()
        check_icon = Path(__file__).with_name("check.svg").as_posix()
        self.setStyleSheet(f"""
            QWidget#page {{ background: {css(c.surface)}; color: {css(c.text)}; }}
            QLabel, QCheckBox {{ background: transparent; color: {css(c.text)}; }}
            QLabel#muted {{ color: {css(c.muted)}; }}
            QFrame#hero {{ background: {css(c.header)}; }}
            QFrame#hero QLabel {{ color: #f1f6f3; }}
            QFrame#hero QLabel#statusTitle {{ color: {css(c.header_ink(phase))}; }}
            QFrame#hero QLabel#statusDescription {{ color: #c3d6cf; }}
            QFrame#evidence {{ background: {css(c.background)}; border-bottom: 1px solid {css(c.line)}; }}
            QFrame#divider {{ background: {css(c.line)}; }}
            QLabel#footer {{ color: {css(c.muted)}; background: {css(c.background)}; padding: 12px 32px; }}
            QLineEdit, QComboBox {{ color: {css(c.text)}; background: {css(c.surface)};
                border: 1px solid {css(c.line)}; border-radius: 6px; padding: 8px 10px;
                selection-background-color: {css(c.accent)}; selection-color: {accent_text}; }}
            QLineEdit {{ placeholder-text-color: {css(c.muted)}; }}
            QLineEdit:focus, QComboBox:focus {{ border: 2px solid {css(c.accent)}; padding: 7px 9px; }}
            QLineEdit:disabled, QComboBox:disabled {{ background: {css(c.background)}; color: {css(c.muted)}; }}
            QComboBox QAbstractItemView {{ background: {css(c.surface)}; color: {css(c.text)};
                selection-background-color: {css(c.accent)}; selection-color: {accent_text}; }}
            QPushButton {{ color: {css(c.text)}; background: {css(c.surface)}; border: 1px solid {css(c.line)};
                border-radius: 6px; padding: 9px 14px; font-weight: 600; }}
            QPushButton:hover {{ background: {css(blend(c.surface, c.accent, .09))}; border-color: {css(c.accent)}; }}
            QPushButton:pressed {{ background: {css(blend(c.surface, c.accent, .18))}; }}
            QPushButton:focus {{ border: 2px solid {css(c.accent)}; padding: 8px 13px; }}
            QPushButton[primary="true"] {{ background: {css(c.accent)}; color: {accent_text}; border-color: {css(c.accent)}; }}
            QPushButton[primary="true"]:hover {{ background: {css(blend(c.accent, c.text, .08))}; }}
            QPushButton[primary="true"]:pressed {{ background: {css(blend(c.accent, c.text, .16))}; }}
            QPushButton[primary="true"]:focus {{ border-color: {css(c.text)}; }}
            QPushButton:disabled {{ background: {css(c.background)}; color: {css(c.muted)}; border-color: {css(c.line)}; }}
            QToolButton {{ color: #d7e8e1; border: 1px solid #667f75; border-radius: 5px; padding: 7px 12px; }}
            QToolButton:hover {{ background: #304f43; }}
            QToolButton:pressed {{ background: #3b6052; }}
            QToolButton:focus {{ border: 2px solid #b2e3cc; padding: 6px 11px; }}
            QToolButton:disabled {{ color: #a0b7ad; border-color: #526b60; }}
            QCheckBox {{ spacing: 8px; padding: 3px; }}
            QCheckBox:focus {{ outline: 1px solid {css(c.accent)}; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {css(c.muted)};
                border-radius: 3px; background: {css(c.surface)}; }}
            QCheckBox::indicator:checked {{ background: #24684d; border-color: #24684d; image: url("{check_icon}"); }}
            QCheckBox::indicator:hover {{ border: 2px solid {css(c.accent)}; }}
            QCheckBox:disabled {{ color: {css(c.muted)}; }}
            QLabel#notice {{ color: {css(c.text)}; background: {css(blend(c.surface, c.warning, .12))};
                border: 1px solid {css(c.warning)}; border-radius: 6px; padding: 10px; }}
            QProgressBar {{ background: {css(c.background)}; border: none; }}
            QProgressBar::chunk {{ background: {css(c.accent)}; }}
        """)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.ApplicationPaletteChange and hasattr(self, "status_title"):
            self._styled_key = None
            self.apply_theme(self.snapshot.get("phase", "checking"))

    def render(self):
        state = self.snapshot
        phase = state.get("phase", "checking")
        self.apply_theme(phase)
        self.status_title.setText("正在关闭" if self.closing else TITLES.get(phase, "状态待确认"))
        self.description.setText("正在释放认证接口，当前认证不会被断开。" if self.closing else state.get("detail", "正在检查认证服务…"))
        self.progress.setVisible(self.pending or self.closing or phase in ("checking", "connecting", "disconnecting"))
        interface = next((item for item in state.get("interfaces", []) if item["name"] == self.interface.currentData()), None)
        self.link_badge.setText("未发现网卡" if not interface else "网线已接入" if interface["carrier"] else "网线未连接")
        if phase == "offline":
            self.link_badge.setText("请接入有线网卡，再刷新状态。" if not interface else
                                    "请插好网线，再连接校园网。" if not interface["carrier"] else "网线已接入")
            if not self.closing and (not interface or not interface["carrier"]):
                self.description.setText(self.link_badge.text())
        self.facts[0].setText("未发现网卡" if not interface else "已接入" if interface["carrier"] else "未接入")
        self.facts[1].setText("已通过" if phase == "online" else TITLES.get(phase, "待确认"))
        self.facts[2].setText("已获取" if interface and interface["ipv4"] else "尚未获取" if interface else "待检测")
        self.interface.setToolTip(str(state.get("interface", "")))

        self.network_hint.setText("未发现有线网卡。请连接有线网卡后重新检测。" if not interface else
                                  ("网络地址已就绪。" if interface["ipv4"] else
                                   "认证已通过，尚未获得网络地址。" if phase == "online" else
                                   "网线已连接，等待认证。" if interface["carrier"] else "请检查网线是否插好。"))
        if phase == "offline" and not self.closing:
            self.context_title.setText("登录校园网")
            self.pages.setCurrentWidget(self.signin_page)
        elif phase == "online" and not self.closing:
            self.context_title.setText("当前连接")
            self.pages.setCurrentWidget(self.connected_page)
        elif phase in ("checking", "connecting", "disconnecting") or self.closing:
            self.context_title.setText("连接正在建立" if phase == "connecting" else "正在处理连接" if phase == "disconnecting" or self.closing else "检查连接状态")
            self.wait_title.setText("连接请求已提交" if phase == "connecting" else "等待服务响应")
            self.wait_hint.setText("认证结果会自动更新，无需重复提交。" if phase == "connecting" else "状态更新后会自动显示结果。")
            self.pages.setCurrentWidget(self.waiting_page)
        else:
            self.context_title.setText("检查后再继续")
            self.recovery_title.setText("下一步")
            self.recovery_hint.setText("请先关闭其他认证前端，应用会继续检测。" if phase == "occupied" else
                                       "请检查后台服务安装或运行状态。应用会继续检测，也可点击右上角刷新。" if phase == "unavailable" else
                                       "先断开当前认证，再重新连接。")
            self.pages.setCurrentWidget(self.failure_page)
        can_edit = state.get("can_connect", False) and not self.pending and not self.closing
        for control in (self.username, self.password):
            control.setEnabled(can_edit)
        self.interface.setEnabled(can_edit and bool(state.get("interfaces")))
        self.connect_button.setEnabled(can_edit and bool(interface and interface["carrier"]))
        self.disconnect_button.setEnabled(state.get("can_disconnect", False) and not self.pending and not self.closing)
        self.connect_button.setVisible(phase == "offline")
        self.disconnect_button.setVisible(phase in ("online", "connecting", "disconnecting", "failed", "unknown"))
        self.refresh.setEnabled(not self.pending and not self.closing)
        self.network_button.setVisible(phase == "online" and bool(interface) and not interface["ipv4"])
        self.network_button.setEnabled(not self.pending and not self.closing)
        self.remember.setEnabled(not self.pending and not self.closing)

    @Slot()
    def connect_account(self):
        if not self.connect_button.isEnabled():
            return
        try:
            username_value(self.username.text())
            text_value(self.password.text(), "password")
        except ProtocolError:
            self.show_notice("请填写完整账号（含账号主体和运营商后缀）及密码；每项最多 253 个 UTF-8 字节。")
            return
        request = LoginRequest(self.username.text(), self.password.text(), self.interface.currentData(), self.remember.isChecked())
        self.password.clear()
        self.notice.hide()
        self.pending = True
        self.render()
        self.login.emit(request)

    @Slot()
    def disconnect_account(self):
        if self.disconnect_button.isEnabled():
            self.password.clear()
            self.notice.hide()
            self.pending = True
            self.render()
            self.disconnect_requested.emit()

    @Slot()
    def get_network(self):
        if not self.network_button.isEnabled() or self.network_button.isHidden():
            return
        self.pending = True
        self.notice.hide()
        self.render()
        self.network_requested.emit()

    @Slot()
    def command_finished(self):
        self.pending = False
        self.render()

    @Slot(str)
    def show_notice(self, message):
        self.notice.setText(message)
        self.notice.show()

    @Slot(int)
    def select_interface(self, index):
        name = self.interface.itemData(index)
        if name:
            self.interface_selected.emit(name)

    @Slot(object)
    def restore_credentials(self, saved):
        if not self.closing:
            self.username.setText(saved.username)
            self.password.setText(saved.password)
            self.remember.blockSignals(True)
            self.remember.setChecked(saved.remember)
            self.remember.blockSignals(False)
        saved.clear()

    def closeEvent(self, event):
        event.ignore()
        if not self.closing:
            self.closing = True
            self.password.clear()
            self.username.clear()
            self.render()
            self.close_requested.emit()

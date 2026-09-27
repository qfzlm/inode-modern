"""OpenDesign V2 native presentation; existing Window action methods are reused."""
from pathlib import Path
from .icons import application_icon

from PySide6.QtCore import Qt, QEvent
from PySide6.QtGui import QAction, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QBoxLayout, QCheckBox, QComboBox, QFrame, QHBoxLayout,
    QLineEdit, QMainWindow, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QToolButton, QVBoxLayout, QWidget,
)

from .window import Window as ActionWindow, TITLES, label as base_label
from .opendesign_visuals import colors, StatusBanner, StatusEmblem, StepRail, line_icon


def label(*args, **kwargs):
    widget = base_label(*args, **kwargs)
    font = widget.font()
    font.setFamilies(['Noto Sans CJK SC', font.family()])
    widget.setFont(font)
    return widget


class Window(ActionWindow):
    """Different widget tree; inherits validation, signals and request lifecycle."""

    def __init__(self):
        # Do not construct the first design's layout. Its action methods operate
        # on the same native controls and emit the same existing Worker signals.
        QMainWindow.__init__(self)
        self.setObjectName('openDesignWindow')
        self.setWindowTitle('iNode Modern')
        self.setWindowIcon(application_icon())
        self.resize(1100, 800)
        self.setMinimumSize(320, 360)
        self.snapshot = {}
        self.pending = self.closing = False
        self._styled_key = None
        self._compact = None
        self._observed_operation = None
        font = self.font()
        font.setPointSizeF(QApplication.font().pointSizeF() * 10 / 9)
        font.setFamilies(["Noto Sans CJK SC", font.family()])
        self.setFont(font)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.setCentralWidget(scroll)
        page = QWidget()
        page.setObjectName('odPage')
        scroll.setWidget(page)
        root = QVBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.workbench = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.workbench.setSpacing(0)
        root.addLayout(self.workbench, 1)

        self.rail = StepRail()
        self.rail.setObjectName('odRail')
        rail = QVBoxLayout(self.rail)
        rail.setContentsMargins(28, 30, 24, 24)
        rail.setSpacing(34)
        rail.addWidget(label('连接步骤', 'odMuted', 11, QFont.Weight.DemiBold))
        self.evidence_dots = []
        self.evidence_values = []
        for index, title in enumerate(('有线链路', '校园网认证', '网络地址'), 1):
            row = QHBoxLayout()
            row.setSpacing(16)
            dot = label(str(index), 'odEvidenceDot', 12)
            dot.setFixedSize(36, 36)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row.addWidget(dot)
            column = QVBoxLayout()
            column.setSpacing(6)
            heading = label(title, '', 12, QFont.Weight.DemiBold)
            heading.setWordWrap(True)
            value = label('待检测', 'odMuted', 10)
            value.setWordWrap(True)
            column.addWidget(heading)
            column.addWidget(value)
            row.addLayout(column, 1)
            rail.addLayout(row)
            self.evidence_dots.append(dot)
            self.evidence_values.append(value)
        self.rail.dots = self.evidence_dots
        rail.addStretch()
        self.rail_note = label('按实际检测结果更新。\n公网连通尚未验证。', 'odMuted', 9)
        self.rail_note.setWordWrap(True)
        self.rail_note.hide()
        self.workbench.addWidget(self.rail)

        self.main_area = QFrame()
        self.main_area.setObjectName('odMain')
        self.main_layout = QVBoxLayout(self.main_area)
        body = self.main_layout
        body.setContentsMargins(28, 24, 28, 22)
        body.setSpacing(0)
        self.link_badge = label('检测中', 'odMuted', 9)
        self.link_badge.hide()
        self.banner = StatusBanner()
        self.banner.setObjectName('odBanner')
        banner_layout = QHBoxLayout(self.banner)
        banner_layout.setContentsMargins(24, 28, 24, 28)
        banner_layout.setSpacing(22)
        self.banner.setMinimumHeight(184)
        self.status_dot = StatusEmblem()
        banner_layout.addWidget(self.status_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        heading = QVBoxLayout()
        heading.setSpacing(10)
        self.status_title = label('正在检测', 'odStatusTitle', 30, QFont.Weight.Bold)
        self.status_title.setWordWrap(True)
        heading.addWidget(self.status_title)
        self.description = label('', 'odMuted', 12)
        self.description.setWordWrap(True)
        heading.addWidget(self.description)
        banner_layout.addLayout(heading, 1)
        body.addWidget(self.banner)
        body.addSpacing(16)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(3)
        self.progress.setAccessibleName('正在等待认证服务响应')
        body.addWidget(self.progress)
        body.addSpacing(12)

        self.summary = QFrame()
        self.summary.setObjectName("odInfoCard")
        summary_layout = QVBoxLayout(self.summary)
        summary_layout.setContentsMargins(24, 22, 24, 20)
        summary_layout.setSpacing(0)
        self.stage_title = label('', 'odStageTitle', 14, QFont.Weight.DemiBold)
        self.stage_detail = label('', 'odMuted', 10)
        self.connection_details = label('', '', 11)
        info_heading = label('连接信息', '', 15, QFont.Weight.DemiBold)
        summary_layout.addWidget(info_heading)
        summary_layout.addSpacing(16)
        self.info_values = []
        self.info_icons = []
        self.info_rows = []
        for index, (caption, symbol) in enumerate((('有线网卡', 'ethernet'), ('IPv4 地址', 'pin'),
                                                    ('认证状态', 'shield'), ('公网连接', 'globe'))):
            row = QHBoxLayout()
            row.setContentsMargins(0, 22, 0, 22)
            row.setSpacing(16)
            icon = label('', '', 10)
            icon.setFixedSize(26, 26)
            self.info_icons.append((icon, symbol))
            row.addWidget(icon)
            key = label(caption, 'odMuted', 12)
            key.setMinimumWidth(112)
            row.addWidget(key)
            value = label('', '', 12)
            value.setWordWrap(True)
            value.setMinimumWidth(0)
            row.addWidget(value, 1)
            self.info_values.append(value)
            self.info_rows.append((row, key, icon))
            summary_layout.addLayout(row)
            if index < 3:
                summary_layout.addWidget(self.rule())
        for item in (self.stage_title, self.stage_detail):
            item.setWordWrap(True)
            summary_layout.addWidget(item)
        # Kept as a text aggregate for accessibility and the existing GUI contract.
        self.connection_details.hide()
        body.addWidget(self.summary)
        body.addSpacing(16)

        self.form = QWidget()
        self.form_layout = QVBoxLayout(self.form)
        self.form_layout.setContentsMargins(0, 0, 0, 0)
        self.form_layout.setSpacing(0)
        body.addWidget(self.form)
        body = self.form_layout
        self.interface = QComboBox()
        self.interface.setObjectName('odInterface')
        self.interface.setAccessibleName('有线网卡')
        self.interface.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.interface.setMinimumContentsLength(10)
        self.interface.currentIndexChanged.connect(self.select_interface)
        self.add_field('有线网卡', self.interface)
        body.addSpacing(14)
        self.username = QLineEdit()
        self.username.setObjectName('odUsername')
        self.username.setAccessibleName('校园网账号')
        self.username.setPlaceholderText('完整账号，保留运营商后缀')
        self.username.setClearButtonEnabled(True)
        self.username.setMaxLength(253)
        self.username.setInputMethodHints(Qt.InputMethodHint.ImhNoPredictiveText | Qt.InputMethodHint.ImhNoAutoUppercase)
        self.add_field('校园网账号', self.username)
        hint = label('按原样提交账号，保留运营商后缀。', 'odMuted', 9)
        hint.setWordWrap(True)
        body.addSpacing(5)
        body.addWidget(hint)
        body.addSpacing(14)
        self.password = QLineEdit()
        self.password.setObjectName('odPassword')
        self.password.setAccessibleName('密码')
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setMaxLength(253)
        self.password.setPlaceholderText('输入校园网密码')
        self.password.setInputMethodHints(Qt.InputMethodHint.ImhHiddenText | Qt.InputMethodHint.ImhSensitiveData
                                         | Qt.InputMethodHint.ImhNoPredictiveText | Qt.InputMethodHint.ImhNoAutoUppercase)
        self.add_field('密码', self.password)
        self.username.returnPressed.connect(self.password.setFocus)
        self.password.returnPressed.connect(self.connect_account)
        body.addSpacing(14)
        body = self.main_layout
        self.security_toggle = QToolButton()
        self.security_toggle.setText('密码保存设置')
        self.security_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.security_toggle.setCheckable(True)
        self.security_toggle.setAccessibleName('展开或收起密码保存设置')
        self.security_toggle.toggled.connect(lambda _: self.render())
        self.remember = QCheckBox('记住密码')
        self.remember.setToolTip('使用 KDE Wallet 安全保存密码；取消勾选会删除已保存密码。')
        self.remember.toggled.connect(self.remember_changed)
        body.addWidget(self.remember)
        wallet = self.wallet_hint = label('由系统钱包安全保存；取消勾选可删除已保存密码。', 'odMuted', 9)
        wallet.setWordWrap(True)
        body.addWidget(wallet)
        body.addStretch()
        self.network_hint = label('', 'odMuted', 9)
        self.network_hint.setWordWrap(True)
        body.addSpacing(12)
        body.addWidget(self.network_hint)
        self.notice = label('', 'odNotice', 10)
        self.notice.setWordWrap(True)
        self.notice.hide()
        body.addWidget(self.notice)
        body.addSpacing(16)
        body.addWidget(self.rule())
        body.addSpacing(16)

        self.actions = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.actions.setSpacing(16)
        self.refresh = QToolButton()
        self.refresh.setText('刷新状态')
        self.refresh.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.refresh.setAccessibleName('重新检测认证服务')
        self.refresh.clicked.connect(self.refresh_requested)
        self.connect_button = QPushButton('连接校园网')
        self.connect_button.setProperty('primary', True)
        self.connect_button.setDefault(True)
        self.connect_button.clicked.connect(self.connect_account)
        self.disconnect_button = QPushButton('断开连接')
        self.disconnect_button.setProperty('destructive', True)
        self.disconnect_button.clicked.connect(self.disconnect_account)
        self.network_button = QPushButton('获取网络地址')
        self.network_button.setProperty('primary', True)
        self.network_button.setToolTip('激活系统中已有的有线 DHCP 连接')
        self.network_button.clicked.connect(self.get_network)
        self.actions.addWidget(self.security_toggle)
        self.actions.addStretch()
        self.actions.addWidget(self.refresh)
        for button in (self.disconnect_button, self.connect_button, self.network_button):
            self.actions.addWidget(button)
        body.addLayout(self.actions)
        self.workbench.addWidget(self.main_area, 1)
        footer = label('关闭窗口不影响当前认证', 'odFooter', 9)
        footer.setWordWrap(True)
        footer.hide()
        action = QAction(self)
        action.setShortcut(QKeySequence.StandardKey.Quit)
        action.triggered.connect(self.close)
        self.addAction(action)
        controls = (self.interface, self.username, self.password, self.remember, self.security_toggle,
                    self.refresh, self.disconnect_button, self.connect_button, self.network_button)
        for first, second in zip(controls, controls[1:]):
            self.setTabOrder(first, second)
        # Same facts as V1, exposed independently for the common test contract.
        self.facts = [self.link_badge, self.evidence_values[1], self.evidence_values[2]]
        self.reflow()
        self.render()
        QApplication.instance().paletteChanged.connect(self.refresh_palette)

    def update_state(self, snapshot):
        # Presentation provenance only. Never infer protocol substeps or causes.
        phase = snapshot.get('phase')
        operation = snapshot.get('operation')
        if phase in ('connecting', 'disconnecting'):
            self._observed_operation = 'connect' if phase == 'connecting' else 'disconnect'
        elif operation in ('connect', 'disconnect'):
            self._observed_operation = operation
        elif phase != 'failed':
            self._observed_operation = None
        super().update_state(snapshot)

    @staticmethod
    def rule():
        rule = QFrame()
        rule.setObjectName('odRule')
        rule.setFixedHeight(1)
        return rule

    def add_field(self, text, control):
        title = label(text, '', 10, QFont.Weight.Medium)
        title.setBuddy(control)
        control.setMinimumHeight(42)
        control.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.form_layout.addWidget(title)
        self.form_layout.addSpacing(6)
        self.form_layout.addWidget(control)

    def reflow(self):
        # A font-relative breakpoint also handles enlarged system fonts.
        compact = self.width() < max(600, self.fontMetrics().horizontalAdvance('M') * 45)
        if compact == self._compact:
            return
        self._compact = compact
        self.workbench.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight)
        self.actions.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight)
        self.rail.setMinimumWidth(0 if compact else 245)
        self.rail.setMaximumWidth(16777215 if compact else 245)
        self.rail_note.hide()
        self.status_dot.setVisible(not compact)
        for row, key, icon in self.info_rows:
            row.setDirection(QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight)
            key.setMinimumWidth(0 if compact else 112)
            icon.setVisible(not compact)
        self.main_layout.setContentsMargins(20 if compact else 28, 24, 20 if compact else 28, 22)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'workbench'):
            self.reflow()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (QEvent.Type.FontChange, QEvent.Type.ApplicationFontChange) and hasattr(self, 'workbench'):
            self.reflow()

    def refresh_palette(self, palette):
        self._styled_key = None
        self.apply_theme(self.snapshot.get("phase", "checking"))

    def apply_theme(self, phase):
        palette = QApplication.palette()
        no_ip = self.snapshot.get('phase') == 'online' and not any(
            item.get('ipv4') for item in self.snapshot.get('interfaces', [])
            if item['name'] == self.interface.currentData())
        key = (palette.cacheKey(), phase, no_ip)
        if key == self._styled_key:
            return
        self._styled_key = key
        c = colors(palette)
        tone = c['error'] if phase == 'failed' else c['warn'] if phase in ('unknown','unavailable','occupied') or no_ip else c['good'] if phase == 'online' else c['muted']
        self.rail.line_color = c['ring']
        self.rail.update()
        self.banner.set_tone(c, phase)
        self.status_dot.set_tone(c, phase)
        for icon, symbol in self.info_icons:
            icon.setPixmap(line_icon(symbol, c['muted'] if symbol == 'globe' else c['good']).pixmap(26, 26))
        for button, symbol in ((self.security_toggle, 'settings'), (self.refresh, 'refresh'), (self.disconnect_button, 'disconnect')):
            button.setIcon(line_icon(symbol, '#ffffff' if symbol == 'disconnect' else c['fg']))
        check_icon = Path(__file__).with_name('check-opendesign-dark.svg' if palette.color(palette.ColorRole.Window).lightnessF() < 0.5 else 'check.svg').as_posix()
        self.setStyleSheet(f'''
            QWidget#odPage, QFrame#odMain {{ background: {c['surface']}; color: {c['fg']}; }}
            QLabel, QCheckBox {{ background: transparent; color: {c['fg']}; }}
            QLabel#odMuted {{ color: {c['muted']}; }}
            QFrame#odRail {{ background: {c['rail']}; border-right: 1px solid {c['border']}; }}
            QFrame#odInfoCard {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 14px; }}
            QFrame#odRule {{ background: {c['border']}; }}
            QLabel#odStatusDot {{ color: {tone}; }}
            QLabel#odEvidenceDot {{ border: 1px solid {c['control_border']}; border-radius: 18px; color: {c['muted']}; }}
            QLabel#odEvidenceDot[stage="done"] {{ background: {c['primary']}; color: {c['on_primary']}; border-color: {c['primary']}; }}
            QLabel#odEvidenceDot[stage="active"] {{ border: 2px solid {c['primary']}; color: {c['primary']}; }}
            QLabel#odEvidenceDot[stage="failed"] {{ background: {c['error_bg']}; color: {c['error']}; border-color: {c['error']}; }}
            QLabel#odEvidenceDot[stage="uncertain"] {{ background: {c['warn_bg']}; color: {c['warn']}; border-color: {c['warn']}; }}
            QLabel#odFooter {{ background: {c['bg']}; color: {c['muted']}; padding: 12px 20px; border-top: 1px solid {c['border']}; }}
            QLineEdit, QComboBox {{ background: {c['surface']}; color: {c['fg']}; border: 1px solid {c['control_border']}; border-radius: 9px; padding: 8px 12px; selection-background-color: {c['primary']}; selection-color: {c['on_primary']}; }}
            QLineEdit {{ placeholder-text-color: {c['muted']}; }}
            QLineEdit:focus, QComboBox:focus {{ border: 2px solid {c['focus']}; padding: 7px 11px; }}
            QLineEdit:disabled, QComboBox:disabled {{ color: {c['muted']}; background: {c['rail']}; }}
            QComboBox QAbstractItemView {{ background: {c['surface']}; color: {c['fg']}; selection-background-color: {c['primary']}; selection-color: {c['on_primary']}; }}
            QPushButton, QToolButton {{ color: {c['fg']}; background: {c['surface']}; border: 1px solid {c['control_border']}; border-radius: 9px; padding: 14px 20px; font-weight: 600; }}
            QPushButton:hover, QToolButton:hover {{ background: {c['hover']}; }}
            QPushButton:focus, QToolButton:focus {{ border: 2px solid {c['focus']}; padding: 13px 19px; }}
            QPushButton[primary="true"] {{ background: {c['primary']}; color: {c['on_primary']}; border-color: {c['primary']}; }}
            QPushButton[primary="true"]:hover {{ background: {c['primary_hover']}; }}
            QPushButton[primary="true"]:focus {{ border-color: {c['fg']}; }}
            QPushButton:pressed, QToolButton:pressed {{ border: 2px solid {c['fg']}; padding: 13px 19px; }}
            QPushButton[destructive="true"] {{ background: {c['danger']}; color: #ffffff; border-color: {c['danger']}; }}
            QPushButton[destructive="true"]:hover {{ background: {c['danger_hover']}; }}
            QPushButton[destructive="true"]:focus {{ border: 2px solid {c['fg']}; }}
            QPushButton:disabled, QToolButton:disabled {{ background: {c['rail']}; color: {c['muted']}; border-color: {c['border']}; }}
            QCheckBox {{ spacing: 10px; padding: 6px 0; }}
            QCheckBox:focus {{ border: 1px solid {c['focus']}; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {c['control_border']}; border-radius: 3px; background: {c['surface']}; }}
            QCheckBox::indicator:checked {{ background: {c['primary']}; border-color: {c['primary']}; image: url("{check_icon}"); }}
            QCheckBox:disabled {{ color: {c['muted']}; }}
            QLabel#odNotice {{ color: {c['fg']}; background: {c['rail']}; border: 1px solid {c['control_border']}; padding: 10px; border-radius: 9px; }}
            QProgressBar {{ background: {c['rail']}; border: none; }}
            QProgressBar::chunk {{ background: {c['primary']}; }}
        ''')

    def render(self):
        state = self.snapshot
        phase = state.get('phase', 'checking')
        interface = next((item for item in state.get('interfaces', [])
                          if item['name'] == self.interface.currentData()), None)
        self.apply_theme(phase)
        title = '准备连接' if phase == 'offline' else TITLES.get(phase, '状态待确认')
        self.status_title.setText('正在关闭' if self.closing else title)
        self.description.setText('正在释放认证接口，当前认证不会被断开。' if self.closing else state.get('detail', '正在检查认证服务…'))
        self.link_badge.setText('未发现网卡' if not interface else '网线已接入' if interface['carrier'] else '网线未连接')
        if phase == 'offline' and not self.closing and (not interface or not interface['carrier']):
            self.description.setText('请接入有线网卡，再刷新状态。' if not interface else '请插好网线，再连接校园网。')
        carrier = bool(interface and interface['carrier'])
        address = interface.get('ipv4', '') if interface else ''
        authenticating = phase == 'connecting'
        auth_failed = phase == 'failed' and self._observed_operation == 'connect'
        auth_text = ('已通过' if phase == 'online' else '正在等待结果' if authenticating
                     else '未确认成功' if auth_failed else '尚未开始' if phase == 'offline'
                     else '正在断开' if phase == 'disconnecting' else '待确认')
        values = ('网线已接入' if carrier else '网线未连接' if interface else '未发现网卡',
                  auth_text, '已获取' if address else '等待获取' if phase == 'online' else '尚未获取')
        tones = ('done' if carrier else 'waiting',
                 'done' if phase == 'online' else 'active' if authenticating else 'failed' if auth_failed
                 else 'uncertain' if phase in ('unknown', 'failed', 'unavailable', 'occupied') else 'waiting',
                 'done' if address else 'waiting')
        for dot, value, text, tone in zip(self.evidence_dots, self.evidence_values, values, tones):
            value.setText(text)
            dot.setProperty('stage', tone)
            dot.setAccessibleName(text)
            dot.style().unpolish(dot)
            dot.style().polish(dot)
        self.form.setVisible(phase == 'offline' and not self.closing)
        self.summary.setVisible(phase != 'offline' or self.closing)
        show_security = phase == 'offline' or self.security_toggle.isChecked()
        self.security_toggle.setVisible(phase != 'offline')
        self.remember.setVisible(show_security)
        self.wallet_hint.setVisible(show_security)
        if phase == 'online':
            stage_title = '当前连接' if address else '下一步：获取网络地址'
            stage_detail = ('已取得 IPv4 地址。公网连通尚未验证。' if address else
                            '校园网认证已通过；获取网络地址后才能继续使用网络。')
        elif authenticating:
            stage_title = '第 2 阶段 · 校园网认证'
            stage_detail = '连接请求已提交，正在等待认证结果。收到结果后会更新此处。'
        elif phase == 'failed':
            stage_title = ('认证阶段 · 未确认成功' if auth_failed else
                           '断开阶段 · 未确认完成' if self._observed_operation == 'disconnect' else
                           '失败阶段待确认')
            stage_detail = '可先断开，确认回到未连接状态后，再检查账号和网线并重试。'
        elif phase == 'unknown':
            stage_title = '尚不能确认连接状态'
            stage_detail = '当前结果不足以判断是否已连接。先刷新状态；仍无法确认时，可尝试断开。'
        elif phase == 'disconnecting':
            stage_title = '正在等待断开确认'
            stage_detail = '收到服务确认后，将返回账号输入界面。'
        else:
            stage_title = '等待认证服务就绪'
            stage_detail = '服务状态确认后，将显示可用操作。'
        if self.closing:
            stage_title, stage_detail = '正在关闭窗口', '当前认证会保持。'
        self.info_values[0].setText(str(interface['name']) if interface else '未发现')
        self.info_values[1].setText(str(address) if address else '尚未获取')
        self.info_values[2].setText('校园网认证已通过' if phase == 'online' else auth_text)
        self.info_values[3].setText('已取得 IPv4 地址，公网连通尚未验证。' if address else '公网连通尚未验证。')
        self.stage_title.setVisible(phase != 'online')
        self.stage_detail.setVisible(phase != 'online')
        self.stage_title.setText(stage_title)
        self.stage_detail.setText(stage_detail)
        self.connection_details.setText('有线网卡  ' + (str(interface['name']) if interface else '未发现')
                                        + '\nIPv4 地址  ' + (str(address) if address else '尚未获取'))
        self.interface.setToolTip(str(state.get('interface', '')))
        self.progress.setVisible(self.pending or self.closing or phase in ('checking','connecting','disconnecting'))
        hint = ''
        if phase == 'online' and interface and not interface['ipv4']:
            hint = '获取网络地址会激活系统中已有的 DHCP 连接。'
        elif phase in ('failed','unknown'):
            hint = ''
        elif phase == 'occupied':
            hint = '请先关闭其他认证前端，应用会继续检测。'
        elif phase == 'unavailable':
            hint = '请检查后台服务安装或运行状态。应用会继续检测。'
        self.network_hint.setText(hint)
        self.network_hint.setVisible(bool(hint))
        can_edit = state.get('can_connect', False) and not self.pending and not self.closing
        for control in (self.username, self.password):
            control.setEnabled(can_edit)
        self.interface.setEnabled(can_edit and bool(state.get('interfaces')))
        self.connect_button.setEnabled(can_edit and bool(interface and interface['carrier']))
        self.disconnect_button.setEnabled(state.get('can_disconnect', False) and not self.pending and not self.closing)
        self.connect_button.setVisible(phase == 'offline')
        self.disconnect_button.setVisible(phase in ('online','connecting','disconnecting','failed','unknown'))
        self.refresh.setEnabled(not self.pending and not self.closing)
        no_address = phase == 'online' and bool(interface) and not interface['ipv4']
        self.network_button.setVisible(no_address)
        self.network_button.setEnabled(not self.pending and not self.closing)
        self.remember.setEnabled(not self.pending and not self.closing)
        primary = phase in ('failed', 'connecting', 'disconnecting') and not no_address
        if self.disconnect_button.property('primary') != primary:
            self.disconnect_button.setProperty('primary', primary)
            self.disconnect_button.style().unpolish(self.disconnect_button)
            self.disconnect_button.style().polish(self.disconnect_button)

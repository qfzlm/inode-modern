"""OpenDesign V2: parity with V1 and actual Qt/Worker/Broker integration."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import unittest
from unittest.mock import patch

from tests import test_desktop_gui as existing_gui
from tests import test_desktop_redesign as existing_redesign

HAS_QT = existing_gui.HAS_QT
if HAS_QT:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLineEdit
    from inode_modern.desktop import app as desktop
    from inode_modern.desktop.window import Window as V1
    from inode_modern.desktop.window_opendesign import Window as V2
    from inode_modern.desktop.opendesign_visuals import LIGHT, DARK
    from inode_modern.desktop.visuals import contrast
    from inode_modern.desktop.preferences import SavedLogin
else:
    V1 = V2 = None

BASE = {'phase': 'offline', 'can_connect': True, 'can_disconnect': False,
        'interface': 'enp5s0', 'interfaces': [{'name': 'enp5s0', 'carrier': True, 'ipv4': ''}]}


class ExistingGuiContract(existing_gui.GuiTests):
    """Run the existing GUI behavior tests against the alternative window."""
    def setUp(self):
        super().setUp()
        build = desktop.build_window
        self.enterContext(patch.object(existing_gui, 'Window', V2))
        self.enterContext(patch.object(existing_gui, 'build_window',
                                      side_effect=lambda app, worker=None: build(app, worker, window_factory=V2)))


@unittest.skipUnless(HAS_QT, "PySide6 not installed")
class OpenDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def window(self, cls=V2, **changes):
        window = cls()
        self.addCleanup(window.deleteLater)
        window.update_state({**BASE, **changes})
        window.show()
        self.app.processEvents()
        return window

    def test_unconfigured_vendor_hint_reaches_visible_window(self):
        from unittest.mock import patch
        from inode_modern.desktop.worker import Worker
        from inode_modern.setup_status import SETUP_HINT
        worker=Worker();worker.model.phase='unavailable'
        states=[];worker.changed.connect(states.append)
        with patch('inode_modern.desktop.worker.vendor_unconfigured',return_value=True):
            worker.publish()
        window=self.window(**states[-1])
        self.assertEqual(window.description.text(),SETUP_HINT)
        self.assertFalse(window.connect_button.isEnabled())

    def test_capabilities_match_first_design_across_states_and_pending_close(self):
        a, b = self.window(V1), self.window()
        for phase in ('offline','checking','connecting','online','disconnecting','failed','unknown','occupied','unavailable'):
            for network in ([], [{'name':'enp5s0','carrier':False,'ipv4':''}], BASE['interfaces'],
                            [{'name':'enp5s0','carrier':True,'ipv4':'192.0.2.1'}]):
                for pending, closing in ((False,False),(True,False),(False,True)):
                    state = {**BASE, 'phase':phase, 'interfaces':network, 'can_connect':phase=='offline',
                             'can_disconnect':phase in ('connecting','online','failed','unknown')}
                    for window in (a,b):
                        window.pending, window.closing = pending, closing
                        window.update_state(state)
                    for name in ('username','password','interface','remember','refresh','connect_button','disconnect_button','network_button'):
                        with self.subTest(phase=phase, pending=pending, closing=closing, control=name):
                            self.assertEqual(getattr(a,name).isEnabled(),getattr(b,name).isEnabled())
                    for name in ('connect_button','disconnect_button','network_button'):
                        self.assertEqual(getattr(a,name).isHidden(),getattr(b,name).isHidden())

    def test_validation_and_exact_input_match_existing_protocol(self):
        for username, password, accepted in (
            ('user', 'password', True), (' user@ct ', ' p a s s ', True),
            ('@ct', 'password', False), ('user@', 'password', False),
            ('a@@ct', 'password', False), ('user@ct', '\0', False),
            ('汉'*83+'@ct', 'password', True), ('汉'*84+'@ct', 'password', False),
            ('user@ct', '密'*85, False), ('user@ct', '', False),
        ):
            w = self.window()
            calls=[]
            w.login.connect(calls.append)
            w.username.setText(username)
            w.password.setText(password)
            w.connect_account()
            with self.subTest(username=username):
                self.assertEqual(bool(calls),accepted)
                if accepted:
                    self.assertEqual((calls[0].username,calls[0].password),(username,password))
                    self.assertEqual(w.password.text(),'')
                    self.assertTrue(w.pending)
                    calls[0].clear()

    def test_independent_evidence_and_plain_status(self):
        w=self.window(interfaces=[{'name':'enp5s0','carrier':True,'ipv4':'192.0.2.1'}],
                      detail='<b>server text</b>')
        self.assertEqual([v.text() for v in w.evidence_values], ['网线已接入','尚未开始','已获取'])
        self.assertEqual(w.description.textFormat(), Qt.TextFormat.PlainText)
        w.update_state({**w.snapshot,'phase':'failed','can_connect':False,'can_disconnect':True})
        self.assertEqual(w.status_title.text(),'操作未完成')
        self.assertEqual(w.evidence_values[2].text(),'已获取')
        self.assertTrue(w.disconnect_button.isVisible())

    def test_stage_provenance_and_state_content(self):
        w = self.window()
        self.assertTrue(w.form.isVisible())
        self.assertFalse(w.summary.isVisible())
        w.update_state({**BASE, 'phase':'connecting', 'can_connect':False, 'can_disconnect':True})
        self.assertFalse(w.form.isVisible())
        self.assertIn('第 2 阶段', w.stage_title.text())
        self.assertEqual(w.evidence_dots[1].property('stage'), 'active')
        w.update_state({**BASE, 'phase':'failed', 'can_connect':False, 'can_disconnect':True})
        self.assertIn('认证阶段', w.stage_title.text())
        self.assertEqual(w.evidence_dots[1].property('stage'), 'failed')
        w.update_state({**BASE, 'phase':'disconnecting'})
        w.update_state({**BASE, 'phase':'failed'})
        self.assertIn('断开阶段', w.stage_title.text())
        w.update_state({**BASE, 'phase':'unknown'})
        self.assertIn('尚不能确认', w.stage_title.text())
        w.update_state({**BASE, 'phase':'failed'})
        self.assertEqual(w.stage_title.text(), '失败阶段待确认')
        w.update_state({**BASE, 'phase':'online', 'can_connect':False, 'can_disconnect':True,
                        'interfaces':[{'name':'enp5s0','carrier':True,'ipv4':'192.0.2.1'}]})
        self.assertFalse(w.form.isVisible())
        self.assertIn('192.0.2.1', w.connection_details.text())
        self.assertIn('公网连通尚未验证', w.stage_detail.text())
        self.assertFalse(w.disconnect_button.property('primary'))
        self.assertFalse(w.remember.isVisible())
        QTest.mouseClick(w.security_toggle, Qt.MouseButton.LeftButton)
        self.assertTrue(w.remember.isVisible())
        self.assertTrue(w.wallet_hint.isVisible())
        w.show_notice('已激活已有有线连接，正在更新网络地址。')
        self.assertEqual(w.snapshot['phase'], 'online')
        w.update_state(BASE)
        self.assertTrue(w.form.isVisible())

    def test_unknown_long_text_is_plain_and_controls_reachable(self):
        w = self.window(phase='unknown', can_connect=False, can_disconnect=True,
                        detail='<b>状态待确认</b>' + '长文本' * 100)
        w.resize(320, 540)
        self.app.processEvents()
        self.assertEqual(w.description.textFormat(), Qt.TextFormat.PlainText)
        scroll = w.centralWidget()
        self.assertEqual(scroll.horizontalScrollBar().maximum(), 0)
        scroll.ensureWidgetVisible(w.disconnect_button)
        self.app.processEvents()
        self.assertTrue(scroll.viewport().rect().contains(
            w.disconnect_button.mapTo(scroll.viewport(), w.disconnect_button.rect().center())))

    def test_network_action_is_single_and_preserves_gates(self):
        w=self.window(phase='online',can_connect=False,can_disconnect=True)
        calls=[]
        w.network_requested.connect(lambda:calls.append(True))
        QTest.mouseClick(w.network_button,Qt.MouseButton.LeftButton)
        w.get_network()
        self.assertEqual(calls,[True])
        self.assertFalse(w.refresh.isEnabled())
        w.command_finished()
        w.update_state(BASE)
        w.get_network()
        self.assertEqual(calls,[True])

    def test_restore_does_not_write_wallet_or_discard_input_on_poll(self):
        w=self.window()
        writes=[]
        w.remember_changed.connect(writes.append)
        saved=SavedLogin('user@ct','test-secret',True)
        w.restore_credentials(saved)
        self.assertFalse(writes)
        self.assertEqual(w.password.text(),'test-secret')
        w.update_state(BASE)
        self.assertEqual(w.password.text(),'test-secret')
        w.show_notice('无法安全保存密码：系统钱包不可用。')
        self.assertTrue(w.notice.isVisible())
        self.assertEqual(w.password.echoMode(),QLineEdit.EchoMode.Password)

    def test_compact_and_large_type_controls_reachable(self):
        original=self.app.font()
        try:
            for scale in (1,2):
                font=self.app.font()
                font.setPointSizeF(original.pointSizeF()*scale)
                self.app.setFont(font)
                w=self.window()
                for width in (540,320):
                    w.resize(width,540)
                    self.app.processEvents()
                    self.assertTrue(w._compact)
                    scroll=w.centralWidget()
                    self.assertEqual(scroll.horizontalScrollBar().maximum(),0)
                    for control in (w.interface,w.username,w.password,w.remember,w.connect_button):
                        scroll.ensureWidgetVisible(control)
                        self.app.processEvents()
                        point=control.mapTo(scroll.viewport(),control.rect().center())
                        self.assertTrue(scroll.viewport().rect().contains(point),(scale,width,control.objectName()))
        finally:
            self.app.setFont(original)

    def test_palette_change_and_srgb_contrast(self):
        original=self.app.palette()
        w=self.window()
        try:
            for c in (LIGHT,DARK):
                p=QPalette(original)
                p.setColor(QPalette.ColorRole.Window,QColor(c['bg']))
                self.app.setPalette(p)
                self.app.processEvents()
                self.assertIn(c['surface'],w.styleSheet())
                for fg,bg in (('fg','surface'),('muted','surface'),('muted','rail'),
                              ('on_primary','primary'),('error','error_bg'),('warn','warn_bg')):
                    self.assertGreaterEqual(contrast(QColor(c[fg]),QColor(c[bg])),4.5)
        finally:
            self.app.setPalette(original)

    def test_real_qt_worker_uds_broker_for_v2(self):
        # Reuse the established real UDS loop, replacing only its Window factory.
        build=desktop.build_window
        with patch.object(existing_redesign,'build_window',
                          side_effect=lambda app,worker:build(app,worker,window_factory=V2)):
            existing_redesign.RedesignTests.test_qt_worker_uds_broker_connect_disconnect_and_close(self)


if __name__=='__main__':
    unittest.main()

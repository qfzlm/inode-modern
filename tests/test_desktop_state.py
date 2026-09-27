import unittest

from inode_modern.desktop.state import SessionState
from inode_modern.protocol import Message, TLV


def status(state=1, result=0, kind=8):
    return Message(kind, (TLV(14, state.to_bytes(4, "big")), TLV(21, result.to_bytes(4, "big")))).safe_summary()


class DesktopStateTests(unittest.TestCase):
    def test_only_confirmed_states_are_named(self):
        model = SessionState()
        for code, expected in ((1, "offline"), (2, "online"), (0, "unknown"), (6, "unknown"), (999, "unknown")):
            model.observe(status(code), 1)
            self.assertEqual(model.phase, expected)
        model.observe(status(2, 99), 2)
        self.assertEqual(model.phase, "unknown")

    def test_cold_start_auxiliary_status_does_not_block_first_login(self):
        model = SessionState()
        model.observe(status(1, 1), 0)
        self.assertEqual(model.phase, "offline")
        self.assertTrue(model.snapshot(1)["can_connect"])
        model.begin("connect", 1)
        model.observe(status(1, 1), 2)
        self.assertEqual(model.phase, "connecting")
        model.observe(status(2, 0), 3)
        self.assertEqual(model.phase, "online")
        model.begin("disconnect", 4)
        model.observe(status(1, 1), 5)
        self.assertEqual(model.phase, "offline")
        self.assertIsNone(model.operation)

    def test_cold_start_fix_does_not_accept_malformed_or_unknown_online_state(self):
        model = SessionState()
        model.observe(status(2, 1), 0)
        self.assertEqual(model.phase, "unknown")
        malformed = Message(8, (TLV(14, b"\0\0\0\1"), TLV(21, b"\1"))).safe_summary()
        model.observe(malformed, 1)
        self.assertEqual(model.phase, "unknown")
        self.assertFalse(model.snapshot(1)["can_connect"])
        model.observe(status(1, 1, kind=11), 2)
        self.assertEqual(model.phase, "unknown")

    def test_connect_requires_real_success_and_tolerates_initial_offline(self):
        model = SessionState()
        model.observe(status(), 0)
        model.begin("connect", 1)
        for code in (1, 0, 6):
            model.observe(status(code), 2)
            self.assertEqual(model.phase, "connecting")
        model.observe(status(2, kind=11), 4)
        self.assertEqual(model.phase, "online")
        self.assertIsNone(model.operation)

    def test_disconnect_ignores_delayed_online_and_temporary_no_response(self):
        model = SessionState()
        model.observe(status(2), 0)
        model.begin("disconnect", 1)
        model.unavailable(4)
        model.observe(status(2), 5)
        self.assertEqual(model.phase, "disconnecting")
        model.observe(status(1), 8)
        self.assertEqual(model.phase, "offline")

    def test_deadline_is_not_an_invented_vendor_error(self):
        model = SessionState()
        model.begin("connect", 0)
        model.observe(status(6), 36)
        self.assertEqual(model.phase, "failed")
        self.assertIn("35 秒", model.detail)
        self.assertNotIn("密码错误", model.detail)
        model.observe(status(2), 40)
        self.assertEqual(model.phase, "online")

    def test_stale_state_does_not_enable_connect(self):
        model = SessionState()
        model.observe(status(1), 1)
        self.assertTrue(model.snapshot(2)["can_connect"])
        self.assertFalse(model.snapshot(9)["can_connect"])
        model.unavailable(9)
        self.assertEqual(model.phase, "unavailable")

    def test_duplicate_or_short_state_cannot_claim_online(self):
        for fields in ((TLV(14, b"\0\0\0\2"), TLV(14, b"\0\0\0\1")), (TLV(14, b"\2"),)):
            model = SessionState()
            message = Message(8, (*fields, TLV(21, b"\0\0\0\0")))
            model.observe(message.safe_summary(), 0)
            self.assertEqual(model.phase, "unknown")


if __name__ == "__main__":
    unittest.main()

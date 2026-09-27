import json
import struct
import unittest

from inode_modern.protocol import Message, ProtocolError, TLV, connect_request


class ProtocolTests(unittest.TestCase):
    def test_known_empty_requests(self):
        self.assertEqual(Message(7).encode(), bytes.fromhex("1f551f560000000007000000"))
        self.assertEqual(Message(3).encode(), bytes.fromhex("1f551f560000000003000000"))

    def test_connect_matches_independent_baseline_fixture(self):
        # Synthetic credentials only. This fixture is independent of the encoder.
        body = (
            b"\x01\x09test@ct" + b"\x02\x08secret" + b"\x07\x08enp5s0" + b"\x1d\x02"
            + bytes.fromhex(
                "100600000001 0f0600000000 110600000000 120600000000"
                "160600000001 0b0600000000 0c0600000000 1e0600000001"
                "1f0600000000 200600000000 170600000000"
            )
        )
        self.assertEqual(len(body), 93)
        expected = bytes.fromhex("1f551f56000000000100005d") + body
        self.assertEqual(connect_request("test@ct", "secret").encode(), expected)

    def test_preserve_suffix_and_password_whitespace(self):
        message = connect_request("test@ct", "  secret ")
        self.assertEqual(message.tlvs[0].value, b"test@ct")
        self.assertEqual(message.tlvs[1].value, b"  secret ")

    def test_reject_suffix_without_account(self):
        for username in ("@ct", "@", "test@"):
            with self.assertRaises(ProtocolError):
                connect_request(username, "synthetic")

    def test_reject_invalid_interface_syntax(self):
        for bad_if in ("enp5s0; id", "eth0$(whoami)", "enp5s0\n", "a" * 16, "", "foo bar"):
            with self.assertRaises(ProtocolError):
                connect_request("test@ct", "secret", bad_if)

    def test_roundtrip_empty_and_maximum_tlv(self):
        original = Message(8, (TLV(29, b""), TLV(255, b"x" * 253)))
        self.assertEqual(Message.decode(original.encode()), original)

    def test_reject_invalid_envelopes(self):
        valid = Message(8, (TLV(14, struct.pack("!I", 99)),)).encode()
        invalid = [valid[:n] for n in range(len(valid))]
        invalid += [valid + b"\0", b"\0" + valid[1:], valid[:4] + b"\0\0\0\1" + valid[8:]]
        for packet in invalid:
            with self.subTest(length=len(packet)):
                with self.assertRaises(ProtocolError):
                    Message.decode(packet)

    def test_reject_bad_tlv_lengths(self):
        for body in (b"\x01", b"\x01\x00", b"\x01\x01", b"\x01\x05xx"):
            header = bytes.fromhex("1f551f560000000008") + len(body).to_bytes(3, "big")
            with self.assertRaises(ProtocolError):
                Message.decode(header + body)

    def test_reject_overlong_empty_and_nul_credentials_without_echo(self):
        for value in ("", "x" * 254, "secret\0tail", "密" * 85):
            with self.assertRaises(ProtocolError) as caught:
                connect_request("test@ct", value)
            if value:
                self.assertNotIn(value, str(caught.exception))

    def test_summary_redacts_password_text_and_unknown_fields(self):
        secret = b"SYNTHETIC_PASSWORD_DO_NOT_LOG"
        message = Message(11, (TLV(2, secret), TLV(99, secret), TLV(14, struct.pack("!I", 99)),
                               TLV(21, struct.pack("!I", 123)), TLV(14, b"x")))
        rendered = json.dumps(message.safe_summary()) + repr(message) + repr(message.tlvs)
        self.assertNotIn(secret.decode(), rendered)
        self.assertNotIn(secret.hex(), rendered)
        self.assertEqual(message.safe_summary()["fields"][2]["value"], 99)
        self.assertEqual(message.safe_summary()["fields"][3]["value"], 123)
        self.assertNotIn("value", message.safe_summary()["fields"][4])
        self.assertNotIn("online", rendered)

    def test_preserve_duplicate_fields(self):
        message = Message(8, (TLV(14, b"\0\0\0\1"), TLV(14, b"\0\0\0\2")))
        self.assertEqual([item["value"] for item in message.safe_summary()["fields"]], [1, 2])


if __name__ == "__main__":
    unittest.main()

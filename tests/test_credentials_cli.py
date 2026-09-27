import contextlib
import getpass
import io
import subprocess
import unittest
import warnings
from unittest.mock import patch

from inode_modern.cli import main
from inode_modern.credentials import CredentialError, _dialog, read_credentials
from inode_modern.protocol import Message, TLV
from inode_modern.protocol import ProtocolError


class CredentialTests(unittest.TestCase):
    def test_dialog_preserves_spaces_and_only_removes_record_newline(self):
        with patch("shutil.which", return_value="/usr/bin/kdialog"), patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=b" secret \n")
            self.assertEqual(_dialog("prompt", True), " secret ")
            self.assertEqual(run.call_args.args[0][-2:], ["--password", "prompt"])
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_cancel_does_not_return_password(self):
        with patch("shutil.which", return_value="kdialog"), patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout=b"synthetic")
            with self.assertRaises(CredentialError):
                _dialog("prompt", True)

    @patch("inode_modern.credentials.protect_process")
    def test_suffix_only_is_rejected_before_password_prompt(self, protect):
        with patch("inode_modern.credentials._dialog", return_value="@ct") as dialog:
            with self.assertRaises(ProtocolError):
                read_credentials(True)
            self.assertEqual(dialog.call_count, 1)

    @patch("inode_modern.credentials.protect_process")
    def test_non_tty_is_rejected(self, protect):
        with patch("sys.stdin", io.StringIO("synthetic\n")):
            with self.assertRaises(CredentialError):
                read_credentials()
        protect.assert_called_once()

    @patch("inode_modern.credentials.protect_process")
    def test_getpass_must_not_fall_back_to_echo(self, protect):
        def fallback(*args):
            warnings.warn("cannot hide", getpass.GetPassWarning)
            self.fail("must abort before echoed input")
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="test@ct"), \
             patch("getpass.getpass", side_effect=fallback):
            with self.assertRaises(CredentialError):
                read_credentials()

    def test_cli_connect_never_prints_credentials_or_claims_success(self):
        output = io.StringIO()
        with patch("inode_modern.cli.Client") as cls, patch("inode_modern.cli.socket.if_nametoindex", return_value=1), \
             patch("inode_modern.cli.read_credentials", return_value=("synthetic@ct", "secret-sentinel")), \
             contextlib.redirect_stdout(output):
            client = cls.return_value.__enter__.return_value
            client.status.return_value = Message(8, (TLV(14, b"\0\0\0\x55"),))
            self.assertEqual(main(["connect", "--dialog"]), 0)
            sent = client.send.call_args.args[0]
            self.assertEqual(sent.tlvs[0].value, b"synthetic@ct")
            self.assertEqual(sent.tlvs[1].value, b"secret-sentinel")
        self.assertNotIn("secret-sentinel", output.getvalue())
        self.assertNotIn("synthetic@ct", output.getvalue())
        self.assertIn("not yet established", output.getvalue())

    def test_cli_checks_daemon_before_prompting(self):
        from inode_modern.client import ClientError
        with patch("inode_modern.cli.Client") as cls, patch("inode_modern.cli.socket.if_nametoindex", return_value=1), \
             patch("inode_modern.cli.read_credentials") as read, contextlib.redirect_stdout(io.StringIO()):
            cls.return_value.__enter__.side_effect = ClientError("occupied")
            self.assertEqual(main(["connect", "--dialog"]), 1)
            read.assert_not_called()

    def test_rejected_password_argument_is_not_echoed(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main(["connect", "--password", "secret-argv-sentinel"])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("secret-argv-sentinel", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

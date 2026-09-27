"""Interactive credentials only: no argv/env/file password interfaces."""

import ctypes
import getpass
import resource
import shutil
import subprocess
import sys
import warnings

from .protocol import username_value


class CredentialError(RuntimeError):
    pass


def protect_process() -> None:
    # Prevent normal Linux process/core dumps before reading any credentials.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE = 4
        raise CredentialError("could not disable process dumps")


def _dialog(prompt: str, secret: bool = False) -> str:
    executable = shutil.which("kdialog")
    if executable is None:
        raise CredentialError("kdialog is unavailable; use a local terminal")
    proc = subprocess.run(
        [executable, "--title", "iNode Modern PoC", "--password" if secret else "--inputbox", prompt],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if proc.returncode != 0:
        raise CredentialError("credential entry cancelled or dialog failed")
    # Remove precisely the single record terminator added by kdialog.
    data = proc.stdout.removesuffix(b"\n")
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise CredentialError("credential entry is not valid UTF-8") from None


def read_credentials(dialog: bool = False) -> tuple[str, str]:
    protect_process()
    if dialog:
        username = _dialog("完整校园网用户名（保留 @ct 后缀）")
        username_value(username)
        password = _dialog("校园网密码（仅本次使用，不保存）", secret=True)
        return username, password
    if not sys.stdin.isatty():
        raise CredentialError("credentials require a local terminal or --dialog; stdin piping is disabled")
    username = input("完整校园网用户名（含 @ct）：")
    username_value(username)
    # getpass otherwise falls back to echoing input on an unsuitable terminal.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("校园网密码（不保存）：")
        except getpass.GetPassWarning:
            raise CredentialError("secure hidden terminal input is unavailable") from None
    return username, password

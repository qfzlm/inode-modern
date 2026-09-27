"""JSON Lines output contains only metadata and confirmed numeric fields."""

import argparse
from datetime import datetime, timezone
import json
import math
import socket
import sys

from .client import Client, ClientError
from .credentials import CredentialError, read_credentials
from .protocol import DISCONNECT, Message, ProtocolError, connect_request


def emit(event: str, **fields) -> None:
    print(json.dumps({"time": datetime.now(timezone.utc).isoformat(),
                      "event": event, **fields}, ensure_ascii=False), flush=True)


def positive(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive finite number") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected a positive finite number")
    return number


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes unknown arguments. Even an unsupported
        # --password option must not reflect a mistakenly supplied secret.
        self.print_usage(sys.stderr)
        self.exit(2, "参数无效；请运行 --help。密码只能通过隐藏交互输入。\n")


def parser() -> argparse.ArgumentParser:
    result = SafeArgumentParser(description="原厂 iNode 的本地 UDP 前端；不会解释未知状态码")
    result.add_argument("--timeout", type=positive, default=3.0, help="单次状态响应超时秒数，默认 3")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="查询 STATE / RESULT 原始数值")
    watch = commands.add_parser("watch", help="轮询状态并接收异步消息")
    connect = commands.add_parser("connect", help="以西财已验证参数发送一次连接请求")
    connect.add_argument("--dialog", action="store_true", help="通过 KDE 输入框读取账号和密码")
    connect.add_argument("--interface", default="enp5s0")
    disconnect = commands.add_parser("disconnect", help="发送断开请求，再查询状态；不假定存在 ACK")
    for command in (watch, connect, disconnect):
        command.add_argument("--observe", type=positive, default=15.0, help="持续观察秒数，默认 15")
        command.add_argument("--interval", type=positive, default=1.0, help="状态查询间隔秒数，默认 1")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "connect":
            try:
                socket.if_nametoindex(args.interface)
            except OSError:
                raise ClientError("selected network interface does not exist") from None
        with Client(args.timeout, lambda message: emit("async", **message.safe_summary())) as client:
            if args.command == "status":
                emit("status", **client.status().safe_summary())
                return 0
            if args.command in ("connect", "disconnect"):
                emit("before", **client.status().safe_summary())
            if args.command == "connect":
                username, password = read_credentials(args.dialog)
                try:
                    request = connect_request(username, password, args.interface)
                    client.send(request)
                finally:
                    # Drop references promptly; Python cannot guarantee secure erasure.
                    username = password = request = None
                emit("connect_sent", take_version=1, take_ip=0,
                     note="request sent; authentication outcome is not yet established")
            elif args.command == "disconnect":
                client.send(Message(DISCONNECT))
                emit("disconnect_sent", note="request sent; no independent ACK is assumed")
            client.observe(args.observe, args.interval,
                           lambda message: emit("status", **message.safe_summary()),
                           lambda: emit("status_timeout", note="retrying only the status query within the observation window"))
            emit("observation_complete", note="raw status only; no unknown state code is labelled online/offline")
        return 0
    except (ClientError, ProtocolError, CredentialError) as exc:
        emit("error", message=str(exc))
        return 1
    except (KeyboardInterrupt, EOFError):
        emit("cancelled", note="stopping this frontend does not automatically disconnect authentication")
        return 130
    except OSError:
        # OS exception strings can include private paths or program arguments.
        emit("error", message="local operating-system operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

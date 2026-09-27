"""Presentation state, independent of Qt and credentials.

STATE=1 is also returned by a cold daemon with auxiliary field 21=1.
For status replies, field 21 comes from sec_GetEadStatus, not an auth result.
Online confirmation retains the verified STATE=2 / field 21=0 combination.
Operation timeouts are frontend outcomes, not invented vendor error codes.
"""

from dataclasses import dataclass


@dataclass
class SessionState:
    phase: str = "checking"
    raw_state: int | None = None
    raw_result: int | None = None
    last_response: float | None = None
    operation: str | None = None
    deadline: float = 0
    detail: str = "正在检查认证服务…"

    def begin(self, operation: str, now: float) -> None:
        self.operation = operation
        self.deadline = now + (35 if operation == "connect" else 20)
        self.phase = "connecting" if operation == "connect" else "disconnecting"
        self.detail = "正在等待校园网认证结果…" if operation == "connect" else "正在等待认证服务断开…"

    def observe(self, summary: dict, now: float) -> None:
        def unique(kind):
            fields = [field for field in summary.get("fields", []) if field.get("type") == kind]
            if len(fields) == 1 and fields[0].get("value_length") == 4:
                return fields[0].get("value")
            return None

        self.raw_state, self.raw_result = unique(14), unique(21)
        self.last_response = now
        known = self.raw_result == 0
        # AuthenMngService::dot1xProcMsg status branch independently reads X1 and
        # EAD status. A fresh STATE=1/field21=1 is idle, not a failed disconnect.
        offline = self.raw_state == 1 and (known or (
            summary.get("msg_type") == 8 and self.raw_result is not None))
        if self.operation == "disconnect":
            if offline:
                self.operation = None
                self.phase, self.detail = "offline", "已断开校园网认证。"
        elif known and self.raw_state == 2:
            self.operation = None
            self.phase, self.detail = "online", "校园网认证已通过。"
        elif self.operation == "connect":
            # An initial offline reply may precede authentication. Keep waiting.
            pass
        elif offline:
            self.phase, self.detail = "offline", "输入完整账号和密码，即可连接校园网。"
        elif self.phase != "failed":
            self.phase, self.detail = "unknown", "服务返回了尚未确认的状态。可先断开，再重新连接。"
        self.check_deadline(now)

    def check_deadline(self, now: float) -> None:
        if self.operation and now >= self.deadline:
            connecting = self.operation == "connect"
            self.operation = None
            self.phase = "failed"
            self.detail = ("未在 35 秒内确认认证成功。请断开后检查账号、密码和网线，再重试。"
                           if connecting else "尚未确认断开，请等待服务恢复响应或再次断开。")

    def unavailable(self, now: float, occupied: bool = False) -> None:
        if self.operation:
            self.check_deadline(now)
            return
        self.phase = "occupied" if occupied else "unavailable"
        self.detail = ("另一个前端正在使用认证接口。请关闭旧 iNode 或正在运行的 CLI。"
                       if occupied else "认证后台未响应。请检查 iNode Modern 后台服务是否已安装并运行；应用会继续检测。")

    def snapshot(self, now: float) -> dict:
        fresh = self.last_response is not None and now - self.last_response <= 5
        return {"phase": self.phase, "detail": self.detail,
                "state": self.raw_state, "result": self.raw_result,
                "responsive": fresh, "operation": self.operation,
                "can_connect": self.phase == "offline" and fresh,
                "can_disconnect": self.phase in ("online", "connecting", "failed", "unknown"),
                "response_age": None if self.last_response is None else max(0, int(now - self.last_response))}

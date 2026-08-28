"""Synchronous fail-closed client for the unregistered private Kingbase MCP."""

from __future__ import annotations

import json
import math
import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


PROTOCOL_VERSION = "2024-11-05"
MAX_PRIVATE_LINE_BYTES = 2_097_152
PRIVATE_TIMEOUT_SECONDS = 25.0
SYSTEM_PATH = "/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin"
PRIVATE_LAUNCHER = (
    Path(__file__).resolve().parents[1]
    / "kingbase-readonly-mcp"
    / "run_kingbase_readonly_mcp.sh"
)


class PrivateMcpUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "private MCP unavailable"


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _assert_finite(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("JSON depth exceeded")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("invalid JSON object key")
            _assert_finite(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _assert_finite(child, depth + 1)


class _ProcessTransport:
    def __init__(self) -> None:
        launcher = PRIVATE_LAUNCHER
        if (
            not launcher.is_absolute()
            or launcher.is_symlink()
            or not launcher.is_file()
            or not os.access(launcher, os.X_OK)
        ):
            raise RuntimeError("private launcher unavailable")
        home = os.environ.get("HOME")
        if not isinstance(home, str) or not os.path.isabs(home) or not os.path.isdir(home):
            raise RuntimeError("private launcher environment unavailable")
        self._process = subprocess.Popen(
            [str(launcher)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"HOME": home, "PATH": SYSTEM_PATH},
            bufsize=0,
            start_new_session=True,
        )
        if self._process.stdin is None or self._process.stdout is None:
            self.terminate()
            raise RuntimeError("private launcher pipes unavailable")
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._stdout, selectors.EVENT_READ)
        self._buffer = bytearray()
        self._closed = False

    def write_line(self, payload: bytes) -> None:
        encoded = payload + b"\n"
        written = self._stdin.write(encoded)
        if written is None or written != len(encoded):
            raise OSError("private request short write")
        self._stdin.flush()

    def read_line(self, timeout_seconds: float, cap: int) -> bytes:
        deadline = time.monotonic() + timeout_seconds
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > cap:
                    raise OverflowError("private response too large")
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                return line
            if len(self._buffer) > cap:
                raise OverflowError("private response too large")
            if self._process.poll() is not None:
                raise EOFError("private child exited")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._selector.select(remaining):
                raise TimeoutError("private response timeout")
            chunk = os.read(self._stdout.fileno(), 65_536)
            if not chunk:
                raise EOFError("private child closed")
            self._buffer.extend(chunk)

    def terminate(self) -> None:
        if getattr(self, "_closed", False):
            return
        self._closed = True
        process = getattr(self, "_process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        selector = getattr(self, "_selector", None)
        if selector is not None:
            selector.close()
        for stream_name in ("_stdin", "_stdout"):
            stream = getattr(self, stream_name, None)
            if stream is not None:
                stream.close()


class PrivateMcpClient:
    def __init__(
        self,
        *,
        transport_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._transport = None
        self._closed = False
        self._next_id = 1
        try:
            self._transport = (transport_factory or _ProcessTransport)()
            result = self._request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "industry-stock-selection-local",
                        "version": "1.0.0",
                    },
                },
            )
            if not (
                isinstance(result, dict)
                and result.get("protocolVersion") == PROTOCOL_VERSION
                and result.get("serverInfo")
                == {"name": "kingbase-readonly-private", "version": "1.0.0"}
            ):
                raise ValueError("unexpected private initialize response")
            self._notify("notifications/initialized", {})
        except Exception:
            self.close()
            raise PrivateMcpUnavailable() from None

    def _encode(self, value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        if self._transport is None:
            raise RuntimeError("private transport unavailable")
        self._transport.write_line(
            self._encode({"jsonrpc": "2.0", "method": method, "params": params})
        )

    def _request(self, method: str, params: dict[str, Any]) -> Any:
        if self._transport is None:
            raise RuntimeError("private transport unavailable")
        request_id = self._next_id
        self._next_id += 1
        self._transport.write_line(
            self._encode(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            )
        )
        raw = self._transport.read_line(PRIVATE_TIMEOUT_SECONDS, MAX_PRIVATE_LINE_BYTES)
        text = raw.decode("utf-8")
        response = json.loads(text, parse_constant=_reject_constant)
        _assert_finite(response)
        if (
            not isinstance(response, dict)
            or response.get("jsonrpc") != "2.0"
            or response.get("id") != request_id
            or set(response) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
            or "error" in response
        ):
            raise ValueError("invalid private response")
        return response["result"]

    def call_catalog(self, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self._request(
                "tools/call",
                {"name": "kingbase_catalog_query", "arguments": arguments},
            )
            if not isinstance(result, dict) or not set(result) <= {"content", "isError"}:
                raise ValueError("invalid private tool result")
            content = result.get("content")
            if (
                not isinstance(content, list)
                or len(content) != 1
                or content[0].get("type") != "text"
                or not isinstance(content[0].get("text"), str)
            ):
                raise ValueError("invalid private tool content")
            value = json.loads(content[0]["text"], parse_constant=_reject_constant)
            _assert_finite(value)
            if not isinstance(value, dict):
                raise ValueError("private tool result is not an object")
            return value
        except Exception:
            self.close()
            raise PrivateMcpUnavailable() from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        transport = self._transport
        self._transport = None
        if transport is not None:
            transport.terminate()

    def __enter__(self) -> "PrivateMcpClient":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

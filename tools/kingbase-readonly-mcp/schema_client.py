import json
import os
import selectors
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


WORKER_STARTUP_TIMEOUT_SECONDS = 5.0
WORKER_ROUND_TRIP_TIMEOUT_SECONDS = 2.0
CLIENT_REQUEST_LINE_CAP = 2_097_152
WORKER_RESPONSE_LINE_CAP = 4_096
CONTRACTS = frozenset(
    {
        "preflightRequest",
        "preflightResponse",
        "catalogRequest",
        "catalogResponse",
    }
)


class SchemaUnavailable(RuntimeError):
    pass


class _ProcessTransport:
    def __init__(self, node_binary: str, worker_path: str | os.PathLike[str] | None = None) -> None:
        if (
            not isinstance(node_binary, str)
            or not os.path.isabs(node_binary)
            or os.path.islink(node_binary)
            or not os.path.isfile(node_binary)
            or not os.access(node_binary, os.X_OK)
        ):
            raise ValueError("invalid node binary")
        worker = (
            Path(__file__).with_name("schema_worker.mjs")
            if worker_path is None
            else Path(worker_path)
        )
        resolved_worker = Path(os.path.realpath(worker))
        if (
            not worker.is_absolute()
            or worker.is_symlink()
            or not worker.is_file()
            or resolved_worker != worker
        ):
            raise ValueError("invalid schema worker")
        self._buffer = bytearray()
        self._process = None
        self._stdin = None
        self._stdout = None
        self._selector = None
        self._closed = False
        try:
            self._process = subprocess.Popen(
                [node_binary, str(worker)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={},
                bufsize=0,
            )
            if self._process.stdin is None or self._process.stdout is None:
                raise RuntimeError("worker pipes unavailable")
            self._stdin = self._process.stdin
            self._stdout = self._process.stdout
            self._selector = selectors.DefaultSelector()
            self._selector.register(self._stdout, selectors.EVENT_READ)
        except Exception:
            self.terminate()
            raise

    def write_line(self, payload: bytes) -> None:
        encoded = payload + b"\n"
        written = self._stdin.write(encoded)
        if written is None or written != len(encoded):
            raise OSError("worker request short write")
        self._stdin.flush()

    def read_line(self, timeout_seconds: float, cap: int) -> bytes:
        deadline = time.monotonic() + timeout_seconds
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > cap:
                    raise OverflowError("worker response too large")
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                return line
            if len(self._buffer) > cap:
                raise OverflowError("worker response too large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("worker response timeout")
            if not self._selector.select(remaining):
                raise TimeoutError("worker response timeout")
            chunk = os.read(self._stdout.fileno(), 4096)
            if not chunk:
                raise EOFError("worker closed")
            self._buffer.extend(chunk)

    def terminate(self) -> None:
        if getattr(self, "_closed", False):
            return
        self._closed = True
        process = getattr(self, "_process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
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


class SchemaClient:
    def __init__(
        self,
        node_binary: str | None = None,
        transport_factory: Callable[[], Any] | None = None,
        *,
        worker_path: str | os.PathLike[str] | None = None,
        contracts: set[str] | frozenset[str] | None = None,
        startup_probe: tuple[str, Any] | None = None,
    ) -> None:
        self._transport = None
        self._closed = False
        self._next_id = 0
        try:
            selected_contracts = CONTRACTS if contracts is None else frozenset(contracts)
            if not selected_contracts or any(
                not isinstance(contract, str) or not contract
                for contract in selected_contracts
            ):
                raise ValueError("invalid contract allowlist")
            self._contracts = frozenset(selected_contracts)
            selected_probe = (
                ("preflightRequest", {})
                if startup_probe is None
                else startup_probe
            )
            if (
                not isinstance(selected_probe, tuple)
                or len(selected_probe) != 2
                or not isinstance(selected_probe[0], str)
                or selected_probe[0] not in self._contracts
            ):
                raise ValueError("invalid startup probe")
            if transport_factory is None:
                resolved = self._resolve_node_binary(node_binary)
                if worker_path is None:
                    transport_factory = lambda: _ProcessTransport(resolved)
                else:
                    transport_factory = lambda: _ProcessTransport(
                        resolved,
                        worker_path=worker_path,
                    )
            self._transport = transport_factory()
            if not self._exchange(
                selected_probe[0],
                selected_probe[1],
                WORKER_STARTUP_TIMEOUT_SECONDS,
            ):
                raise ValueError("worker bootstrap validation failed")
        except Exception:
            self._abort()
            raise SchemaUnavailable("contract validation unavailable") from None

    @staticmethod
    def _resolve_node_binary(node_binary: str | None) -> str:
        candidate = node_binary if node_binary is not None else shutil.which("node")
        if not candidate:
            raise FileNotFoundError("node binary unavailable")
        resolved = os.path.realpath(candidate)
        if (
            not os.path.isabs(resolved)
            or os.path.islink(resolved)
            or not os.path.isfile(resolved)
            or not os.access(resolved, os.X_OK)
        ):
            raise ValueError("invalid node binary")
        return resolved

    def _abort(self) -> None:
        self._closed = True
        if self._transport is not None:
            try:
                self._transport.terminate()
            except Exception:
                pass

    def _exchange(
        self,
        contract: str,
        instance: Any,
        timeout_seconds: float,
    ) -> bool:
        if contract not in self._contracts:
            raise ValueError("unknown contract")
        request_id = self._next_id
        request = {
            "id": request_id,
            "contract": contract,
            "instance": instance,
        }
        encoded = json.dumps(
            request,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > CLIENT_REQUEST_LINE_CAP:
            raise OverflowError("worker request too large")
        self._transport.write_line(encoded)
        raw = self._transport.read_line(timeout_seconds, WORKER_RESPONSE_LINE_CAP)
        response = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(response, dict)
            or set(response) != {"id", "valid"}
            or isinstance(response.get("id"), bool)
            or not isinstance(response.get("id"), int)
            or response["id"] != request_id
            or not isinstance(response.get("valid"), bool)
        ):
            raise ValueError("invalid worker response")
        self._next_id += 1
        return response["valid"]

    def validate(self, contract: str, instance: Any) -> bool:
        if self._closed:
            raise SchemaUnavailable("contract validation unavailable")
        try:
            return self._exchange(
                contract,
                instance,
                WORKER_ROUND_TRIP_TIMEOUT_SECONDS,
            )
        except Exception:
            self._abort()
            raise SchemaUnavailable("contract validation unavailable") from None

    def close(self) -> None:
        self._abort()

    def __enter__(self) -> "SchemaClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

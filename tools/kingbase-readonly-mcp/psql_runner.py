import json
import hashlib
import os
import secrets
import selectors
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

from canonical import canonical_json
from contracts import PROFILE
from sql_templates import SqlPlan


PSQL_WALL_TIMEOUT_SECONDS = 20
PSQL_STDOUT_CAP = 1_048_576
PSQL_STDERR_CAP = 65_536
PUBLIC_RESPONSE_CAP = 1_048_576
PSQL_BINARY = "/opt/homebrew/Cellar/postgresql@17/17.7_1/bin/psql"
PSQL_BINARY_SHA256 = "205085ef1cee6455fbd24f3cde1f171120d2e5677292478ebaee52b61249ecd5"
FIXED_LIBPQ_OPTIONS = (
    "-c default_transaction_read_only=on "
    "-c search_path=ai_dw -c standard_conforming_strings=on "
    "-c statement_timeout=15000 -c lock_timeout=3000"
)


@dataclass(frozen=True)
class BoundedCompleted:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class PsqlResult:
    preflight: dict[str, Any] | None
    business: dict[str, Any] | None
    error_code: str | None


class OutputLimitExceeded(RuntimeError):
    pass


class QueryFailed(RuntimeError):
    def __str__(self) -> str:
        return "query failed"


class ResultTooLarge(RuntimeError):
    def __str__(self) -> str:
        return "result exceeds limit"


def _resolve_psql_binary(candidate: str | None = None) -> str:
    selected = candidate if candidate is not None else PSQL_BINARY
    resolved = os.path.realpath(selected)
    if (
        resolved != PSQL_BINARY
        or os.path.islink(resolved)
        or not os.path.isfile(resolved)
        or not os.access(resolved, os.X_OK)
    ):
        raise QueryFailed()
    digest = hashlib.sha256()
    try:
        with open(resolved, "rb") as executable:
            for chunk in iter(lambda: executable.read(65_536), b""):
                digest.update(chunk)
    except OSError:
        raise QueryFailed() from None
    if digest.hexdigest() != PSQL_BINARY_SHA256:
        raise QueryFailed()
    return resolved


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def bounded_run(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: float,
    stdout_cap: int,
    stderr_cap: int,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> BoundedCompleted:
    process = popen(
        args,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        bufsize=0,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise RuntimeError("subprocess pipes unavailable")

    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_cap, "stderr": stderr_cap}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    input_offset = 0
    deadline = time.monotonic() + timeout_seconds

    try:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if input_bytes is not None:
            if process.stdin is None:
                raise RuntimeError("subprocess stdin unavailable")
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("subprocess timeout")
            events = selector.select(remaining)
            if not events:
                raise TimeoutError("subprocess timeout")
            for key, mask in events:
                name = key.data
                stream = key.fileobj
                if name == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),
                            input_bytes[input_offset : input_offset + 65_536],
                        )
                    except BrokenPipeError:
                        written = len(input_bytes) - input_offset
                    input_offset += written
                    if input_offset >= len(input_bytes):
                        selector.unregister(stream)
                        stream.close()
                    continue

                chunk = os.read(stream.fileno(), 65_536)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > limits[name]:
                    raise OutputLimitExceeded(name)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("subprocess timeout")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise TimeoutError("subprocess timeout") from None
        return BoundedCompleted(
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
        )
    except Exception:
        _terminate_process(process)
        raise
    finally:
        selector.close()
        for stream in (getattr(process, "stdin", None), process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _parse_marker_payload(line: str, marker: str) -> dict[str, Any]:
    payload = line[len(marker) :]
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("marker payload is not an object")
    return value


def parse_psql_output(plan: SqlPlan, stdout: bytes) -> PsqlResult:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise QueryFailed() from None
    lines = [line for line in text.splitlines() if line]
    if lines == ["KBRM1_READ_ONLY_REQUIRED"]:
        return PsqlResult(None, None, "READ_ONLY_REQUIRED")
    if lines == ["KBRM1_DATA_CONTRACT_MISMATCH"]:
        return PsqlResult(None, None, "DATA_CONTRACT_MISMATCH")

    preflight_marker = "KBRM1_PREFLIGHT_OK|"
    business_marker = "KBRM1_BUSINESS_V1|"
    try:
        preflight_lines = [line for line in lines if line.startswith(preflight_marker)]
        business_lines = [line for line in lines if line.startswith(business_marker)]
        recognized = len(preflight_lines) + len(business_lines)
        if len(preflight_lines) != 1 or recognized != len(lines):
            raise ValueError("invalid marker set")
        if plan.operation == "kingbase_readonly_preflight":
            if business_lines:
                raise ValueError("unexpected business marker")
        elif len(business_lines) != 1:
            raise ValueError("missing business marker")
        preflight = _parse_marker_payload(preflight_lines[0], preflight_marker)
        business = (
            _parse_marker_payload(business_lines[0], business_marker)
            if business_lines
            else None
        )
    except (ValueError, json.JSONDecodeError):
        raise QueryFailed() from None
    return PsqlResult(preflight, business, None)


def run_psql(
    plan: SqlPlan,
    password: Any,
    *,
    run: Callable[..., BoundedCompleted] = bounded_run,
    psql_binary: str | None = None,
) -> PsqlResult:
    resolved_psql = _resolve_psql_binary(psql_binary)
    home = os.environ.get("HOME")
    if not isinstance(home, str) or not os.path.isabs(home) or not os.path.isdir(home):
        raise QueryFailed()
    args = [resolved_psql, "-X", "-w", "-v", "ON_ERROR_STOP=1"]
    for name, value in plan.variables.items():
        args.extend(["-v", f"{name}={value}"])
    args.extend(
        [
            "--dbname",
            f"service={PROFILE} options='{FIXED_LIBPQ_OPTIONS}'",
        ]
    )

    password_value = password.reveal()
    child_env = {
        "HOME": home,
        "PGPASSWORD": password_value,
        "PSQL_HISTORY": "/dev/null",
        "PGCONNECT_TIMEOUT": "5",
        "PGOPTIONS": FIXED_LIBPQ_OPTIONS,
        "PGAPPNAME": "kingbase-readonly-v1:" + secrets.token_hex(16),
    }
    try:
        completed = run(
            args,
            input_bytes=plan.sql.encode("utf-8"),
            env=child_env,
            timeout_seconds=PSQL_WALL_TIMEOUT_SECONDS,
            stdout_cap=PSQL_STDOUT_CAP,
            stderr_cap=PSQL_STDERR_CAP,
        )
    except OutputLimitExceeded:
        raise ResultTooLarge() from None
    except (TimeoutError, OSError):
        raise QueryFailed() from None
    finally:
        del password_value

    if completed.returncode != 0:
        raise QueryFailed()
    return parse_psql_output(plan, completed.stdout)


def enforce_public_response_cap(response: Any) -> None:
    if len(canonical_json(response)) > PUBLIC_RESPONSE_CAP:
        raise ResultTooLarge()

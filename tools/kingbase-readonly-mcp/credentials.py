from typing import Any, Callable

from contracts import KEYCHAIN_SERVICE
from psql_runner import BoundedCompleted, bounded_run


class AuthUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "credential unavailable"


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    def __str__(self) -> str:
        return "[REDACTED]"


def read_password(
    run: Callable[..., BoundedCompleted] = bounded_run,
) -> Secret:
    try:
        completed = run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-w",
            ],
            timeout_seconds=5,
            stdout_cap=4096,
            stderr_cap=65_536,
        )
        if completed.returncode != 0:
            raise ValueError("keychain command failed")
        value = completed.stdout.decode("utf-8").rstrip("\r\n")
        if not value or any(char in value for char in ("\x00", "\r", "\n")):
            raise ValueError("invalid secret")
        return Secret(value)
    except Exception:
        raise AuthUnavailable() from None

"""
作者：elvis
日期：2026-08-18
作用：MACOS_PROCESS_LIST_MATCH_LAUNCH_IDENTITY_V1 纯函数谓词
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FdId:
    """被保留的可执行文件身份摘要。"""

    canonical_path: str
    device: str
    inode: str
    sha256: str


@dataclass(frozen=True)
class FakeProc:
    """测试注入的进程身份，不读取真实进程表。"""

    pid: int
    device: str
    inode: str
    sha256: str


@dataclass(frozen=True)
class ScanResult:
    """V1 扫描结果；扫描未完成时禁止伪造空命中集合。"""

    scan_complete: bool
    matched_pids: list[int] | None


def scan_v1(fd: FdId, procs: list[FakeProc] | None) -> ScanResult:
    """按 device/inode 或 sha256 匹配所有注入的同二进制活进程。"""
    if procs is None:
        return ScanResult(False, None)
    hits = []
    for proc in procs:
        if (
            (proc.device, proc.inode) == (fd.device, fd.inode)
            or proc.sha256 == fd.sha256
        ):
            hits.append(proc.pid)
    return ScanResult(True, sorted(set(hits)))

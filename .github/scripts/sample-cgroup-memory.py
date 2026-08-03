#!/usr/bin/env python3
"""Continuously sample one cgroup-v2 memory.current file with strict bounds."""

from __future__ import annotations

import os
import signal
import stat
import sys
import time
from typing import NoReturn


MAX_SOURCE_BYTES = 64
MAX_RUNTIME_SECONDS = 30.0
SAMPLE_INTERVAL_SECONDS = 0.01

stopping = False


def fail(message: str) -> NoReturn:
    raise SystemExit(f"cgroup memory sampler failed: {message}")


def request_stop(_signum: int, _frame: object) -> None:
    global stopping
    stopping = True


def require_absolute(path: str, label: str) -> None:
    if not path or not os.path.isabs(path) or os.path.normpath(path) != path:
        fail(f"{label} path is not absolute and normalized")


def require_absent(path: str, label: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    fail(f"{label} path already exists")


def read_sample(descriptor: int) -> int:
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = os.read(descriptor, MAX_SOURCE_BYTES + 1)
    if (
        not payload
        or len(payload) > MAX_SOURCE_BYTES
        or not payload.endswith(b"\n")
        or not payload[:-1].isdigit()
    ):
        fail("memory.current contained malformed data")
    value = int(payload[:-1])
    if value < 0:
        fail("memory.current contained a negative value")
    return value


def publish_number(descriptor: int, value: int) -> None:
    payload = f"{value}\n".encode("ascii")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    written = os.write(descriptor, payload)
    if written != len(payload):
        fail("could not publish a complete sample")
    os.fsync(descriptor)


def stop_requested(path: str) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != 0
    ):
        fail("stop marker metadata is unsafe")
    return True


def main() -> None:
    if len(sys.argv) != 5:
        fail("expected SOURCE OUTPUT READY STOP arguments")
    source_path, output_path, ready_path, stop_path = sys.argv[1:]
    for path, label in (
        (source_path, "source"),
        (output_path, "output"),
        (ready_path, "ready"),
        (stop_path, "stop"),
    ):
        require_absolute(path, label)
    control_parent = os.path.dirname(output_path)
    if any(
        os.path.dirname(path) != control_parent
        for path in (ready_path, stop_path)
    ):
        fail("control files do not share one directory")
    for path, label in (
        (output_path, "output"),
        (ready_path, "ready"),
        (stop_path, "stop"),
    ):
        require_absent(path, label)

    source_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_fd = os.open(source_path, source_flags)
    ready_fd = -1
    try:
        metadata = os.fstat(source_fd)
        if not stat.S_ISREG(metadata.st_mode):
            fail("source is not a regular cgroup control file")

        peak = read_sample(source_fd)
        ready_fd = os.open(
            ready_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        publish_number(ready_fd, peak)

        deadline = time.monotonic() + MAX_RUNTIME_SECONDS
        while not stopping and not stop_requested(stop_path):
            if time.monotonic() >= deadline:
                fail("stop marker was not received within the runtime bound")
            time.sleep(SAMPLE_INTERVAL_SECONDS)
            sample = read_sample(source_fd)
            if sample > peak:
                peak = sample
                publish_number(ready_fd, peak)

        sample = read_sample(source_fd)
        if sample > peak:
            peak = sample
            publish_number(ready_fd, peak)

        output_fd = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            publish_number(output_fd, peak)
        finally:
            os.close(output_fd)
    finally:
        if ready_fd >= 0:
            os.close(ready_fd)
        os.close(source_fd)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    main()

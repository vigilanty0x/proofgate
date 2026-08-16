"""Race-resistant, no-follow reads anchored beneath an evaluation root."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import stat
from typing import BinaryIO, Iterator


class UnsafePathError(OSError):
    """A path cannot be opened without crossing a symlink or non-directory."""


class FileBoundError(OSError):
    """A regular file exceeds the caller's explicit byte bound."""

    def __init__(self, maximum: int, observed: int):
        super().__init__(f"file exceeds {maximum} bytes")
        self.maximum = maximum
        self.observed = observed


@dataclass(frozen=True)
class FileDigest:
    size: int
    sha256: str


def _absolute_parts(path: str | Path) -> tuple[str, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    anchor = absolute.anchor
    if not anchor:
        raise UnsafePathError("evaluation root has no filesystem anchor")
    return tuple(part for part in absolute.parts if part != anchor)


def _relative_parts(relative: str | Path, *, allow_root: bool = False) -> tuple[str, ...]:
    value = os.fspath(relative)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise UnsafePathError("path must be a non-empty string without NUL bytes")
    normalized = value.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("//") or (
        len(normalized) >= 2 and normalized[1] == ":"
    ):
        raise UnsafePathError("path must be relative to the evaluation root")
    parts = tuple(part for part in candidate.parts if part not in {"", "."})
    if ".." in parts:
        raise UnsafePathError("path must not traverse parent directories")
    if not parts and not allow_root:
        raise UnsafePathError("path must name a file below the evaluation root")
    return parts


def _unsafe_open_error(exc: OSError, *, label: str) -> OSError:
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return UnsafePathError(f"{label} crosses a symlink or non-directory component")
    return exc


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_directory_component(parent_fd: int, component: str, *, label: str) -> int:
    try:
        descriptor = os.open(component, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _unsafe_open_error(exc, label=label) from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise UnsafePathError(f"{label} is not a directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_root(root: str | Path) -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        # The fallback performs component checks and handle identity validation,
        # but POSIX openat is the only path used by supported release CI.
        return _open_root_fallback(root)
    try:
        descriptor = os.open(os.path.abspath(os.sep), _directory_flags())
    except OSError as exc:
        raise UnsafePathError(f"cannot anchor evaluation root: {exc}") from exc
    try:
        for component in _absolute_parts(root):
            next_descriptor = _open_directory_component(
                descriptor,
                component,
                label="evaluation root",
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_root_fallback(root: str | Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(root)))
    current = Path(absolute.anchor)
    for component in _absolute_parts(absolute):
        current = current / component
        try:
            if current.is_symlink():
                raise UnsafePathError("evaluation root crosses a symlink component")
        except OSError as exc:
            raise UnsafePathError(f"cannot inspect evaluation root: {exc}") from exc
    try:
        descriptor = os.open(absolute, _directory_flags())
    except OSError as exc:
        raise _unsafe_open_error(exc, label="evaluation root") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise UnsafePathError("evaluation root is not a directory")
    return descriptor


def _open_directory_under_root(root: str | Path, relative: str | Path) -> int:
    descriptor = _open_root(root)
    try:
        for component in _relative_parts(relative, allow_root=True):
            next_descriptor = _open_directory_component(descriptor, component, label=os.fspath(relative))
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def open_regular_file(root: str | Path, relative: str | Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one regular file beneath ``root`` without following any symlink.

    Every directory component is opened relative to its already-open parent.  The
    returned file descriptor therefore remains bound to the inspected inode even
    if an attacker concurrently replaces a pathname.
    """

    parts = _relative_parts(relative)
    directory_fd = _open_root(root)
    file_fd: int | None = None
    try:
        for component in parts[:-1]:
            next_fd = _open_directory_component(directory_fd, component, label=os.fspath(relative))
            os.close(directory_fd)
            directory_fd = next_fd
        try:
            file_fd = os.open(parts[-1], _file_flags(), dir_fd=directory_fd)
        except OSError as exc:
            raise _unsafe_open_error(exc, label=os.fspath(relative)) from exc
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError(f"{relative} is not a regular file")
        handle = os.fdopen(file_fd, "rb", closefd=True)
        file_fd = None
        try:
            yield handle, info
        finally:
            handle.close()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def stat_regular_file(root: str | Path, relative: str | Path) -> os.stat_result:
    with open_regular_file(root, relative) as (_handle, info):
        return info


def read_regular_file(root: str | Path, relative: str | Path, *, maximum: int) -> bytes:
    if type(maximum) is not int or maximum < 0:
        raise ValueError("maximum must be a non-negative integer")
    with open_regular_file(root, relative) as (handle, info):
        if info.st_size > maximum:
            raise FileBoundError(maximum, info.st_size)
        data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise FileBoundError(maximum, len(data))
        return data


def hash_regular_file(root: str | Path, relative: str | Path, *, maximum: int) -> FileDigest:
    if type(maximum) is not int or maximum < 0:
        raise ValueError("maximum must be a non-negative integer")
    digest = hashlib.sha256()
    size = 0
    with open_regular_file(root, relative) as (handle, info):
        if info.st_size > maximum:
            raise FileBoundError(maximum, info.st_size)
        while True:
            chunk = handle.read(min(1024 * 1024, maximum - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise FileBoundError(maximum, size)
            digest.update(chunk)
    return FileDigest(size=size, sha256=digest.hexdigest())


def walk_regular_files(root: str | Path, relative: str | Path, *, maximum_entries: int) -> list[str]:
    """Return regular files below a directory, refusing every symlink encountered."""

    if type(maximum_entries) is not int or maximum_entries < 1:
        raise ValueError("maximum_entries must be a positive integer")
    base_parts = _relative_parts(relative, allow_root=True)
    root_fd = _open_directory_under_root(root, relative)
    found: list[str] = []
    seen_entries = 0

    def visit(directory_fd: int, nested: tuple[str, ...]) -> None:
        nonlocal seen_entries
        try:
            names = sorted(entry.name for entry in os.scandir(directory_fd))
        except OSError as exc:
            raise UnsafePathError(f"cannot inventory directory safely: {exc}") from exc
        for name in names:
            seen_entries += 1
            if seen_entries > maximum_entries:
                raise FileBoundError(maximum_entries, seen_entries)
            try:
                child_fd = os.open(name, _file_flags(), dir_fd=directory_fd)
            except OSError as exc:
                raise _unsafe_open_error(exc, label="/".join((*base_parts, *nested, name))) from exc
            try:
                info = os.fstat(child_fd)
                if stat.S_ISLNK(info.st_mode):
                    raise UnsafePathError("directory inventory encountered a symlink")
                if stat.S_ISDIR(info.st_mode):
                    visit(child_fd, (*nested, name))
                elif stat.S_ISREG(info.st_mode):
                    found.append("/".join((*nested, name)))
            finally:
                os.close(child_fd)

    try:
        visit(root_fd, ())
    finally:
        os.close(root_fd)
    return found

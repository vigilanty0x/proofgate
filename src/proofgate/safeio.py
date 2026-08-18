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
    """A path cannot be opened without crossing an untrusted link or non-directory."""


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
    if len(normalized) >= 2 and normalized[1] == ":":
        raise UnsafePathError("path must be relative to the evaluation root")
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("//"):
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
        | getattr(os, "O_BINARY", 0)
    )


def _is_link_or_reparse(info: os.stat_result) -> bool:
    """Return true for POSIX symlinks and Windows reparse points/junctions."""

    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _trusted_root(root: str | Path) -> Path:
    """Resolve the caller-supplied trust anchor before no-follow traversal.

    The evaluation root itself is the trust boundary.  Resolving it once permits
    normal platform aliases such as macOS ``/var -> /private/var`` while every
    evidence path *below* that root remains no-follow/fail-closed.
    """

    value = os.path.abspath(os.fspath(root))
    return Path(os.path.realpath(value))


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
        raise UnsafePathError("descriptor-relative root opens are unavailable on this platform")
    trusted = _trusted_root(root)
    try:
        descriptor = os.open(os.path.abspath(os.sep), _directory_flags())
    except OSError as exc:
        raise UnsafePathError(f"cannot anchor evaluation root: {exc}") from exc
    try:
        for component in _absolute_parts(trusted):
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


def _fallback_root(root: str | Path) -> Path:
    trusted = _trusted_root(root)
    info = os.stat(trusted)
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("evaluation root is not a directory")
    return trusted


def _fallback_path(
    root: str | Path,
    relative: str | Path,
    *,
    require_directory: bool = False,
) -> Path:
    """Validate a path on platforms without secure ``openat`` directory FDs.

    Every untrusted component is inspected without following links/reparse
    points.  The root itself is already a resolved caller-supplied trust anchor.
    """

    root_path = _fallback_root(root)
    parts = _relative_parts(relative, allow_root=require_directory)
    current = root_path
    for index, component in enumerate(parts):
        current = current / component
        info = os.lstat(current)
        if _is_link_or_reparse(info):
            raise UnsafePathError(f"{relative} crosses a symlink or reparse point")
        if index < len(parts) - 1 or require_directory:
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafePathError(f"{relative} crosses a non-directory component")

    # A second containment check catches platform path aliases and case folding.
    resolved_root = os.path.normcase(os.path.realpath(os.fspath(root_path)))
    resolved_target = os.path.normcase(os.path.realpath(os.fspath(current)))
    try:
        common = os.path.commonpath([resolved_root, resolved_target])
    except ValueError as exc:
        raise UnsafePathError("path is not on the evaluation root volume") from exc
    if os.path.normcase(common) != resolved_root:
        raise UnsafePathError("path escapes the evaluation root")
    return current


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
def _open_regular_file_fallback(
    root: str | Path,
    relative: str | Path,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    target = _fallback_path(root, relative)
    before = os.lstat(target)
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise UnsafePathError(f"{relative} is not a regular no-follow file")
    try:
        descriptor = os.open(target, _file_flags())
    except OSError as exc:
        raise _unsafe_open_error(exc, label=os.fspath(relative)) from exc
    handle: BinaryIO | None = None
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise UnsafePathError(f"{relative} is not a regular file")
        # Revalidate the pathname after opening.  Where stable inode identifiers
        # are available, bind the pathname check to the opened handle as well.
        second = os.lstat(_fallback_path(root, relative))
        if _is_link_or_reparse(second):
            raise UnsafePathError(f"{relative} became a link during open")
        if before.st_dev and before.st_ino and after.st_dev and after.st_ino:
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise UnsafePathError(f"{relative} changed during open")
        if second.st_dev and second.st_ino and after.st_dev and after.st_ino:
            if (second.st_dev, second.st_ino) != (after.st_dev, after.st_ino):
                raise UnsafePathError(f"{relative} changed during verification")
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        yield handle, after
    finally:
        if handle is not None:
            handle.close()
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def open_regular_file(root: str | Path, relative: str | Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one regular file beneath ``root`` without following untrusted links.

    POSIX uses descriptor-relative no-follow traversal.  Other platforms use a
    conservative component/reparse validation fallback plus handle identity
    checks where the platform exposes stable identifiers.
    """

    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        with _open_regular_file_fallback(root, relative) as opened:
            yield opened
        return

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


def _walk_regular_files_fallback(
    root: str | Path,
    relative: str | Path,
    *,
    maximum_entries: int,
) -> list[str]:
    base = _fallback_path(root, relative, require_directory=True)
    found: list[str] = []
    seen_entries = 0

    def visit(directory: Path, nested: tuple[str, ...]) -> None:
        nonlocal seen_entries
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise UnsafePathError(f"cannot inventory directory safely: {exc}") from exc
        try:
            for entry in entries:
                seen_entries += 1
                if seen_entries > maximum_entries:
                    raise FileBoundError(maximum_entries, seen_entries)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise UnsafePathError(f"cannot inspect directory entry safely: {exc}") from exc
                if _is_link_or_reparse(info):
                    raise UnsafePathError("directory inventory encountered a symlink or reparse point")
                child = directory / entry.name
                if stat.S_ISDIR(info.st_mode):
                    # Revalidate the component before descending so a replacement
                    # becomes a blockage instead of being followed.
                    _fallback_path(root, child.relative_to(_fallback_root(root)), require_directory=True)
                    visit(child, (*nested, entry.name))
                elif stat.S_ISREG(info.st_mode):
                    found.append("/".join((*nested, entry.name)))
        finally:
            for entry in entries:
                try:
                    entry.close()  # type: ignore[attr-defined]
                except (AttributeError, OSError):
                    pass

    visit(base, ())
    return found


def walk_regular_files(root: str | Path, relative: str | Path, *, maximum_entries: int) -> list[str]:
    """Return regular files below a directory, refusing every link encountered."""

    if type(maximum_entries) is not int or maximum_entries < 1:
        raise ValueError("maximum_entries must be a positive integer")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        return _walk_regular_files_fallback(root, relative, maximum_entries=maximum_entries)

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

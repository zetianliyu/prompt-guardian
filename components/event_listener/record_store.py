"""Writable-path resolution and a shared record store.

Why this module exists: LangBot installs a plugin as a **verified read-only
artifact**. ``PluginArtifactStore.install_package()`` calls
``_make_tree_read_only()``, which chmods the extracted tree to ``0o555``/``0o444``,
and the shared worker profile additionally bind-mounts that tree read-only at
``/plugin`` inside nsjail while setting ``--cwd /plugin``. A relative path such
as ``review_audit.jsonl`` therefore lands inside a read-only tree and every
append fails with ``PermissionError`` / ``OSError: Read-only file system``.

The writable paths the Runtime gives a plugin worker are ``/data`` (the
per-installation data directory), ``$HOME`` and ``$TMPDIR``. This module picks
the first one that survives a real write probe, and keeps the most recent rows
in memory as well so the ``pg`` command can show them even when no directory is
writable at all. That command is the only working read-back channel: the
Runtime never launches a worker with a captured stderr pipe, so
``PluginLogBuffer.start_reader()`` is never called and the WebUI plugin log
panel cannot display plugin output.
"""

from __future__ import annotations

import collections
import json
import os
import tempfile
from typing import Any

ENV_DATA_DIR = "PROMPT_GUARDIAN_DATA_DIR"
RUNTIME_FILE_STORAGE_ENV = "LANGBOT_PLUGIN_FILE_STORAGE_DIR"
JAIL_DATA_DIR = "/data"

KIND_REVIEW = "review"
KIND_INCIDENT = "incident"

DEFAULT_REVIEW_NAME = "review_audit.jsonl"
DEFAULT_INCIDENT_NAME = "incidents.jsonl"

MEMORY_ROWS = 200
TAIL_READ_BYTES = 256 * 1024

_memory: dict[str, collections.deque] = {}
_resolved: tuple[str, str] | None = None
_rejected: list[tuple[str, str, str]] = []


def plugin_root() -> str:
    """The plugin directory: two levels above ``components/event_listener/``."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))


def probe_writable(directory: str, may_create: bool = True) -> str:
    """Return ``""`` when *directory* accepts a file, else a short error string.

    A real create/unlink probe, not ``os.access``: the read-only artifact tree
    and a read-only bind mount both report differently through ``access()``
    depending on the mount and the effective uid.
    """
    if not directory:
        return "empty path"
    try:
        if not os.path.isdir(directory):
            if not may_create:
                return "directory does not exist"
            os.makedirs(directory, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix=".pg-probe-", dir=directory)
        os.close(fd)
        os.unlink(probe)
        return ""
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def candidates() -> list[tuple[str, str, bool]]:
    """``(label, directory, may_create)`` in preference order.

    ``/data`` and ``$HOME`` are never created: outside the sandbox those names
    point at the host filesystem root and creating them would be wrong.
    """
    out: list[tuple[str, str, bool]] = []
    override = (os.environ.get(ENV_DATA_DIR) or "").strip()
    if override:
        out.append((f"环境变量 {ENV_DATA_DIR}", override, True))
    out.append(("运行时数据目录 /data", JAIL_DATA_DIR, False))
    transfer = (os.environ.get(RUNTIME_FILE_STORAGE_ENV) or "").strip()
    if transfer:
        install_root = os.path.dirname(transfer.rstrip("/\\"))
        if install_root:
            out.append(("安装目录下的 data/", os.path.join(install_root, "data"), True))
    root = plugin_root()
    out.append(("插件目录", root, False))
    home = (os.environ.get("HOME") or "").strip()
    if home:
        out.append(("HOME", home, False))
    out.append(("临时目录", tempfile.gettempdir(), False))
    return out


def resolve_dir(refresh: bool = False) -> tuple[str, str]:
    """Return ``(directory, label)`` of the first writable candidate.

    Cached, because every blocked message would otherwise re-probe the whole
    list. Pass ``refresh=True`` after the operator changes the environment.
    """
    global _resolved, _rejected
    if _resolved is not None and not refresh:
        return _resolved
    rejected: list[tuple[str, str, str]] = []
    chosen = ("", "")
    seen: set[str] = set()
    for label, directory, may_create in candidates():
        try:
            key = os.path.abspath(directory)
        except Exception:
            continue
        if not key or key in seen:
            continue
        seen.add(key)
        error = probe_writable(directory, may_create)
        if error:
            rejected.append((label, directory, error))
            continue
        chosen = (directory, label)
        break
    _resolved = chosen
    _rejected = rejected
    return chosen


def rejected_dirs() -> list[tuple[str, str, str]]:
    """``(label, directory, reason)`` for every candidate that failed the probe."""
    if _resolved is None:
        resolve_dir()
    return list(_rejected)


def resolve_path(configured: str, default_name: str) -> tuple[str, str]:
    """Return ``(path, note)`` for a configured record file.

    An absolute path is honoured when its parent accepts a write. A relative
    one is reduced to its basename and placed in the auto-resolved directory —
    keeping it relative to the plugin directory is exactly the bug this module
    exists to fix.
    """
    name = (configured or "").strip()
    note = ""
    if name and os.path.isabs(name):
        parent = os.path.dirname(name) or os.sep
        error = probe_writable(parent)
        if not error:
            return name, ""
        note = f"配置的绝对路径不可写（{error}），已改用自动目录"
    name = os.path.basename(name) or default_name
    directory, _label = resolve_dir()
    if not directory:
        return "", note or "没有找到任何可写目录"
    return os.path.join(directory, name), note


def remember(kind: str, row: dict[str, Any]) -> None:
    """Keep *row* in the in-process ring buffer for *kind*."""
    bucket = _memory.get(kind)
    if bucket is None:
        bucket = collections.deque(maxlen=MEMORY_ROWS)
        _memory[kind] = bucket
    bucket.append(row)


def memory_count(kind: str) -> int:
    return len(_memory.get(kind) or ())


def append(
    kind: str,
    row: dict[str, Any],
    configured: str,
    default_name: str,
) -> tuple[str, str]:
    """Remember *row* and append it as JSONL. Returns ``(path, error)``.

    The ring buffer is filled first and unconditionally, so a record is still
    readable from chat when no directory turns out to be writable.
    """
    remember(kind, row)
    path, note = resolve_path(configured, default_name)
    if not path:
        return "", note or "没有找到任何可写目录"
    line = json.dumps(row, ensure_ascii=False) + "\n"
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
    except Exception as exc:
        return path, f"{type(exc).__name__}: {exc}"
    return path, note


def tail(
    kind: str,
    limit: int,
    configured: str,
    default_name: str,
) -> tuple[list[dict[str, Any]], str, str]:
    """Return ``(rows, source, path)``, oldest first. *source* is file/memory."""
    path, _note = resolve_path(configured, default_name)
    if path and os.path.isfile(path):
        rows = _read_tail(path, limit)
        if rows:
            return rows, "file", path
    bucket = list(_memory.get(kind) or ())
    return bucket[-limit:] if limit > 0 else bucket, "memory", path


def _read_tail(path: str, limit: int) -> list[dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - TAIL_READ_BYTES))
            chunk = fh.read()
    except Exception:
        return []
    lines = chunk.decode("utf-8", "replace").splitlines()
    if size > TAIL_READ_BYTES and lines:
        # The first line of the window is very likely cut in half.
        lines = lines[1:]
    rows: list[dict[str, Any]] = []
    for line in lines[-limit:] if limit > 0 else lines:
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def file_stats(path: str) -> tuple[int, int]:
    """``(byte_size, line_count)`` for *path*; ``(-1, -1)`` when unreadable."""
    if not path or not os.path.isfile(path):
        return -1, -1
    try:
        size = os.path.getsize(path)
        count = 0
        with open(path, "rb") as fh:
            for _ in fh:
                count += 1
        return size, count
    except Exception:
        return -1, -1


def runtime_facts() -> dict[str, str]:
    """Facts an operator needs to locate the files, read from this process."""
    root = plugin_root()
    try:
        cwd = os.getcwd()
    except Exception as exc:
        cwd = f"<unavailable: {type(exc).__name__}>"
    return {
        "cwd": cwd,
        "plugin_root": root,
        "plugin_root_writable": "否" if probe_writable(root, False) else "是",
        "home": os.environ.get("HOME", "") or "<unset>",
        "tmpdir": tempfile.gettempdir(),
        "sandboxed": "是" if os.path.isdir(JAIL_DATA_DIR) else "否/未知",
    }

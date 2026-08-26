"""Normalize operator-supplied admin IDs.

LangBot's plugin config UI and the session monitor copy-paste both produce
shapes this plugin used to mishandle:

* ``array[string]`` sometimes arrives as a raw string. Iterating it then
  sends one private message per *character*.
* Session monitor lines look like
  ``C2C_MESSAGE_CREATE, person 4D59667BBE54DD358CB83E0C242C485B``.
  That whole string is not a valid ``target_id``.
* QQ official bots need the user openid, not the QQ number.

This module has no LangBot SDK dependency so it can be unit-tested offline.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Session-monitor / pipeline labels the operator is likely to paste.
_EVENT_PREFIX = re.compile(
    r"^\s*(?:C2C_MESSAGE_CREATE|GROUP_AT_MESSAGE_CREATE|AT_MESSAGE_CREATE|"
    r"DIRECT_MESSAGE_CREATE|GROUP_MESSAGE_CREATE|FRIEND_MESSAGE)\s*,\s*",
    re.IGNORECASE,
)
_KIND_PREFIX = re.compile(
    r"^\s*(?:person|c2c|user|friend|private|member)\s*[,:：]\s*",
    re.IGNORECASE,
)
_KIND_THEN_ID = re.compile(
    r"(?:person|c2c|user|friend|private)\s+([A-Za-z0-9_-]{5,})",
    re.IGNORECASE,
)
_SPLIT_IDS = re.compile(r"[\n\r,;；、]+")
_IGNORED_TOKENS = {
    "C2C_MESSAGE_CREATE",
    "GROUP_AT_MESSAGE_CREATE",
    "AT_MESSAGE_CREATE",
    "DIRECT_MESSAGE_CREATE",
    "GROUP_MESSAGE_CREATE",
    "FRIEND_MESSAGE",
    "PERSON",
    "C2C",
    "USER",
    "FRIEND",
    "PRIVATE",
    "MEMBER",
    "GROUP",
}
_BARE_ID = re.compile(r"^[A-Za-z0-9_-]{5,}$")

def needs_group_fallback(mode: str, private_ok: bool, adapter: str) -> bool:
    """Decide whether the group should carry the admin ticket."""
    mode = (mode or "private_then_group").strip().lower()
    if mode == "group":
        return True
    if mode != "private_then_group":
        return False
    if private_ok:
        return False
    return True



def is_qqofficial_adapter(adapter: str) -> bool:
    name = (adapter or "").strip().lower().replace("_", "").replace("-", "")
    return name in {"qqofficial", "officialqq", "qqbotofficial"} or "qqofficial" in name


def adapter_from_bot_info(info: Any) -> str:
    if not isinstance(info, dict):
        return "unknown"
    bot = info.get("bot") if isinstance(info.get("bot"), dict) else info
    if not isinstance(bot, dict):
        return "unknown"
    for key in ("adapter", "adapter_name", "adapterName"):
        value = bot.get(key)
        if value:
            return str(value).strip()
    return "unknown"


def coerce_admin_ids(raw: Any) -> list[str]:
    """Turn whatever the config page stored into a list of target IDs."""
    collected: list[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        if item and item not in seen:
            seen.add(item)
            collected.append(item)

    for token in _flatten(raw):
        for extracted in extract_ids_from_token(token):
            add(extracted)
    return collected


def extract_ids_from_token(token: str) -> list[str]:
    text = (token or "").strip().strip("\"'“”")
    if not text:
        return []

    text = _EVENT_PREFIX.sub("", text).strip()
    kind_match = _KIND_THEN_ID.search(text)
    if kind_match:
        return [kind_match.group(1)]

    text = _KIND_PREFIX.sub("", text).strip()
    if text.upper() in _IGNORED_TOKENS:
        return []
    if _BARE_ID.fullmatch(text):
        return [text]
    if text:
        return [text]
    return []


def _flatten(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        if stripped[0] in "[{":
            try:
                parsed = json.loads(stripped)
            except (json.JSONDecodeError, TypeError, ValueError):
                parsed = None
            if parsed is not None:
                return _flatten(parsed)
        # Keep "C2C_MESSAGE_CREATE, person OPENID" as one token so the
        # comma does not turn the event name into a fake user id.
        if _EVENT_PREFIX.match(stripped) or _KIND_THEN_ID.search(stripped):
            return [stripped]
        return [part.strip() for part in _SPLIT_IDS.split(stripped) if part.strip()]
    if isinstance(raw, dict):
        return _flatten(list(raw.values()))
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            out.extend(_flatten(item))
        return out
    text = str(raw).strip()
    return [text] if text else []

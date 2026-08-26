"""Extract non-secret bot metadata needed by optional direct transports."""

from __future__ import annotations

from typing import Any


_ID_KEYS = ("app_id", "appId", "client_id", "clientId")
_SECRET_KEYS = (
    "app_secret",
    "appSecret",
    "client_secret",
    "clientSecret",
    "secret",
)
_NESTED_KEYS = ("bot", "config", "credentials", "credential", "account", "data")


def _first_string(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def qqofficial_credentials(info: Any) -> tuple[str, str]:
    """Best-effort read of credentials already exposed by LangBot.

    The plugin never logs or persists the secret. Older LangBot runtimes expose
    only adapter metadata, in which case the returned pair is empty and the
    legacy manifest fields remain the fallback. We deliberately do not scrape
    arbitrary config values: a WeChat token or unrelated secret must not be
    sent to QQ's token endpoint.
    """
    visited: set[int] = set()

    def walk(value: Any) -> tuple[str, str]:
        if not isinstance(value, dict) or id(value) in visited:
            return "", ""
        visited.add(id(value))
        app_id = _first_string(value, _ID_KEYS)
        secret = _first_string(value, _SECRET_KEYS)
        if app_id and secret:
            return app_id, secret
        for key in _NESTED_KEYS:
            found = walk(value.get(key))
            if found[0] and found[1]:
                return found
        return "", ""

    return walk(info)

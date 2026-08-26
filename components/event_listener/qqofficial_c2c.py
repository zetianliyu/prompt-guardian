"""Proactive C2C send for QQ official bots.

LangBot's ``qqofficial`` adapter implements ``reply_message`` (used for the
group intercept reply) but its ``send_message`` is a no-op (``pass``). The
plugin therefore cannot private-message an admin through the SDK on that
adapter. This helper talks to the QQ Bot HTTP API directly when the operator
supplies AppID + Secret.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

TOKEN_URL = "https://bots.qq.com/app/getAppAccessToken"
PROD_API = "https://api.sgroup.qq.com"
SANDBOX_API = "https://sandbox.api.sgroup.qq.com"


class QQOfficialC2CSender:
    def __init__(self) -> None:
        self._token: str = ""
        self._token_expire_at: float = 0.0
        self._token_app_id: str = ""

    async def send(
        self,
        *,
        app_id: str,
        secret: str,
        openid: str,
        content: str,
        sandbox: bool = False,
    ) -> None:
        # Imported lazily so unit tests can stub ``_http_json`` without
        # pulling asyncio into import-time.
        import asyncio

        token = await asyncio.to_thread(self._access_token, app_id, secret)
        base = SANDBOX_API if sandbox else PROD_API
        url = f"{base}/v2/users/{openid}/messages"
        status, body = await asyncio.to_thread(
            self._http_json,
            "POST",
            url,
            {
                "Authorization": f"QQBot {token}",
                "Content-Type": "application/json",
            },
            {"content": content, "msg_type": 0},
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"QQ C2C HTTP {status}: {body[:500]}")

    def _access_token(self, app_id: str, secret: str) -> str:
        now = time.time()
        if (
            self._token
            and self._token_app_id == app_id
            and now < self._token_expire_at - 60
        ):
            return self._token
        status, body = self._http_json(
            "POST",
            TOKEN_URL,
            {"Content-Type": "application/json"},
            {"appId": app_id, "clientSecret": secret},
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"QQ token HTTP {status}: {body[:500]}")
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"QQ token 返回不是 JSON: {body[:200]}") from exc
        token = str(data.get("access_token") or "")
        if not token:
            raise RuntimeError(f"QQ token 响应无 access_token: {body[:300]}")
        try:
            ttl = int(data.get("expires_in") or 7200)
        except (TypeError, ValueError):
            ttl = 7200
        self._token = token
        self._token_app_id = app_id
        self._token_expire_at = now + max(ttl, 60)
        return token

    def _http_json(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> tuple[int, str]:
        raw = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=raw, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return int(response.status), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace") if exc.fp else str(exc)
            return int(exc.code), body

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any
from plugin_log import log

from langbot_plugin.api.entities.builtin.platform import message as platform_message

from admin_ids import coerce_admin_ids, is_qqofficial_adapter
from qqofficial_c2c import QQOfficialC2CSender

CST = timezone(timedelta(hours=8))
QUESTION_LIMIT = 1500


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


@dataclass
class NotifyResult:
    admin_ids: list[str] = field(default_factory=list)
    bot_uuid: str = ""
    adapter: str = ""
    private_delivered: list[str] = field(default_factory=list)
    private_errors: list[str] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def private_ok(self) -> bool:
        return bool(self.private_delivered)


class IncidentRecorder:
    """Append-only JSONL tickets + optional admin private-message notify."""

    def __init__(self, plugin: Any) -> None:
        self.plugin = plugin
        self._lock = asyncio.Lock()
        self._qq_c2c = QQOfficialC2CSender()

    def _resolve_path(self, incidents_path: str) -> str:
        path = (incidents_path or "incidents.jsonl").strip() or "incidents.jsonl"
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base, path)

    def build_incident(
        self,
        *,
        platform: str,
        bot_uuid: str,
        group_id: str,
        group_name: str,
        sender_id: str,
        sender_name: str,
        question: str,
        ptd: dict[str, Any],
        llm: dict[str, Any] | None,
        action: str = "blocked",
    ) -> dict[str, Any]:
        llm = llm or {}
        return {
            "time": now_iso(),
            "platform": _safe_str(platform, "unknown"),
            "bot_uuid": _safe_str(bot_uuid),
            "group_id": _safe_str(group_id),
            "group_name": _safe_str(group_name, _safe_str(group_id)),
            "sender_id": _safe_str(sender_id),
            "sender_name": _safe_str(sender_name, _safe_str(sender_id)),
            "question": question,
            "ptd_score": int(ptd.get("score") or 0),
            "ptd_severity": _safe_str(ptd.get("severity"), "unknown"),
            "ptd_reason": _safe_str(ptd.get("reason")),
            "llm_is_injection": llm.get("is_injection"),
            "llm_confidence": llm.get("confidence"),
            "llm_reason": _safe_str(llm.get("reason")),
            "action": action,
        }

    def format_admin_message(self, incident: dict[str, Any]) -> str:
        question = incident.get("question") or ""
        if len(question) > QUESTION_LIMIT:
            question = question[:QUESTION_LIMIT] + "\n…(已截断)"
        return (
            "【提示词注入标记】需人工客服处理\n"
            f"平台: {incident.get('platform')}\n"
            f"群: {incident.get('group_name')}（{incident.get('group_id')}）\n"
            f"用户: {incident.get('sender_name')}（{incident.get('sender_id')}）\n"
            f"时间: {incident.get('time')}\n"
            f"规则: severity={incident.get('ptd_severity')} score={incident.get('ptd_score')}\n"
            f"LLM: injection={incident.get('llm_is_injection')} conf={incident.get('llm_confidence')}\n"
            f"原因: {incident.get('llm_reason') or incident.get('ptd_reason') or '-'}\n"
            "原文:\n"
            f"{question}"
        )

    async def append_jsonl(self, incidents_path: str, incident: dict[str, Any]) -> str:
        path = self._resolve_path(incidents_path)
        line = json.dumps(incident, ensure_ascii=False) + "\n"
        async with self._lock:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        return path

    def _target_types(self, adapter: str) -> list[str]:
        if is_qqofficial_adapter(adapter):
            return ["c2c", "person"]
        return ["person", "c2c"]

    async def _send_via_sdk(
        self,
        *,
        bot_uuid: str,
        adapter: str,
        uid: str,
        chain: Any,
    ) -> None:
        last_error: Exception | None = None
        for target_type in self._target_types(adapter):
            try:
                await self.plugin.send_message(
                    bot_uuid=bot_uuid,
                    target_type=target_type,
                    target_id=uid,
                    message_chain=chain,
                )
                return
            except Exception as exc:
                last_error = exc
                log.warning(
                    f"send_message target_type={target_type} "
                    f"id={uid} failed: {exc}"
                )
        if last_error is not None:
            raise last_error

    async def notify_admins(
        self,
        *,
        bot_uuid: str,
        admin_user_ids: Any,
        incident: dict[str, Any],
        adapter: str = "",
        qqofficial_app_id: str = "",
        qqofficial_secret: str = "",
        qqofficial_sandbox: bool = False,
        trust_qqofficial_send_message: bool = False,
    ) -> NotifyResult:
        result = NotifyResult(
            admin_ids=coerce_admin_ids(admin_user_ids),
            bot_uuid=_safe_str(bot_uuid),
            adapter=_safe_str(adapter, "unknown"),
        )
        if not result.admin_ids:
            result.skipped_reason = (
                "管理员用户 ID 为空或无法解析。"
                "请在插件配置里填写会话监控里 person 后面那串 openid，"
                "不要填流水线「管理员」开关，也不要整段粘贴 C2C_MESSAGE_CREATE。"
            )
            log.warning(f"skip private notify: {result.skipped_reason}")
            return result
        if not result.bot_uuid:
            result.skipped_reason = "bot_uuid 为空，无法主动发私聊。"
            log.warning(f"skip private notify: {result.skipped_reason}")
            return result

        log.info(
            f"notifying admins={result.admin_ids} "
            f"adapter={result.adapter} bot={result.bot_uuid}"
        )
        text = self.format_admin_message(incident)
        chain = platform_message.MessageChain([platform_message.Plain(text=text)])
        official = is_qqofficial_adapter(result.adapter)
        http_ready = official and bool(qqofficial_app_id) and bool(qqofficial_secret)

        for uid in result.admin_ids:
            delivered = False
            errors: list[str] = []

            if http_ready:
                try:
                    await self._qq_c2c.send(
                        app_id=qqofficial_app_id,
                        secret=qqofficial_secret,
                        openid=uid,
                        content=text,
                        sandbox=qqofficial_sandbox,
                    )
                    delivered = True
                    log.info(f"QQ official C2C delivered to {uid}")
                except Exception as exc:
                    errors.append(f"qq-http:{exc}")
                    log.error(f"QQ official C2C to {uid} failed: {exc}")

            sdk_usable = (not official) or trust_qqofficial_send_message or not delivered
            if sdk_usable and not delivered:
                if official and not trust_qqofficial_send_message:
                    errors.append(
                        "qqofficial 适配器的 send_message 是空实现，"
                        "未配置 AppID/Secret 时无法主动私聊"
                    )
                else:
                    try:
                        await self._send_via_sdk(
                            bot_uuid=result.bot_uuid,
                            adapter=result.adapter,
                            uid=uid,
                            chain=chain,
                        )
                        delivered = True
                    except Exception as exc:
                        errors.append(f"sdk:{exc}")

            if delivered:
                result.private_delivered.append(uid)
            else:
                result.private_errors.append(f"{uid}: {'; '.join(errors) or 'unknown'}")

        return result

    async def record(
        self,
        *,
        incidents_path: str,
        bot_uuid: str,
        admin_user_ids: Any,
        incident: dict[str, Any],
        adapter: str = "",
        qqofficial_app_id: str = "",
        qqofficial_secret: str = "",
        qqofficial_sandbox: bool = False,
        trust_qqofficial_send_message: bool = False,
    ) -> NotifyResult:
        notify = NotifyResult()
        try:
            notify = await self.notify_admins(
                bot_uuid=bot_uuid,
                admin_user_ids=admin_user_ids,
                incident=incident,
                adapter=adapter,
                qqofficial_app_id=qqofficial_app_id,
                qqofficial_secret=qqofficial_secret,
                qqofficial_sandbox=qqofficial_sandbox,
                trust_qqofficial_send_message=trust_qqofficial_send_message,
            )
        except Exception as exc:
            log.error(f"admin notify failed: {exc}")
            notify.private_errors.append(str(exc))

        ticket = dict(incident)
        ticket["notify_admin_ids"] = notify.admin_ids
        ticket["notify_private_delivered"] = notify.private_delivered
        ticket["notify_private_errors"] = notify.private_errors
        ticket["notify_skipped"] = notify.skipped_reason
        try:
            await self.append_jsonl(incidents_path, ticket)
        except Exception as exc:
            log.error(f"write incident jsonl failed: {exc}")
        return notify

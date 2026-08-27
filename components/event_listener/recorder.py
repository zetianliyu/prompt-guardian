from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any
from plugin_log import log

from langbot_plugin.api.entities.builtin.platform import message as platform_message

from admin_ids import coerce_admin_ids, is_qqofficial_adapter
from notify_manager import (
    TRANSPORT_NONE,
    TRANSPORT_QQ_HTTP,
    TRANSPORT_SDK,
    resolve_platform,
    resolve_transport,
    validate_admin_target,
)
from qqofficial_c2c import QQOfficialC2CSender
import record_store

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
    platform: str = ""
    transport: str = ""
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
        async with self._lock:
            path, error = record_store.append(
                record_store.KIND_INCIDENT,
                incident,
                incidents_path,
                record_store.DEFAULT_INCIDENT_NAME,
            )
        if error:
            raise OSError(f"{path or '<no writable dir>'}: {error}")
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
        platform_choice: str = "auto",
        text: str = "",
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
        result.platform = resolve_platform(platform_choice, result.adapter)
        qq_ready = bool(qqofficial_app_id) and bool(qqofficial_secret)
        result.transport, transport_reason = resolve_transport(
            result.platform,
            qq_credentials_ready=qq_ready,
            trust_qqofficial_send_message=trust_qqofficial_send_message,
        )

        if not result.admin_ids:
            result.skipped_reason = (
                "管理员用户 ID 为空或无法解析。"
                "请在插件配置里填写对应平台的账号标识："
                "QQ 官方填 openid，企业微信内部应用填 userid|agentid，"
                "企微智能机器人 / 微信填该平台的用户标识。"
            )
            log.warning(f"skip private notify: {result.skipped_reason}")
            return result
        if result.transport == TRANSPORT_NONE:
            result.skipped_reason = transport_reason
            log.warning(
                f"skip private notify: platform={result.platform} {transport_reason}"
            )
            return result
        if result.transport == TRANSPORT_SDK and not result.bot_uuid:
            result.skipped_reason = "bot_uuid 为空，无法通过 LangBot 发私聊。"
            log.warning(f"skip private notify: {result.skipped_reason}")
            return result

        log.info(
            f"notifying admins={result.admin_ids} adapter={result.adapter} "
            f"platform={result.platform} transport={result.transport} "
            f"bot={result.bot_uuid or '-'}"
        )
        body = text or self.format_admin_message(incident)
        chain = platform_message.MessageChain([platform_message.Plain(text=body)])

        for uid in result.admin_ids:
            invalid = validate_admin_target(result.platform, uid)
            if invalid:
                result.private_errors.append(f"{uid}: {invalid}")
                log.warning(f"admin id rejected: {invalid}")
                continue

            try:
                if result.transport == TRANSPORT_QQ_HTTP:
                    await self._qq_c2c.send(
                        app_id=qqofficial_app_id,
                        secret=qqofficial_secret,
                        openid=uid,
                        content=body,
                        sandbox=qqofficial_sandbox,
                    )
                else:
                    await self._send_via_sdk(
                        bot_uuid=result.bot_uuid,
                        adapter=result.adapter,
                        uid=uid,
                        chain=chain,
                    )
            except Exception as exc:
                result.private_errors.append(f"{uid}: {result.transport}:{exc}")
                log.error(f"admin notify to {uid} via {result.transport} failed: {exc}")
                continue

            result.private_delivered.append(uid)
            log.info(f"admin notify delivered to {uid} via {result.transport}")

        return result

    async def record(
        self,
        *,
        incidents_path: str,
        bot_uuid: str,
        admin_user_ids: Any,
        incident: dict[str, Any],
        adapter: str = "",
        platform_choice: str = "auto",
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
                platform_choice=platform_choice,
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
        ticket["notify_platform"] = notify.platform
        ticket["notify_transport"] = notify.transport
        ticket["notify_private_delivered"] = notify.private_delivered
        ticket["notify_private_errors"] = notify.private_errors
        ticket["notify_skipped"] = notify.skipped_reason
        try:
            path = await self.append_jsonl(incidents_path, ticket)
            log.info(f"incident ticket written to {path}")
        except Exception as exc:
            log.error(f"write incident jsonl failed: {exc}")
        return notify

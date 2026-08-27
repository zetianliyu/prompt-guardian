"""``!pg`` — read Prompt Guardian's own records from a chat session.

This exists because LangBot cannot show a plugin's log output at all. The
Runtime builds the plugin worker's controller without ``capture_stderr=True``
(``worker_launcher.create_controller``), so ``process.stderr`` is ``None`` and
``PluginLogBuffer.start_reader()`` is never called — the WebUI plugin log panel
has no source to display, no matter what the plugin logs. Records are therefore
read back over the one channel a plugin fully controls: a command.

Access is limited to the configured admin ids, or to a caller LangBot itself
marks as privileged. The records quote group members verbatim, so they must not
be readable by whoever happens to type the command in a group.
"""

from __future__ import annotations

import os
import sys
from typing import Any, AsyncGenerator

from langbot_plugin.api.definition.components.command.command import Command
from langbot_plugin.api.entities.builtin.command.context import (
    CommandReturn,
    ExecuteContext,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_LISTENER_DIR = os.path.join(os.path.dirname(_HERE), "event_listener")
for _path in (_HERE, _LISTENER_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from admin_ids import coerce_admin_ids  # noqa: E402
import record_store  # noqa: E402

PRIVILEGED_LEVEL = 2
DEFAULT_ROWS = 3
MAX_ROWS = 10
RAW_CLIP = 400

HELP_TEXT = (
    "Prompt Guardian 记录查询\n"
    "!pg log [条数]     最近的复核记录（默认 3，最多 10）\n"
    "!pg tickets [条数] 最近的拦截病单\n"
    "!pg where          记录文件的实际路径与可写性诊断\n"
    "!pg stats          记录条数统计\n"
    "仅配置里的管理员可用。"
)


def _clip(value: Any, limit: int) -> str:
    text = str(value if value is not None else "")
    if len(text) <= limit:
        return text
    return text[:limit] + "…(截断)"


def _row_count(params: list[str]) -> int:
    for token in params:
        try:
            wanted = int(token)
        except (TypeError, ValueError):
            continue
        return max(1, min(MAX_ROWS, wanted))
    return DEFAULT_ROWS


def _format_review(row: dict[str, Any]) -> str:
    verdict = "拦截" if row.get("action") == "blocked" else "放行"
    llm = "未复核"
    if row.get("llm_attempted"):
        if row.get("llm_usable"):
            llm = (
                f"注入={row.get('llm_is_injection')} "
                f"置信度={row.get('llm_confidence')}"
            )
        else:
            llm = "复核输出无法解析（按 fail open 放行）"
    lines = [
        f"[{row.get('time', '')}] {verdict}",
        f"群: {row.get('group_name') or row.get('group_id') or '-'}"
        f"  用户: {row.get('sender_name') or row.get('sender_id') or '-'}",
        f"规则: {row.get('ptd_severity', '-')} {row.get('ptd_score', '-')} 分"
        f" | {_clip(row.get('ptd_reason'), 120)}",
        f"复核: {llm}",
    ]
    if row.get("llm_reason"):
        lines.append(f"复核理由: {_clip(row.get('llm_reason'), 200)}")
    if row.get("llm_raw"):
        lines.append(f"模型原始返回: {_clip(row.get('llm_raw'), RAW_CLIP)}")
    lines.append(f"原文: {_clip(row.get('question'), 300)}")
    return "\n".join(lines)


def _format_ticket(row: dict[str, Any]) -> str:
    delivered = row.get("notify_private_delivered") or []
    errors = row.get("notify_private_errors") or []
    lines = [
        f"[{row.get('time', '')}] {row.get('action', 'blocked')}",
        f"群: {row.get('group_name') or row.get('group_id') or '-'}"
        f"  用户: {row.get('sender_name') or row.get('sender_id') or '-'}",
        f"规则: {row.get('ptd_severity', '-')} {row.get('ptd_score', '-')} 分",
        f"私聊送达: {len(delivered)} 个" + (f"，失败 {len(errors)} 个" if errors else ""),
        f"原文: {_clip(row.get('question'), 300)}",
    ]
    return "\n".join(lines)


class PromptGuardianCommand(Command):
    """``!pg`` with ``log`` / ``tickets`` / ``where`` / ``stats`` subcommands."""

    def _config(self) -> dict[str, Any]:
        try:
            cfg = self.plugin.get_config() or {}
        except Exception:
            cfg = {}
        return cfg if isinstance(cfg, dict) else {}

    def _denied(self, context: ExecuteContext) -> str:
        """Return "" when the caller may read records, else a refusal message."""
        if int(getattr(context, "privilege", 0) or 0) >= PRIVILEGED_LEVEL:
            return ""
        admins = coerce_admin_ids(self._config().get("admin_user_ids"))
        sender = str(getattr(context.session, "sender_id", "") or "")
        if sender and sender in admins:
            return ""
        return (
            "只有管理员可以查看复核记录。"
            "请把你的用户 ID 填进插件配置的「管理员用户 ID」，或在 LangBot 里把该会话设为管理员。"
        )

    async def initialize(self) -> None:
        await super().initialize()

        @self.subcommand("log", help="最近的复核记录", usage="!pg log [条数]", aliases=["logs", "review"])
        async def _log(
            command: PromptGuardianCommand, context: ExecuteContext
        ) -> AsyncGenerator[CommandReturn, None]:
            denied = command._denied(context)
            if denied:
                yield CommandReturn(text=denied)
                return
            cfg = command._config()
            limit = _row_count(context.crt_params)
            rows, source, path = record_store.tail(
                record_store.KIND_REVIEW,
                limit,
                str(cfg.get("review_audit_path") or ""),
                record_store.DEFAULT_REVIEW_NAME,
            )
            if not rows:
                yield CommandReturn(
                    text=(
                        "还没有复核记录。\n"
                        "复核只在 LLM 实际被调用时才会产生记录：standby 模式下"
                        "规则判为 none 的消息不会送去复核。\n"
                        f"文件位置: {path or '<没有可写目录>'}"
                    )
                )
                return
            header = f"最近 {len(rows)} 条复核记录（来源: {'文件' if source == 'file' else '内存'}）"
            body = "\n\n".join(_format_review(row) for row in reversed(rows))
            yield CommandReturn(text=f"{header}\n\n{body}")

        @self.subcommand("tickets", help="最近的拦截病单", usage="!pg tickets [条数]", aliases=["ticket"])
        async def _tickets(
            command: PromptGuardianCommand, context: ExecuteContext
        ) -> AsyncGenerator[CommandReturn, None]:
            denied = command._denied(context)
            if denied:
                yield CommandReturn(text=denied)
                return
            cfg = command._config()
            limit = _row_count(context.crt_params)
            rows, source, path = record_store.tail(
                record_store.KIND_INCIDENT,
                limit,
                str(cfg.get("incidents_path") or ""),
                record_store.DEFAULT_INCIDENT_NAME,
            )
            if not rows:
                yield CommandReturn(
                    text=f"还没有拦截病单。\n文件位置: {path or '<没有可写目录>'}"
                )
                return
            header = f"最近 {len(rows)} 条拦截病单（来源: {'文件' if source == 'file' else '内存'}）"
            body = "\n\n".join(_format_ticket(row) for row in reversed(rows))
            yield CommandReturn(text=f"{header}\n\n{body}")

        @self.subcommand("where", help="记录文件的实际路径", usage="!pg where", aliases=["path", "paths"])
        async def _where(
            command: PromptGuardianCommand, context: ExecuteContext
        ) -> AsyncGenerator[CommandReturn, None]:
            denied = command._denied(context)
            if denied:
                yield CommandReturn(text=denied)
                return
            cfg = command._config()
            directory, label = record_store.resolve_dir(refresh=True)
            facts = record_store.runtime_facts()
            review_path, review_note = record_store.resolve_path(
                str(cfg.get("review_audit_path") or ""), record_store.DEFAULT_REVIEW_NAME
            )
            ticket_path, ticket_note = record_store.resolve_path(
                str(cfg.get("incidents_path") or ""), record_store.DEFAULT_INCIDENT_NAME
            )
            lines = [
                "记录文件位置（进程内实测，不是推测）",
                f"选用目录: {directory or '<没有可写目录>'}（{label or '无'}）",
                f"复核审计: {review_path or '-'}" + (f"  ⚠ {review_note}" if review_note else ""),
                f"拦截病单: {ticket_path or '-'}" + (f"  ⚠ {ticket_note}" if ticket_note else ""),
                "",
                f"进程工作目录: {facts['cwd']}",
                f"插件目录: {facts['plugin_root']}（可写: {facts['plugin_root_writable']}）",
                f"HOME: {facts['home']}  TMPDIR: {facts['tmpdir']}",
                f"检测到沙箱 /data: {facts['sandboxed']}",
            ]
            rejected = record_store.rejected_dirs()
            if rejected:
                lines.append("")
                lines.append("跳过的候选目录:")
                for cand_label, cand_dir, reason in rejected:
                    lines.append(f"- {cand_label} {cand_dir}: {reason}")
            yield CommandReturn(text="\n".join(lines))

        @self.subcommand("stats", help="记录条数统计", usage="!pg stats", aliases=["stat"])
        async def _stats(
            command: PromptGuardianCommand, context: ExecuteContext
        ) -> AsyncGenerator[CommandReturn, None]:
            denied = command._denied(context)
            if denied:
                yield CommandReturn(text=denied)
                return
            cfg = command._config()
            review_path, _ = record_store.resolve_path(
                str(cfg.get("review_audit_path") or ""), record_store.DEFAULT_REVIEW_NAME
            )
            ticket_path, _ = record_store.resolve_path(
                str(cfg.get("incidents_path") or ""), record_store.DEFAULT_INCIDENT_NAME
            )
            review_size, review_lines = record_store.file_stats(review_path)
            ticket_size, ticket_lines = record_store.file_stats(ticket_path)

            def describe(size: int, count: int, memory: int) -> str:
                if count < 0:
                    return f"文件不存在，内存中 {memory} 条"
                return f"文件 {count} 条 / {size} 字节，内存中 {memory} 条"

            yield CommandReturn(
                text="\n".join(
                    [
                        "记录统计",
                        "复核审计: "
                        + describe(
                            review_size,
                            review_lines,
                            record_store.memory_count(record_store.KIND_REVIEW),
                        ),
                        "拦截病单: "
                        + describe(
                            ticket_size,
                            ticket_lines,
                            record_store.memory_count(record_store.KIND_INCIDENT),
                        ),
                        f"内存最多保留 {record_store.MEMORY_ROWS} 条，插件重启后清空。",
                    ]
                )
            )

        @self.subcommand("*", help="用法", usage="!pg")
        async def _fallback(
            command: PromptGuardianCommand, context: ExecuteContext
        ) -> AsyncGenerator[CommandReturn, None]:
            unknown = context.crt_params[0] if context.crt_params else ""
            prefix = f"未知子命令: {unknown}\n\n" if unknown else ""
            yield CommandReturn(text=prefix + HELP_TEXT)

        # ``Command._execute`` dispatches on an exact key, so ``Subcommand.aliases``
        # alone never routes anything. Bind each alias to the same entry.
        for alias, target in (
            ("logs", "log"),
            ("review", "log"),
            ("ticket", "tickets"),
            ("path", "where"),
            ("paths", "where"),
            ("stat", "stats"),
            ("help", "*"),
        ):
            if target in self.registered_subcommands:
                self.registered_subcommands[alias] = self.registered_subcommands[target]

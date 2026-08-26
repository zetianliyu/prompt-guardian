from __future__ import annotations

from langbot_plugin.api.definition.plugin import BasePlugin


class PromptGuardian(BasePlugin):
    """Rule + LLM review prompt-injection guard for LangBot group chats."""

    async def initialize(self) -> None:
        await super().initialize()

    def __del__(self) -> None:
        pass

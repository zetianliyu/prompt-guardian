"""Pick and validate the transport used to reach an admin.

The routing below is taken from LangBot's own adapters
(``src/langbot/pkg/platform/sources/``), not from guesswork:

* ``qqofficial.py`` implements ``send_message`` as a bare ``pass``. The SDK call
  cannot deliver a DM at all, so QQ official bots need the direct C2C HTTP API
  and therefore an AppID/AppSecret.
* ``wecombot.py`` (WeCom smart bot), ``openclaw_weixin.py`` and
  ``wechatpad.py`` (personal WeChat) and ``wecom.py`` (WeCom internal app) all
  implement ``send_message``. Those platforms need **no** plugin-side
  credentials: selecting the bot in the config is enough.
* ``wecom.py`` does ``parts = target_id.split('|')`` and ``int(parts[1])``, so a
  WeCom internal-app admin id must be written ``userid|agentid``.
* ``wecombot.py`` only sends when the bot runs in WS mode; with
  ``enable-webhook`` on, its ``send_message`` body is ``pass``.
"""

from __future__ import annotations

AUTO = "auto"
QQ_OFFICIAL = "qq_official"
WECOM_BOT = "wecom_bot"
WECOM_APP = "wecom_app"
WECHAT = "wechat"
DISABLED = "disabled"

PLATFORMS = {AUTO, QQ_OFFICIAL, WECOM_BOT, WECOM_APP, WECHAT, DISABLED}

TRANSPORT_QQ_HTTP = "qq_c2c_http"
TRANSPORT_SDK = "langbot_send_message"
TRANSPORT_NONE = "none"

# adapter name (normalized) -> platform
ADAPTER_PLATFORMS = {
    "qqofficial": QQ_OFFICIAL,
    "qqbotpy": QQ_OFFICIAL,
    "wecombot": WECOM_BOT,
    "wecomai": WECOM_BOT,
    "wecomaibot": WECOM_BOT,
    "wecom": WECOM_APP,
    "wecomcs": WECOM_BOT,
    "openclawweixin": WECHAT,
    "openclaw": WECHAT,
    "wechatpad": WECHAT,
    "gewechat": WECHAT,
}


def normalize_adapter(adapter: str) -> str:
    return (adapter or "").strip().lower().replace("_", "").replace("-", "")


def platform_from_adapter(adapter: str) -> str:
    """Map an adapter name onto a notify platform, or ``""`` when unknown."""
    name = normalize_adapter(adapter)
    if not name:
        return ""
    if name in ADAPTER_PLATFORMS:
        return ADAPTER_PLATFORMS[name]
    if "qqofficial" in name or "officialqq" in name:
        return QQ_OFFICIAL
    return ""


def resolve_platform(configured: str, adapter: str) -> str:
    """Operator choice wins; ``auto`` falls back to the bot's adapter."""
    choice = (configured or AUTO).strip().lower()
    if choice not in PLATFORMS:
        choice = AUTO
    if choice != AUTO:
        return choice
    return platform_from_adapter(adapter) or AUTO


def resolve_transport(
    platform: str,
    *,
    qq_credentials_ready: bool,
    trust_qqofficial_send_message: bool = False,
) -> tuple[str, str]:
    """Return ``(transport, reason)`` for the resolved platform.

    ``reason`` is empty when a transport is available, and otherwise carries an
    operator-facing explanation that ends up in the ticket and the group
    fallback message.
    """
    if platform == DISABLED:
        return TRANSPORT_NONE, "管理员私聊通知已在配置里关闭。"
    if platform == QQ_OFFICIAL:
        if qq_credentials_ready:
            return TRANSPORT_QQ_HTTP, ""
        if trust_qqofficial_send_message:
            return TRANSPORT_SDK, ""
        return (
            TRANSPORT_NONE,
            "QQ 官方适配器的 send_message 是空实现，需要填写 AppID + AppSecret "
            "才能主动私聊；否则只能走群内补发。",
        )
    # WeCom / WeChat / unknown adapters: LangBot implements send_message.
    return TRANSPORT_SDK, ""


def validate_admin_target(platform: str, target: str) -> str:
    """Return an error message for an unusable admin id, else ``""``."""
    value = (target or "").strip()
    if not value:
        return "管理员 ID 为空。"
    if platform == WECOM_APP:
        parts = value.split("|")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip().isdigit():
            return (
                f"企业微信内部应用的管理员 ID 必须写成 userid|agentid（agentid 为数字），"
                f"当前是 {value!r}。LangBot 的 wecom 适配器会按 | 拆分并把第二段转成整数。"
            )
    if platform == QQ_OFFICIAL and value.isdigit():
        return (
            f"QQ 官方机器人需要 openid，不是 QQ 号（当前 {value!r}）。"
            "请在会话监控里复制 person 后面那串 32 位 openid。"
        )
    return ""

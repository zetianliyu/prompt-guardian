# Prompt Guardian

LangBot 4.x plugin: **rule pre-filter + LLM review** against prompt injection in group chats. On a confirmed hit it **blocks the message** (the main LLM never sees it), writes a ticket with **which group / which user / what they asked**, and notifies configured admins so human support can follow up.

This is **not** an AstrBot plugin. The detection rule library (PTD 4.1.0) comes from [oyxning/astrbot_plugin_antipromptinjector](https://github.com/oyxning/astrbot_plugin_antipromptinjector) (AGPL-3.0). Keywords, weights and thresholds are unchanged; three regexes were repaired because upstream used JavaScript-style `\u{XXXX}` escapes that make Python's `re` throw on import. See `NOTICE`.

Chinese install notes: `readme/README_zh_Hans.md`.

## What changed in v0.1.4

**Admin DMs now work on QQ, WeCom and WeChat** via a new
**`admin_notify_platform`** selector (auto / QQ official / WeCom smart bot /
WeCom internal app / personal WeChat / disabled). Verified against LangBot's own
adapters — only QQ official needs credentials:

| Platform | LangBot adapter `send_message` | Plugin credentials |
|---|---|---|
| WeCom smart bot `wecombot` | implemented (WS mode; a stub when `enable-webhook` is on) | **none** |
| WeCom internal app `wecom` | implemented | **none**, but the admin id must be `userid\|agentid` |
| Personal WeChat `openclaw_weixin` / `wechatpad` | implemented | **none** |
| QQ official `qqofficial` | **stub (`pass`)** | AppID + AppSecret, for direct C2C HTTP |
| QQ OneBot `aiocqhttp` | implemented | none |

Adding BotId/secret/token fields for WeCom and WeChat would duplicate secrets
LangBot already holds and widen the exposure surface for no gain, so they were
deliberately left out. The QQ credential fields are now `show_if`-gated and only
appear for `auto` / `qq_official`.

WeCom internal-app ids are validated before sending, because `wecom.py` does
`target_id.split('|')` then `int(parts[1])` — a bare userid would throw inside
the adapter. A plain QQ number given to a QQ official bot is likewise rejected up
front with a message asking for the openid.

Tickets now carry `notify_platform` / `notify_transport`. The offline suite runs
63 checks, including per-platform transport routing.

### Known issue

Inspecting review records still does not work: the plugin log panel stays empty
and `review_audit.jsonl` records nothing. This is still being investigated — do
not rely on it.

## How it works

```
GroupNormalMessageReceived
  → whitelist / disabled / empty text → pass
  → PTD 4.1 local score (no LLM cost)
  → operator overrides (disabled rules, custom rules, thresholds)
  → standby + severity none → pass
  → invoke_llm semantic review (optional)
  → confirmed injection → prevent_default
       write incidents.jsonl
       private-message admins (QQ official uses HTTP C2C; otherwise group fallback)
       optional group refusal
```

LLM review modes (same meaning as the AstrBot prototype):

- `standby` (default): review only when rules return a non-`none` severity
- `active`: review every group message
- `disabled`: rules only; block on `medium` / `high`

LLM JSON must report `is_injection: true` **and** `confidence >= 0.6` to confirm. The review prompt now requires a valid JSON object with concrete values, not placeholder text. If a review was actually attempted but its output is malformed, the message fails open; if no model is configured, local `medium` / `high` rules remain authoritative.

Every review attempt is written to the plugin stderr log, including clean messages that are ultimately passed through. Each audit entry includes the local score/severity, selected review model, parsed verdict/reason, bounded raw model output, and final pass/block decision. The same records are persisted to `review_audit.jsonl` (configurable via `review_audit_path`), separately from blocked-message tickets in `incidents.jsonl`; passed messages are not privately notified to admins.

## Install

1. Copy this entire directory into LangBot's `plugins/` folder (or install from local path in the WebUI).
2. Restart LangBot, or wait for plugin reload.
3. Open **Extensions → Prompt Guardian** and set:
   - **Review LLM** — model used for semantic review
   - **Admin user IDs** — see below
   - For QQ official bots that must actually DM: **AppID + AppSecret**

## Admin notify (read this)

LangBot pipeline "this session is an admin" does **not** feed this plugin. Only **Admin user IDs** in the plugin config does.

- **OneBot**: put the QQ number.
- **QQ official** (`C2C_MESSAGE_CREATE` in session monitor): put **only** the openid after `person` (32 hex chars). Do **not** paste `C2C_MESSAGE_CREATE, person …` and do **not** use the QQ number.

LangBot's `qqofficial` adapter implements `reply_message` (the group intercept reply) but `send_message` is `pass`. Private admin DMs therefore never left the plugin. v0.1.1 talks to the QQ Bot HTTP API when AppID/Secret are set, and otherwise posts the ticket in the same group (`admin_notify_mode=private_then_group`).

## Managing the rule library

The library ships **52 regex rules**, **136 weighted keywords**, 58 suspicious phrases and a set of derived signals. Weights add up; a message is only blocked once the total reaches a threshold. All of it is managed from the plugin config page:

- **Thresholds** — `medium` = 7, `high` = 11 by default. Raise them when legitimate messages get flagged; lower them when attacks slip through. Try this before disabling rules.
- **Custom keywords** — one `keyword:weight` per line, e.g. `帮我绕过审核:5`.
- **Custom regexes** — one `pattern:weight` per line, e.g. `内部\s*工号\s*\d{4,}:7`. A trailing `:number` is read as the weight only when it lands in 1-10, so a pattern like `\d{2}:\d{2}` keeps its last segment. Broken patterns are skipped with a log line.
- **Disabled built-in rules** — one rule name per line. Works for regex rule names, built-in keywords and derived signal names.

`docs/RULES.md` is the full catalogue (name, weight, description for every rule) and ships with the plugin — you need it to know what to type into the disable list. Regenerate it after a rule-library upgrade:

```bash
python scripts/dump_rules.py
```

Overrides are applied to the **output** of `ptd_core.py` rather than to the module itself, which stays byte-for-byte upstream apart from the regex repair documented in `NOTICE`.

Known trade-off: disabling a rule does not retract synergy bonuses (e.g. `multi_high_risk`) the library already granted for it, so the score can read slightly high. For a guard, erring strict is the safe direction.

## Platform notes

Primary target: **group chats**.

| Platform | Group messages | Group name / sender name | Admin private notify |
|---|---|---|---|
| QQ OneBot v11 | yes | yes | yes |
| QQ official | yes (usually @) | openids | not via `send_message` (adapter stub); HTTP C2C or group fallback |
| Personal WeChat (OpenClaw) | adapter-dependent (docs emphasize 1:1) | falls back to ids | yes if the bot can DM the admin |
| WeCom internal app | **no group chat** in the official support table | n/a | private notify still possible |

When a name is missing the ticket stores the raw id.

## Ticket format

Each line of `incidents.jsonl`:

```json
{
  "time": "2026-08-24T12:00:00+08:00",
  "platform": "aiocqhttp",
  "bot_uuid": "...",
  "group_id": "123456",
  "group_name": "support-test",
  "sender_id": "10001",
  "sender_name": "Alice",
  "question": "full original text",
  "ptd_score": 14,
  "ptd_severity": "high",
  "ptd_reason": "...",
  "llm_is_injection": true,
  "llm_confidence": 0.86,
  "llm_reason": "...",
  "action": "blocked",
  "notify_admin_ids": ["4D59667BBE54DD358CB83E0C242C485B"],
  "notify_private_delivered": [],
  "notify_private_errors": ["..."],
  "notify_skipped": ""
}
```

## Verify locally

```bash
python scripts/verify_ptd.py
```

Checks syntax, manifest YAML, PTD scoring (benign / jailbreak / Unicode obfuscation), LLM JSON parsing, and the incident recorder.

The LLM-parser, SDK-wiring and recorder checks need the plugin SDK. Without it they are skipped rather than failing:

```bash
python -m venv ~/.venvs/prompt-guardian
~/.venvs/prompt-guardian/bin/pip install langbot-plugin PyYAML
~/.venvs/prompt-guardian/bin/python scripts/verify_ptd.py
```

Keep the virtualenv outside the plugin directory — anything inside it gets copied into LangBot's `plugins/`.

## License

GNU Affero General Public License v3.0. Rule engine source from AstrBot Anti-Prompt Injector; combined work is AGPL-3.0.

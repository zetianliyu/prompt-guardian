"""Operator-managed overrides on top of the vendored PTD rule library.

``ptd_core.py`` is third-party AGPL code and is deliberately left untouched, so
everything here works on the *result* of ``PromptThreatDetector.analyze()``
rather than on its internals: disabled signals are subtracted, custom signals
are added, and the severity is recomputed against operator thresholds.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from plugin_log import log
import scope_packs

WEIGHT_MIN = 1
WEIGHT_MAX = 10
DEFAULT_CUSTOM_WEIGHT = 5

CONFIG_KEYS = (
    "rule_medium_threshold",
    "rule_high_threshold",
    "disabled_rule_names",
) + scope_packs.CONFIG_KEYS


def split_weight(entry: str, default: int = DEFAULT_CUSTOM_WEIGHT) -> tuple[str, int]:
    """Split a ``value:weight`` entry, tolerating colons inside ``value``.

    The tail counts as a weight only when it is a number inside the allowed
    range, so a regex like ``\\d{2}:\\d{2}`` or a pattern such as ``port:8080``
    keeps its final segment instead of silently losing it.
    """
    body, separator, tail = entry.rpartition(":")
    if separator and tail.strip().isdigit():
        weight = int(tail.strip())
        if WEIGHT_MIN <= weight <= WEIGHT_MAX:
            return body.strip(), weight
    return entry.strip(), default


def parse_keyword_rules(entries: Iterable[Any]) -> list[tuple[str, int]]:
    rules: list[tuple[str, int]] = []
    for entry in entries or []:
        keyword, weight = split_weight(str(entry))
        if keyword:
            rules.append((keyword, weight))
    return rules


def parse_regex_rules(entries: Iterable[Any]) -> list[tuple[re.Pattern[str], int]]:
    """Compile operator regexes, dropping (and reporting) the broken ones.

    An unparseable pattern must never take the plugin down, so it is skipped
    instead of raised.
    """
    rules: list[tuple[re.Pattern[str], int]] = []
    for entry in entries or []:
        pattern_text, weight = split_weight(str(entry))
        if not pattern_text:
            continue
        try:
            rules.append((re.compile(pattern_text, re.IGNORECASE), weight))
        except re.error as exc:
            log.warning(f"ignoring invalid custom regex {pattern_text!r}: {exc}")
    return rules


def parse_disabled_names(entries: Iterable[Any]) -> set[str]:
    return {str(entry).strip().lower() for entry in entries or [] if str(entry).strip()}


def _compile_scope_regexes(
    sources: Iterable[tuple[str, int, str, str]],
) -> list[tuple[re.Pattern[str], int, str, str]]:
    """Compile pack patterns; a broken one is skipped, never raised."""
    compiled: list[tuple[re.Pattern[str], int, str, str]] = []
    for pattern_text, weight, origin, group in sources:
        try:
            compiled.append((re.compile(pattern_text, re.IGNORECASE), weight, origin, group))
        except re.error as exc:
            log.warning(f"ignoring invalid scope regex {pattern_text!r}: {exc}")
    return compiled


def coerce_threshold(value: Any, fallback: int) -> int:
    try:
        threshold = int(value)
    except (TypeError, ValueError):
        return fallback
    return threshold if threshold > 0 else fallback


def config_fingerprint(config: dict[str, Any]) -> str:
    """Cheap identity for the override-relevant config, for cache invalidation."""
    return repr([config.get(key) for key in CONFIG_KEYS])


def severity_for(score: int, medium_threshold: int, high_threshold: int) -> str:
    if score >= high_threshold:
        return "high"
    if score >= medium_threshold:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def has_scope_signal(analysis: dict[str, Any]) -> bool:
    """Did anything the operator selected match, as opposed to a PTD signal?

    Used when 提示词注入/越狱 is unticked: PTD keeps scoring jailbreaks, but its
    score must not be the reason a message is reviewed or blocked when the
    operator said they do not care about that scope.
    """
    in_scope = {scope_packs.SOURCE_SCOPE, scope_packs.SOURCE_CUSTOM}
    return any(
        str(signal.get("source") or "") in in_scope
        for signal in analysis.get("signals") or []
    )


class RuleOverrides:
    def __init__(
        self,
        *,
        medium_threshold: int,
        high_threshold: int,
        keyword_rules: list[tuple[str, int]],
        regex_rules: list[tuple[re.Pattern[str], int]],
        disabled_names: set[str],
        scope: scope_packs.ScopeSelection | None = None,
    ) -> None:
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        # Supplementary rules the operator typed in ("补充关键词/正则"), tagged
        # `custom`. They exist to patch gaps in the ticked scopes, not as a
        # feature of their own.
        self.keyword_rules = keyword_rules
        self.regex_rules = regex_rules
        self.disabled_names = disabled_names
        self.scope = scope or scope_packs.ScopeSelection.from_config({})
        self.scope_keyword_rules = (
            self.scope.pack_keyword_rules() + self.scope.custom_target_rules()
        )
        self.scope_regex_rules = _compile_scope_regexes(self.scope.pack_regex_sources())

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        *,
        default_medium: int,
        default_high: int,
    ) -> RuleOverrides:
        medium = coerce_threshold(config.get("rule_medium_threshold"), default_medium)
        high = coerce_threshold(config.get("rule_high_threshold"), default_high)
        if high < medium:
            high = medium
        scope = scope_packs.ScopeSelection.from_config(config)
        return cls(
            medium_threshold=medium,
            high_threshold=high,
            keyword_rules=parse_keyword_rules(scope.keyword_entries),
            regex_rules=parse_regex_rules(scope.regex_entries),
            disabled_names=parse_disabled_names(config.get("disabled_rule_names") or []),
            scope=scope,
        )

    @property
    def active(self) -> bool:
        return bool(
            self.keyword_rules
            or self.regex_rules
            or self.disabled_names
            or self.scope_keyword_rules
            or self.scope_regex_rules
        )

    def apply(self, analysis: dict[str, Any], text: str) -> dict[str, Any]:
        signals = list(analysis.get("signals") or [])
        score = int(analysis.get("score") or 0)

        if self.disabled_names:
            kept: list[dict[str, Any]] = []
            for signal in signals:
                if str(signal.get("name", "")).strip().lower() in self.disabled_names:
                    # Synergy bonuses PTD already granted for this signal are left
                    # in place — over-scoring is the safe direction for a guard.
                    score -= int(signal.get("weight") or 0)
                else:
                    kept.append(signal)
            signals = kept

        lowered = text.lower()

        # Scope packs and custom objects: recall only. Each group contributes at
        # most PACK_SCORE_CAP however many of its rules fire, so a scope hit
        # lands at `low` and goes to review instead of blocking on its own.
        group_budget: dict[str, int] = {}

        def add_scope_signal(signal: dict[str, Any], group: str, weight: int) -> int:
            spent = group_budget.get(group, 0)
            allowance = max(0, scope_packs.PACK_SCORE_CAP - spent)
            granted = min(weight, allowance)
            group_budget[group] = spent + granted
            signal["counted_weight"] = granted
            signals.append(signal)
            return granted

        for keyword, weight, origin, group in self.scope_keyword_rules:
            if keyword.lower() in lowered:
                score += add_scope_signal(
                    {
                        "type": "keyword",
                        "name": keyword,
                        "detail": keyword,
                        "weight": weight,
                        "source": scope_packs.SOURCE_SCOPE,
                        "origin": origin,
                        "description": f"{origin}：命中关键词「{keyword}」",
                    },
                    group,
                    weight,
                )

        for pattern, weight, origin, group in self.scope_regex_rules:
            try:
                match = pattern.search(text)
            except Exception as exc:
                log.warning(f"scope regex {pattern.pattern!r} failed: {exc}")
                continue
            if match:
                score += add_scope_signal(
                    {
                        "type": "regex",
                        "name": pattern.pattern,
                        "detail": match.group(0)[:160],
                        "weight": weight,
                        "source": scope_packs.SOURCE_SCOPE,
                        "origin": origin,
                        "description": f"{origin}：命中正则「{pattern.pattern}」",
                    },
                    group,
                    weight,
                )

        for keyword, weight in self.keyword_rules:
            if keyword.lower() in lowered:
                signals.append(
                    {
                        "type": "keyword",
                        "name": keyword,
                        "detail": keyword,
                        "weight": weight,
                        "source": scope_packs.SOURCE_CUSTOM,
                        "origin": "补充关键词",
                        "description": f"命中自定义关键词「{keyword}」",
                    }
                )
                score += weight

        for pattern, weight in self.regex_rules:
            try:
                match = pattern.search(text)
            except Exception as exc:
                log.warning(f"custom regex {pattern.pattern!r} failed: {exc}")
                continue
            if match:
                signals.append(
                    {
                        "type": "regex",
                        "name": pattern.pattern,
                        "detail": match.group(0)[:160],
                        "weight": weight,
                        "source": scope_packs.SOURCE_CUSTOM,
                        "origin": "补充正则",
                        "description": f"命中自定义正则「{pattern.pattern}」",
                    }
                )
                score += weight

        score = max(0, score)
        adjusted = dict(analysis)
        adjusted["signals"] = signals
        adjusted["score"] = score
        adjusted["severity"] = severity_for(
            score, self.medium_threshold, self.high_threshold
        )
        # PTD builds `reason` from the first three signals; rebuild it so the
        # incident ticket reflects the overridden set rather than the raw one.
        adjusted["reason"] = (
            "，".join(str(signal.get("description", "")) for signal in signals[:3])
            if signals
            else ""
        )
        return adjusted

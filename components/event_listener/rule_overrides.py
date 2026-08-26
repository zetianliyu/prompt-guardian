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

WEIGHT_MIN = 1
WEIGHT_MAX = 10
DEFAULT_CUSTOM_WEIGHT = 5

CONFIG_KEYS = (
    "rule_medium_threshold",
    "rule_high_threshold",
    "custom_keywords",
    "custom_regex_rules",
    "disabled_rule_names",
)


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


class RuleOverrides:
    def __init__(
        self,
        *,
        medium_threshold: int,
        high_threshold: int,
        keyword_rules: list[tuple[str, int]],
        regex_rules: list[tuple[re.Pattern[str], int]],
        disabled_names: set[str],
    ) -> None:
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.keyword_rules = keyword_rules
        self.regex_rules = regex_rules
        self.disabled_names = disabled_names

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
        return cls(
            medium_threshold=medium,
            high_threshold=high,
            keyword_rules=parse_keyword_rules(config.get("custom_keywords") or []),
            regex_rules=parse_regex_rules(config.get("custom_regex_rules") or []),
            disabled_names=parse_disabled_names(config.get("disabled_rule_names") or []),
        )

    @property
    def active(self) -> bool:
        return bool(self.keyword_rules or self.regex_rules or self.disabled_names)

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
        for keyword, weight in self.keyword_rules:
            if keyword.lower() in lowered:
                signals.append(
                    {
                        "type": "keyword",
                        "name": keyword,
                        "detail": keyword,
                        "weight": weight,
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

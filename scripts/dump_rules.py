#!/usr/bin/env python3
"""Generate docs/RULES.md — the catalogue operators need to disable rules by name.

Everything is read out of the live detector (and, for signal names that are
built at match time rather than declared, out of the ptd_core source), so the
catalogue cannot drift from the rule library it documents.
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTENER = os.path.join(ROOT, "components", "event_listener")
sys.path.insert(0, LISTENER)

from ptd_core import PromptThreatDetector  # noqa: E402

LITERAL_SIGNAL_NAME = re.compile(r'"name":\s*"([^"]+)"')


def derived_signal_names(declared: set[str]) -> list[str]:
    """Signal names emitted by detector internals rather than the rule table."""
    with open(os.path.join(LISTENER, "ptd_core.py"), encoding="utf-8") as fh:
        source = fh.read()
    return sorted(set(LITERAL_SIGNAL_NAME.findall(source)) - declared)


def render(detector: PromptThreatDetector) -> str:
    declared = {str(sig["name"]) for sig in detector.regex_signatures}
    lines: list[str] = []
    add = lines.append

    add("# 规则库清单")
    add("")
    add(f"规则引擎：**{detector.name} {detector.version}**")
    add("")
    add(
        f"默认判定阈值：`medium` = **{detector.medium_threshold}** 分，"
        f"`high` = **{detector.high_threshold}** 分。"
        "可在插件配置里改（medium / high 判定阈值）。"
    )
    add("")
    add("> 本文件由 `python scripts/dump_rules.py` 自动生成，请勿手改。")
    add("")
    add("## 怎么用")
    add("")
    add(
        "某条规则老是误杀正常消息时，把下面表格里的**规则名**原样填进插件配置的"
        "「停用的内置规则」，一行一个。"
    )
    add("")
    add(
        "注意：同一个名字可能同时对应一条正则规则和一个关键词"
        "（例如 `越狱模式`），按名停用会把两者一起关掉。"
    )
    add("")
    add(
        "命中多条规则时分数累加，达到阈值才拦截。所以比起停用规则，"
        "先试着调高阈值往往影响更小。"
    )
    add("")

    add(f"## 正则规则（{len(detector.regex_signatures)} 条）")
    add("")
    add("| 规则名 | 权重 | 说明 |")
    add("|---|---|---|")
    for sig in sorted(detector.regex_signatures, key=lambda s: (-int(s["weight"]), str(s["name"]))):
        name = str(sig["name"]).replace("|", "\\|")
        description = str(sig.get("description", "")).replace("|", "\\|")
        add(f"| `{name}` | {sig['weight']} | {description} |")
    add("")

    by_weight: dict[int, list[str]] = defaultdict(list)
    for keyword, weight in detector.keyword_weights.items():
        by_weight[int(weight)].append(str(keyword))
    add(f"## 关键词（{len(detector.keyword_weights)} 个）")
    add("")
    add("子串匹配，不区分大小写。规则名就是关键词本身。")
    add("")
    for weight in sorted(by_weight, reverse=True):
        keywords = sorted(by_weight[weight])
        add(f"### 权重 {weight}（{len(keywords)} 个）")
        add("")
        add(" ".join(f"`{kw}`" for kw in keywords))
        add("")

    phrases = sorted(str(p) for p in detector.suspicious_phrases)
    add(f"## 可疑语句（{len(phrases)} 条，每条权重 2）")
    add("")
    add("规则名就是语句本身。")
    add("")
    add(" ".join(f"`{p}`" for p in phrases))
    add("")

    markers = sorted(str(m) for m in detector.marker_keywords)
    add(f"## 结构标记（{len(markers)} 个）")
    add("")
    add(
        "这些不是独立规则：命中几个就合并成一条名为 `payload_marker` 的信号，"
        "权重 = min(3, 命中数) × 2。要关就填 `payload_marker`。"
    )
    add("")
    add(" ".join(f"`{m}`" for m in markers))
    add("")

    domains = sorted(str(d) for d in detector.malicious_domains)
    add(f"## 恶意域名（{len(domains)} 个）")
    add("")
    add("命中后归入 `external_reference` 等信号，不单独按域名停用。")
    add("")
    add(" ".join(f"`{d}`" for d in domains))
    add("")

    derived = derived_signal_names(declared)
    add(f"## 派生信号（{len(derived)} 个）")
    add("")
    add(
        "编码检测、外链、启发式判断产生的信号，权重按命中情况计算，不是固定值。"
        "填下面的名字即可停用。"
    )
    add("")
    add(" ".join(f"`{name}`" for name in derived))
    add("")

    return "\n".join(lines) + "\n"


def main() -> int:
    detector = PromptThreatDetector()
    content = render(detector)
    if "--stdout" in sys.argv[1:]:
        sys.stdout.write(content)
        return 0
    output = os.path.join(ROOT, "docs", "RULES.md")
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {os.path.relpath(output, ROOT)} ({len(content)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

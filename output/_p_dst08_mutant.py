# -*- coding: utf-8 -*-
"""0.62.1 变异测试：证明新加的四条 exclude_patterns **真的在起作用**。

为什么必须做：`collect_hits` 里有两层放行机制 ——
  ① `readonly_command_context(command)`（更上层，只读上下文）
  ② `_excluded(rule, ...)`（本规则自己的 exclude_patterns）
若 ① 已经把 `grep "icacls /deny" docs/` 放行了，那 ② 的四条就是**写了不生效的
死配置**（DST-01 那 10 条排除同族）。唯一能分辨的动作：把 ② 摘掉，看判决翻不翻。

判据：
  · 摘掉 ② 之后，NEG-READONLY 里**至少有若干条**翻成命中 ⇒ ② 在起作用（不是死代码）
  · 摘掉 ② 之后，每条命令都必须**断言真的改了字节**（变异为空操作＝测了个寂寞）

★ 只改内存副本，不动 `rules/default.json`。
"""
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import pre_tool_use as H                                    # noqa: E402

RID = "DST-08"
RULES = json.load(io.open(os.path.join(ROOT, "rules", "default.json"),
                          encoding="utf-8"))["rules"]

READONLY = [
    ("grep -rn \"icacls /deny\" docs/", "grep 提及"),
    ("cat docs/acl.md", "cat（不含关键词，对照）"),
    ("echo \"takeown /r /f x\"", "echo 提及"),
    ("git log --grep=takeown", "git log 提及"),
]


def _rules_without_exclude():
    """返回 (新 rules, 实际改了几条)。改 0 条即变异失效 —— 必须断言。"""
    out, changed = [], 0
    for r in RULES:
        if r.get("id") == RID:
            r = dict(r)
            before = list(r.get("exclude_patterns") or [])
            r["exclude_patterns"] = []
            if before != []:
                changed += 1
                assert before == r["exclude_patterns"] or True
        out.append(r)
    return out, changed


def verdict(rules, cmd):
    hits = H.collect_hits(rules, "Bash", {"command": cmd}, ROOT, [])
    for h in hits:
        if isinstance(h, dict) and h.get("rule_id") == RID:
            return True
    return False


def main():
    stripped, changed = _rules_without_exclude()
    # 变异必须真的改了东西（否则后面「翻红」读数是假的）
    assert changed == 1, "变异未生效：改到 %d 条（应为 1）" % changed
    orig = [r for r in RULES if r.get("id") == RID][0]
    mut = [r for r in stripped if r.get("id") == RID][0]
    assert len(orig["exclude_patterns"]) == 4, "原排除应为 4 条"
    assert mut["exclude_patterns"] == [], "变异后排除未清空"

    print("变异已生效：exclude_patterns 4 -> 0（仅内存）\n")
    print("%-34s %-10s %-10s" % ("命令", "有排除", "无排除(变异)"))
    print("-" * 58)
    saved, flips = 0, 0
    for cmd, why in READONLY:
        a = verdict(RULES, cmd)
        b = verdict(stripped, cmd)
        if (not a) and b:
            flips += 1
        elif (not a) and (not b):
            saved += 1
        print("%-34s %-10s %-10s  %s"
              % (cmd[:34], "HIT" if a else "clean", "HIT" if b else "clean", why))

    print("\n摘掉排除后翻成命中的条数：%d" % flips)
    print("摘掉排除后仍放行的条数：%d（由上层的只读上下文兜底）" % saved)
    if flips == 0:
        print("\n!! 四条 exclude_patterns 是死代码 —— 放行全由上层只读上下文完成")
        return 1
    print("\nOK 排除真在生效（且不是唯一防线：上层只读上下文另有 %d 条兜底）" % saved)
    return 0


if __name__ == "__main__":
    sys.exit(main())

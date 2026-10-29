# -*- coding: utf-8 -*-
"""0.62.1 第三轮：上层 `readonly_command_context` 认识哪些只读命令？

上一轮变异已证：`grep` / `cat` / `echo` / `git log` 的放行由**上层**完成，
本规则的 exclude_patterns 对它们零贡献。那么四条排除到底还有没有价值，
取决于上层**不认识**哪些只读命令 —— 不认识的那些，才是排除真正在挡的。

做法：对每条候选命令，同时跑「有排除 / 无排除」两版。
  有排除 clean + 无排除 HIT  ⇒ 这条排除**有真实贡献**（记 +1）
  两版都 clean              ⇒ 上层已覆盖，排除在本条上冗余
  两版都 HIT                ⇒ 排除对它无效（漏在两层之外，需另补）
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

# 每条都含 DST-08 的关键词（/deny 或 /reset /t 或 takeown … /r），且形态是只读
CAND = [
    ("grep -rn \"icacls /deny\" docs/", "unix grep", "grep"),
    ("cat docs/acl.md # icacls /deny", "unix cat 带词", "cat"),
    ("type docs\\acl.md | findstr \"/deny\"", "win type+findstr", "type/findstr"),
    ("findstr /c:\"icacls /deny\" docs\\a.md", "win findstr 单独", "findstr"),
    ("where /r . acl.md # icacls /deny", "win where", "where"),
    ("head -40 docs/acl.md # takeown /r", "unix head", "head"),
    ("Get-Content docs\\acl.md | Select-String \"/deny\"", "powershell", "ps"),
    ("echo icacls /deny", "unix echo", "echo"),
    ("git show HEAD:docs/acl.md # icacls /deny", "git show", "git"),
]


def _strip():
    out, n = [], 0
    for r in RULES:
        if r.get("id") == RID:
            r = dict(r)
            if r.get("exclude_patterns"):
                n += 1
            r["exclude_patterns"] = []
        out.append(r)
    assert n == 1, "变异未生效"
    return out


def hit(rules, cmd):
    return any(isinstance(h, dict) and h.get("rule_id") == RID
               for h in H.collect_hits(rules, "Bash", {"command": cmd}, ROOT, []))


def main():
    stripped = _strip()
    print("%-46s %-12s %-12s %s" % ("命令", "有排除", "无排除", "排除是否在挡"))
    print("-" * 92)
    contrib, redundant, holes = [], [], []
    for cmd, why, fam in CAND:
        a, b = hit(RULES, cmd), hit(stripped, cmd)
        if (not a) and b:
            tag = "★ 有贡献"
            contrib.append((why, cmd))
        elif (not a) and (not b):
            tag = "冗余(上层兜底)"
            redundant.append(why)
        else:
            tag = "!! 漏在两层外"
            holes.append((why, cmd))
        print("%-46s %-12s %-12s %s" % (cmd[:46], "HIT" if a else "clean",
                                        "HIT" if b else "clean", tag))

    print("\n有贡献 %d 条：%s" % (len(contrib), ", ".join(w for w, _ in contrib) or "-"))
    print("冗余   %d 条：%s" % (len(redundant), ", ".join(redundant) or "-"))
    print("漏洞   %d 条：%s" % (len(holes), ", ".join(w for w, _ in holes) or "-"))
    for w, c in holes:
        print("  !! %s -> %s" % (w, c))
    return 0 if not holes else 2


if __name__ == "__main__":
    sys.exit(main())

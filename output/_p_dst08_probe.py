# -*- coding: utf-8 -*-
"""0.62.1 DST-08 双向探针 —— 只认 `collect_hits`（唯一实现）的裁决。

为什么必须喂样本：DST-08 的 pattern 是**两层转义**（JSON 里 `\\b` = 正则 `\b`），
写错一层时正则语法依然合法、`re.compile` 不报错，只有喂一条它该放行/该拦的样本
才抓得到（DST-01 的 10 条排除就是这么静默失效的：全写成 `\\bgrep\\b`）。

三组腿：
  POS   该拦的（含 Windows 等价、顺序颠倒、大写）
  NEG   不该拦的（单文件运维、只读提及）
  CHAIN 排除**不得**放行链式真命令 —— 否则这次改动等于亲手开了一个后门
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

POS = [
    ("chmod -R 755 /var/www", "unix 递归改权限"),
    ("chmod 000 /etc/passwd", "unix 权限清零"),
    ("chown -R nobody /data", "unix 递归改属主"),
    ("icacls C:\\data /deny Everyone:(F)", "win 拒绝 ACE"),
    ("icacls C:\\data\\* /reset /t", "win 递归 reset"),
    ("icacls /T C:\\data /reset", "win 递归 reset（颠倒＋大写）"),
    ("takeown /f C:\\Windows\\System32 /r /d y", "win 递归夺权"),
    ("takeown /r /f C:\\Windows", "win 递归夺权（颠倒）"),
    ("ICACLS C:\\DATA /DENY *S-1-1-0", "win 全大写"),
]
NEG = [
    ("chmod 644 notes.txt", "单文件改权限"),
    ("chown user file.txt", "单文件改属主"),
    ("icacls C:\\data /reset", "单文件重置继承（无 /t）"),
    ("icacls C:\\data /grant dev:(F)", "授予权限"),
    ("icacls C:\\data /remove:d Everyone", "移除拒绝 ACE（修复）"),
    ("takeown /f C:\\mydir\\a.txt", "单文件夺回属主"),
    ("takeown /f C:\\data\\reports.txt", "路径里带 /r 开头的名字"),
    ("grep -rn \"icacls /deny\" docs/", "只读提及"),
    ("cat notes.md", "对照腿：完全不含关键词"),
    ("git log --grep=takeown", "只读 git"),
]
CHAIN = [
    ("grep -rn \"icacls /deny\" docs/ && icacls C:\\x /deny Everyone",
     "只读前缀后接真命令"),
    ("cat notes.md && takeown /f C:\\x /r", "只读前缀后接递归夺权"),
]


def verdict(cmd):
    """跑 collect_hits，返回 (是否命中 RID, match_kind 或 None)。"""
    hits = H.collect_hits(RULES, "Bash", {"command": cmd}, ROOT, [])
    got = None
    for h in hits:
        rid = h.get("rule_id") if isinstance(h, dict) else None
        if rid == RID:
            got = h.get("match_kind") or h.get("kind") or "?"
            break
    return (got is not None), got


def main():
    bad = []
    print("== POS 该拦 ==")
    for cmd, why in POS:
        ok, kind = verdict(cmd)
        print("  %s %-24s %s" % ("HIT " if ok else "MISS", kind or "-", why))
        if not ok:
            bad.append("POS 漏拦[%s] %s" % (why, cmd))
        elif kind != "command":
            bad.append("POS 通道错[%s] %s -> %s" % (why, cmd, kind))

    print("== NEG 不该拦 ==")
    for cmd, why in NEG:
        ok, kind = verdict(cmd)
        print("  %s %-24s %s" % ("BAD " if ok else "clean", kind or "-", why))
        if ok:
            bad.append("NEG 误拦[%s] %s -> %s" % (why, cmd, kind))

    print("== CHAIN 排除不得放行真命令 ==")
    for cmd, why in CHAIN:
        ok, kind = verdict(cmd)
        print("  %s %-24s %s" % ("HIT " if ok else "MISS", kind or "-", why))
        if not ok:
            bad.append("CHAIN 被排除误放行[%s] %s" % (why, cmd))

    n = len(POS) + len(NEG) + len(CHAIN)
    print("\n%d 条样本：%d 通过，%d 不通过" % (n, n - len(bad), len(bad)))
    for b in bad:
        print("  !! " + b)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())

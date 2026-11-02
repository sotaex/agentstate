#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-6 · 保留期与销毁（方案书 §3.3 第 7 段）

方案书原文：「**零**：`audit_chain.py` 无任何删除/轮转逻辑 ⇒ **保留期＝永久，不是 7 天**」
—— 这一句是**断言**，没有实测支撑。本工具把它变成可复算的读数：

  Q1 磁盘上实际保留了多少天、多少条、多少字节？（现取现报，带读取时刻）
  Q2 代码里到底有没有删除／轮转路径？（AST 扫，不靠读注释）

★ Q2 的探针必须自证有牙，否则「0 处删除」等于「我没找对文件」：
   腿 1  真实目标文件上扫一遍（读得到才算数）
   腿 2  正控：人造一个含 `os.remove` / `shutil.rmtree` 的样本 ⇒ 必须检出
   腿 3  负控：人造一个只读样本 ⇒ 必须 0 命中

只读；夹具在系统 TEMP（D 盘禁 unlink）。不改产品、不写账本。

用法：
  python output/lineB/b6_retention.py [--audit <dir>] [--root <dir>]
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import os
import re
import shutil
import sys
import tempfile

# 账本日文件名的唯一形态（`.psl/audit/lock_events.jsonl` 不是审计记录，
# 混进来会让 `date.fromisoformat('lock_events')` 直接崩 —— 实测撞过一次）
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")

# 删除/轮转的**语法指纹**：调用名（属性形态）+ 模块名
DESTRUCTIVE_CALLS = {
    "remove", "unlink", "rmdir", "removedirs", "rmtree",
    "rename", "replace", "truncate", "move",
}
DESTRUCTIVE_MODS = {"os", "shutil", "pathlib", "send2trash"}

# ★ 2026-11-03：这两类**必须分开数**。
#   原先它们合成一个 `strong`，结论写「删除／轮转调用 N 处」—— 而实测目标是
#   `audit_chain.py` 的 3 处，全部是 `os.replace`：
#     · L102 锁事件日志轮转（`.jsonl` → `.1`，只留一代）—— **真轮转**，但对象不是审计记录；
#     · L304 偷锁时把残骸改名 `.away` —— 不是记录；
#     · L593 日锚 manifest 原子写（tmp → 正式）—— **根本不是删除**。
#   合成一栏的后果：结论说「有 3 处删除／轮转」，读者会以为**审计记录被删**。
#   这是「异质单位做加减」的变体：删与改名不是同一种事，相加之后的那个数
#   既不是删除数也不是改名数。
HARD_DELETE = {"remove", "unlink", "rmdir", "removedirs", "rmtree"}
SOFT_RENAME = {"rename", "replace", "truncate", "move"}

# 轮转/保留期关键词（只在**字符串常量**里找，属弱证据，单列）
ROTATE_KEYWORDS = ("retention", "rotate", "prune", "purge")

CANDIDATES = (
    "audit_chain.py",
    "hooks/audit_chain.py",
    "psl/audit_chain.py",
    "tools/audit_chain.py",
)


def _resolve_target(root: str):
    for rel in CANDIDATES:
        p = os.path.join(root, rel.replace("/", os.sep))
        if os.path.isfile(p):
            return rel, p
    return None, None


def _func_name(desc: str) -> str:
    """从 `os.replace(...)` 取 `replace`。分类只认函数名，不认整串描述。"""
    return desc.split("(")[0].split(".")[-1]


def scan_ast(path: str):
    """返回 (强证据 hits, 弱证据 hits)，各为 [(lineno, 描述)]。"""
    src = open(path, encoding="utf-8", errors="replace").read()
    tree = ast.parse(src, filename=path)
    strong, weak = [], []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = node.func.value
            modname = base.id if isinstance(base, ast.Name) else (
                base.attr if isinstance(base, ast.Attribute) else None)
            attr = node.func.attr
            if attr in DESTRUCTIVE_CALLS and (modname in DESTRUCTIVE_MODS or modname is None):
                strong.append((node.lineno, "%s.%s(...)" % (modname or "?", attr)))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in DESTRUCTIVE_CALLS:
                strong.append((node.lineno, "%s(...)" % node.func.id))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            for kw in ROTATE_KEYWORDS:
                if kw in low:
                    weak.append((node.lineno, "字符串含 %r" % kw))
                    break
    return strong, weak


def _write_sample(dirpath: str, name: str, body: str) -> str:
    p = os.path.join(dirpath, name)
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(body)
    return p


def emit_json(path: str, payload: dict) -> int:
    """落盘并**回读自证**，返回可解析内容的字符数。

    ★ 「探针没有牙」这种情况也必须落盘。只在有结论时才写产出件，
      会让「今天没测出结论」与「今天没跑」在目录里一模一样 ——
      而这正是本工具要反对的那种同貌。
    """
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    with open(path, encoding="utf-8") as fh:
        back = json.load(fh)
    return len(json.dumps(back, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=os.path.join(".psl", "audit"))
    ap.add_argument("--root", default=".")
    ap.add_argument("--json", dest="json_out", default=None, metavar="PATH",
                    help="把这次读数写成 json（同一条命令重跑会覆盖，不叠加）")
    a = ap.parse_args()

    root = a.root
    audit = a.audit if os.path.isdir(a.audit) else os.path.join(root, a.audit)

    print("=" * 74)
    print("B-6 · 保留期与销毁 ｜ 读取时刻 %s"
          % dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 74)

    if not os.path.isdir(audit):
        print("★ 账本目录不存在：%s" % audit)
        return 2

    # ---------- Q1：磁盘实况 ----------
    days = []
    total_lines = total_bytes = 0
    skipped = []
    for name in sorted(os.listdir(audit)):
        p = os.path.join(audit, name)
        if not os.path.isfile(p) or not name.endswith(".jsonl"):
            continue
        if not _DAY_RE.match(name):
            skipped.append(name)
            continue
        if name.endswith(".lock") or ".away-" in name:
            skipped.append(name)
            continue
        n = 0
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    n += 1
        sz = os.path.getsize(p)
        total_lines += n
        total_bytes += sz
        days.append((name[:-6], n, sz))

    if not days:
        print("❌ 一个日文件都没读到 —— 读数无效")
        return 1

    days.sort()
    first, last = days[0][0], days[-1][0]
    span = (dt.date.fromisoformat(last) - dt.date.fromisoformat(first)).days + 1
    print("\n[Q1] 磁盘实况")
    print("  日文件 %d 个 ｜ 覆盖 %s → %s（日历跨度 %d 天）｜ 记录 %d 条 ｜ %.1f MB"
          % (len(days), first, last, span, total_lines, total_bytes / 1048576.0))
    print("  实有天数 %d ＝ 跨度 %d − 空洞 %d" % (len(days), span, span - len(days)))
    if skipped:
        print("  已排除（非记录）：%s" % ", ".join(skipped[:6]))
    biggest = max(days, key=lambda d: d[2])
    print("  最大一天：%s ｜ %d 条 ｜ %.1f MB"
          % (biggest[0], biggest[1], biggest[2] / 1048576.0))
    print("  ⇒ 实际保留＝全部历史：最早 %s，距今 %d 天（不是 7 天）"
          % (first, (dt.date.today() - dt.date.fromisoformat(first)).days))

    # ---------- Q2：代码里的删除/轮转 ----------
    rel, path = _resolve_target(root)
    print("\n[Q2] 代码里的删除／轮转路径")
    if not path:
        print("  ❌ 找不到 audit_chain.py（候选：%s）—— 不许据此说「零删除」" % (CANDIDATES,))
        return 1
    print("  被测文件：%s（%d 字节）" % (rel, os.path.getsize(path)))

    strong, weak = scan_ast(path)
    n_del = [h for h in strong if _func_name(h[1]) in HARD_DELETE]
    n_ren = [h for h in strong if _func_name(h[1]) in SOFT_RENAME]
    print("  删除调用（remove/unlink/rmtree…）%d 处 ｜ 改名·截断（rename/replace/move）%d 处"
          % (len(n_del), len(n_ren)))
    print("  弱证据（关键词字符串）%d 处" % len(weak))
    for ln, desc in n_del[:15]:
        print("    L%-5d [删除] %s" % (ln, desc))
    for ln, desc in n_ren[:15]:
        print("    L%-5d [改名] %s" % (ln, desc))
    if len(strong) > 15:
        print("    …… 另 %d 处" % (len(strong) - 15))
    for ln, desc in weak[:5]:
        print("    L%-5d [弱] %s" % (ln, desc))

    # ---------- 腿 2 / 腿 3：探针有牙 ----------
    tmp = tempfile.mkdtemp(prefix="b6_fixture_")
    try:
        pos = _write_sample(tmp, "pos.py", (
            "import os, shutil\n"
            "def f(p):\n"
            "    os.remove(p)\n"
            "    shutil.rmtree(p)\n"
            "    os.replace(p, p + '.bak')\n"
        ))
        neg = _write_sample(tmp, "neg.py", (
            "def f(p):\n"
            "    return open(p).read()\n"
        ))
        pos_strong, _ = scan_ast(pos)
        neg_strong, _ = scan_ast(neg)
        print("\n[腿 2] 正控：人造 os.remove ＋ shutil.rmtree ＋ os.replace ⇒ 必须检出")
        print("  %s 命中 %d 处 %s"
              % ("✅" if len(pos_strong) >= 3 else "❌", len(pos_strong),
                 [d for _, d in pos_strong]))
        print("\n[腿 3] 负控：纯读样本 ⇒ 必须 0 命中")
        print("  %s 命中 %d 处" % ("✅" if not neg_strong else "❌", len(neg_strong)))
        # ★ 腿 4（2026-11-03 加）：**分类器必须能翻面，且两栏各有一条正控**。
        #   没有这条，`_func_name` 一旦坏了（比如改成取模块名），n_del 与 n_ren
        #   会同时变 0，结论就变成「删除 0 处」—— 与真的没有删除**一模一样**。
        #   这是第十四族：永远清白的判据与真判据同貌，只能靠「该进这栏的必须进」来验。
        #   ★ 11-03 补：原先正控样本里只有删除，`改名` 那一栏的期望值是 0 ——
        #     等于「改名分支坏了」与「没有改名」也同貌。真账本里那 3 处 os.replace
        #     是外部事实，不能拿它当分类器的牙齿。现在两条正控分别落两栏。
        _pos_del = [h for h in pos_strong if _func_name(h[1]) in HARD_DELETE]
        _pos_ren = [h for h in pos_strong if _func_name(h[1]) in SOFT_RENAME]
        print("\n[腿 4] 分类：删除样本进「删除」栏、改名样本进「改名」栏（两栏都要非空）")
        print("  %s 删除 %d 处 ｜ 改名 %d 处（期望 2 / 1）"
              % ("✅" if len(_pos_del) == 2 and len(_pos_ren) == 1 else "❌",
                 len(_pos_del), len(_pos_ren)))
        cls_ok = len(_pos_del) == 2 and len(_pos_ren) == 1
        teeth = len(pos_strong) >= 3 and not neg_strong and cls_ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    def _payload(verdict: str) -> dict:
        return {
            "read_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "audit_dir": os.path.abspath(audit),
            "target": rel,
            "target_bytes": os.path.getsize(path) if path else None,
            "q1": {
                "files": len(days), "first": first, "last": last,
                "span_days": span, "records": total_lines,
                "bytes": total_bytes,
                "biggest": {"day": biggest[0], "records": biggest[1],
                            "bytes": biggest[2]},
                "excluded": skipped,
                "retention_looks_permanent": True,
            },
            "q2": {
                "strong_n": len(strong),
                "delete_n": len(n_del),
                "rename_n": len(n_ren),
                "delete": [{"line": ln, "desc": d} for ln, d in n_del],
                "rename": [{"line": ln, "desc": d} for ln, d in n_ren],
                "weak_n": len(weak),
            },
            "teeth": {"positive_hits": len(pos_strong),
                      "negative_hits": len(neg_strong),
                      # ★ 腿 4 也必须进产物（2026-11-03）：只在屏幕上印「分类能翻面」，
                      #   明天复核的人看不到 —— 而「删除 0 处」这句话的可信度全押在
                      #   「分类器真的会分」上，押在没人能复查的地方不合适。
                      "class_flip_ok": bool(cls_ok),
                      "class_pos_delete": len(_pos_del),
                      "class_pos_rename": len(_pos_ren),
                      "ok": bool(teeth)},
            "verdict": verdict,
        }

    def _write(verdict: str) -> None:
        if not a.json_out:
            return
        try:
            n = emit_json(a.json_out, _payload(verdict))
            print("已写 %s（可解析 %d 字符）" % (a.json_out, n))
        except Exception as exc:                        # noqa: BLE001
            print("✗ 写出失败：%s: %s" % (type(exc).__name__, exc))

    print("\n" + "-" * 74)
    if not teeth:
        print("判定：❌ 探针没有牙 —— 「零删除」不可作为结论")
        _write("no_teeth")
        return 1
    print("判定：探针有牙（正控命中、负控 0、分类能翻面）")
    if not n_del:
        print("结论：`%s` 里**删除调用 0 处** ⇒ 审计记录不会被删，"
              "保留期在新代码落地前等同永久。" % rel)
        print("     与方案书 §3.3 第 7 段的断言一致，但现在是**可复算读数**，不是引用。")
        if n_ren:
            print("     另有 %d 处改名／截断，**不是删除**：%s。"
                  % (len(n_ren), "、".join("L%d %s" % (ln, d) for ln, d in n_ren)))
            print("     ⇒ 对象须人读：原子写（tmp ⇒ 正式）与日志轮转在 AST 上同貌，"
                  "本工具不替它们下结论。")
        _write("no_delete_call")
    else:
        print("结论：`%s` 里有 %d 处**删除**调用 —— 需逐处判定是否作用于审计记录。"
              % (rel, len(n_del)))
        for ln, d in n_del[:10]:
            print("     L%-5d %s" % (ln, d))
        _write("has_delete_call")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""两份验证器的**对照试验**：同一个事实、两套实现，必须给出同一个判定。

为什么要有这一支：`challenge/verify.py` 是「公开挑战件」，产品承诺它**零依赖、可被第三方
离线复算**，所以它**不许** import 库内代码——两份实现会长期并存。既然并存，
就不能靠「大家写得一样」来保证一致，只能靠**同一组夹具同时喂给两边**，看结论对不对得上。
（这正是本项目的老病：同一事实多处实现。这里不是消灭重复，是**给重复上锁**。）

五组夹具（每组都同时问两个验证器）：

  F1 完好链                         两边都必须 rc=0
  F2 改内容、不重算                 两边都必须 rc=2
  F3 尾部截断、锚不动               两边都必须 rc=2
  F4 同长度重写 + 清单 size 同步     **至少一方**必须 rc=2（谁先抓住都算，打印在明处）
  F5 正常追加（锚在旧位置、文件长了）两边都必须 rc=0   ← 防误报腿，缺它等于鼓励假警报

★ F4 是最难的一条：自哈希重算过、字节数没变 ⇒ 只剩「锚记的那条记录还在不在」这一条路。
★ 只用标准库；只在系统 TEMP 建夹具；仓库零写入。
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOLS_V = os.path.join(REPO, "tools", "verify_chain.py")
CHAL_V = os.path.join(REPO, "challenge", "verify.py")


def canon(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def chain(n, tool="Bash"):
    prev_full, out = "", []
    for i in range(n):
        rec = {"ts": "2026-11-01T00:00:%02d+08:00" % i, "type": "pre_tool_use",
               "tool": tool, "decision": "allow", "seq": i}
        rec["prev"] = prev_full[-16:]
        h = hashlib.sha256((prev_full + canon(rec)).encode("utf-8")).hexdigest()
        rec["hash"] = h
        prev_full = h
        out.append(rec)
    return out


def rehash_from(recs, idx):
    """从第 idx 条起重算 hash 链（模拟「改一条、把尾巴全部重算」的攻击者）。"""
    prev = recs[idx - 1]["hash"] if idx else ""
    for i in range(idx, len(recs)):
        recs[i]["prev"] = prev[-16:]
        recs[i].pop("hash", None)
        recs[i]["hash"] = hashlib.sha256((prev + canon(recs[i])).encode("utf-8")).hexdigest()
        prev = recs[i]["hash"]
    return recs


def dump(d, name, recs, anchor):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    man = {name: {"size": anchor[0], "last_hash": anchor[1]}}
    with open(os.path.join(d, "day_manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False)
    return p


def size_of(recs):
    return sum(len(json.dumps(r, ensure_ascii=False, sort_keys=True)) + 1 for r in recs)


def ask(verifier, d):
    r = subprocess.run([sys.executable, "-E", "-X", "utf8", verifier, d],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def build(root):
    """五组夹具：(名字, 目录, tools 期望, challenge 期望)"""
    cases = []
    day = "2026-11-01.jsonl"

    # F1 完好
    d = os.path.join(root, "f1"); os.makedirs(d)
    recs = chain(3)
    dump(d, day, recs, (size_of(recs), recs[-1]["hash"]))
    cases.append(("F1 完好链", d, 0, 0))

    # F2 改内容不重算
    d = os.path.join(root, "f2"); os.makedirs(d)
    recs = chain(3)
    anchor = (size_of(recs), recs[-1]["hash"])
    recs[1]["tool"] = "Bosh"          # 同长度替换，字节数不变
    dump(d, day, recs, anchor)
    cases.append(("F2 改内容不重算", d, 2, 2))

    # F3 尾部截断、锚不动
    d = os.path.join(root, "f3"); os.makedirs(d)
    recs = chain(3)
    anchor = (size_of(recs), recs[-1]["hash"])
    dump(d, day, recs[:2], anchor)
    cases.append(("F3 尾部截断", d, 2, 2))

    # F4 同长度重写 + 清单 size 同步（锚留旧 hash）
    d = os.path.join(root, "f4"); os.makedirs(d)
    recs = chain(3)
    old_tail = recs[-1]["hash"]
    recs[-1]["tool"] = "Bosh"         # 只改末条，长度不变
    rehash_from(recs, 2)
    assert size_of(recs) == size_of(chain(3)), "F4 夹具自身失效：字节数变了"
    assert recs[-1]["hash"] != old_tail, "F4 夹具自身失效：hash 没变"
    dump(d, day, recs, (size_of(recs), old_tail))
    cases.append(("F4 同长度重写", d, None, None))     # None = 不要求某一方，只要求「至少一方」

    # F5 正常追加（锚在旧位置）
    d = os.path.join(root, "f5"); os.makedirs(d)
    recs = chain(3)
    anchor = (size_of(recs), recs[-1]["hash"])
    more = recs + chain(2)
    rehash_from(more, 3)
    dump(d, day, more, anchor)
    cases.append(("F5 正常追加", d, 0, 0))
    return cases


def main():
    root = tempfile.mkdtemp(prefix="diffv_")
    fails = []
    try:
        print("%-20s %-14s %-14s %s" % ("夹具", "tools/verify", "challenge", "判定"))
        for name, d, exp_t, exp_c in build(root):
            rc_t, out_t = ask(TOOLS_V, d)
            rc_c, out_c = ask(CHAL_V, d)
            if exp_t is None and exp_c is None:
                ok = (rc_t == 2) or (rc_c == 2)
                who = "、".join(x for x, r in (("tools", rc_t), ("challenge", rc_c)) if r == 2) or "无"
                note = "至少一方抓住：%s" % who
            else:
                ok = (rc_t == exp_t) and (rc_c == exp_c)
                note = "期望 %s/%s" % (exp_t, exp_c)
            if not ok:
                fails.append(name)
            print("%-20s %-14s %-14s %s  %s"
                  % (name, "rc=%d" % rc_t, "rc=%d" % rc_c, "OK" if ok else "MISMATCH", note))
            if not ok:
                for tag, out in (("tools", out_t), ("challenge", out_c)):
                    body = [l for l in out.splitlines() if l.strip()][:3]
                    print("      %s: %s" % (tag, " | ".join(body)))

        print("\n判定：%s" % ("五组全部对上" if not fails else "不上的：" + "、".join(fails)))
        return 0 if not fails else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

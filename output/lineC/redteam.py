# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C-5 红队：攻击自己的检测器，看它们会不会照常报绿。

出处：开工卡 W4。验收三条：
  ① 至少 3 个「检测器会瞎」的场景，每个带最小复现；
  ② 每个场景**必须能证明现有检测器确实报了绿**（否则是臆想）；
  ③ 产出写进 BLIND_SPOTS。

──────────────────────────────────────────────────────────────────────────
为什么必须「先证明干净账本报绿」
──────────────────────────────────────────────────────────────────────────
如果一上来就攻击，然后看到「还是绿」，无法区分两种情况：
  (a) 攻击成功，检测器瞎了；
  (b) 检测器本来就坏，对什么都报绿。
所以每个臂都先跑一次基线：**基线不绿 ⇒ 这个臂作废**，不许拿来当战果。

──────────────────────────────────────────────────────────────────────────
停止线（开工卡 W4）
──────────────────────────────────────────────────────────────────────────
**不许为了让红队赢而放宽检测器。** 红队赢了就如实记成盲区；红队输了
（检测器抓到了）也是好结果，同样如实记。

──────────────────────────────────────────────────────────────────────────
本文件的一个核心结论，先说在前面
──────────────────────────────────────────────────────────────────────────
A1/A2 都是**自己算的 hash 跟自己比**：
    A1: recompute_hash(rec, prev) == rec["hash"]
    A2: rec["prev"] == 上一条 rec["hash"][-16:]
攻击者只要改完内容**把整链重算一遍**，两个都必然通过——这不是检测器的 bug，
是「内部自洽检查」的定义。真正能抓住整链重写的只有 L2 外部锚，而今天没有。
本文件把这个论断从**文字声明**变成**可执行的最小复现**。
"""

import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
#: 本文件就在 lineC 里；但也允许被挪到 output/ 下跑，所以按目录名判断一次。
LINE_C = HERE if os.path.basename(HERE) == "lineC" else os.path.join(HERE, "lineC")
#: ★ 2026-11-03：`auditor.py` 跟着包搬进了仓库根的 `linec/`（它是运行时的一部分，
#:   报告的「账本自洽」整条腿由它提供），本文件是研发工具、留在原地。
_runtime = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, "linec"))
AUDITOR = os.path.join(_runtime, "auditor.py")


# --------------------------------------------------------------------------- 账本构造


def canon(rec: Dict[str, Any]) -> str:
    """与 auditor.canon 逐字一致（AUDIT_SCHEMA v1.2 §2）。"""
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def seal_chain(recs: List[Dict[str, Any]], prev_full: str = "") -> List[Dict[str, Any]]:
    """给一批记录接上合法链。**攻击者也要用这个**——重算链是攻击的一部分。"""
    out: List[Dict[str, Any]] = []
    for rec in recs:
        body = dict(rec)
        body["prev"] = prev_full[-16:] if prev_full else ""
        body.pop("hash", None)
        h = hashlib.sha256((prev_full + canon(body)).encode("utf-8")).hexdigest()
        body["hash"] = h
        out.append(body)
        prev_full = h
    return out


def build_ledger(root: str, days: int = 3, per_day: int = 4,
                 with_manifest: bool = True) -> Dict[str, Any]:
    """造一个**自洽**的账本：A1/A2/A3 必须全绿，否则后面所有臂都不成立。"""
    os.makedirs(root, exist_ok=True)
    man: Dict[str, Any] = {}
    for d in range(days):
        day = "2026-10-%02d" % (10 + d)
        recs: List[Dict[str, Any]] = []
        for i in range(per_day):
            recs.append({
                "ts": "%sT%02d:%02d:00+08:00" % (day, 3, i * 2),
                "type": "pre_tool_use",
                "tool": "Bash",
                "action": "allow",
                "decision": "allow",
                "reason": "baseline",
                "note": "record-%d-%d" % (d, i),
            })
        sealed = seal_chain(recs)
        path = os.path.join(root, day + ".jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for r in sealed:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if with_manifest:
            man[day + ".jsonl"] = {
                "size": os.path.getsize(path),
                # ★ 必须是**完整 64 位**：auditor 拿 ent["last_hash"] 与
                #   recs[-1]["hash"]（完整值）直接比，存后 16 位会永远对不上。
                "last_hash": sealed[-1]["hash"],
                "updated_at": "%sT23:59:00+08:00" % day,
            }
    if with_manifest:
        with open(os.path.join(root, "day_manifest.json"), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump(man, fh, ensure_ascii=False, indent=1)
    return man


def read_day(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def write_day(path: str, recs: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def refresh_manifest(root: str) -> None:
    """攻击者也要把清单改对——否则 A3 会抓到。"""
    mpath = os.path.join(root, "day_manifest.json")
    man: Dict[str, Any] = {}
    for p in sorted(glob.glob(os.path.join(root, "20*.jsonl"))):
        recs = read_day(p)
        man[os.path.basename(p)] = {
            "size": os.path.getsize(p),
            "last_hash": (recs[-1].get("hash", "") if recs else ""),
            "updated_at": "2026-10-31T23:59:00+08:00",
        }
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)


# --------------------------------------------------------------------------- 跑检测器


def run_auditor(root: str, declare: Optional[int] = None) -> Tuple[Dict[str, str], int]:
    """跑真 auditor，返回 `({维度: 状态}, 退出码)`。"""
    cmd = [sys.executable, "-E", "-X", "utf8", AUDITOR, "--root", root, "--json"]
    if declare is not None:
        cmd += ["--declare", str(declare)]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode == 2:
        raise RuntimeError("auditor 自己没跑起来：%s" % (p.stderr or "").strip()[:120])
    try:
        data = json.loads(p.stdout)
    except Exception:
        raise RuntimeError("auditor 输出不是 JSON：%s" % (p.stdout or "")[:120])
    return ({f["dim"]: f["status"] for f in data.get("findings", [])}, p.returncode)


def green(status: Dict[str, str], dims: Tuple[str, ...]) -> bool:
    """这几个维度是不是「没报红」。

    ★ 判据是「不是 FAIL」，不是「等于 PASS」。auditor 有 WARN 档（A3 历史缺锚、
      A4 并发倒序），WARN 不进退出码——把 WARN 算成红，会让红队把「本来就有的
      性质偏离」当成自己的战果。
    """
    return all(status.get(d, "?") != "FAIL" for d in dims)


# --------------------------------------------------------------------------- 四个攻击


def atk_r1_rewrite(root: str) -> Tuple[bool, str]:
    """R1 改一条记录的内容 + 整链重算 + 清单重算。

    改什么：把 `action` 从 allow 改成 allow 但 `note` 换掉——模拟「事后抹掉
    某次操作的记录内容」，同时保持条数不变。
    """
    path = sorted(glob.glob(os.path.join(root, "20*.jsonl")))[0]
    recs = read_day(path)
    recs[1]["note"] = "TAMPERED-BY-REDTEAM"
    recs[1]["action"] = "block"          # 把一次放行改写成一次拦截
    write_day(path, seal_chain(recs))
    refresh_manifest(root)
    st, _ = run_auditor(root)
    ok = green(st, ("A1 内容完整", "A2 链连续", "A3 日清单"))
    return ok, "A1=%s A2=%s A3=%s" % (
        st.get("A1 内容完整"), st.get("A2 链连续"), st.get("A3 日清单"))


def atk_r2_delete(root: str) -> Tuple[bool, str]:
    """R2 删掉中间一条记录 + 重算链 + 重算清单。

    这是最朴素的一种：**让一次操作从未发生过**。
    """
    path = sorted(glob.glob(os.path.join(root, "20*.jsonl")))[1]
    recs = read_day(path)
    kept = recs[:1] + recs[2:]           # 挖掉第 2 条
    write_day(path, seal_chain(kept))
    refresh_manifest(root)
    st, _ = run_auditor(root)
    ok = green(st, ("A1 内容完整", "A2 链连续", "A3 日清单", "A4 时间单调"))
    return ok, "删 1 条后 A1=%s A2=%s A3=%s A4=%s" % (
        st.get("A1 内容完整"), st.get("A2 链连续"),
        st.get("A3 日清单"), st.get("A4 时间单调"))


def atk_r3_ts_sorted(root: str) -> Tuple[bool, str]:
    """R3 把倒序的 ts 改成严格递增 + 重算链。

    ★ 这一条最阴：A4 在真账本上**天天报红**（实测 493 处倒序，是并发排队性质）。
    攻击者只要把 ts 排好，A4 就从「红」变「绿」——于是**一个真实的性质偏离
    被抹掉了，而抹掉它的人正好让报告变好看**。
    「让报告变绿」和「让账本变干净」在这里是同一个动作。
    """
    path = sorted(glob.glob(os.path.join(root, "20*.jsonl")))[0]
    recs = read_day(path)
    # 先制造倒序：第 2 条的时间早于第 1 条（03:00），后面几条仍在 03:04 之后
    recs[1]["ts"] = "2026-10-10T02:00:00+08:00"
    write_day(path, seal_chain(recs))
    refresh_manifest(root)
    st_before, _ = run_auditor(root)
    before = st_before.get("A4 时间单调")

    # 攻击：排成**严格递增**（不许手写一个值——上一版把第 2 条改成 03:30，
    # 而第 3 条是 03:04，于是又造出一个新倒序，看起来像「检测器抓住了」，
    # 其实是量具自己错了。铁律 22：先怀疑量具。）
    recs2 = read_day(path)
    for i, r in enumerate(recs2):
        r["ts"] = "2026-10-10T03:%02d:00+08:00" % i
    write_day(path, seal_chain(recs2))
    refresh_manifest(root)
    st_after, _ = run_auditor(root)
    after = st_after.get("A4 时间单调")
    # A4 报倒序时是 WARN（不进退出码），所以判据是「从 WARN/FAIL 变成 PASS」
    ok = (before in ("WARN", "FAIL") and after == "PASS"
          and green(st_after, ("A1 内容完整", "A2 链连续")))
    return ok, "改 ts 前 A4=%s → 改后 A4=%s（A1=%s A2=%s）" % (
        before, after, st_after.get("A1 内容完整"), st_after.get("A2 链连续"))


def atk_r4_drop_manifest(root: str) -> Tuple[bool, str]:
    """R4 直接删掉 `day_manifest.json`。

    ★ 删证据比伪造证据省事：A3 从「检查日清单」变成 **SKIP「本维度不适用」**，
    而 SKIP 在 auditor 的退出码里**不算失败**（`return 1 if any FAIL`）。
    于是「我把清单删了」和「这个账本本来就没有清单」在报告里长得一样。
    """
    mpath = os.path.join(root, "day_manifest.json")
    os.remove(mpath)
    st, rc = run_auditor(root)
    ok = (st.get("A3 日清单") == "SKIP" and rc == 0)
    return ok, "A3=%s 退出码=%d" % (st.get("A3 日清单"), rc)


# --------------------------------------------------------------------------- 主流程


ARMS = []


def arm(name, fn, root):
    try:
        ok, detail = fn(root)
    except Exception as exc:
        ok, detail = False, "臂自己崩了：%s: %s" % (type(exc).__name__, exc)
    ARMS.append((name, ok, detail))
    tag = "红队赢" if ok else "被抓住"
    print("[%s] %-22s %s" % (tag, name, detail))


def main() -> int:
    print("=" * 78)
    print("C-5 红队：攻击自己的检测器")
    print("=" * 78)

    # ---- 基线：干净账本必须全绿，否则后面都不成立 ----
    tmp0 = tempfile.mkdtemp(prefix="rt_base_")
    try:
        build_ledger(tmp0)
        st, rc = run_auditor(tmp0)
        dims = ["A1 内容完整", "A2 链连续", "A3 日清单", "A4 时间单调"]
        if not green(st, tuple(dims)) or rc != 0:
            print("[停] 基线账本就不绿：%s（rc=%d）" % (st, rc))
            print("     ⇒ 后面所有臂作废。先修基线构造，不许拿坏基线当战果。")
            return 2
        print("[基线] 干净账本 3 天 × 4 条：A1/A2/A3/A4 全绿，rc=0")
        st2, _ = run_auditor(tmp0, declare=12)
        print("[基线] 给 --declare 12：A5=%s" % st2.get("A5 总量"))
    finally:
        shutil.rmtree(tmp0, ignore_errors=True)

    # ---- 四个攻击臂，各自独立临时目录 ----
    specs = [
        ("R1 改一条+整链重算", atk_r1_rewrite),
        ("R2 删中间一条", atk_r2_delete),
        ("R3 排好 ts 掩盖倒序", atk_r3_ts_sorted),
        ("R4 删掉日清单", atk_r4_drop_manifest),
    ]
    for name, fn in specs:
        tmp = tempfile.mkdtemp(prefix="rt_")
        try:
            build_ledger(tmp)
            arm(name, fn, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ---- R2 的另一面：A5 是唯一能抓删记录的量具，但它依赖外部声明 ----
    # ★ 拆成两个臂，不许合成一个「有条件赢」——合成会让「赢了」和「输了」互相掩护。
    tmp = tempfile.mkdtemp(prefix="rt_r2b_")
    try:
        build_ledger(tmp)
        atk_r2_delete(tmp)

        st_no, _ = run_auditor(tmp)
        no_won = st_no.get("A5 总量") != "FAIL"
        ARMS.append(("R2b 删记录·无声明", no_won, "A5=%s" % st_no.get("A5 总量")))
        print("[%s] %-22s A5=%s"
              % ("红队赢" if no_won else "被抓住", "R2b 删记录·无声明",
                 st_no.get("A5 总量")))

        st_yes, rc_yes = run_auditor(tmp, declare=12)
        yes_won = st_yes.get("A5 总量") != "FAIL"
        ARMS.append(("R2c 删记录·有声明", yes_won,
                     "A5=%s rc=%d" % (st_yes.get("A5 总量"), rc_yes)))
        print("[%s] %-22s A5=%s（rc=%d）"
              % ("红队赢" if yes_won else "被抓住", "R2c 删记录·有声明",
                 st_yes.get("A5 总量"), rc_yes))
        if not yes_won:
            print("       ⇒ A5 能抓，但前提是有人**从账本之外**声明「本该有多少条」。"
                  "声明本身若也来自账本，就等于自己给自己作证。")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("-" * 78)
    won = sum(1 for _, ok, _ in ARMS if ok)
    print("红队赢了 %d 条／共 %d 条。**赢的意思是：检测器对这次篡改照常报绿。**"
          % (won, len(ARMS)))
    print()
    print("结论（写进 BLIND_SPOTS，不许只写在文档里）：")
    print("  · A1/A2 是「自己算的 hash 跟自己比」⇒ 整链重算必然通过。")
    print("  · A3 依赖 day_manifest.json ⇒ 删掉它比伪造它省事，且 SKIP 不算失败。")
    print("  · A4 在真账本上天天报红（并发排队性质）⇒ 排好 ts 就能让红变绿，")
    print("    而**「让报告变绿」与「抹掉真实性质偏离」是同一个动作**。")
    print("  · A5 是唯一能抓删记录的量具，但它要求「条数从账本之外声明」。")
    print()
    print("  ⇒ 本工具证明的是**内部自洽（L0）**，不证明**未被整链重写**。")
    print("     要排除后者需要 L2 外部锚，今天没有（铁律 42：L0 ✅／L1 ⚠️／L2 ❌）。")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())

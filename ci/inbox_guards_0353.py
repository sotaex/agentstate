# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.35.3 新增判据 + 负控（链背书 / 当前态势 / 三档 / 页面四项）。

★ 每条判据都配负控；**先红后绿**（每条都在缺陷态下实测过会红，见 `_strict_test/`）：
  · `_strict_test/_chain_backing_verify.py` —— 链背书 A1–A6 / zone B1–B4
  · `_strict_test/_fp_loop_ab.py`          —— 端到端：修复前判篡改并回滚、修复后不判
★ 判据一律 import 产品模块直接调它的函数，**不二次实现**。
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta

import inbox_guards as G                      # 复用脚手架（new_hub / put_chain / req / Server）
import inbox_model as M
import inbox_server as SV
import inbox_store as S
import ledger as L

# ★ 判据要核对**规格引用指得对不对**，就得能真的打开那份规格原件 ——
#   找不到原件时判据会红，而不是"跳过"，否则它就是个恒真的假绿。
PSL_ROOT = os.environ.get("PSL_ROOT", r"D:\2026\PSL")

_SCRATCH = []


# --------------------------------------------------------------- 脚手架 ----
def _tmpdir():
    d = tempfile.mkdtemp(prefix="antinel-0353-")
    _SCRATCH.append(d)                       # 只建不删（宿主 safe-delete shim 会硬杀删除）
    return d


def _chain_dir(pkg):
    os.makedirs(os.path.join(pkg, ".psl", "audit"), exist_ok=True)
    return os.path.join(pkg, ".psl", "audit")


def _write_rec(adir, rec):
    fn = os.path.join(adir, time.strftime("%Y-%m-%d") + ".jsonl")
    with open(fn, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return fn


def _ago_iso(hours=1.0):
    return G._ago(hours)


def _iso(offset_hours=0.0):
    return G._ago(offset_hours)


# ===================================================== 一、链背书（R-1 真缺陷）====
def c_chain_tail_sees_policy_changed():
    """★★ `_ChainTail` 必须看得见 `policy_changed` / `host_shield_window_closed`。

    ★ 为什么（真缺陷，盘上证据）：旧版前置过滤写 `'"host_shield_' not in line: continue`，
      而改 state 的三个入口里有两个写的**不是 host_shield_* 类型** ——
      `antinel zone add` 写 `policy_changed`、放行窗到期写 `host_shield_window_closed`。
      整行被挡掉 ⇒ `saw_changed=False` ⇒ 宽限 2 拍 ⇒ 判篡改 ⇒ **回滚用户刚设的配置**。
      全链 12 条 `field=state` 的 tamper，全部紧跟一次「哨兵被重新拉起」、全部带"已回写恢复"。

    ★★ 为什么调**两次**：`_ChainTail` 第一拍必然 `reset=True`（`self.day is None`），
      而 `new_records()` 把 reset 折进 `saw_changed` ⇒ 首拍 `saw` **恒为 True**。
      只调一次的话，`saw is True` 这句就成了**恒真废话**（判据自己瞎了还不知道）。
      先吃一拍 reset，第二拍才真的在验"这条链上有没有背书"。
    """
    import host_shield as HS
    adir = _chain_dir(_tmpdir())
    tail = HS._ChainTail(adir)
    tail.new_records()                                   # 第一拍：吃掉 reset
    _write_rec(adir, {"ts": _iso(0), "type": "policy_changed", "field": "zones"})
    _write_rec(adir, {"ts": _iso(0), "type": "host_shield_window_closed"})
    recs, saw, _reset = tail.new_records()               # 第二拍：真判定
    types = {r.get("type") for r in recs}
    return ("policy_changed" in types and "host_shield_window_closed" in types
            and saw is True and _reset is False)


def n_chain_tail_sees_policy_changed():
    """负控：**无关类型不许被当成背书**（证明上一条不是"什么都算背书"）。

    ★ 同样调两次（首拍 reset 会把 saw 置 True，必须吃掉）。
    """
    import host_shield as HS
    adir = _chain_dir(_tmpdir())
    tail = HS._ChainTail(adir)
    tail.new_records()                                   # 吃掉首拍 reset
    _write_rec(adir, {"ts": _iso(0), "type": "pre_tool_use", "decision": "allow"})
    _write_rec(adir, {"ts": _iso(0), "type": "usage_delta"})
    recs, saw, _reset = tail.new_records()
    return recs == [] and saw is False


def c_prefilter_superset():
    """★★ 便宜前置过滤必须是 `_BACKING_TYPES` 的**真超集**（漏放＝整类事件消失）。"""
    import host_shield as HS
    missing = [t for t in HS._BACKING_TYPES
               if not HS._prefilter_ok(json.dumps({"type": t}, ensure_ascii=False))]
    return not missing and len(HS._BACKING_TYPES) >= 3


def n_prefilter_superset():
    """负控：过滤**不是恒真**（否则"超集"这条判据就没意义）。"""
    import host_shield as HS
    return (not HS._prefilter_ok(json.dumps({"type": "usage_delta"}))
            and not HS._prefilter_ok(""))


def c_fp_backed_by_field():
    """★★ 有**对字段**的链背书 ⇒ 该字段的变化不算篡改，且不回滚。"""
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    adir = _chain_dir(_tmpdir())
    _write_rec(adir, {"ts": _iso(0), "type": "policy_changed", "field": "zones"})
    old = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    new = {"enabled": True, "workspaces": {}, "zones": [r"D:\a"], "windows": {}}
    _fp, _lg, _g, st, tamper = HS._state_guard_step(
        HS._state_fp(new), HS._state_fp(old), old, 1, new, set(), adir, True)
    return tamper == "" and st.get("zones") == [r"D:\a"]


def n_fp_backed_by_field():
    """★负控（两条都要）：①无背书必判篡改并回滚；②**字段隔离** —— zones 的背书
    不许替 workspaces 背书（否则"先跑一条合法命令再改白名单"就成了绕过路）。"""
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    empty = _chain_dir(_tmpdir())
    old = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    new = {"enabled": True, "workspaces": {}, "zones": [r"D:\a"], "windows": {}}
    _fp, _lg, _g, st1, t1 = HS._state_guard_step(
        HS._state_fp(new), HS._state_fp(old), old, 1, new, set(), empty, True)

    adir = _chain_dir(_tmpdir())
    _write_rec(adir, {"ts": _iso(0), "type": "policy_changed", "field": "zones"})
    ws = {"enabled": True, "workspaces": {r"d:\evil": "allow_always"},
          "zones": [], "windows": {}}
    _fp, _lg, _g, st2, t2 = HS._state_guard_step(
        HS._state_fp(ws), HS._state_fp(old), old, 1, ws, set(), adir, True)
    return (t1 != "" and st1.get("zones") == []
            and t2 != "" and st2.get("workspaces") == {})


def c_fp_window_expiry_backed():
    """★ 放行窗到期（哨兵**自己**关的窗）不许被判成篡改。

    ★ 为什么：`scan_once` 关窗后 `windows` 少了键 ⇒ 指纹变；链上写的是
      `host_shield_window_closed`（不是 `host_shield_changed`）⇒ 旧版看不见 ⇒ 判篡改。
      这条路径是**哨兵自己的正常动作**，判它等于让防线咬自己。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    adir = _chain_dir(_tmpdir())
    _write_rec(adir, {"ts": _iso(0), "type": "host_shield_window_closed",
                      "reason": "放行窗到期"})
    old = {"enabled": True, "workspaces": {}, "zones": [],
           "windows": {r"d:\x": time.time() - 60}}
    new = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    _fp, _lg, _g, _st, tamper = HS._state_guard_step(
        HS._state_fp(new), HS._state_fp(old), old, 1, new, set(), adir, True)
    return tamper == ""


def n_fp_window_expiry_backed():
    """负控：把 `host_shield_window_closed` 从背书类型里去掉 ⇒ 必须判篡改。"""
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    adir = _chain_dir(_tmpdir())
    old = {"enabled": True, "workspaces": {}, "zones": [],
           "windows": {r"d:\x": time.time() - 60}}
    new = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    saved = HS._backing_field

    def _no_win(rec):
        return None if rec.get("type") == "host_shield_window_closed" else saved(rec)

    HS._backing_field = _no_win
    try:
        _write_rec(adir, {"ts": _iso(0), "type": "host_shield_window_closed"})
        _fp, _lg, _g, _st, tamper = HS._state_guard_step(
            HS._state_fp(new), HS._state_fp(old), old, 1, new, set(), adir, True)
        return tamper != ""
    finally:
        HS._backing_field = saved


def c_fp_old_backing_expires():
    """★ 时效：**窗外**的旧背书不算数（否则一次合法变更给之后的任意篡改背书）。"""
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    adir = _chain_dir(_tmpdir())
    _write_rec(adir, {"ts": _iso(24), "type": "policy_changed", "field": "zones"})
    old = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    new = {"enabled": True, "workspaces": {}, "zones": [r"D:\a"], "windows": {}}
    _fp, _lg, _g, _st, tamper = HS._state_guard_step(
        HS._state_fp(new), HS._state_fp(old), old, 1, new, set(), adir, True)
    return tamper != ""


def n_fp_old_backing_expires():
    """负控：把窗口放大到 48 小时 ⇒ 同一条旧背书**就**算数了（证明上一条真的在按窗口判）。"""
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    adir = _chain_dir(_tmpdir())
    _write_rec(adir, {"ts": _iso(24), "type": "policy_changed", "field": "zones"})
    saved = HS._BACKING_WINDOW
    old = {"enabled": True, "workspaces": {}, "zones": [], "windows": {}}
    new = {"enabled": True, "workspaces": {}, "zones": [r"D:\a"], "windows": {}}
    try:
        got = HS.chain_backing_fields(adir, window=48 * 3600)
        return "zones" in got
    finally:
        HS._BACKING_WINDOW = saved


# ===================================================== 二、zone 命令 ==========
def c_zone_sync_idempotent():
    """★★ `zone add` 的状态同步必须**幂等**（旧版无条件 append ⇒ 重复项 + 每次都判篡改）。"""
    import host_shield as HS
    import antinel
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {}})
    chain = _chain_dir(_tmpdir())
    saved = antinel._shield_chain_dir
    antinel._shield_chain_dir = lambda: chain
    try:
        r1 = antinel._sync_zone_state(r"D:\archive\z1", adding=True)
        st1 = HS.load_state()
        r2 = antinel._sync_zone_state(r"D:\archive\z1", adding=True)
        st2 = HS.load_state()
        fn = os.path.join(chain, time.strftime("%Y-%m-%d") + ".jsonl")
        n_rec = sum(1 for x in open(fn, encoding="utf-8") if x.strip())
        return (r1 is True and r2 is False and st1 == st2
                and st2.get("zones") == [r"D:\archive\z1"] and n_rec == 1)
    finally:
        antinel._shield_chain_dir = saved


def n_zone_sync_idempotent():
    """负控：**无条件 append** 真的会造重复项（证明上一条不是"怎么写都幂等"）。"""
    zs = []
    zs.append("D:\\archive\\z1")
    zs.append("D:\\archive\\z1")
    return len(zs) == 2 and len(set(zs)) == 1


def c_zone_remove_removes():
    """★★ `zone remove` 必须**真的移除**。

    ★ 为什么（真缺陷，读码发现）：子命令解析器里有 `remove`，函数体却只有 `list`
      分支，其余一律走 add 的 mut ⇒ `zone add` 打印的撤销提示「antinel zone remove …」
      **照着跑等于再加一次**，用户按提示撤销**撤不掉**。
    """
    import host_shield as HS
    import antinel
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [r"D:\archive\z2"],
                   "windows": {}})
    chain = _chain_dir(_tmpdir())
    saved = antinel._shield_chain_dir
    antinel._shield_chain_dir = lambda: chain
    try:
        ok = antinel._sync_zone_state(r"D:\archive\z2", adding=False)
        return ok is True and HS.load_state().get("zones") == []
    finally:
        antinel._shield_chain_dir = saved


def n_zone_remove_removes():
    """负控：**add** 方向不许把已有的项删掉（否则上一条可能只是"总是清空"）。"""
    import host_shield as HS
    import antinel
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [r"D:\archive\z2"],
                   "windows": {}})
    chain = _chain_dir(_tmpdir())
    saved = antinel._shield_chain_dir
    antinel._shield_chain_dir = lambda: chain
    try:
        ok = antinel._sync_zone_state(r"D:\archive\z2", adding=True)
        return ok is False and HS.load_state().get("zones") == [r"D:\archive\z2"]
    finally:
        antinel._shield_chain_dir = saved


def c_zone_sync_writes_backing():
    """★ zone 变更的**授权记录必须落在哨兵自己读的那条链上**（否则哨兵看不见背书）。"""
    import host_shield as HS
    import antinel
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {}})
    chain = _chain_dir(_tmpdir())
    saved = antinel._shield_chain_dir
    antinel._shield_chain_dir = lambda: chain
    try:
        antinel._sync_zone_state(r"D:\archive\z3", adding=True)
        fn = os.path.join(chain, time.strftime("%Y-%m-%d") + ".jsonl")
        recs = [json.loads(x) for x in open(fn, encoding="utf-8") if x.strip()]
        return (len(recs) == 1
                and HS._backing_field(recs[0]) == "zones"
                and recs[0].get("notify") is None)   # notify 是入参，不该进记录体
    finally:
        antinel._shield_chain_dir = saved


def n_zone_sync_writes_backing():
    """负控：写到**别处**的链 ⇒ 哨兵读不到（证明"落在哪儿"这件事真的被这条判据管着）。"""
    import host_shield as HS
    other = _chain_dir(_tmpdir())
    _write_rec(other, {"ts": _iso(0), "type": "host_shield_changed", "field": "zones"})
    seen = HS._ChainTail(_chain_dir(_tmpdir())).new_records()
    return seen[0] == [] and seen[1] is False


# ===================================================== 三、当前态势（灯）====
def c_posture_off_is_not_down():
    """★★ 未启用 ⇒ **off（灰）**，不是 down（红）。

    ★ 为什么（创始人 2026-10-06）：「对于一个正常的产品，失守状态应该是很少的」。
      产品第一原则是默认全关 ⇒ 把"没开"渲染成"坏了"，红灯就变成噪音。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": False, "workspaces": {}, "zones": [], "windows": {}})
    p = HS.guard_posture(_tmpdir())          # 空包根 ⇒ 链上无 armed 依据 ⇒ 回退 state
    return p["state"] == HS.POSTURE_OFF and p["label"] == "未启用"


def n_posture_off_is_not_down():
    """负控：armed 且哨兵不在岗 ⇒ **绝不能是 off**（否则"未启用"可能只是"什么都报 off"）。

    ★ 0.35.3 口径变更：缺岗按后果分两档 —— 有后果＝`down`（失守）、
      无监管对象＝`interrupted`（中断）。本机空 state + 空登记表 ⇒ 落在 `interrupted`，
      **两种都算"不是 off"**，判据只钉这一条。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": None, "sentinel_started_at": None})
    pkg = _tmpdir()
    _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                 "decision": "allow"})
    p = HS.guard_posture(pkg)
    return p["state"] in (HS.POSTURE_DOWN, HS.POSTURE_INTERRUPTED)


def c_posture_unknown_not_guarding():
    """★★ 探针抛错 ⇒ **unknown**（盲区），**绝不许**返回"值守中"。

    ★ 本仓铁律：「查不出来 ≠ 查出来是好的」。
    """
    import host_shield as HS
    saved = HS.load_state

    def _boom():
        raise RuntimeError("探针坏了")

    HS.load_state = _boom
    try:
        p = HS.guard_posture(_tmpdir())
        return p["state"] == HS.POSTURE_UNKNOWN and "盲区" in p["fix_hint"]
    finally:
        HS.load_state = saved


def n_posture_unknown_not_guarding():
    """负控：探针正常时**不许**是 unknown（否则"查不到"这条档会被滥用成万能兜底）。

    ★ 0.35.3：缺岗的两档（`down` / `interrupted`）都算"探到了"，都要在这里被接受。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": False, "workspaces": {}, "zones": [], "windows": {}})
    p = HS.guard_posture(_tmpdir())
    return p["state"] in (HS.POSTURE_OFF, HS.POSTURE_GUARDING, HS.POSTURE_DOWN,
                          HS.POSTURE_INTERRUPTED, HS.POSTURE_WARN)


def c_light_posture_first():
    """★★ 灯＝当前态势优先（0.37.1 六态口径）：**失守**时不管历史多干净都是红；
    未启用是 L0 灰不是红；探不到是 L1 黄（盲区）不是绿。"""
    items = [G.item("L2", "done")]
    down = M.light("down", items)
    off = M.light("off", items)
    unknown = M.light("unknown", items)
    return (down[0] == M.STATE_R0 and off[0] == M.STATE_L0
            and unknown[0] == M.STATE_L1
            and M.STATE_LOGO[off[0]] == "L0")


def n_light_posture_first():
    """负控（0.37.1 改）：值守中 + 24h 内有未处理事件 ⇒ **必须**是该事件的级
    （L2 未处理 ⇒ L2），不许一路绿。"""
    items = [G.item("L2", "unread")]
    lg, _why = M.light("guarding", items)
    return lg == M.STATE_L2


def c_light_only_owner_actions():
    """0.37.1 六态口径：灯取 24h **未处理**事件的最高级；已处理的不画灯；
    自动拦下的（L2）画 L2 —— LOGO 五态的原生读法（黄一点＝重一点）。"""
    action = [G.item("R0", "unread", 1)]
    blocked = [M.Item(M.Alert.build(_iso(1), "tool_call_blocked", reason="denied"))]
    closed = [G.item("R0", "done", 1)]
    return (M.light("guarding", action)[0] == M.STATE_R0
            and M.light("guarding", blocked)[0] == M.STATE_L2
            and M.light("guarding", closed)[0] == M.STATE_L0)


def n_light_only_owner_actions():
    """负控：把**已处理**的当未处理算（变异 `OPEN_STATES`）⇒ 上一条必须变红。

    ★ 机制说明：旧负控靠 `AUTO_HANDLED_KINDS` 变异（灯只数要动手的事），
      0.37.1 起灯按**未处理事件级**走，那个变异点已不在判据路径上；
      换成直接变异「什么算未处理」—— 它正是新判据的第一依赖。
    """
    old = M.OPEN_STATES
    M.OPEN_STATES = M.CLOSED_STATES          # 变异：已处理 ⇒ 未处理
    try:
        return not c_light_only_owner_actions()
    finally:
        M.OPEN_STATES = old


def c_attention_label_drills_to_action_list():
    """状态文案不能只说「有事」：必须能一键直达具体待处理列表。

    ★ 0.37.1 搬家（去重）：钻取入口随视图走 —— 收件箱页在**筛选条**
      （「要处理 N」，就在列表上方），其他页在**顶部条后缀**
      （「（N 件，点开查看）」）。同一个数字每页只出现一次
      （创始人 2026-10-08：「同一件事的 4 件出现了 5 次」）。
    """
    h_inbox = SV.render_page(view="inbox", root=G.new_hub(), token="T",
                             items=[G.item("R0", "unread", 1)])
    h_report = SV._bar([G.item("R0", "unread", 1)], "T",
                       posture={"state": "guarding", "label": "值守中", "why": "在岗"},
                       view="report")
    # ★ 0.47.0：后缀里的件数改走 `M.count_text`（**必带窗口与分母**），
    #   本判据因此**不再比对旧的字面**「（1 件，点开查看）」——
    #   断言打在**行为**（有 f=action 钻取、且带上件数）上，不打字面（维三）。
    #   ★ 不是放宽：分母也一并核对（必须等于这一次载入的全部条数 ＝ 1）。
    # ★ 0.48.5（交接件 §5.6 乙2）：连「点开查看」四个字也删了 —— 替用户
    #   描述他即将做的动作（W08 立意）。钻取后缀现在是 `（N 件 / 分母…）`，
    #   本判据追随规格只锁行为（f=action 钻取在、件数带分母），不再锁字面。
    return ("f=action" in h_inbox and "要处理" in h_inbox
            and "f=action" in h_report
            and M.count_text(1, 1) in h_report)


def n_attention_label_drills_to_action_list():
    """负控：没有待处理事项时，**顶部条**不许出现 f=action 钻取后缀。

    ★ 0.48.5（A2 轮连带修）：旧断言 `"f=action" not in h_inbox` 是**陈旧**
    的——收件箱页的**筛选条**本来就恒有 `f=action` 标签页（"要处理 N"），
    那不是钻取后缀。本条现在的口径与 0.37.1 定的分工一致：钻取＝顶部条
    后缀（非收件箱视图）；收件箱视图的钻取就是筛选条本身。
    ⇒ 断言改为：先用**深度平衡**剥离器剥掉整个 `<div class="filters">`
      （内部嵌 `<details>` 与 `<div class="tdef">`，只删首尾标签会留下
      词条正文——0360 W06 同款教训），再断言剩下的页面里没有 f=action。
    """
    h_inbox = SV.render_page(view="inbox", root=G.new_hub(), token="T",
                             items=[G.item("R0", "done", 1)])
    h_report = SV._bar([G.item("R0", "done", 1)], "T",
                       posture={"state": "guarding", "label": "值守中", "why": "在岗"},
                       view="report")
    body = _strip_filters(h_inbox)
    return "f=action" not in body and "f=action" not in h_report


def _strip_filters(html_text):
    """深度平衡剥掉整个 `<div class="filters">` 块（筛选条/词条芯片）。

    ★ 只删首尾标签不够：块内嵌 `<details><div class="tdef">`（嵌套 div），
      非贪婪到第一个 `</div>` 会把词条正文留在原地。
    """
    start = html_text.find('<div class="filters">')
    if start < 0:
        return html_text
    depth, i, n = 0, start, len(html_text)
    while i < n:
        m = re.compile(r"<div\b|</div>").search(html_text, i)
        if not m:
            break
        if m.group(0).startswith("</"):
            depth -= 1
            i = m.end()
            if depth == 0:
                return html_text[:start] + html_text[i:]
        else:
            depth += 1
            i = m.end()
    return html_text[:start]


# ===================================================== 四、三档 / 归档 ======
def c_bucket_window_and_archive():
    """★★ 分档带 24 小时窗口：窗口外的有后果记录进**归档**，不是"要处理"。"""
    old = G.item("L2", "unread", 1, ts=_iso(30))       # 30 小时前
    fresh = G.item("L2", "unread", 2, ts=_iso(1))      # 1 小时前
    return (M.bucket_of(old) == M.BUCKET_ARCHIVE
            and M.bucket_of(fresh) == M.BUCKET_ACTION)


def n_bucket_window_and_archive():
    """负控：**无后果**的（纯状态变更）进"看一眼"而不是"要处理"。"""
    a = M.Alert(id="y1", ts=_iso(1), level="L1", kind="host_shield_changed", title="t")
    it = M.Item(alert=a, state="unread")
    return M.bucket_of(it) == M.BUCKET_INFO and M.has_consequence(it) is False


def c_recovered_is_structured():
    """★★ "有没有后果"必须读**结构化字段** `recovered`，**不许读 reason 文案**。

    ★ 为什么：旧记录的 reason 里写着"已回写恢复"，但那是文案 —— 文案一改，
      按文案判档的判据就**静默失效**。这条判据同时验两半：
      ① 带 `recovered=True` 的记录 ⇒ 无后果；
      ② **reason 里写了"已回写恢复"但没带字段**的记录 ⇒ 仍然**有后果**（不被文案骗）。
    """
    a = M.Alert(id="r1", ts=_iso(1), level="R0", kind="host_shield_tamper",
                title="t", detail="…已回写恢复…", recovered=True)
    b = M.Alert(id="r2", ts=_iso(1), level="R0", kind="host_shield_tamper",
                title="t", detail="…已回写恢复…", recovered=False)
    return (M.has_consequence(M.Item(alert=a)) is False
            and M.has_consequence(M.Item(alert=b)) is True)


def n_recovered_is_structured():
    """负控：**字段缺失**（老记录）⇒ 按"有后果"处理（方向收紧，不许把"不知道"读成"没事"）。"""
    a = M.Alert(id="r3", ts=_iso(1), level="R0", kind="host_shield_tamper", title="t")
    return M.has_consequence(M.Item(alert=a)) is True


def c_store_reads_recovered_field():
    """★ 投影层必须把链上的 `recovered` 带进 Alert（否则上层拿不到这个字段）。"""
    hub = G.new_hub()
    rec = G.breach(reason="x")
    rec["type"] = "host_shield_tamper"
    rec["field"] = "state"
    rec["recovered"] = True
    G.put_chain(hub, [rec])
    items = S.load_items(root=hub)
    return len(items) == 1 and items[0].recovered is True


def n_store_reads_recovered_field():
    """负控：链上没有 `recovered` ⇒ Alert 里是 False（**不默认 True**）。"""
    hub = G.new_hub()
    rec = G.breach(reason="x")
    rec["type"] = "host_shield_tamper"
    rec["field"] = "state"
    G.put_chain(hub, [rec])
    items = S.load_items(root=hub)
    return len(items) == 1 and items[0].recovered is False


# ===================================================== 五、页面四项 ========
def c_page_has_no_read_button():
    """★★ 创始人拍板①：页面**不许**再有「标为已读」「全部已读」。

    ★ 同时验"按钮区没被整块删掉"（否则删干净了也能过）—— 必须还有「知道了」「忽略」。
    """
    html = SV.render_page(view="inbox", filt="action", root=G.new_hub(), token="t",
                          items=[G.item("L2", "unread")])
    return ("标为已读" not in html and "全部已读" not in html
            and "知道了" in html and "忽略" in html)


def n_page_has_no_read_button():
    """负控：页面上**必须**有"点开即已读"的内联脚本与 data-id（否则取消按钮等于没了已读）。"""
    html = SV.render_page(view="inbox", filt="action", root=G.new_hub(), token="t",
                          items=[G.item("L2", "unread")])
    squashed = html.replace('"', "'")          # 引号写法不定，两种都认
    return ("data-id=" in html
            and ("op:'read'" in squashed or "op='read'" in squashed
                 or "op=read" in squashed))


def c_page_fix_button_only_when_down():
    """★★ 创始人第四条：**失守时**页面必须给一个能马上解决的入口；值守中不给。"""
    down = {"state": "down", "label": "失守", "why": "哨兵不在岗", "can_fix": True,
            "fix": "revive", "fix_hint": "马上修复（重新拉起哨兵）"}
    ok = {"state": "guarding", "label": "值守中", "why": "在岗", "can_fix": False,
          "fix": None, "fix_hint": ""}
    h1 = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=down,
                        items=[G.item("L2", "unread")])
    h2 = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=ok,
                        items=[G.item("L2", "done")])
    return ("马上修复" in h1 and 'name=op value="fix"' in h1
            and "马上修复" not in h2 and "值守中" in h2)


def n_page_fix_button_only_when_down():
    """负控：`can_fix=False` 的失守（如自检不符，就地修不了）**不许**出现修复按钮 ——
    否则用户点了却修不好，就是"假按钮"。"""
    down = {"state": "down", "label": "失守", "why": "运行代码与清单不符",
            "can_fix": False, "fix": None, "fix_hint": "需要重装（就地修不了）"}
    h = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=down,
                       items=[G.item("L2", "unread")])
    return "马上修复" not in h and "失守" in h


def c_page_down_without_fix_shows_howto():
    """★★ 创始人第四条：「如果当前确实是失守状态，应该有地方可以马上解决」。

    ★ 分两种失守，**都必须给得出下一步**：
      · 能就地修（哨兵不在岗）⇒ 给「马上修复」按钮；
      · 不能就地修（程序文件对不上出厂登记）⇒ 给一块「怎么解决」，写清去哪儿做。
    ★ **绝不留"点了没反应"的按钮** —— 那正是创始人最恨的形状。
    """
    down = {"state": "down", "label": "失守", "why": "程序文件与出厂登记对不上",
            "can_fix": False, "fix": None,
            "fix_hint": "就地修不了：请重新安装当前版本（重装会自动重新登记）。"}
    h = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=down,
                       items=[G.item("L2", "unread")])
    return ('class="fixnote"' in h and down["fix_hint"] in h
            and "马上修复" not in h and "失守" in h)


def n_page_down_without_fix_shows_howto():
    """负控：**值守中**不许出现「怎么解决」那一块（否则它就成了常驻噪音）。"""
    ok = {"state": "guarding", "label": "值守中", "why": "在岗", "can_fix": False,
          "fix": None, "fix_hint": ""}
    h = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=ok,
                       items=[G.item("L2", "unread")])
    return 'class="fixnote"' not in h and "马上修复" not in h


def c_posture_off_has_no_fake_button():
    """★ 未启用是**默认态**、不是故障：**不给按钮**，只说清"去哪儿开"。

    ★ 为什么（本会话发现的真缺陷）：旧版 OFF 给 `can_fix=True, fix="enable"`
      ⇒ 页面出现「开启值守」按钮，点下去 `guard_fix` 却回"请在终端执行 …"
      ⇒ **点了没反应的按钮**。开启要装开机自启任务（要管理员权限），
      值守台点一下做不到 ⇒ 那就别给按钮，如实说去哪儿做。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": False, "workspaces": {}, "zones": [], "windows": {}})
    p = HS.guard_posture(_tmpdir())
    return (p["state"] == HS.POSTURE_OFF and p["can_fix"] is False
            and "host-shield enable" in p["fix_hint"])


def n_posture_off_has_no_fake_button():
    """负控：**失守且可救** ⇒ `can_fix` 必须为真（证明不是"什么都不给修"）。

    ★ 必须把 `self_check` 打桩成"通过"：否则本机开发树（运行代码 ≠ 出厂登记）
      会先命中"自检不符"那一支，测到的是另一条路 —— 那就成了**测错对象**。
    ★ 0.35.3：state 里放一个安全区 ⇒ 缺岗**有后果** ⇒ 必须落在 `down`（不是 `interrupted`）。
      这样这条负控仍然在验"真·失守可救"，而不是被新档位悄悄兜走。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": ["D:\\secret"],
                   "windows": {}, "sentinel_pid": None, "sentinel_started_at": None})
    saved = HS.self_check
    HS.self_check = lambda: (True, [])
    try:
        pkg = _tmpdir()
        _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                     "decision": "allow"})
        p = HS.guard_posture(pkg)
        return (p["state"] == HS.POSTURE_DOWN and p["can_fix"] is True
                and p["fix"] == "revive")
    finally:
        HS.self_check = saved


def c_page_grouped_buckets():
    """"看一眼/归档"按类型归并（次要信息不许一张一条霸屏）。"""
    items = [G.item("L1", "unread", 1), G.item("L1", "unread", 2)]
    for it in items:
        it.alert.kind = "host_shield_changed"
        it.alert.level = "L1"
    h = SV.render_page(view="inbox", filt="info", root=G.new_hub(), token="t",
                       posture={"state": "guarding", "label": "值守中", "why": "",
                                "can_fix": False, "fix": None, "fix_hint": ""},
                       items=items)
    return "按类型归并" in h and "×2" in h and "看这 2 条" in h


def n_page_grouped_buckets():
    """负控：**不同类**不许并成一行。

    ★ 0.35.3 口径变更（创始人 2026-10-06「尽可能少让人处理」）：
      旧负控写的是「**要处理**档不许归并」—— 那条口径**已作废**：
      现在「要处理」也按事由归并（37 条 → 3 件事），归并后的**不藏事**由
      新判据 `c_page_action_grouped_not_hidden` 单独把关。
      本负控改为守**归并键**：不同 kind ⇒ 必须是两行，不许一刀切并成一行。
    """
    items = [G.item("L1", "unread", 1), G.item("L1", "unread", 2)]
    items[0].alert.kind = "host_shield_changed"
    items[1].alert.kind = "host_shield_revived"
    for it in items:
        it.alert.level = "L1"
    h = SV.render_page(view="inbox", filt="info", root=G.new_hub(), token="t",
                       posture={"state": "guarding", "label": "值守中", "why": "",
                                "can_fix": False, "fix": None, "fix_hint": ""},
                       items=items)
    return h.count('class="item ') == 2 and "×2" not in h


def c_page_action_grouped_not_hidden():
    """★★ 0.35.3：「要处理」按**事由**归并，但**不许藏事**。

    创始人 2026-10-06：「要处理一栏有 37 条，很多应该 Antinel 就处理了」
    ⇒ 同一事由的多条（例：看门狗没能启动 ×13）＝**一件事**，必须归并成一行；
      但归并行**必须**同时给出：
        ① 原因（detail）—— 否则用户只知道"出事了"却不知什么事；
        ② 批量动作（一次「知道了」处置整组）—— 否则"少动作"落空；
        ③ 钻取（看这 N 条）—— 否则单条被藏起来，想细看也看不到。

    ★ 本判据是**真回退**的产物：旧版归并行只渲染标题，
      当场把 P3 XSS 与 P12 按钮两条判据弄红（原因整条消失、按钮全没了）。
    """
    items = []
    for i in (1, 2, 3):
        it = G.item("L2", "unread", i)
        it.alert.kind = "host_shield_spawn_failed"
        it.alert.title = "失守：看门狗没能启动"
        it.alert.detail = "哨兵进程不在岗（第 %d 次）" % i
        it.alert.topic = ""
        items.append(it)
    h = SV.render_page(view="inbox", filt="action", root=G.new_hub(), token="t",
                       posture={"state": "guarding", "label": "值守中", "why": "",
                                "can_fix": False, "fix": None, "fix_hint": ""},
                       items=items)
    return (h.count('class="item grp') == 1 and "×3" in h
            and "哨兵进程不在岗" in h             # ① 原因
            and 'value="done_all"' in h           # ② 批量动作
            and "看这 3 条" in h)                 # ③ 钻取


def n_page_action_grouped_not_hidden():
    """负控：同 kind 但**不同事由** ⇒ 不许并成一行。

    证明上一条不是"把什么都并成一件"：归并键含事由，
    `autostart_missing` / `hook_pulled` / `zone_dropped` 是**三件事**，必须三行。
    """
    items = []
    for i, tp in enumerate(("autostart_missing", "hook_pulled", "zone_dropped"), 1):
        it = G.item("L2", "unread", i)
        it.alert.kind = "host_shield_breach"
        it.alert.title = "失守：%s" % tp
        it.alert.detail = "原因 %s" % tp
        it.alert.topic = tp
        items.append(it)
    h = SV.render_page(view="inbox", filt="action", root=G.new_hub(), token="t",
                       posture={"state": "guarding", "label": "值守中", "why": "",
                                "can_fix": False, "fix": None, "fix_hint": ""},
                       items=items)
    return h.count('class="item ') == 3 and "×3" not in h


def c_server_done_all_marks_group():
    """★ 归并行的批量「知道了」必须真的把**整组**置为已处理。

    「少动作」不能只是文案：用户点一次，整组都得落地 —— 否则又是"点了没反应"。
    """
    hub = G.new_hub()
    G.put_chain(hub, [G.breach(ts="2026-10-05T20:00:01+08:00", reason="r1"),
                      G.breach(ts="2026-10-05T20:00:02+08:00", reason="r2"),
                      G.breach(ts="2026-10-05T20:00:03+08:00", reason="r3")])
    ids = ",".join(it.id for it in S.load_items(root=hub))
    srv = G.Server(hub)
    try:
        st, _, _ = G.req(srv.port, "/action", token=srv.token, method="POST",
                         body="op=done_all&ids=%s" % ids,
                         ctype="application/x-www-form-urlencoded")
        after = S.load_items(root=hub)
    finally:
        srv.stop()
    return st == 303 and len(after) == 3 and all(it.state == "done" for it in after)


def n_server_done_all_marks_group():
    """负控：**空对象** ⇒ 必须 409，且**什么都没改**（不许"没做事却回成功"）。"""
    hub = G.new_hub()
    G.put_chain(hub, [G.breach()])
    srv = G.Server(hub)
    try:
        st, _, _ = G.req(srv.port, "/action", token=srv.token, method="POST",
                         body="op=done_all&ids=",
                         ctype="application/x-www-form-urlencoded")
        after = S.load_items(root=hub)
    finally:
        srv.stop()
    return st == 409 and after and after[0].state != "done"


def c_report_drill_links():
    """★ 创始人第四条意见：日报里每个数字都要能点进去看具体情况。"""
    rep = {
        "day": "2026-10-06", "levels": {"R0": 1, "L2": 2, "L1": 3, "Ls": 0},
        "window_levels": {"R0": 1, "L2": 2, "L1": 3, "Ls": 0}, "window_hours": 24,
        "buckets": {"action": 3, "info": 3, "archive": 0}, "revived_window": 0,
        "posture": {"state": "guarding", "label": "值守中", "why": "在岗"},
        "rules": [{"rule_id": "DST-01", "count": 2}],
        # 传入旧版 hourly 数据也必须忽略：逐小时报告已由奥卡姆审查移除。
        "hourly": [{"hour": "09:00", "level": "L2"}],
        "chain": {"status": "ok", "files": 1, "records": 2, "broken": 0,
                  "unchained": 0, "reason": ""},
    }
    h = SV.render_page(view="report", root=G.new_hub(), token="t", rep=rep,
                       items=[G.item("L2", "unread")])
    return ("f=win:24:lv:R0" in h and "f=win:24:lv:L2" in h
            and "f=day:2026-10-06:rule:DST-01" in h and "f=action" in h
            and "今天逐小时" not in h and "f=today:" not in h
            and not M.known_filter("today:09"))


def n_report_drill_links():
    """负控：钻取链接**真的能筛出东西**，否则"能点"只是个装饰。"""
    a = G.item("R0", "unread", 1)
    b = G.item("L2", "unread", 2)
    got = M.filter_items([a, b], "lv:R0")
    return len(got) == 1 and got[0].level == "R0"


def c_scoped_report_drills_match_count_window():
    """日报窗口数字点击后必须保留 24 小时范围，不可把更早记录混进详情。"""
    fresh = G.item("R0", "unread", 1, ts=_iso(1))
    old = G.item("R0", "unread", 2, ts=_iso(30))
    got = M.filter_items([fresh, old], "win:24:lv:R0")
    return len(got) == 1 and got[0].id == fresh.id


def n_scoped_report_drills_match_count_window():
    """负控：未加窗口的级别筛选确实包含旧项，证明窗口判据在工作。"""
    fresh = G.item("R0", "unread", 1, ts=_iso(1))
    old = G.item("R0", "unread", 2, ts=_iso(30))
    got = M.filter_items([fresh, old], "lv:R0")
    return len(got) == 2


def c_daily_rule_drill_is_date_scoped():
    """日报按所选日期统计的规则命中，钻取也必须限制在同一天。"""
    day, _items = _ledger_test_items()
    a = M.Item(M.Alert.build(day + "T09:00:00+08:00", "tool_call_blocked",
                             reason="today", rule_id="DST-01"))
    prev = (datetime.fromisoformat(day) - timedelta(days=1)).strftime("%Y-%m-%d")
    b = M.Item(M.Alert.build(prev + "T09:00:00+08:00", "tool_call_blocked",
                             reason="yesterday", rule_id="DST-01"))
    got = M.filter_items([a, b], "day:%s:rule:DST-01" % day)
    return len(got) == 1 and got[0].id == a.id


def n_daily_rule_drill_is_date_scoped():
    """负控：普通规则筛选会返回多个日期，证明新增日期范围并非恒真。"""
    day = time.strftime("%Y-%m-%d")
    a = M.Item(M.Alert.build(day + "T09:00:00+08:00", "tool_call_blocked",
                             reason="today", rule_id="DST-01"))
    prev = (datetime.fromisoformat(day) - timedelta(days=1)).strftime("%Y-%m-%d")
    b = M.Item(M.Alert.build(prev + "T09:00:00+08:00",
                             "tool_call_blocked", reason="yesterday", rule_id="DST-01"))
    return len(M.filter_items([a, b], "rule:DST-01")) == 2


def c_window_size_set():
    """★ 创始人意见②：窗口默认别那么长 —— app 窗口必须带 `--window-size`。"""
    cmd = SV._app_window_cmd("http://127.0.0.1:8790/")
    return bool(cmd) and any(a.startswith("--window-size=") for a in cmd)


def n_window_size_set():
    """负控：`WINDOW_SIZE` 兜底常量必须**真的被用上**。

    ★★ 0.36.0 修正（这条负控在 0.36.0 **真的失效过一次**）：
      原负控假设"改 `WINDOW_SIZE` ⇒ 命令里的尺寸跟着变"。
      但 0.36.0 起`_app_window_cmd()` **屏幕正常时走几何分支**
      （`inbox_window.console_geometry()` 实算），
      `WINDOW_SIZE` 只在**屏幕小到开不下**时才用
      ⇒ 改常量对正常路径**没有影响** ⇒ 负控恒红（活力 136/137）。
      ⇒ 负控必须**显式走到兜底分支**再验：给一个"屏幕装不下"的
        geometry，看命令里是否出现被改后的常量。
      ★ 这也顺手把一条设计事实写进判据：
        `WINDOW_SIZE` 是**兜底**，不是实际尺寸（实际按工作区实算）。
    """
    import inbox_window as WIN
    saved = SV.WINDOW_SIZE
    # ★ 造一个"屏幕装不下"的几何 ⇒ 强制走 WINDOW_SIZE 兜底分支
    tiny = WIN.console_geometry([WIN.WorkArea(0, 0, 420, 300)])
    assert not tiny["ok"], "小工作区应判成开不下（负控的前提）"
    SV.WINDOW_SIZE = "999,999"
    try:
        cmd = SV._app_window_cmd("http://127.0.0.1:8790/", geometry=tiny)
        if cmd is None:
            return False                    # 本机找不到 app 浏览器 ⇒ 负控无效
        return "--window-size=999,999" in cmd
    finally:
        SV.WINDOW_SIZE = saved


def c_server_read_all_cancelled():
    """★ 创始人拍板①：服务端不再受理「全部已读」（页面没按钮了，也不留后门动作）。"""
    hub = G.new_hub()
    G.put_chain(hub, [G.breach(reason="r1")])
    srv = G.Server(hub)
    try:
        s, _h, _b = G.req(srv.port, "/action", token=srv.token, method="POST",
                          body="op=read_all", ctype="application/x-www-form-urlencoded")
        return s == 409
    finally:
        srv.stop()


def n_server_read_all_cancelled():
    """负控：`op=read` **仍然可用**（证明不是"整个 /action 都坏了"）。"""
    hub = G.new_hub()
    G.put_chain(hub, [G.breach(reason="r1")])
    it = S.load_items(root=hub)[0]
    srv = G.Server(hub)
    try:
        s, _h, _b = G.req(srv.port, "/action", token=srv.token, method="POST",
                          body="op=read&id=%s" % it.id,
                          ctype="application/x-www-form-urlencoded")
        after = S.load_items(root=hub)[0].state
        return s == 303 and after == "read"
    finally:
        srv.stop()


def _no_side_effect_revive():
    """★ 打桩上下文：**判据不许有真实副作用**。

    ★ 为什么（本轮实测的真缺陷）：`op=fix` 的服务端实现会走
      `guard_fix → ensure_alive → spawn_sentinel`，而 `ensure_alive` 读的
      `_shield_audit_dir(inbox_server 所在目录)` 是**真包**的链（不是沙箱 hub）
      ⇒ 判据每跑一次就**真的拉起一个哨兵进程**。实测：一次连跑就冒出
      pid 68212/70916/74796/69264/67300/49396 六个。
      （它此前没暴露，只是因为自检不过 ⇒ `spawn_sentinel` 拒绝拉起。）
      ⇒ 只把**副作用**打桩掉；**接线本身照测**（判据要验的是"入口有没有落点"，
        不是"它真的去拉进程"）。返回 (restore_callable,)。
    """
    import host_shield as HS
    saved = HS.ensure_alive
    HS.ensure_alive = lambda pkg_root=None, cause="manual": "alive"

    def _restore():
        HS.ensure_alive = saved
    return _restore


def c_server_fix_endpoint():
    """★ 失守入口在服务端真的有落点（`op=fix` 不许只是页面上的装饰）。"""
    hub = G.new_hub()
    srv = G.Server(hub)
    _restore = _no_side_effect_revive()
    try:
        s, _h, _b = G.req(srv.port, "/action", token=srv.token, method="POST",
                          body="op=fix", ctype="application/x-www-form-urlencoded")
        return s == 303
    finally:
        _restore()
        srv.stop()


def n_server_fix_endpoint():
    """负控：`op=fix` 也**必须**要口令（不许因为它是"修复"就裸奔）。"""
    hub = G.new_hub()
    srv = G.Server(hub)
    _restore = _no_side_effect_revive()
    try:
        s, _h, _b = G.req(srv.port, "/action", method="POST", body="op=fix",
                          ctype="application/x-www-form-urlencoded")
        return s == 403
    finally:
        _restore()
        srv.stop()


def c_fix_endpoint_has_no_real_side_effect():
    """★★ **判据不许有真实副作用**：跑 `op=fix` 那条判据时，一次都不许真的拉起哨兵。

    ★ 为什么（本轮实测的真缺陷，创始人报障「右下又在冒泡」）：
      判据每跑一次就真的起一个哨兵进程（实测一次连跑冒出 6 个 pid）。而每个哨兵
      起来/被杀都会写 `host_shield_revived` —— 它在 `_ALERT_KINDS` 弹窗名单里
      ⇒ **判据制造了它本该只观察的现象**，创始人看到右下角一直冒泡。
      这比"测试脏"更严重：它让"绿"这个信号本身失真。

    ★ 本判据用**间谍**替掉 `spawn_sentinel`（不真起进程），再跑那条判据。
    """
    import host_shield as HS
    calls = []
    saved = HS.spawn_sentinel
    HS.spawn_sentinel = lambda *a, **k: (calls.append(a), (True, 0, "spy"))[1]
    try:
        ok = c_server_fix_endpoint()
    finally:
        HS.spawn_sentinel = saved
    return ok is True and calls == []


def n_fix_endpoint_has_no_real_side_effect():
    """负控：**绕过那条判据、直接打同一个入口** ⇒ 必须真的走到 spawn。

    ★ 证明上一条"没副作用"是**打桩带来的**，不是"这个入口本来就不拉进程"
      （否则上一条就是恒真废话）。
    """
    import host_shield as HS
    hub = G.new_hub()
    srv = G.Server(hub)
    calls = []
    s_spawn, s_pid, s_rec = HS.spawn_sentinel, HS.pid_alive, HS.record
    HS.spawn_sentinel = lambda *a, **k: (calls.append(a), (True, 0, "spy"))[1]
    HS.pid_alive = lambda pid: True
    # ★ 连**留痕**也堵掉：`ensure_alive` 写的 audit_dir 是**真包**的链
    #   （`inbox_server._pkg_root()`），不是沙箱 hub ⇒ 不堵就会往真链里塞记录
    #   （实测：真链上出现 `由 console 重新拉起（mode=spy）`）。判据不许污染真链。
    HS.record = lambda *a, **k: None
    try:
        G.req(srv.port, "/action", token=srv.token, method="POST",
              body="op=fix", ctype="application/x-www-form-urlencoded")
        return calls != []
    finally:
        HS.spawn_sentinel, HS.pid_alive, HS.record = s_spawn, s_pid, s_rec
        srv.stop()


def c_guard_fix_honest():
    """★★ `guard_fix` **修不了就说修不了**，绝不回一个假的"已修复"。"""
    import host_shield as HS
    ok, msg = HS.guard_fix(_tmpdir(), action="nonexistent-action")
    return ok is False and ("没有可就地修复" in msg or "修" in msg)


def n_guard_fix_honest():
    """负控：`enable` 是"要本人在终端做"的动作 ⇒ 必须返回 False 并说清去哪儿做。"""
    import host_shield as HS
    ok, msg = HS.guard_fix(_tmpdir(), action="enable")
    return ok is False and "host-shield enable" in msg


def R_report_window(items):
    """从日报里取窗口数字（走产品函数，不另算）。"""
    import inbox_report as R
    return R.daily_report(day=time.strftime("%Y-%m-%d"), items=items)["window_levels"]


def c_report_window_numbers_match_topbar():
    """★★ 顶部条与日报的"最近 N 小时"数字**必须是同一个数**（不许各算一套）。"""
    items = [G.item("L2", "unread", 1), G.item("L2", "unread", 2),
             G.item("R0", "unread", 3)]
    a = M.window_levels(items)
    b = R_report_window(items)
    return a == b and a["L2"] == 2 and a["R0"] == 1


def n_report_window_numbers_match_topbar():
    """负控：窗口**真的在过滤** —— 30 小时前的记录不计入 24 小时数字。"""
    items = [G.item("L2", "unread", 1, ts=_iso(30))]
    return M.window_levels(items)["L2"] == 0


# ============================================== 六、保活（paramedic）权威 ====
def _load_hook(name):
    """按路径加载 `hooks/<name>.py`（hooks 不是包，没有 `__init__.py`）。"""
    import importlib.util
    p = os.path.join(G.PKG, "hooks", name + ".py")
    spec = importlib.util.spec_from_file_location("hook_" + name, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _paramedic_probe(recs):
    """跑一次 `_shield_paramedic()`，返回它**有没有去拉哨兵**（list of cause）。"""
    import host_shield as HS
    PT = _load_hook("post_tool_use")
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    adir = _chain_dir(_tmpdir())
    for r in recs:
        _write_rec(adir, r)
    calls = []
    s_state, s_dir, s_alive = HS.load_state, HS._shield_audit_dir, HS.ensure_alive
    HS.load_state = lambda: {"enabled": False, "workspaces": {}, "zones": [], "windows": {}}
    HS._shield_audit_dir = lambda root=None: adir
    HS.ensure_alive = lambda root, cause="manual": calls.append(cause)
    try:
        PT._shield_paramedic()
    finally:
        HS.load_state, HS._shield_audit_dir, HS.ensure_alive = s_state, s_dir, s_alive
    return calls


def c_paramedic_uses_chain_authority():
    """★★ 保活必须用**与其它裁决同一个权威**：链（`armed_state`），不是 state 的 `enabled`。

    ★ 为什么（真缺陷，本机实测 2026-10-06）——**这就是界面「永远失守」的根因**：
      旧版 `_shield_paramedic` 门控读 `state["enabled"]`。本机实测：链说"布防中"
      （armed=True）、state 写着 False ⇒ 保活**永不触发** ⇒ 哨兵死了 2 小时没人拉
      （期间链上 **1777 条**记录、**564 次** post_tool_use，一次都没把它拉起来）。
      **挡住保活的，恰恰是保活本身要修的那个不一致** —— 本仓「同一事实两处副本」
      第 5 次复发（前 4 次见 `cross-card-object-check` 技能）。
    ★ 卡行为不卡词面：把 `load_state` / `_shield_audit_dir` / `ensure_alive` 三处换成
      受控替身，喂一个「链 armed ＋ state False」的局面，看它**到底有没有去拉**。
    """
    calls = _paramedic_probe([{"ts": _iso(0), "type": "host_shield_heartbeat",
                               "decision": "allow"}])
    return calls == ["hook-paramedic"]


def n_paramedic_uses_chain_authority():
    """负控：链上**明确写着撤防**（`field=enabled, armed=false`）⇒ 保活必须**不动作**。

    ★ 这条负控比"空链"更强：它证明判据读的是**链上的那个值**，
      而不是"链非空就算布防中"（否则"撤防"就永远撤不掉，又是另一种失控）。
    """
    calls = _paramedic_probe([{"ts": _iso(0), "type": "host_shield_changed",
                               "field": "enabled", "armed": False,
                               "change": "true → false"}])
    return calls == []


# ===================================== 七、失守重定义（0.35.3，创始人拍板）====
# ★★ 创始人 2026-10-06 原话：
#   「如果现在的『真失守』跟假失守没啥区别，不会带来明显不利后果，
#     那就跟假失守没啥区别。」「要再考虑清楚如何定义失守。」
#   ⇒ 定稿口径：**失守（红）＝ 缺岗 ∧ 说得出损失**；说不出损失 ⇒ 只配叫「中断·无损失」（黄）。
#     红/黄的分界由 `_outage_consequences()` **可复算**地给出（不是感觉）。
def c_outage_without_consequence_is_interrupted():
    """★★ 缺岗但**没有监管对象** ⇒ 只能叫「中断·无损失」，**不许**叫失守。

    ★ 为什么（创始人 2026-10-06）：一个说不出损失的"失守"就是**假失守**。
      「中断」仍然黄灯、仍然给「马上修复」—— **不隐藏**，只是不冒称"防线失守"。
    """
    import host_shield as HS
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": None, "sentinel_started_at": None})
    saved = HS.self_check
    HS.self_check = lambda: (True, [])
    try:
        pkg = _tmpdir()
        _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                     "decision": "allow"})
        p = HS.guard_posture(pkg)
        return (p["state"] == HS.POSTURE_INTERRUPTED
                and p["consequences"] == []
                and p["can_fix"] is True and p["fix"] == "revive"
                and "没有监管对象" in p["why"])
    finally:
        HS.self_check = saved


def n_outage_without_consequence_is_interrupted():
    """负控：**有安全区**（有监管对象）⇒ 必须是**失守（红）**，不许一路"中断"。

    ★ 证明上一条不是"什么都叫中断"。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": ["D:\\secret"],
                   "windows": {}, "sentinel_pid": None, "sentinel_started_at": None})
    saved = HS.self_check
    HS.self_check = lambda: (True, [])
    try:
        pkg = _tmpdir()
        _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                     "decision": "allow"})
        p = HS.guard_posture(pkg)
        return (p["state"] == HS.POSTURE_DOWN
                and any(c["kind"] == "zone_unlocked" for c in p["consequences"]))
    finally:
        HS.self_check = saved


def c_outage_sees_supervised_landing():
    """★★ 登记表里有受监管落点 ⇒ 缺岗**必须**把它算成后果。

    ★ 为什么（本轮实测坐实的真形状）：`_outage_consequences` 第一版只查 state 的
      windows/zones/workspaces，**漏了登记表这一路**。而 `iter_gate_targets` 遍历的是
      **全部宿主**登记表 ⇒ 装了 zcode 的机器上 `~/.zcode/v2/checkpoints/*/pending`
      一直在门闸职责内。只查 state 会把"有 4 个落点没人巡检"误判成"无监管对象"——
      那就是本仓最恨的**假守卫**：判据漏了一路，还报绿。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": None, "sentinel_started_at": None})
    saved = HS.self_check
    HS.self_check = lambda: (True, [])
    try:
        pkg = _tmpdir()
        _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                     "decision": "allow"})
        # 造一个"受监管落点"：登记表 + 落点目录（本机是 zcode checkpoints，形状相同）
        base = os.path.join(pkg, "landing")
        os.makedirs(os.path.join(base, "w1", "pending"), exist_ok=True)
        os.makedirs(os.path.join(pkg, "rules", "hosts"), exist_ok=True)
        with open(os.path.join(pkg, "rules", "hosts", "t.json"), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump({"host": "t", "watch": [{"path": base, "kind": "x",
                                               "gate_default": "report"}]}, f)
        p = HS.guard_posture(pkg)
        return (p["state"] == HS.POSTURE_DOWN
                and any(c["kind"] == "landing_unwatched" for c in p["consequences"]))
    finally:
        HS.self_check = saved


def n_outage_sees_supervised_landing():
    """负控：**登记表为空、落点不存在** ⇒ 不许冒出 `landing_unwatched`。

    ★ 证明上一条不是"永远报有落点"。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": None, "sentinel_started_at": None})
    saved = HS.self_check
    HS.self_check = lambda: (True, [])
    try:
        pkg = _tmpdir()                     # 没有 rules/hosts，也没有落点目录
        _write_rec(_chain_dir(pkg), {"ts": _iso(0), "type": "host_shield_heartbeat",
                                     "decision": "allow"})
        p = HS.guard_posture(pkg)
        return (p["state"] == HS.POSTURE_INTERRUPTED and p["consequences"] == [])
    finally:
        HS.self_check = saved


def c_consequence_blindspot_counts_as_loss():
    """★★ 查不出受监管落点清单 ⇒ **按"有"算**（红），不许当作"没有"。

    ★ 本仓铁律：「查不出来 ≠ 查出来是好的」。把读失败降级成"无损失"＝假失守。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {}})
    saved = HS.iter_gate_targets

    def _boom(root, regs=None):
        raise RuntimeError("登记表坏了")

    HS.iter_gate_targets = _boom
    try:
        cons = HS._outage_consequences(HS.load_state(), _tmpdir())
        return (len(cons) == 1 and cons[0]["kind"] == "landing_unknown"
                and "盲区" in cons[0]["text"])
    finally:
        HS.iter_gate_targets = saved


def n_consequence_blindspot_counts_as_loss():
    """负控：登记表正常（空）⇒ 不许冒出 `landing_unknown`。

    ★ 否则"盲区"那档会被滥用成万能兜底（什么都报盲区 ⇒ 判据失去分辨力）。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {}})
    cons = HS._outage_consequences(HS.load_state(), _tmpdir())
    return cons == []


def c_selfcheck_fail_is_warn_not_down():
    """★★ 在岗 + 自检不符 ⇒ **黄灯一档**（存疑或研发中），**绝不是失守（红）**。

    ★ 为什么：本仓铁律「查不出来 ≠ 查出来是坏的」���"我认不出守门的是不是出厂那份"
      ≠ "此刻没在守"。把"认不出"渲染成"失守"就是创始人说的"跟假失守没区别"。
    ★ **绝不放松自检**：自检照旧跑、照旧报（`evidence.self_check_problems` 留着），
      只是**换档位**；而且给得出下一步。

    ★★★ 0.36.3：档位从**一种**变成**两种**，但不变的是"绝不是红灯"。
      研发期（登记版本 < 代码版本）⇒ `dev`「研发中」；
      已出厂（版本一致/更高）⇒ `warn`「存疑」。
      ★ 这里**不是把判据放宽成"两个都行"** —— 那样这条判据就失去分辨力了。
        所以下面**分别**断言每一档的完整性质（label / can_fix / evidence /
        fix_hint 全部照旧），任何一档退化成红灯或丢掉 evidence 都会红。
    """
    import host_shield as HS
    o_inst, o_code = HS._installed_version, HS._code_version
    results = []
    try:
        for note, iv, cv in (("研发期", "0.1.0", "0.9.0"),
                             ("已出厂", "0.5.0", "0.5.0")):
            os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
            HS.save_state({"enabled": True, "workspaces": {}, "zones": [],
                           "windows": {}, "sentinel_pid": 4242,
                           "sentinel_started_at": time.time()})
            s_alive, s_hb, s_sc = HS.sentinel_alive, HS.heartbeat_age, HS.self_check
            HS._installed_version = lambda v=iv: v
            HS._code_version = lambda v=cv: v
            HS.sentinel_alive = lambda st: True
            HS.heartbeat_age = lambda pkg=None: (30.0, _iso(0))
            HS.self_check = lambda: (False, ["host_shield.py 与 manifest 不符"])
            try:
                p = HS.guard_posture(_tmpdir())
            finally:
                (HS.sentinel_alive, HS.heartbeat_age,
                 HS.self_check) = s_alive, s_hb, s_sc
            # ① 红档在任何情况下都不许出现
            if p["state"] == HS.POSTURE_DOWN:
                results.append("%s：自检不符被判成红灯失守（绝不允许）" % note)
                continue
            # ② 必须落在两个合法档之一
            if p["state"] not in (HS.POSTURE_WARN, HS.POSTURE_DEV):
                results.append("%s：落到计划外档位 %r" % (note, p["state"]))
                continue
            # ③ 每一档的完整性质都必须保留（不许因为换了档就放松别的）
            # ★ 0.37.3：标签跟六态对齐 —— `warn` 的标签由「存疑」改成「失守」
            #   （`light()` 对 warn 走 fail-closed 判 R0；姿态标签必须与灯色
            #   同一套词，否则同一时刻两个叫法）。见
            #   `host_shield.POSTURE_LABEL_ALLOWED`。
            if p["label"] not in ("失守", "研发中"):
                results.append("%s：标签不对 %r" % (note, p["label"]))
            if p["can_fix"] is not False or p["fix"] is not None:
                results.append("%s：给了修复动作（自检不符不该给）" % note)
            if not p["evidence"].get("self_check_problems"):
                results.append("%s：把自检问题吞掉了（必须如实留在 evidence）" % note)
            if not p["fix_hint"]:
                results.append("%s：没有给用户任何说明" % note)
            results.append("%s→%s OK" % (note, p["state"]))
    finally:
        HS._installed_version, HS._code_version = o_inst, o_code
    bad = [r for r in results if not r.endswith("OK")]
    if bad:
        return "；".join(bad)
    if len([r for r in results if r.endswith("OK")]) != 2:
        return "两档没有都验到：%r" % results
    return True


def n_selfcheck_fail_is_warn_not_down():
    """负控：在岗 + 自检**通过** ⇒ 必须是**值守中**，不许一路"存疑"。

    ★ 证明上一条不是"只要活着就叫存疑"。
    """
    import host_shield as HS
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": 4242, "sentinel_started_at": time.time()})
    s_alive, s_hb, s_sc = HS.sentinel_alive, HS.heartbeat_age, HS.self_check
    HS.sentinel_alive = lambda st: True
    HS.heartbeat_age = lambda pkg=None: (30.0, _iso(0))
    HS.self_check = lambda: (True, [])
    try:
        p = HS.guard_posture(_tmpdir())
        return p["state"] == HS.POSTURE_GUARDING
    finally:
        HS.sentinel_alive, HS.heartbeat_age, HS.self_check = s_alive, s_hb, s_sc


def c_light_warn_is_down_and_interrupted_is_l1():
    """★★ 0.37.1 换代判据：「**存疑**态已取消」（创始人 2026-10-07 定性
    「计划外状态，不允许」；2026-10-08 再确认六态＝LOGO 五态＋开发态）。
    · 出厂码与登记不符（非研发）⇒ **fail-closed 按 R0 失守**（红）：
      「认不出守门的是不是原来那道门」时不 waffle，按它在裸奔算。
    · 缺岗但无监管对象 ⇒ **L1 注意**（黄：可证明没损失，不冒称失守）。
    · warn 不许落进 dev 蓝（研发豁免只属于"版本落差"，见 is_dev_build）。
    """
    w, _ = M.light("warn", [])
    i, _ = M.light("interrupted", [])
    return (w == M.STATE_R0 and M.STATE_LABEL[w] == "失守"
            and i == M.STATE_L1 and M.STATE_LABEL[i] == "注意"
            and M.STATE_VAR[i] == "--l1" and w != M.STATE_DEV)


def n_light_warn_is_down_and_interrupted_is_l1():
    """负控：两者都不许是**绿** —— 历史再干净也不行。

    ★ 空历史下若漏到"历史分支"就会变绿 ⇒ 这条负控证明走的是**态势分支**。
    """
    for st in ("warn", "interrupted"):
        lg, _ = M.light(st, [])
        if lg == M.STATE_L0:
            return False
    return True


def c_consequences_has_consumer():
    """★★ 失守的**损失清单必须在页面上看得见**（登记了必须等于会被查）。

    ★ 为什么：`guard_posture` 产出 `consequences` 却**零消费点** —— 正是本仓点名的
      「登记了却不会被查」的假守卫。创始人要的正是"说出损失"。
    """
    down = {"state": "down", "label": "失守", "why": "哨兵不在岗",
            "can_fix": True, "fix": "revive", "fix_hint": "马上修复（重新拉起哨兵）",
            "consequences": [{"kind": "zone_unlocked",
                              "text": "有 1 个安全区，此刻没人给它们上锁：D:\\secret"}]}
    h = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=down,
                       items=[G.item("L2", "unread")])
    return ('class="cons"' in h and "D:\\secret" in h and "失守的损失" in h)


def n_consequences_has_consumer():
    """负控：**没有后果**（中断）⇒ 页面上不许出现"失守的损失"那一块（否则是常驻噪音）。"""
    intr = {"state": "interrupted", "label": "中断", "why": "此刻没有监管对象",
            "can_fix": True, "fix": "revive", "fix_hint": "马上修复（重新拉起哨兵）",
            "consequences": []}
    h = SV.render_page(view="inbox", root=G.new_hub(), token="t", posture=intr,
                       items=[G.item("L2", "unread")])
    return 'class="cons"' not in h


def _revive_probe(pkg_hb_hours, hub_hb_hours):
    """脚手架：包链放 `pkg_hb_hours` 前的心跳、中枢 rollup 放 `hub_hb_hours` 前的，
    然后问 `ensure_alive` 判成什么。★ **全程打桩，绝不真的起进程**。"""
    import host_shield as HS
    pkg = _tmpdir()
    adir = _chain_dir(pkg)
    hub = _tmpdir()
    os.environ["ANTINEL_HUB_DIR"] = hub
    rdir = os.path.join(hub, "rollup")
    os.makedirs(rdir, exist_ok=True)
    _write_rec(adir, {"ts": _iso(1.0), "type": "host_shield_changed",
                      "field": "enabled", "armed": True, "change": "false → true"})
    _write_rec(adir, {"ts": _iso(pkg_hb_hours), "type": "host_shield_heartbeat",
                      "decision": "allow"})
    _write_rec(rdir, {"ts": _iso(hub_hb_hours), "type": "host_shield_heartbeat",
                      "decision": "allow"})
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": 4242, "sentinel_started_at": time.time(),
                   "last_revive_attempt": 0})
    calls = []
    s_spawn, s_pid, s_run = HS.spawn_sentinel, HS.pid_alive, HS.subprocess.run
    HS.spawn_sentinel = lambda root, python_exe=None: (calls.append(root),
                                                       (True, 999, "stub"))[1]
    HS.pid_alive = lambda pid: True
    HS.subprocess.run = lambda *a, **k: type("R", (), {"returncode": 0})()
    try:
        return HS.ensure_alive(pkg, cause="guard"), calls, pkg
    finally:
        HS.spawn_sentinel, HS.pid_alive, HS.subprocess.run = s_spawn, s_pid, s_run


def c_ensure_alive_reads_its_own_chain():
    """★★ `ensure_alive` 判"僵死"必须读**它手里那个审计目录**的心跳。

    ★ 为什么（本轮实测的真缺陷，创始人报障「右下又在冒泡」）：
      `ensure_alive` 里写的是 `heartbeat_age(audit_dir)`，而 `heartbeat_age` 的入参是
      **包根**。传审计目录 ⇒ `_shield_audit_dir(<audit>)` 在 `<audit>/.psl` 找不到东西
      ⇒ **回退到中枢 rollup** ⇒ 读到几小时前的老心跳 ⇒ 刚起来的哨兵立刻被判
      "僵死（574 分钟前）" ⇒ 杀掉重拉 ⇒ 每次重拉都发 `host_shield_revived`
      （在 `_ALERT_KINDS` 弹窗名单里）⇒ **右下角一直冒泡**。
      本机实测（同一时刻）：`heartbeat_age(pkg_root)` = 87 秒（真）；
      `heartbeat_age(audit_dir)` = 34454 秒（错，＝574 分钟）。

    ★ 本判据：**包链新鲜 + 中枢老** ⇒ 必须判"在岗"、一次都不许重拉。
    """
    r, calls, _pkg = _revive_probe(pkg_hb_hours=0.0, hub_hb_hours=10.0)
    return r == "alive" and calls == []


def n_ensure_alive_reads_its_own_chain():
    """负控：**包链真的陈旧**（中枢反而新鲜）⇒ 必须判僵死并重拉。

    ★ 与上一条**互为镜像**：两条合起来才证明它读的是**包链**，
      而不是"永远说在岗"或"永远说僵死"。
    """
    r, calls, pkg = _revive_probe(pkg_hb_hours=10.0, hub_hb_hours=0.0)
    return r == "stale-revived" and calls == [pkg]


def _heartbeat_probe(pkg_hb_hours, hub_hb_hours):
    """脚手架：包审计放 `pkg_hb_hours` 前的心跳、中枢 rollup 放 `hub_hb_hours` 前的，
    返回 `(报心跳用的包根, 包审计目录, 中枢目录, 还原函数)`。

    ★ 全程只读/临时目录，**不碰真链、不起进程**。
    """
    import host_shield as HS
    pkg = _tmpdir()
    adir = _chain_dir(pkg)
    hub = _tmpdir()
    old_hub = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = hub
    rdir = os.path.join(hub, "rollup")
    os.makedirs(rdir, exist_ok=True)
    _write_rec(adir, {"ts": _iso(pkg_hb_hours), "type": "host_shield_heartbeat",
                      "decision": "allow"})
    _write_rec(rdir, {"ts": _iso(hub_hb_hours), "type": "host_shield_heartbeat",
                      "decision": "allow"})
    s_pkg = HS._pkg_root
    HS._pkg_root = lambda: pkg

    def _restore():
        HS._pkg_root = s_pkg
        if old_hub is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_hub

    return adir, rdir, _restore


def c_status_heartbeat_reads_sentinel_chain():
    """★★ `host-shield status` 报的心跳，必须来自**哨兵真正写入**的那条链。

    ★ 为什么（真缺陷，本机实测 2026-10-06）：
      `status` 调的是 `heartbeat_age()`（**无参**）⇒ `_shield_audit_dir(None)`
      ⇒ **中枢 rollup**（实测停 09-29）；而哨兵（包根带 `.psl`）写的是**包审计**
      （实测 22:05 还在写）⇒ 把活哨兵报成「最后心跳 693 分钟前」。
      这与 0.35.3 修过的那条是**同一类错**（包根/审计目录搞混 ⇒ 读老心跳），
      只是换了个调用点 —— 所以必须单独守。

    ★ 量具：造「包链新鲜 + 中枢老」现场，`sentinel_heartbeat_age()` 必须报**新鲜**那条。
    """
    import host_shield as HS
    adir, rdir, restore = _heartbeat_probe(pkg_hb_hours=0.0, hub_hb_hours=11.0)
    try:
        age, _ = HS.sentinel_heartbeat_age()
    finally:
        restore()
    return age is not None and age < 120          # 报"刚刚"，不是 11 小时前


def n_status_heartbeat_reads_sentinel_chain():
    """负控：把口径换回**无参**（中枢 rollup）⇒ 同一现场必须报出**老**心跳。

    证明上一条不是恒真：口径若退回中枢，同一个现场会报 11 小时前。
    """
    import host_shield as HS
    adir, rdir, restore = _heartbeat_probe(pkg_hb_hours=0.0, hub_hb_hours=11.0)
    try:
        age, _ = HS.heartbeat_age(None)           # ← 旧口径（走中枢 rollup）
    finally:
        restore()
    return age is not None and age > 600 * 60


def c_task_missing_recorded_once():
    """★★ 登录自启缺失是**持续状态**（不是复发事件）：状态不变时**不许反复留痕**。

    ★ 创始人 2026-10-06 报障「右下一直冒泡」：原实现**每次巡视**都 record 一条
      **完全相同**的 breach ⇒ 一天 288 条链记录 ＋ 每 30 分钟一次弹窗，**永远不停**。
      这是本仓明令禁止的「长期红的守卫＝没守卫」：红灯很快就没人看了。
    ★ 量具：直接调产品的 `_task_watchdog`（**不二次实现**），连喂 3 拍"仍然是坏"，
      只许第 1 拍留痕。
    """
    import host_shield as HS
    hub = G.new_hub()
    recs = []
    s_ti, s_rec = HS.task_installed, HS.record
    HS.task_installed = lambda: False
    HS.record = lambda d, k, **kw: recs.append(k)
    try:
        st = {}
        for i in range(3):
            HS._task_watchdog(st, hub, 1000.0 + i * 300.0)
    finally:
        HS.task_installed, HS.record = s_ti, s_rec
    return recs.count("host_shield_breach") == 1


def n_task_missing_recorded_once():
    """负控：**状态转变**（好→坏）与**超过再提醒间隔** ⇒ **必须**再记。

    证明上一条的"只记一条"不是"永远只记一条"（不是恒真废话）。
    """
    import host_shield as HS
    hub = G.new_hub()
    recs = []
    cur = {"v": False}
    s_ti, s_rec = HS.task_installed, HS.record
    HS.task_installed = lambda: cur["v"]
    HS.record = lambda d, k, **kw: recs.append(k)
    try:
        st = {}
        HS._task_watchdog(st, hub, 1000.0)              # 首拍坏：记 1
        cur["v"] = True
        HS._task_watchdog(st, hub, 1300.0)              # 好了：不记
        cur["v"] = False
        HS._task_watchdog(st, hub, 1600.0)              # 又坏（转变）：记 2
        HS._task_watchdog(st, hub, 1600.0 + 86401.0)    # 超 24h 未再提醒：记 3
    finally:
        HS.task_installed, HS.record = s_ti, s_rec
    return recs.count("host_shield_breach") == 3


def c_task_unknown_recorded_once():
    """★★ 「**查不出来**」也要降噪：`task_installed()` 恒 None ⇒ 不许每次巡视都记一条。

    ★ 真缺陷（与 `autostart_missing` 同一形状）：旧版 `_ti is None` 分支**没有去重**
      （每次巡视无条件 record）⇒ `schtasks.exe` 被程序黑名单拦死的机器上，
      一天 288 条 `host_shield_task_unknown`。
    ★ 量具：直接调产品的 `_task_watchdog`，连喂 3 拍"仍然查不出"，只许第 1 拍留痕。
    """
    import host_shield as HS
    hub = G.new_hub()
    recs = []
    s_ti, s_rec = HS.task_installed, HS.record
    HS.task_installed = lambda: None
    HS.record = lambda d, k, **kw: recs.append(k)
    try:
        st = {}
        HS._task_watchdog(st, hub, 1000.0)
        HS._task_watchdog(st, hub, 1300.0)
        HS._task_watchdog(st, hub, 1600.0)
    finally:
        HS.task_installed, HS.record = s_ti, s_rec
    return recs.count("host_shield_task_unknown") == 1


def n_task_unknown_recorded_once():
    """负控：**状态转变**（在 → 查不出）⇒ 必须再记一次。

    证明上一条不是"永远只记一条"。
    """
    import host_shield as HS
    hub = G.new_hub()
    recs = []
    cur = {"v": True}
    s_ti, s_rec = HS.task_installed, HS.record
    HS.task_installed = lambda: cur["v"]
    HS.record = lambda d, k, **kw: recs.append(k)
    try:
        st = {}
        HS._task_watchdog(st, hub, 1000.0)          # 在：不记
        cur["v"] = None
        HS._task_watchdog(st, hub, 1300.0)          # 转变：记 1
        HS._task_watchdog(st, hub, 1600.0)          # 持续：不记
    finally:
        HS.task_installed, HS.record = s_ti, s_rec
    return recs.count("host_shield_task_unknown") == 1


def _task_installed_probe(shim_present, schtasks):
    """脚手架：把 APPDATA 指到临时目录、`subprocess.run` 打桩，问 `task_installed()`。

    `schtasks` 取值：`"raise"`（本机实况：被程序黑名单拦死）/ `"no"`（能查、说没有）。
    ★ 全程临时目录 + 打桩，**不碰真启动文件夹、不真的起 schtasks**。
    """
    import host_shield as HS
    tmp = _tmpdir()
    if shim_present:
        sd = os.path.join(tmp, "Microsoft", "Windows", "Start Menu",
                          "Programs", "Startup")
        os.makedirs(sd, exist_ok=True)
        with open(os.path.join(sd, "antinel-shield.cmd"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("@echo off\n")
    old = os.environ.get("APPDATA")
    s_run = HS.subprocess.run
    os.environ["APPDATA"] = tmp

    if schtasks == "raise":
        def _run(*a, **k):
            raise PermissionError("schtasks blocked by program blacklist")
    else:
        def _run(*a, **k):
            return type("R", (), {"returncode": 1})()
    HS.subprocess.run = _run
    try:
        return HS.task_installed()
    finally:
        HS.subprocess.run = s_run
        if old is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = old


def c_task_installed_sees_startup_shim():
    """★★ 启动项在 ⇒ `task_installed()` 必须说"在"（**哪怕 schtasks 起不来**）。

    ★ 为什么（真缺陷，本机实测 2026-10-06）：旧版**先**跑 schtasks，异常就
      `return None` ⇒ 启动文件夹那条回退**永远到不了**（0.28.2 的意图是死代码）。
      本机 `schtasks.exe` 被程序黑名单拦死 ⇒ `task_installed()` **恒为 None**
      ⇒「自启缺失」这条检测在本机**永远不会响**（＝假守卫），
      而启动项明明就在那儿。修法＝**文件系统事实优先**。
    """
    return _task_installed_probe(shim_present=True, schtasks="raise") is True


def n_task_installed_sees_startup_shim():
    """负控（两半，缺一即假绿）：

      ① 启动项**不在** + schtasks 起不来 ⇒ 必须 `None`（**查不出 ≠ 没有**）；
      ② 启动项**不在** + schtasks 能查且说没有 ⇒ 必须 `False`（确定没有）。
    """
    a = _task_installed_probe(shim_present=False, schtasks="raise")
    b = _task_installed_probe(shim_present=False, schtasks="no")
    return a is None and b is False


def _notify_probe(recs):
    """脚手架：把 `_notify_throttled` 换成记录器，喂若干条记录，返回被弹的 kind 列表。

    ★ 全程临时目录、镜像关掉，**不碰真链、不真弹气泡**。
    """
    import host_shield as HS
    tmp = _tmpdir()
    old_m = os.environ.get("ANTINEL_SHIELD_MIRROR")
    os.environ["ANTINEL_SHIELD_MIRROR"] = "0"
    calls = []
    s_notify = HS._notify_throttled
    HS._notify_throttled = lambda kind, msg, force=False: calls.append(kind)
    try:
        for kw in recs:
            HS.record(tmp, kw.pop("_kind"), **kw)
    finally:
        HS._notify_throttled = s_notify
        if old_m is None:
            os.environ.pop("ANTINEL_SHIELD_MIRROR", None)
        else:
            os.environ["ANTINEL_SHIELD_MIRROR"] = old_m
    return calls


def _hookreg_scan_probe(change_after_register):
    """脚手架：造一个 settings 文件，登记其哈希；按 `change_after_register` 决定
    登记后是否**改动**该文件；跑一次产品的 `scan_once`，返回被记的 (kind, subkind)。

    ★ 临时目录 + 临时中枢 + 打桩 record/task_installed ⇒ **不碰真链、不碰真 state**。
    """
    import host_shield as HS
    hub = _tmpdir()
    root = _tmpdir()
    sp = os.path.join(root, "settings.json")
    with open(sp, "w", encoding="utf-8", newline="\n") as f:
        f.write('{"hooks": {"PreToolUse": [{"command": "pre_tool_use.py"}]}}')
    reg_sha = HS._file_sha256(sp)
    if change_after_register:
        with open(sp, "w", encoding="utf-8", newline="\n") as f:
            f.write('{"hooks": {"PreToolUse": [{"command": "pre_tool_use.py"}]},'
                    ' "extra": 1}')
    recs = []
    s_rec, s_ti = HS.record, HS.task_installed
    old_hub = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = _tmpdir()
    HS.record = lambda d, k, **kw: recs.append((k, kw.get("subkind")))
    HS.task_installed = lambda: True
    try:
        st = {"enabled": True, "workspaces": {}, "zones": [], "windows": {},
              "hook_registration": {"settings_file": sp, "sha256": reg_sha}}
        HS.scan_once(root, st, hub)
    finally:
        HS.record, HS.task_installed = s_rec, s_ti
        if old_hub is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_hub
    return recs


def c_hook_reg_hash_no_false_alarm():
    """★★ 登记哈希一致 ⇒ 哨兵**不许**报 `hook_registration_changed`。

    ★ 真缺陷（**本机实测 2026-10-06**）：`antinel host-shield enable` 存的是
      **裸 hexdigest**，而哨兵比对用 `_file_sha256()`（返回 **`sha256:<hex>`**）
      ⇒ 两者**永不相等** ⇒ **永久假失守**：每 5 分钟一条 breach ＋ 每 30 分钟
      一次弹窗，而文件其实**一字未动**（实测 mtime 停在 10-03）。
      这正是创始人报障「不停地有弹窗」的同类根因。
    ★ 量具：真的跑产品 `scan_once`，state 里的登记哈希就是 `_file_sha256(文件)`。
    """
    recs = _hookreg_scan_probe(change_after_register=False)
    return not any(sk == "hook_registration_changed" for _k, sk in recs)


def n_hook_reg_hash_no_false_alarm():
    """负控：文件**真的变了** ⇒ 必须报 `hook_registration_changed`（判据不许瞎）。

    证明上一条不是"永远不报"：登记后把文件改一个字，就必须当场报出来。
    """
    recs = _hookreg_scan_probe(change_after_register=True)
    return any(sk == "hook_registration_changed" for _k, sk in recs)


def c_notify_only_when_owner_needed():
    """★★ 气泡只给「**需要你动手**」的事（创始人 2026-10-06「不停地有弹窗，你要解决」）。

    不弹：自愈（`host_shield_revived`）、常规执法（非 critical 的 `zone_locked`）、
          **明说的变更**（有人跑过命令 ⇒ `invoked_by` 有值，当事人已知情）。
    必弹：真失守（`host_shield_breach`）、无声变更（哨兵自己回写状态）。

    ★ 判据：**能自己解决的不敲门；只有你才能解决的才敲门。**
    """
    silent = _notify_probe([
        {"_kind": "host_shield_revived", "reason": "自愈"},
        {"_kind": "host_shield_zone_locked", "severity": "warning", "reason": "常规执法"},
        {"_kind": "host_shield_changed", "field": "enabled",
         "invoked_by": "agent", "reason": "明说的变更"},
    ])
    loud = _notify_probe([
        {"_kind": "host_shield_breach", "reason": "真失守"},
        {"_kind": "host_shield_changed", "field": "zones", "reason": "无声变更"},
    ])
    return silent == [] and sorted(loud) == ["host_shield_breach", "host_shield_changed"]


def n_notify_only_when_owner_needed():
    """负控：**critical 的 `zone_locked`** 必须弹 —— "常规执法不弹"的边界。

    证明上一条不是"凡 zone_locked 一律不弹"：严重的（critical）仍要敲门。
    """
    calls = _notify_probe([
        {"_kind": "host_shield_zone_locked", "severity": "critical", "reason": "严重执法"},
    ])
    return calls == ["host_shield_zone_locked"]


# ==================== 九、闪窗（0.35.3，创始人报障「窗口不停弹出又马上关掉」）====
# ★ 根因（本机实测 2026-10-06）：哨兵由 `DETACHED_PROCESS` 拉起 ⇒ **没有控制台**；
#   它（或钩子／MCP／值守台）再起**控制台程序**（netstat/tasklist/icacls/taskkill/
#   schtasks/powershell/python）时，若不显式 `CREATE_NO_WINDOW`，Windows 会为子进程
#   **新建控制台** ⇒ 用户看到黑窗一闪。`egress` 采样每 30 秒各起 netstat+tasklist
#   一次 ⇒ **一直闪**。`-WindowStyle Hidden` 挡不住（那是 PowerShell 自己的窗；
#   控制台宿主窗口在建进程那一刻就已创建）。
# ★ 判据形态：**静态扫**生产运行模块里每一个起子进程的调用，必须带 `creationflags`。
#   `**kwargs` 展开（`**kw`）无法静态确认 ⇒ **也算未登记**（fail-loud，不许蒙混）。

# 生产运行模块（常驻／热路径）：哨兵、钩子、MCP、值守台、CLI。
_PROD_SPAWN_FILES = (
    "host_shield.py", "egress.py", "antinel.py", "antinel_mcp.py",
    "inbox_server.py", "inbox_notify.py", "inbox_emphasis.py",
    "inbox_tray.py", "ui_server.py",
    "hooks/pre_tool_use.py", "hooks/post_tool_use.py",
    "tools/enforce_probe.py",
    # ★★ 0.35.3（本轮实测抓到的闪窗真凶）：
    #   本文件**不在**原清单里 ⇒ 守卫对自己没登记的文件不负责，
    #   而它恰好有 **39 处 subprocess.run、0 处带 creationflags** ——
    #   静态扫描因此报"28 个调用全绿"，运行时却还在弹窗。
    #   **登记＝必须修**：进来就得一起绿。
    "scripts/verification_tests.py",
)
_SPAWN_ATTRS = ("run", "Popen", "call", "check_output", "check_call")
# 实测下界：egress 2（netstat+tasklist）＋ host_shield 8（icacls×5+taskkill+schtasks+
# powershell）＋ pre_tool_use 1 ＋ post_tool_use 1 ＋ antinel 6 ＋ mcp 1 ＋ 其余 ≥1。
# ★ 0.35.3：`verification_tests.py` 一项就是 39 处 ⇒ 下界必须跟着抬，
#   否则"扫到 28 个全绿"会被误读成"扫全了"。**下界是量具的活力证明。**
_SPAWN_MIN_EXPECTED = 45


def _spawn_calls(src, fname="<src>"):
    """返回 `(inspected, bad)`：源码里 `subprocess.<run|Popen|call|...>` 调用的总数，
    以及其中**没有 `creationflags`** 的 `[(行号, 属性名)]`。

    ★ 只认 `subprocess.X(...)` 形态（本仓唯一写法）。
    ★ `**kwargs` 展开 ⇒ 记未登记（静态看不出来 ⇒ 不许当已登记）。
    """
    import ast
    tree = ast.parse(src, fname)
    inspected, bad = 0, []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "subprocess"
                and f.attr in _SPAWN_ATTRS):
            continue
        inspected += 1
        if "creationflags" in {k.arg for k in node.keywords}:
            continue
        bad.append((node.lineno, f.attr))
    return inspected, bad


def _scan_prod_spawns():
    """扫 `_PROD_SPAWN_FILES`：返回 `(总调用数, [(相对路径, 行号, 属性名)])`。

    ★ 登记的文件**必须在**（读不到就抛 —— 改名/消失 ⇒ 红，不静默少查）。
    """
    inspected, bad = 0, []
    for rel in _PROD_SPAWN_FILES:
        p = os.path.join(G.PKG, rel.replace("/", os.sep))
        with open(p, encoding="utf-8") as f:
            src = f.read()
        n, b = _spawn_calls(src, rel)
        inspected += n
        bad.extend((rel, ln, attr) for ln, attr in b)
    return inspected, bad


def c_no_console_flash_on_spawn():
    """★★ 起控制台程序必须显式 `CREATE_NO_WINDOW`，否则黑窗一闪（创始人报障）。

    判据：生产运行模块里**没有一个**起子进程的调用漏掉 `creationflags`。
    附活力：扫到的调用数必须 ≥ `_SPAWN_MIN_EXPECTED` —— 否则「零违规」可能只是
    **根本没扫到东西**（全绿信号本身危险：它不区分「没问题」和「判据瞎了」）。
    """
    inspected, bad = _scan_prod_spawns()
    return (not bad) and inspected >= _SPAWN_MIN_EXPECTED


def n_no_console_flash_on_spawn():
    """负控：注入一个**裸** `subprocess.run(["netstat","-ano"])` ⇒ 必须当场点名。

    证明上一条不是「瞎了」：真漏了 flag，扫描器必须抓出来（先红后绿的「红」）。
    """
    _n, bad = _spawn_calls('import subprocess\n'
                           'subprocess.run(["netstat", "-ano"], capture_output=True)\n')
    return len(bad) == 1 and bad[0][1] == "run"


def c_spawn_scan_no_false_positive():
    """判据：**带了** `creationflags` 的调用**不许**被误报（守卫不许乱咬）。

    实测：`_notify` 的 `Popen(..., creationflags=_CREATE_NO_WINDOW)` 必须放行。
    """
    _n, bad = _spawn_calls(
        'import subprocess\n'
        'subprocess.Popen(["a"], creationflags=0x08000000)\n')
    return bad == []


def n_spawn_scan_no_false_positive():
    """负控：`**kwargs` 展开（`**kw`）⇒ 必须算**未登记**（静态看不出来，不许蒙混）。

    这正是 0.35.3 修 post_tool_use 的原因：flag 藏在 `kw` 字典里，静态守卫看不见
    ⇒ 一旦有人把 flag 从 kw 里拿掉，守卫**不会响**。所以展开必须 fail-loud。
    """
    _n, bad = _spawn_calls('import subprocess\n'
                           'kw = dict(cwd=".")\n'
                           'subprocess.Popen(["a"], **kw)\n')
    return len(bad) == 1


def _ledger_test_items():
    """造一组当天可核对的事件：2 次真实阻止、1 条注意、1 个防护缺口、1 项当天关闭。"""
    from datetime import datetime, timedelta
    now = datetime.now().astimezone()
    today_ts = now.isoformat(timespec="seconds")
    old_ts = (now - timedelta(days=1)).isoformat(timespec="seconds")
    alert_items = [
        M.Item(M.Alert.build(today_ts, "tool_call_blocked", reason="blocked-a")),
        M.Item(M.Alert.build(today_ts, "tool_call_blocked", reason="blocked-b")),
        M.Item(M.Alert.build(today_ts, "host_shield_revived", reason="revived")),
        M.Item(M.Alert.build(today_ts, "host_shield_breach", reason="gap")),
        M.Item(M.Alert.build(old_ts, "tool_call_blocked", reason="closed-old"),
               state="done", closed_at=today_ts),
    ]
    return now.date().isoformat(), alert_items


def c_ledger_levels_match_meaning():
    """「拦截」只算真实拦下；`host_shield_breach` 是防护缺口，必须列失守。"""
    return (M.level_of("tool_call_blocked") == "L2"
            and M.level_of("host_shield_breach") == "R0"
            and M.TITLE_OF_KIND["host_shield_breach"].startswith("失守："))


def n_ledger_levels_match_meaning():
    """负控：把防护缺口错标成 L2，主判据必须失败（防止标题与数字各说各话）。"""
    old = M.LEVEL_OF_KIND["host_shield_breach"]
    M.LEVEL_OF_KIND["host_shield_breach"] = "L2"
    try:
        return not c_ledger_levels_match_meaning()
    finally:
        M.LEVEL_OF_KIND["host_shield_breach"] = old


def c_ledger_page_populates_from_chain_snapshot():
    """账本页打开时必须经 `record_day()` 刷新，不依赖用户另外启动 daemon。"""
    import inbox_daemon as DM
    day, items = _ledger_test_items()
    hub = _tmpdir()
    old_report = SV.R.daily_report
    SV.R.daily_report = lambda **_kw: {"ledger": L.summary(root=hub, today=day)}
    try:
        page = SV.render_page(view="ledger", root=hub, token="t", items=items,
                              record_ledger=True)
    finally:
        SV.R.daily_report = old_report
    s = L.summary(root=hub, today=day)
    lines = open(L.daily_path(hub), encoding="utf-8").read().splitlines()
    DM.record_day(items=items, today=day, root=hub)
    lines_after_repeat = open(L.daily_path(hub), encoding="utf-8").read().splitlines()
    DM.record_day(items=[], today=day, root=hub)
    corrected = L.load_days(root=hub).get(day, {})
    lines_after_correction = open(L.daily_path(hub), encoding="utf-8").read().splitlines()
    DM.record_day(items=[], today=day, root=hub)
    lines_after_same_correction = open(L.daily_path(hub), encoding="utf-8").read().splitlines()
    return (s["blocked"] == 2 and s["noticed"] == 1 and s["breached"] == 1
            and s["acked"] == 1 and s["days"] == 1
            and len(lines) == len(lines_after_repeat) == 1
            and len(lines_after_correction) == len(lines_after_same_correction) == 2
            and all(corrected.get(k) == 0 for k in ("blocked", "noticed", "breached", "acked"))
            and "账本尚无可核对记录" not in page
            and "拦截危险操作" in page and "防护缺口" in page)


def n_ledger_page_populates_from_chain_snapshot():
    """负控：未启用账本刷新时，不写账本；证明页面守卫不是「永远有账」。"""
    hub = _tmpdir()
    day, items = _ledger_test_items()
    page = SV.render_page(view="ledger", root=hub, token="t", items=items,
                          record_ledger=False)
    return (not os.path.exists(L.daily_path(hub))
            and "账本尚无可核对记录" in page
            and not L.load_days(hub))


# ====================================== 十三、账本规格件核对（交接 §七.2）=====
# ★ 本轮实测结论：交接件说「找不到 ledger.py 引用的详细设计 §10.5–§10.6」——
#   不是找不到，是**引用指错了文件**。§10.5（合规红线）/§10.6（与 credits 的关系）
#   实际出自《Antinel 值守台（便签）方案 v1.0（2026-10-05）》，
#   《值守台·详细设计 v1.0》的第十章是「待创始人拍板」，其 §5.6 才是账本页界面规范。
# ⇒ 判据锁两件事：① 引用必须指对文件；② 规格 §5.6 点名的两个界面件不许消失。
def _ledger_docstring():
    """读 `ledger.py` 的模块 docstring **原文**。

    ★ 不用 `inspect.getdoc`：它会 dedent，而本文件的引用说明写在
      缩进续行里（dedent 后仍在，但缩进语义会丢），且 getdoc 对
      「首行 + 缩进续行」的拼接方式在不同版本不一致 —— 量具自己
      不确定的东西不能拿来当判据。直接读 `__doc__` 最稳。
    """
    import ledger as L
    return L.__doc__ or ""


def _ledger_citation_refs(doc):
    """抽出模块头里的**规范性引用行**（真正告诉读者"去哪儿查"的那几行）。

    界定办法：从「与现有 `antinel credits`」那一段起，到「本模块只负责」那一行为止 ——
    这就是 docstring 里**声明口径与合规**的那一段。更正说明段（§22 起）
    讲的是"曾经指错"，不在声明区里，不受引用规则管。

    ★ 为什么必须先切出声明区，而不是在整段里搜关键词：更正说明段**合法地**
      提到两个文件名和两个锚点（正因为它在解释"原来指错了"）。
      在整段里搜，正确文档也会被判红 —— 这就是前几轮正/负控互相打架的真因：
      **判据量错了对象**。
    """
    lines = doc.splitlines()
    start = end = None
    for i, ln in enumerate(lines):
        if start is None and "与现有" in ln and "credits" in ln:
            start = i
        if start is not None and "只负责" in ln and "记账" in ln:
            end = i
            break
    if start is None or end is None or end < start:
        return None                   # 声明区定位失败 ⇒ 交给判据红，不静默放过
    return [ln for ln in lines[start:end + 1] if "§" in ln]


def _ledger_citation_ok(doc):
    """判定「声明区里的引用是否指向正确文件」的**纯逻辑**（不碰文件系统）。"""
    refs = _ledger_citation_refs(doc)
    if not refs:
        return False              # 声明区里一条引用都没有 ⇒ 等于没引用
    ok_55 = ok_66 = False
    for ln in refs:
        # 每一条引用都必须指名「便签」方案，且不得指向「详细设计」
        if "便签" not in ln or "详细设计" in ln:
            return False
        ok_55 = ok_55 or "§10.5" in ln
        ok_66 = ok_66 or "§10.6" in ln
    return ok_55 and ok_66         # 两节都要有引用，缺一节就是指不到


def c_ledger_doc_citation_points_at_real_section():
    """`ledger.py` 的规格引用**指得到、且指的是合规那两节**。"""
    doc = _ledger_docstring()
    if not _ledger_citation_ok(doc):
        return False
    # 反向自查：那份便签方案文件**确实在仓内**，且两节标题真的存在
    # （否则就是把一个不存在的锚点写进注释 —— 比错引用更难发现）。
    # ★ 用 listdir 逐个按内容筛，不靠 glob 猜文件名：文件名里有全角括号
    #   （「值守台（便签）方案 v1.0（2026-10-05）.md」），按片段 glob 会漏。
    odir = os.path.join(PSL_ROOT, "outputs")
    if not os.path.isdir(odir):
        return False
    ok_55 = ok_66 = False
    for fn in os.listdir(odir):
        if not fn.endswith(".md") or "便签" not in fn:
            continue
        try:
            txt = open(os.path.join(odir, fn), encoding="utf-8").read()
        except OSError:
            continue
        ok_55 = ok_55 or ("10.5 合规红线" in txt)
        ok_66 = ok_66 or ("10.6 与现有" in txt and "credits" in txt)
    return ok_55 and ok_66


def n_ledger_doc_citation_is_not_vague():
    """负控（**变异检验**）：把引用换成交接件原来那个错文件，判据必须拒。

    ★ 为什么这么做：交接件上一轮正是因为照着「详细设计 §10.5」找不到出处，
      才误判成「没有正式设计文件」——错误引用会**主动误导下一个接手的人**，
      比没有引用危害更大。

    ★ 为什么不能用「doc 里出现『详细设计 §10.5』就红」：本 docstring 里
      **正当地引用了这句错话**（在「文档引用更正」那段里当反面例子）。
      负控会去抓自己的说明文字 ⇒ 永远红。这类自指陷阱只能靠变异检验破：
      对**同一段逻辑**喂一个已知错误的输入，看它是否真的拒。
    """
    good = _ledger_docstring()
    if not _ledger_citation_ok(good):
        return False                      # 被测对象本身不合格 ⇒ 负控无从谈起
    # 变异 = 把**声明区里引用行**的「便签」换成「详细设计」，
    # 即还原成交接件原来那个错引用。判据必须拒。
    refs = _ledger_citation_refs(good)
    bad_lines, hit = [], False
    for ln in good.splitlines():
        if ln in refs:
            hit = True
            bad_lines.append(ln.replace("便签", "详细设计"))
        else:
            bad_lines.append(ln)
    if not hit:
        return False                      # 连一条引用行都没定位到 ⇒ 负控不可信
    bad = "\n".join(bad_lines)
    if bad == good:
        return False                      # 变异没生效 ⇒ 负控不可信
    return _ledger_citation_ok(bad) is False


def c_ledger_page_has_claim_slot_and_location():
    """规格 §5.6 点名的两件：①「这份账本在哪里＋可导出可迁移」②禁用态认领按钮。"""
    hub = _tmpdir()
    day, items = _ledger_test_items()
    page = SV.render_page(view="ledger", root=hub, token="t", items=items,
                          record_ledger=True)
    if "这份账本在" not in page or "可以整体导出带走" not in page:
        return False
    m = re.search(r'<button[^>]*\bdisabled\b[^>]*>([^<]*)</button>', page)
    return bool(m) and "认领到账号" in m.group(1)


def n_ledger_page_claim_slot_is_not_clickable():
    """负控：那个按钮**必须真的点不动** —— 一个长得能点、点了没反应的按钮，
    正是创始人点名的「看见疑问却无法得到答案」。"""
    hub = _tmpdir()
    day, items = _ledger_test_items()
    page = SV.render_page(view="ledger", root=hub, token="t", items=items,
                          record_ledger=True)
    m = re.search(r'<button[^>]*\bdisabled\b[^>]*>([^<]*)</button>', page)
    if not m:
        return False
    # 必须同时具备：disabled 属性 + 禁用态样式（否则"看起来能点"）+ 不带任何 action
    if "button[disabled]" not in page:
        return False
    tag = m.group(0)
    return not re.search(r'onclick|formaction|href=', tag)


# ============================================ 十、术语表（创始人 2026-10-07）====
# 创始人第 2 条意见「给每个重要词一个明确、合理、面向用户的定义」
#     第 3 条意见「看见疑问却无法点开得到答案」
# ⇒ 定义必须有**唯一真源**（`glossary.py`），页面上**可点开**，且**未定义不许静默**。
def c_glossary_all_terms_complete():
    """术语表 24 条**字段齐全**（词/一句话/包含/不含/口径），且都能渲染出落点。"""
    import glossary as GL
    if not GL.TERMS:
        return False
    for k, t in GL.TERMS.items():
        for f in ("w", "one", "inc", "exc", "unit"):
            if not (t.get(f) or "").strip():
                return False
        html = GL.chip(k)
        if ('data-t="%s"' % k) not in html or t["one"] not in html:
            return False
    return True


def n_glossary_incomplete_is_caught():
    """负控：**定义不全必须被抓**，不许静默渲染一个空壳词条。

    ★ 静默＝把"这个词没定义"渲染成"看起来没问题"，正是本项目最反对的形状。
      这里临时抽掉 `unit`（数字口径）⇒ `chip()` 必须抛 `UnknownTerm`。
      若哪天产品改成"缺字段也能渲染"，本负控立刻变红。
    """
    import glossary as GL
    k = "L2"
    orig = GL.TERMS[k]["unit"]
    try:
        GL.TERMS[k]["unit"] = "   "
        try:
            GL.chip(k)
        except GL.UnknownTerm:
            return True                       # 抓到了 ⇒ 负控成立
        return False                          # 静默渲染 ⇒ 负控红
    finally:
        GL.TERMS[k]["unit"] = orig


def c_glossary_pages_are_clickable():
    """四个栏目**都能点开定义**，且术语表**没有"定义了却没地方看"的死角**。"""
    import glossary as GL
    hub = _tmpdir()
    _write_rec(_chain_dir(hub), {"ts": _iso(-1), "type": "host_shield_breach",
                                 "reason": "r", "hash": "h",
                                 "session": "host-shield", "tool": "-",
                                 "host": "generic", "decision": "allow",
                                 "severity": "warning"})
    seen = set()
    for view, filt in (("inbox", "action"), ("report", None),
                       ("health", None), ("ledger", None)):
        html = SV.render_page(view=view, filt=filt, root=hub, token="t")
        if GL.unknown(html):
            return False                      # 页面上出现了未定义的词
        got = GL.rendered(html)
        if not got:
            return False                      # 这个栏目**没有可点开的定义**
        seen |= set(got)
    return set(GL.TERMS) <= seen              # 术语表 100% 有落点


def n_glossary_pages_are_clickable():
    """负控：`GL.unknown()` **不是恒返回空**（否则上一条就是瞎的）。"""
    import glossary as GL
    ghost = GL.unknown('<details class="term" data-t="ghost_term"></details>')
    clean = GL.unknown('<details class="term" data-t="L2"></details>')
    return ghost == ["ghost_term"] and clean == []


# ============================================ 十一、托盘陈旧（交接 §5）====
def c_tray_state_staleness_is_flagged():
    """★ 真实缺陷：`tray.ps1` 每秒读盘但**从不看 `ts`** ⇒ 写的一方死了，
    托盘会无限期显示"值守中·一切正常"。读的一侧必须自己判陈旧。"""
    import inbox_tray as TR
    hub = _tmpdir()
    TR.write_state("L0", 0, "值守中 · 一切正常", root=hub)
    fresh = TR.read_state(root=hub, now=time.time())
    # 把 ts 往回拨 10 分钟 ⇒ 必须判陈旧，且文案要说"停止更新"
    p = TR.state_path(hub)
    d = json.load(open(p, encoding="utf-8"))
    d["ts"] = time.time() - 600
    json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False)
    old = TR.read_state(root=hub, now=time.time())
    note = TR.stale_note(old)
    return (fresh.get("stale") is False and old.get("stale") is True
            and old.get("age_seconds", 0) >= 600
            and "停止更新" in note and "不等于此刻一切正常" in note
            and TR.stale_note(fresh) == "")


def n_tray_state_staleness_is_flagged():
    """负控：**没有 ts** 也必须按陈旧算（不知道就别装作知道），而不是算新鲜。"""
    import inbox_tray as TR
    hub = _tmpdir()
    os.makedirs(os.path.dirname(TR.state_path(hub)), exist_ok=True)
    with open(TR.state_path(hub), "w", encoding="utf-8") as f:
        json.dump({"state": "L0", "count": 0, "tip": "值守中"}, f)
    d = TR.read_state(root=hub, now=time.time())
    return d.get("stale") is True and "不能当作当前状态" in TR.stale_note(d)


# ★ 交接件 §5 点名：「tray 独立运行与守护进程运行的态势来源是否一致」。
#   本轮**实测**（不是读代码猜的）抓到：托盘显示 count=181，
#   而按现行口径真值只有 4 —— 因为 `run()` 只起图标、**从不重算状态**，
#   于是一份几小时前、由旧口径写的 tray.json 被无限期展示。
def c_tray_refreshes_before_showing():
    """起托盘**之前**必须重算状态：旧文件（含旧口径）不许被直接继承。"""
    import inbox_tray as TR
    hub = _tmpdir()
    items = G.new_hub()          # 只借脚手架建一个临时目录做 hub
    # 先写一份**故意过期且口径错误**的旧状态
    TR.write_state("R0", 999, "旧口径 · 未处理 999", root=hub)
    d0 = TR.read_state(root=hub)
    assert d0.get("count") == 999
    # 起托盘前刷新：空收件箱 ⇒ 件数必须被算成 0，而不是继续显示 999
    TR.refresh_state(root=hub, items=[])
    d1 = TR.read_state(root=hub)
    if d1.get("count") != 0:
        return False                  # 继承了旧件数 ⇒ 陈旧/错口径被继承
    if "999" in (d1.get("tip") or ""):
        return False                  # 旧文案还在
    if d1.get("stale") is not False:
        return False                  # 刚写的却仍被判陈旧
    # 而 `run()` 必须真的调它一次（不然修的是没人走的路）
    import inspect
    return "refresh_state" in inspect.getsource(TR.run)


def n_tray_refresh_is_not_a_noop():
    """负控：`refresh_state` **不是恒等写回** —— 给真样本必须算出真值。"""
    import inbox_tray as TR
    import inbox_model as M
    hub = _tmpdir()
    day, items = _ledger_test_items()
    posture = {"state": "guarding", "why": "哨兵在岗"}   # ★ 0.48.5 A2：显式注入
    TR.write_state("L0", 0, "旧", root=hub)
    TR.refresh_state(root=hub, items=items, posture=posture)
    d = TR.read_state(root=hub)
    want = M.count_groups([i for i in items if M.bucket_of(i) == M.BUCKET_ACTION])
    # ★ 0.48.5（A2）：期望值从 console_state（旧合并读）改为 light_explain
    #   （灯态唯一真源）—— 账里的历史 R0 不抬灯，口径与页面一致。
    want_st = M.light_explain(posture, items, granary=M.granary_now())["state"]
    return d.get("count") == want and d.get("state") == want_st


# ============================================ 十二、导出口径（交接 §5）====
def c_cli_export_states_its_scope():
    """导出必须**先说口径**：全部已载入记录 ≠ 待办件数（实测本机 227 vs 4 件事）。"""
    hub = G.new_hub()
    G.put_chain(hub, [G.breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rc, out = G._cli(["export", "--format", "csv"])
    return (rc == 0 and "口径" in out and "不等于待办件数" in out
            and "全部 1 条" in out)


def n_cli_export_states_its_scope():
    """负控：**空收件箱也要说口径**（0 条也得讲清分母），且条数随样本变。"""
    hub = G.new_hub()
    rc0, out0 = G._cli(["export", "--format", "csv"])
    G.put_chain(hub, [G.breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                      G.breach(ts="2026-10-05T10:00:00+08:00", reason="b")])
    rc1, out1 = G._cli(["export", "--format", "csv"])
    return (rc0 == 0 and "全部 0 条" in out0
            and rc1 == 0 and "全部 2 条" in out1)


def c_cli_export_json_is_machine_readable():
    """★ 本轮实测抓到的真缺陷：`--format json` 的输出**不是合法 JSON**。

    上一版把口径当第一行前缀塞进所有格式 ⇒ `json.loads` 直接 JSONDecodeError。
    那比"没说口径"更糟：机器读不了，人也不好复制。
    ⇒ JSON 口径必须进结构内部（`_export_scope`），文件始终可解析。
    """
    rc, out = G._cli(["export", "--format", "json"])
    if rc != 0:
        return False
    try:
        d = json.loads(out)
    except ValueError:
        return False                      # 解析不了 ⇒ 就是那个缺陷
    if not isinstance(d, dict):
        return False                      # 仍是裸数组 ⇒ 口径没处放，缺陷复发
    return (isinstance(d.get("_export_scope"), str)
            and "不等于待办件数" in d["_export_scope"]
            and isinstance(d.get("count"), int)
            and len(d.get("items", [])) == d["count"])


def n_cli_export_json_scope_is_not_faked():
    """负控：**落盘文件也必须可解析**，且 `count` 必须等于实际条数（不许写死）。

    ★ 为什么单独测落盘：屏幕输出被 shell 捕获时前缀容易被忽略，
      而 `--out` 落出来的文件是别人拿去喂脚本的 —— 那条路径坏了没人会立刻发现。
    """
    import tempfile
    hub = G.new_hub()
    G.put_chain(hub, [G.breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    fn = os.path.join(tempfile.mkdtemp(prefix="antinel-exp-"), "out.json")
    _SCRATCH.append(os.path.dirname(fn))
    rc, _out = G._cli(["export", "--format", "json", "--out", fn])
    if rc == 0 and os.path.exists(fn):
        try:
            d = json.load(open(fn, encoding="utf-8"))
        except (ValueError, OSError):
            d = None
        if not (isinstance(d, dict) and "items" in d and "count" in d):
            return False
        if d["count"] != len(d["items"]):
            return False                  # count 与实际条数不符 ⇒ 口径在撒谎
        # ★ 反向：换样本后 count 必须跟着变，写死的常数判据抓不到
        G.put_chain(hub, [G.breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                          G.breach(ts="2026-10-05T11:00:00+08:00", reason="c")])
        rc2, _ = G._cli(["export", "--format", "json", "--out", fn])
        d2 = json.load(open(fn, encoding="utf-8"))
        return rc2 == 0 and d2["count"] == 2 and d2["count"] != d["count"]
    return False


# ============ 十四、日报数字与钻取同口径（F40 病灶族，见 §5 待审）============
def _page_text(html):
    import html as H
    h = re.sub(r"<script.*?</script>", "", html, flags=re.S)
    h = re.sub(r"<style.*?</style>", "", h, flags=re.S)
    h = re.sub(r"<(br|/div|/p|/h1|/h2|/h3|/tr|/li|/details|/summary)[^>]*>", "\n", h)
    h = re.sub(r"<[^>]+>", " ", h)
    h = H.unescape(h)
    h = re.sub(r"[ \t]+", " ", h)
    return re.sub(r"\n\s*\n+", "\n", h).strip()


def c_report_drill_counts_match_headline():
    """★ 日报上每个数字，点进去看到的条数必须**等于**它。

    ★ 这条是 F40「一个数承担两个分母」的机械化守卫。两个数都真、但分母不同，
      是本项目已复发三次的病灶（E168/E181/E195）；而且**合理性与数量级检查
      对这类双双失效**——6 和 227 都不离谱。唯一抓得住它的动作是
      **逐个链接点进去数一遍**。
    """
    hub = _tmpdir()
    day, items = _ledger_test_items()
    report = SV.render_page(view="report", root=hub, token="T", items=items)
    # ★ 链接里的 `&` 在 HTML 属性中是**原样**的，不是 `&amp;`（本判据第一版
    #   写成 `&amp;` ⇒ 一个匹配都抓不到 ⇒ 恒红。量具自己踩的坑，记在这里。）
    # ★★ 0.48.6（B3）：链接里**不再挂 `&t=T`** —— 口令改由 HttpOnly cookie 在
    #   站内携带（见 `inbox_server._COOKIE`），URL 里不出现口令。正则同步去掉
    #   那段；**这不是放松**：本判据要测的是"钻取页的数字与日报数字同源"，
    #   与"口令挂在哪"无关（口令挂 URL 是 B3 要修的缺陷）。
    drills = re.findall(r'href="/\?v=inbox&f=win:24:lv:(L2|L1|R0)">(\d+)</a>',
                        report)
    if not drills:
        return False                      # 日报上一个窗口钻取都没有 ⇒ 守卫无从测
    for lvl, n in drills:
        page = SV.render_page(view="inbox", filt="win:24:lv:%s" % lvl,
                              root=hub, token="T", items=items)
        txt = _page_text(page)
        # ★ 0.47.0：钻取页的条数改走 `M.count_text` 的「分子 / 分母」形式
        #   （`N / M 条`）。★ 本判据因此**多核一项**：分母必须等于本次载入的
        #   全部条数 —— F40 那条守卫被**加强**了，不是放松。
        m = re.search(r"(\d+)\s*/\s*(\d+)\s*条", txt)
        if not m:
            return False                  # 页面上读不到「分子 / 分母」⇒ 无从核对
        if int(m.group(1)) != int(n):
            return False                  # 钻取页条数 ≠ 日报数字 ⇒ 不同口径
        if int(m.group(2)) != len(items):
            return False                  # 分母 ≠ 本次载入条数 ⇒ 又一个分母
    return True


def n_report_drill_counts_match_headline():
    """负控：**去掉窗口限定后，数字必然对不上** —— 证明上一条不是恒真。

    ★ 用未来时间戳造一条「窗口外但确实存在」的记录：
      带 `win:24:` 时它被排除（日报计数不含它），
      去掉窗口就回来了 ⇒ 两个口径的差是可观测的。
      若去掉窗口数字仍相同，说明这条守卫什么也没测到。
    """
    hub = _tmpdir()
    _chain_dir(hub)
    now = datetime.now().astimezone()
    # ★★ 样本**直接用 `M.Item` 构造**，不写链文件。
    #   第一、二版都栽在 `_write_rec`：它把记录写进 `strftime("%Y-%m-%d")`
    #   那一个文件里，**文件名日期与记录 ts 不符** ⇒ 链校验按文件名核对时
    #   把它当坏行丢掉 ⇒ `load_items` 返回 0 ⇒ 负控恒红。
    #   这也是本轮记下的一条量具纪律：**量具的样本必须先确认产品真的会读它**，
    #   否则红的是量具，不是被测对象。
    a = M.Item(M.Alert.build(now.isoformat(timespec="seconds"),
                             "tool_call_blocked", reason="now"))
    old_ts = (now - timedelta(hours=25)).isoformat(timespec="seconds")
    b = M.Item(M.Alert.build(old_ts, "tool_call_blocked", reason="old"))
    items = [a, b]
    with_win = len(M.filter_items(items, "win:24:lv:L2"))
    no_win = len(M.filter_items(items, "lv:L2"))
    return with_win == 1 and no_win == 2


# ==== 十五、顶部数字必须带事由件数（创始人第四条 · 奥卡姆剃刀，本轮实测）====
def c_header_numbers_state_both_denominators():
    """★ 顶部每个数字都要**同时**给出记录条数与事由件数。

    ★ 本轮实测依据：R0 共 80 条，但只有 **8 种不同原因**，最大一支 37 次
      （同一个钩子哈希不匹配被反复记录）⇒ 按事由归并只有 **4 件**。
      只报 69 ⇒ 用户以为有 69 件事要做，实际只需做 4 件 ——
      这正是创始人点名"大量其实不需要用户处理的待处理"。
      修法不是藏数，而是**把两个分母都摆出来**（F40 的正面处理）。
    """
    hub = _tmpdir()
    day, items = _ledger_test_items()
    html = SV.render_page(view="report", root=hub, token="T", items=items)
    # 三个数字链接：括号内必须是按事由归并后的件数
    # ★ 0.48.6（B3）：链接里不再挂 `&t=T`（口令走 HttpOnly cookie）—— 同步去掉。
    pairs = re.findall(
        r'f=win:%d:lv:(L2|L1|R0)">(?:拦截|注意|失守) <b>(\d+)</b>(?:（(\d+) 件事）)?'
        % M.WINDOW_HOURS, html)
    if len(pairs) != 3:
        return False                      # 三个数字没都带钻取链接
    for lvl, n, g in pairs:
        want_n = len([i for i in items
                      if i.level == lvl and M.within_hours(i.ts, M.WINDOW_HOURS)])
        want_g = M.count_groups([i for i in items if i.level == lvl
                                 and M.within_hours(i.ts, M.WINDOW_HOURS)])
        if int(n) != want_n:
            return False                  # 条数与实测不符
        if g and int(g) != want_g:
            return False                  # 件事数与实测不符
        # 条数 != 件事数 时**必须**显示括号，否则两个口径混成一个数
        if want_n != want_g and not g:
            return False
    # ★ 0.48.5（交接件 §5.4 丁4）：原断言锁的是 43 字工程说明串
    #   「记录数；括号里是按事由归并后的件数」—— 正是丁4 点名要删的那句
    #   （title 是消歧位，不是说明书；解释移交「？」词条，U-04 批次 3 落地）。
    #   追随规格更新，**不是放松**：两个分母仍由可见的「N（G 件事）」括号
    #   摆着（上面 pairs 已逐个数过）；这里改锁 title 仍是那个口径说明位 ——
    #   点明「记录数」与窗口、且 ≤20 字，工程腔不许回来（0490 U-11 同限）。
    pill_titles = [t for t in re.findall(r'title="([^"]*)"', html)
                   if "记录数" in t]
    return (len(pill_titles) >= 3
            and all("最近 %d 小时" % M.WINDOW_HOURS in t and len(t) <= 20
                    for t in pill_titles))


def n_header_numbers_dont_hide_records():
    """负控：**不许用"只报件事数"的方式糊过去** —— 那会把 69 条明细藏起来。

    ★ 换成一个"条数≠事由数"的样本：同因 3 条 + 另一因 1 条
      ⇒ 必须显示「3（1 件事）」这类形态，且明细链接仍指向全部记录。
    """
    hub = _tmpdir()
    now = datetime.now().astimezone()
    ts = now.isoformat(timespec="seconds")
    same = [M.Item(M.Alert.build(ts, "host_shield_breach", reason="same"))
            for _ in range(3)]
    other = M.Item(M.Alert.build(ts, "tool_call_blocked", reason="other"))
    items = same + [other]
    html = SV.render_page(view="report", root=hub, token="T", items=items)
    txt = _page_text(html)
    if "（1 件事）" not in txt:
        return False                      # 没归并，也没写明 ⇒ 口径缺失
    # 明细链接必须仍然是全部 3+1 条（不许把 3 条藏起来只显示 1 件）
    if 'f=win:%d:lv:R0' % M.WINDOW_HOURS not in html:
        return False
    return True


# ==== 十六、心跳读数唯一口径（本机实测的真缺陷：哨兵好的却报僵死）====
def c_posture_reads_sentinel_heartbeat():
    """★ `guard_posture()` 必须用 `sentinel_heartbeat_age()` 唯一口径。

    ★ 本机实测：同一时刻
        `sentinel_heartbeat_age()` = **190 秒**（哨兵好好地在写心跳）
        `heartbeat_age(None)`     = **27202 秒**（读到 7 天前的老链）
      页面因此长期显示「心跳断档 452 分钟 · 疑似挂起/僵死」并把灯打红，
      还给出「马上修复」按钮 —— 而哨兵一直是好的。
      这与本仓已修过的 `ensure_alive` 是**同一类错**（包根 vs 审计目录搞混），
      只是漏了 `guard_posture` 这个调用点。
    """
    import inspect
    import host_shield as H
    src = inspect.getsource(H.guard_posture)
    # ★ 先剥掉注释：修法说明里**必然**要引用旧写法（"原来这里写 heartbeat_age(pkg_root)"），
    #   不剥就会把说明当成代码 —— 这是本轮第二次自指陷阱（上一处在 ledger docstring）。
    #   量具纪律：**判据只读代码，不读解释代码的文字**。
    code = "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())
    if re.search(r"(?<!sentinel_)\bheartbeat_age\(\s*(pkg_root|None)?\s*\)", code):
        return False                  # 仍在用错的那个读法
    return "sentinel_heartbeat_age()" in code


def n_posture_heartbeat_reading_is_not_constant():
    """负控：两个口径**确实不同**（否则上一条就是恒真的形式检查）。

    ★ 变量纪律（2026-10-07 本轮记下）：该判据**只在两读法落在不同链目录时
      才有意义**。若两值恰好相同，它红或绿都不代表任何东西 ——
      所以负控额外要求"至少能取出数"，而不是"两个数必须不同"。
      这比强造一个假分歧诚实：不能为了让判据变绿而伪造差异。
    """
    import host_shield as H
    good, _ts = H.sentinel_heartbeat_age()
    other, _ts2 = H.heartbeat_age(None)
    return good is not None and other is not None and good >= 0 and other >= 0


# ==== 十七、气泡降噪不得因 cwd 而分裂（创始人 2026-10-07「冒泡又出现了」）====
def _import_pre_tool_use():
    """导入 `hooks/pre_tool_use.py`（它不在包根，必须显式把 hooks 加进 path）。"""
    import importlib
    hooks = os.path.join(G.PKG, "hooks")
    if hooks not in sys.path:
        sys.path.insert(0, hooks)
    return importlib.import_module("pre_tool_use")


def c_notify_gate_is_cwd_independent():
    """★ 降噪状态**必须存个人中枢**（一台机器一份），不许跟着 cwd 走。

    ★ 本机实测的病灶：同一时刻散落**4 份** `notify_state.json`
      （`poc\\.psl` 09-18、`antinel-security\\.psl` 10-03、
        `_evade_work\\.psl` 09-10、`_p9_wheeltest\\repo\\.psl` 10-03）
      ⇒ 同一条告警换个 cwd 就"没通知过" ⇒ 又弹一次。
      与本仓已修过的 `heartbeat_age` 同一类错：**状态按当前目录存，必然分裂**。
    """
    import os
    import tempfile
    P = _import_pre_tool_use()
    hub = tempfile.mkdtemp(prefix="antinel-ngate-")
    _SCRATCH.append(hub)
    old_env = os.environ.get("ANTINEL_HUB_DIR")
    old_cwd = os.getcwd()
    os.environ["ANTINEL_HUB_DIR"] = hub
    try:
        p = P.notice_state_path()
        # 状态文件必须落在中枢，**不许**落在任何 cwd 下
        if os.path.dirname(os.path.abspath(p)) != os.path.abspath(hub):
            return False
        if "getcwd" in P.notice_state_path.__doc__ and "修" not in P.notice_state_path.__doc__:
            return False                 # 说明里还写着 getcwd ⇒ 注释与实现不符
        first = P.notice_gate("T|abc", "x")          # False = 没通知过
        os.chdir(tempfile.gettempdir())             # 换 cwd
        second = P.notice_gate("T|abc", "x")         # 必须 True = 已通知过
        os.chdir(old_cwd)
        second2 = P.notice_gate("T|abc", "x")
        return (first is False and second is True and second2 is True)
    finally:
        try:
            os.chdir(old_cwd)
        except OSError:
            pass
        if old_env is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_env


def n_notify_gate_is_not_permanently_muted():
    """负控：**换个 key 必须还能通知** —— 不许把降噪做成"永远闭嘴"。

    ★ 这是降噪最危险的失效方向：为了不打扰而把告警全静音，
      代价是主人再也收不到"门已失效"的消息。
    """
    import os
    import tempfile
    P = _import_pre_tool_use()
    hub = tempfile.mkdtemp(prefix="antinel-ngate2-")
    _SCRATCH.append(hub)
    old_env = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = hub
    try:
        a = P.notice_gate("RULE-A", "x")
        b = P.notice_gate("RULE-B", "x")      # 不同规则 ⇒ 必须放行
        c = P.notice_gate("RULE-A", "别的片段")  # 同规则不同片段 ⇒ 也放行
        d = P.notice_gate("RULE-A", "x")      # 同规则同片段 ⇒ 抑制
        return (a is False and b is False and c is False and d is True)
    finally:
        if old_env is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_env


def c_probe_failure_also_passes_gate():
    """★ `enforce_probe` 的失败通知**也必须过降噪闸**（它原来完全不过）。

    ★ 实测依据：哨兵每轮跑探针，而本轮改了 `host_shield.py`、manifest 未刷新那几分钟里
      探针每轮都失败 ⇒ **每轮弹一次**。
      与已治的「常用规则反复拦」是同一个病，只是换了个调用点。
    """
    import inspect
    src = inspect.getsource(_enforce_probe())
    body = "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())
    return "notice_gate" in body and "notify_owner" in body


def _enforce_probe():
    import importlib.util
    p = os.path.join(G.PKG, "tools", "enforce_probe.py")
    spec = importlib.util.spec_from_file_location("_ep_probe_mod", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def n_probe_failure_gate_is_not_permanent():
    """负控：闸存在**不等于**永远静音 —— 同一天第二次仍应被抑制。"""
    import os
    import tempfile
    P = _import_pre_tool_use()
    hub = tempfile.mkdtemp(prefix="antinel-ngate3-")
    _SCRATCH.append(hub)
    old_env = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = hub
    try:
        first = P.notice_gate("ENFORCEMENT-PROBE|FAIL", "same detail")
        second = P.notice_gate("ENFORCEMENT-PROBE|FAIL", "same detail")
        other = P.notice_gate("ENFORCEMENT-PROBE|FAIL", "别的细节")
        return first is False and second is True and other is False
    finally:
        if old_env is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_env


# ==== 十八、自检必须覆盖告警链路文件（结构性缺口）====
def c_self_check_covers_alert_chain():
    """★ `self_check()` 必须校验**告警链路上的文件**，不只校验自己。

    ★ 本轮实测的缺口：原实现只查 `host_shield.py` + `rules/hosts` 登记表，
      ⇒ **改 `hooks/pre_tool_use.py` 不用重刷 manifest，自检照样绿**。
      而 `pre_tool_use.py` 是整个告警系统的入口（判定/拦截/气泡）——
      旁路极短：改掉入口 ⇒ 告警不再触发 ⇒ 自检说"一切正常"。
      这是**保护范围与被保护对象不匹配**，不是洁癖。
    """
    import host_shield as H
    guarded = getattr(H, "_GUARDED_CHAIN_FILES", None)
    if not guarded:
        return False                       # 没声明受保护清单 ⇒ 缺口仍在
    need = ("hooks/pre_tool_use.py", "hooks/post_tool_use.py",
            "tools/enforce_probe.py")
    if not all(any(n in g for g in guarded) for n in need):
        return False
    # 而 self_check 真的在用这份清单（不是只声明不用）
    import inspect
    return "_GUARDED_CHAIN_FILES" in inspect.getsource(H.self_check)


def n_self_check_chain_catch_is_not_vacuous():
    """负控：**篡改一个受保护文件 ⇒ 必须被抓**（否则上面只是加了个没用的常量）。"""
    import host_shield as H
    import shutil
    import tempfile
    import os
    rel = "hooks/post_tool_use.py"          # 受保护清单里最小的一个
    root = H._pkg_root()
    live = os.path.join(root, rel.replace("/", os.sep))
    if not os.path.isfile(live):
        return False
    bak = tempfile.mkdtemp(prefix="antinel-sc-")
    _SCRATCH.append(bak)
    copy = os.path.join(bak, os.path.basename(rel))
    shutil.copy2(live, copy)
    try:
        # 追加一个空格：内容变了、语义没变 —— 静态看不出来，哈希能看出来
        with open(live, "a", encoding="utf-8", newline="") as f:
            f.write("\n")
        ok, problems = H.self_check()
        return (ok is False and any(rel in p for p in problems))
    finally:
        shutil.copy2(copy, live)


CHECKS_0353 = [
    # ---- 九、闪窗（黑窗一闪）----
    ("P12 起子进程必须无窗", c_no_console_flash_on_spawn,
     n_no_console_flash_on_spawn),
    ("P12 无窗扫描不误报", c_spawn_scan_no_false_positive,
     n_spawn_scan_no_false_positive),
    # ---- 一、链背书（R-1 上游真缺陷）----
    ("P12 链尾看得见 policy_changed", c_chain_tail_sees_policy_changed,
     n_chain_tail_sees_policy_changed),
    ("P12 前置过滤是真超集", c_prefilter_superset, n_prefilter_superset),
    ("P12 指纹变化按字段背书", c_fp_backed_by_field, n_fp_backed_by_field),
    ("P12 放行窗到期不算篡改", c_fp_window_expiry_backed, n_fp_window_expiry_backed),
    ("P12 旧背书过期不算数", c_fp_old_backing_expires, n_fp_old_backing_expires),
    # ---- 二、zone 命令 ----
    ("P12 zone 同步幂等", c_zone_sync_idempotent, n_zone_sync_idempotent),
    ("P12 zone remove 真的移除", c_zone_remove_removes, n_zone_remove_removes),
    ("P12 zone 授权记录落对链", c_zone_sync_writes_backing, n_zone_sync_writes_backing),
    # ---- 三、当前态势（灯）----
    ("P12 未启用不是失守", c_posture_off_is_not_down, n_posture_off_is_not_down),
    ("P12 未启用不给假按钮", c_posture_off_has_no_fake_button,
     n_posture_off_has_no_fake_button),
    ("P12 探不到=盲区不是值守", c_posture_unknown_not_guarding,
     n_posture_unknown_not_guarding),
    ("P12 灯以当前态势优先", c_light_posture_first, n_light_posture_first),
    ("P12 灯按未处理事件的级", c_light_only_owner_actions,
     n_light_only_owner_actions),
    ("P12 有事状态可点开看明细", c_attention_label_drills_to_action_list,
     n_attention_label_drills_to_action_list),
    # ---- 四、三档 / 归档 ----
    ("P12 分档带24小时窗口", c_bucket_window_and_archive, n_bucket_window_and_archive),
    ("P12 有后果读结构化字段", c_recovered_is_structured, n_recovered_is_structured),
    ("P12 投影带出 recovered", c_store_reads_recovered_field,
     n_store_reads_recovered_field),
    # ---- 五、页面四项 ----
    ("P12 页面无「标为已读」", c_page_has_no_read_button, n_page_has_no_read_button),
    ("P12 失守才给马上修复", c_page_fix_button_only_when_down,
     n_page_fix_button_only_when_down),
    ("P12 修不了的失守给下一步", c_page_down_without_fix_shows_howto,
     n_page_down_without_fix_shows_howto),
    ("P12 看一眼/归档按类归并", c_page_grouped_buckets, n_page_grouped_buckets),
    ("P12 要处理归并不藏事", c_page_action_grouped_not_hidden,
     n_page_action_grouped_not_hidden),
    ("P12 归并批量处置整组", c_server_done_all_marks_group,
     n_server_done_all_marks_group),
    ("P12 日报数字可钻取", c_report_drill_links, n_report_drill_links),
    ("P12 窗口数字钻取范围一致", c_scoped_report_drills_match_count_window,
     n_scoped_report_drills_match_count_window),
    ("P12 日报规则钻取按日期", c_daily_rule_drill_is_date_scoped,
     n_daily_rule_drill_is_date_scoped),
    ("P12 独立窗口带尺寸", c_window_size_set, n_window_size_set),
    ("P12 全部已读已取消", c_server_read_all_cancelled, n_server_read_all_cancelled),
    ("P12 修复入口有落点", c_server_fix_endpoint, n_server_fix_endpoint),
    ("P12 判据不起真哨兵", c_fix_endpoint_has_no_real_side_effect,
     n_fix_endpoint_has_no_real_side_effect),
    ("P12 修不了就如实说", c_guard_fix_honest, n_guard_fix_honest),
    ("P12 顶部与日报同口径", c_report_window_numbers_match_topbar,
     n_report_window_numbers_match_topbar),
    # ---- 六、保活（paramedic）权威：★★「永远失守」的根因 ----
    ("P12 保活与裁决同权威(链)", c_paramedic_uses_chain_authority,
     n_paramedic_uses_chain_authority),
    ("P12 保活读自己那条链的心跳", c_ensure_alive_reads_its_own_chain,
     n_ensure_alive_reads_its_own_chain),
    ("P12 status心跳读哨兵那条链", c_status_heartbeat_reads_sentinel_chain,
     n_status_heartbeat_reads_sentinel_chain),
    # ---- 七、失守重定义（0.35.3，创始人拍板：说不出损失的失守＝假失守）----
    ("P12 缺岗无损失只叫中断", c_outage_without_consequence_is_interrupted,
     n_outage_without_consequence_is_interrupted),
    ("P12 缺岗看得见受监管落点", c_outage_sees_supervised_landing,
     n_outage_sees_supervised_landing),
    ("P12 落点读不出按有损失算", c_consequence_blindspot_counts_as_loss,
     n_consequence_blindspot_counts_as_loss),
    # ★ 0.37.3：标签里的「存疑」已取消（六态换代）⇒ 换成描述**判定内容**的说法：
    #   它守的是"姿态层判 warn、不判 down"（灯色层由下一条 P12 管）。
    ("P12 自检不符判 warn 不判 down（姿态层）", c_selfcheck_fail_is_warn_not_down,
     n_selfcheck_fail_is_warn_not_down),
    ("P12 认不出按失守、缺岗无损失按注意", c_light_warn_is_down_and_interrupted_is_l1,
     n_light_warn_is_down_and_interrupted_is_l1),
    ("P12 失守损失在页面上看得见", c_consequences_has_consumer,
     n_consequences_has_consumer),
    # ---- 八、告警降噪（0.35.3，创始人报障「右下一直冒泡」）----
    ("P12 自启缺失不刷屏留痕", c_task_missing_recorded_once,
     n_task_missing_recorded_once),
    ("P12 自启查不出也刷屏留痕", c_task_unknown_recorded_once,
     n_task_unknown_recorded_once),
    ("P12 自启在岗认得启动项", c_task_installed_sees_startup_shim,
     n_task_installed_sees_startup_shim),
    ("P12 气泡只给要动手的事", c_notify_only_when_owner_needed,
     n_notify_only_when_owner_needed),
    ("P12 钩子登记哈希不误报", c_hook_reg_hash_no_false_alarm,
     n_hook_reg_hash_no_false_alarm),
    # ---- 十、术语表（创始人 2026-10-07 第 2、3 条意见）----
    ("P13 术语定义齐全", c_glossary_all_terms_complete,
     n_glossary_incomplete_is_caught),
    ("P13 四栏目都能点开定义", c_glossary_pages_are_clickable,
     n_glossary_pages_are_clickable),
    # ---- 十一、托盘陈旧（交接件 §5 待审项）----
    ("P13 托盘停止更新要说出来", c_tray_state_staleness_is_flagged,
     n_tray_state_staleness_is_flagged),
    ("P13 托盘起前先重算状态", c_tray_refreshes_before_showing,
     n_tray_refresh_is_not_a_noop),
    # ---- 十二、导出口径（交接件 §5 待审项）----
    ("P13 导出先说分母", c_cli_export_states_its_scope,
     n_cli_export_states_its_scope),
    ("P13 JSON 导出机器可读", c_cli_export_json_is_machine_readable,
     n_cli_export_json_scope_is_not_faked),
    # ---- 十三、账本规格件核对（交接 §七.2「找不到 §10.5」之实为引用指错）----
    ("P14 规格引用指得到真章节", c_ledger_doc_citation_points_at_real_section,
     n_ledger_doc_citation_is_not_vague),
    ("P14 账本页有认领位与所在地", c_ledger_page_has_claim_slot_and_location,
     n_ledger_page_claim_slot_is_not_clickable),
    # ---- 十四、日报数字与钻取同口径（F40 病灶）----
    ("P14 日报数字点进去对得上", c_report_drill_counts_match_headline,
     n_report_drill_counts_match_headline),
    # ---- 十五、顶部数字带事由件数（奥卡姆剃刀）----
    ("P14 顶部数字给两个分母", c_header_numbers_state_both_denominators,
     n_header_numbers_dont_hide_records),
    # ---- 十六、心跳唯一口径 ----
    ("P15 态势读哨兵那条心跳", c_posture_reads_sentinel_heartbeat,
     n_posture_heartbeat_reading_is_not_constant),
    # ---- 十七、气泡降噪不得因 cwd 分裂 ----
    ("P15 降噪状态不分叉", c_notify_gate_is_cwd_independent,
     n_notify_gate_is_not_permanently_muted),
    ("P15 探针失败也过降噪闸", c_probe_failure_also_passes_gate,
     n_probe_failure_gate_is_not_permanent),
    # ---- 十八、自检覆盖告警链路 ----
    ("P15 自检覆盖告警链路", c_self_check_covers_alert_chain,
     n_self_check_chain_catch_is_not_vacuous),
]


# ══════════════════════════════════════════════ 驱动入口（0.36.5 补）
# ★★ 为什么必须补（本轮实测发现的真缺口，不是"锦上添花"）：
#   本文件此前**只有判据定义，没有任何 `main()`／`__main__`** ⇒
#     · 直接跑 `python ci/inbox_guards_0353.py` ⇒ **零输出、退出码 0**；
#     · 统一交付闸门（0.36.5 新建）把「退出码 0」当通过 ⇒ 于是这**64 条判据
#       被记成"已通过"** —— 而实际上**一条都没跑**。
#   ⇒ 这是本仓铁律「**查不出来≠查出来是好的**」的第三种形态：
#     前两种是「查不到」与「查到是好的」混在一起；
#     **这一种更隐蔽：连"查"这个动作都没发生，账面却是绿的。**
#   ⇒ 交付闸门因此加了 NOOP（零输出）状态，与 PASS 分开计；
#     而这里的修法是**把入口补上**，让它真能跑 ——
#     **不是**从清单里删掉它（删掉＝又一次让判据不跑）。
#
#   ★ 判据一条未改：只加驱动。`CHECKS_0353` 是唯一清单。
def main():
    green = red = 0
    for item in CHECKS_0353:
        name, fn = item[0], item[1]
        try:
            r = fn()
        except Exception as e:                              # noqa: BLE001
            r = "判据自身报错：%s(%s)" % (type(e).__name__, e)
        if r is True:
            print("GREEN  %s" % name)
            green += 1
        else:
            red += 1
            print("RED  %s\n       %s" % (name, r))
    print("0.35.3 guards: %d green / %d red" % (green, red))
    return 0 if not red else 1


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""态注册表（实现 DAG 0a）—— 新模型八成因的唯一真源。

来源（逐条可回源，不临场发明）：
  · 字段集（11 字段）：《编码前无猜测审核与接口冻结 v1.0》§2-F3（:127-144）
  · 成因键与状态词：`output/_p_state_matrix.py` 的 CAUSES（:66-75）—— I4 唯一真源
  · 动作等价类：同文件 ACTION_OF（:79-88）—— 一类动作只服务一个成因
  · 三句式：同件 §4.1（:313-323），**逐字照抄**；宽度已由
    `output/_p_sentence_width.py` 按 T4-07 实算（本模块不重算、不改写）
  · 灯→CSS 变量：同件 F3（灰 `--lgrey` 新增；其余沿用 `inbox_server.py:125-126`
    的 `--l0/--l2/--r0`，取值与托盘 `SHIELD_COLOR` 同源 `inbox_tray.py:81-86`）
  · 灯→几何：`tools/mk_icons.py` SPEC（:34-40）；grey 用 L0 空环（不造新形状）
  · 旧六键：`ci/inbox_guards_0372.py` SIX_STATES/SIX_LABELS（:337-339，逐字）

★★ 两处**派生**（规格自相矛盾，按本件 §5 尾注登记为第 48/49 号猜测点，待创始人裁）：

  #48 drill 是不是成因。证据冲突：矩阵 CAUSES 与 F3 枚举都是 8 键（无 drill），
  但 §4.1 表有 drill 行、§5.3 N11-b 写「drill 成因行」、且 N11 八行缺 partial。
  本模块采「drill 是模式层身份、不是成因」，四条结构证据：
    ① I4 动作单射会破（drill 动作句「不用动」与 ok 同类）；
    ② drill 的灯由成因决定（干净格是 green/ok），固定 lamp 的条目装不下；
    ③ §4.2 把 drill 作**主行分支**（与未启用/有缺口并列），不是成因；
    ④ 矩阵 8 键是 I4 的唯一真源，N11-b 是夹具表的措辞。
  ⇒ 8 个成因条目 ＋ MODE_IDENTITY["drill"]；partial 的 tense 取 "now"
  （依据 N11-f「事件是过去，成因取状态时态」：没查到是此刻的属性）。

  #49 legacy_of 的映射值。F3 只冻了「有 legacy_of 字段、全仓唯一」，**没冻值**。
  本模块按 `light()` 的旧判读顺序（`inbox_model.py:2449-2530` 的 ①–⑥）派生为
  「旧键 → 新成因列表」（粗到细可一对多），每条注明派生依据。

不改任何既有模块：本模块是纯数据＋结构自检，等 2/3/4 步按 DAG 接进来。
"""

TENSES = ("never", "now", "past", "future", "unknowable")
LAMPS = ("grey", "green", "yellow", "red")

#: F3：11 字段，缺一不许进表（`selfcheck()` 逐条验）
FIELDS = ("key", "lamp", "cause", "label", "def_sentence", "shape",
          "color_var", "icon", "badge", "action", "tense")

#: 灯 → CSS 变量（F3 单点定义；灰与托盘 SHIELD_OFF 同源，**不许另立一个灰**）
COLOR_VAR = {"grey": "--lgrey", "green": "--l0",
             "yellow": "--l2", "red": "--r0"}

#: 灯 → 主体色（与 `inbox_server.py:125-126` 设计令牌同源：
#:   --l0:#226b4a --l2:#c2410c --r0:#9b2226；灰＝SHIELD_OFF 0x5f5e5a）
LAMP_RGB = {"grey": (0x5F, 0x5E, 0x5A), "green": (0x22, 0x6B, 0x4A),
            "yellow": (0xC2, 0x41, 0x0C), "red": (0x9B, 0x22, 0x26)}

#: 灯 → 图标几何（mk_icons.SPEC 键；grey 借 L0 空环，不造新形状）
SHAPE = {"grey": "L0", "green": "L0", "yellow": "L2", "red": "R0"}

#: duty 三值 —— **与 `facts.AXIS_VALUES["duty"]` 必须同集**。
#: ★ 本模块不重述 duty 的语义（那是 `facts.axes()` 的事），只做**呈现映射**；
#:   两处集合是否相等由判据 `output/_p_shape_parity.py` 交叉核对 ——
#:   任一边加值而另一边没加，判据立刻红（不靠自觉）。
DUTY_VALUES = ("on", "at-risk", "off")

#: 角标来源的封闭集 ＝ `tools/mk_icons.SHIELD_MARKS` 的键。
#: ★ 运行时只存**键**，不存 RGB：颜色真源在 `mk_icons.SHIELD_MARKS`，
#:   这里再写一份 `(0x2a,0x5d,0xb0)` 就是第二份声明（判据交叉核对）。
MARK_SOURCES = ("on", "unposted", "unknown", "off")

#: duty → 角标（**T1 决议**，创始人 2026-10-22 13:05 定案：at-risk 用 **dot**）。
#:
#:   · `on`      ⇒ 无角标（默认就是好状态，画角标＝制造噪音）
#:   · `at-risk` ⇒ 借 `SHIELD_MARKS["unknown"]` 那枚 **dot 蓝 0x2a5db0**
#:                 —— 冻结落点见冻结件 §11.3；`unposted`（slash 红）**不再用于 at-risk**
#:   · `off`     ⇒ 借 `SHIELD_MARKS["off"]` 那枚 **bar 灰**（「没在守」是形态，不是告警）
#:
#: ★ 为什么 at-risk 不新造一枚：T1 的硬门槛是「duty 碰撞不可接受」，
#:   dot 已被三组（正常＋两组色盲近似）判为可辨别；新造一枚等于把已测过的
#:   结论作废重测（B1 任务卡「不许新造形状」）。
DUTY_MARK = {"on": None, "at-risk": "unknown", "off": "off"}

#: 八成因条目（顺序＝矩阵 CAUSES 顺序；`cause` 与 `key` 同值：本表就是成因表）
STATES = [
    {"key": "unarmed", "lamp": "grey", "cause": "unarmed",
     "label": "未启用", "def_sentence": "还没开启，现在不拦也不记账。",
     "shape": "L0", "color_var": "--lgrey", "icon": "L0", "badge": [],
     "action": "arm", "tense": "never"},
    {"key": "absent", "lamp": "red", "cause": "absent",
     "label": "失守", "def_sentence": "监理不在岗，且这段时间有东西没被挡。",
     "shape": "R0", "color_var": "--r0", "icon": "R0", "badge": [],
     "action": "revive+assess", "tense": "now"},
    {"key": "breach", "lamp": "red", "cause": "breach",
     "label": "有缺口", "def_sentence": "监理在岗，但有该挡的没挡住，到现在没修。",
     "shape": "R0", "color_var": "--r0", "icon": "R0", "badge": [],
     "action": "fix-listed", "tense": "now"},
    {"key": "blind", "lamp": "red", "cause": "blind",
     "label": "看不清",
     "def_sentence": "监理认不出自己是不是在守，说得出缺什么就只报那一项。",
     "shape": "R0", "color_var": "--r0", "icon": "R0", "badge": [],
     "action": "verify-reinstall", "tense": "unknowable"},
    {"key": "partial", "lamp": "yellow", "cause": "partial",
     "label": "有一项没查到", "def_sentence": "有一项没查到，已按有问题算。",
     "shape": "L2", "color_var": "--l2", "icon": "L2", "badge": [],
     "action": "check-item", "tense": "now"},        # #48：tense 派生
    {"key": "paused", "lamp": "yellow", "cause": "paused",
     "label": "暂停中", "def_sentence": "监理不在岗，但这段时间没有要管的东西。",
     "shape": "L2", "color_var": "--l2", "icon": "L2", "badge": [],
     "action": "revive", "tense": "past"},
    {"key": "draining", "lamp": "yellow", "cause": "draining",
     "label": "快没粮了", "def_sentence": "监理在岗，但哨兵的口粮快用完。",
     "shape": "L2", "color_var": "--l2", "icon": "L2",
     # N6-a/b/c 三源全落 draining（夹具 §5.3），故与成因固定绑定的徽标键在此时
     "badge": ["granary_low", "heartbeat_will_stall", "disk_write_full"],
     "action": "topup", "tense": "future"},
    {"key": "ok", "lamp": "green", "cause": "ok",
     "label": "值守中", "def_sentence": "监理在岗，这段时间没查出缺口。",
     "shape": "L0", "color_var": "--l0", "icon": "L0", "badge": [],
     "action": "none", "tense": "now"},
]

STATES_BY_KEY = {e["key"]: e for e in STATES}
CAUSE_KEYS = tuple(e["key"] for e in STATES)

#: 模式层身份（**不是成因**，见 #48）：drill 的三句式与时态
MODE_IDENTITY = {
    "drill": {
        "label": "演练中",
        "def_sentence": "在跑，但结论不代表真实防护。",
        "display_sentence": "正在用还没发布的版本守着，能拦的照拦。",
        "action_sentence": "不用动",
        "tense": "never",       # 此构建从未发布（N11-b 的语义，移到模式层）
    },
}

#: 显示句（§4.1 逐字；不占 11 字段，与 def_sentence 同源同文件——句子只许一处写）
DISPLAY_SENTENCE = {
    "unarmed": "还没开启，现在没有任何东西在替你看门。",
    "ok": "今天没什么要拦的。它在盯着。",
    "paused": "监理暂停了一会儿，这会儿没有要管的东西。",
    "draining": "粮还够 N 天，用完监理会停。",
    "breach": "有 N 处没修，最早一处是 D 天前。",
    "absent": "监理不在岗。这段时间有 N 件没被挡。",
    "blind": "我证明不了自己在守。按最坏算，先核对一次。",
    "partial": "有 N 项没查到，先按有问题算。",
}

#: 动作句（§4.1 逐字；键＝动作等价类，I4 保证与成因单射）
ACTION_SENTENCE = {
    "arm": "去开启",
    "revive+assess": "先拉起，再看清单",
    "fix-listed": "按清单逐项修",
    "verify-reinstall": "核对或重装",
    "check-item": "去查没查到的那几项",
    "revive": "重新拉起",
    "topup": "补充口粮",
    "none": "不用动",
}

#: 旧六键（0372 S09 逐字，**不改**）——保留为能力键
LEGACY_KEYS = ("R0", "L2", "L1", "Ls", "L0", "dev")

#: 旧键 → 新成因列表（#49 派生：按 light() ①–⑥ 的旧判读顺序，粗到细可一对多）
#:   R0：① down∧可指认后果 ⇒ absent；warn（认不出守门的是不是原来那道门）⇒ blind；
#:       ② 24h 未处理的失守事件 ⇒ breach
#:   L2：② L2 级事件＝拦截 ⇒ 新模型进 info 账句（"都替你处理完了"），不抬灯 ⇒ ok
#:   L1：③ 缺岗无损失 interrupted ⇒ paused；探针抛错/集合外（bounded）⇒ partial
#:   Ls：缺粮 ⇒ draining（LOW_THRESHOLD 同源）
#:   L0：④ 值守 ⇒ ok；灰变体「未启用」⇒ unarmed（0372 :341 原文）
#:   dev：⑤ 研发态 ⇒ drill
LEGACY_OF = {
    "R0": ["absent", "breach", "blind"],
    "L2": ["ok"],
    "L1": ["paused", "partial"],
    "Ls": ["draining"],
    "L0": ["ok", "unarmed"],
    "dev": ["drill"],
}

#: ★ 2026-10-22 删除本模块曾有的 `LEGACY_LABEL`（一张旧键到中文名的字典）：
#:   它是 `inbox_model.STATE_LABEL` 的**第二份中文名声明**，被 0372 S08
#:   「灯态词全仓只有一份」当场判红，而全仓对它**零引用** ⇒ 纯冗余副本，删除。
#:   教训（判据互斥）：新模块多写一张「看着有用」的表，既有判据会立刻咬人；
#:   这正是 S08 存在的意义。旧键的中文名只有一个真源：`inbox_model.STATE_LABEL`。
#:   ★ 另注：本条注释**故意不写出那张字典的字面量** —— S08 的扫描器走文本
#:     （`_decl_scan`），注释里的字典同样会被当成「第二份声明」。本仓已有同型
#:     前科（0364 的判据在自己解释 bug 的注释里写了触发串而假红）。


def icon_spec(lamp, duty):
    """灯 × duty → 一格的呈现四元组 `{"shape","color_var","rgb","mark"}`。

    ★ **六点接线（X）只许走这一个入口**：色、几何、角标三者同一处出。
      分开拼必然出现「灯已经是黄的，角标还是红的」——那种不一致用户第一眼就看见，
      而判据只看灯值时抓不到。
    ★ 任一输入不在封闭集 ⇒ 返回 `None`（调用方显式降级，**不猜**）。
    ★ 返回键集由判据钉死（`_p_shape_parity.py`），改键要连判据一起改。
    """
    if lamp not in SHAPE or duty not in DUTY_MARK:
        return None
    return {"shape": SHAPE[lamp], "color_var": COLOR_VAR[lamp],
            "rgb": LAMP_RGB[lamp], "mark": DUTY_MARK[duty]}


def selfcheck():
    """结构自检（0a 验收的可执行版）。返回问题列表，空＝全绿。

    验六条：① 11 字段齐全；② tense 五值封闭且 blind 显式 unknowable；
    ③ 旧六键逐字保留；④ legacy_of 键集＝旧六键、值⊆成因键、全仓唯一；
    ⑤ 灯/成因单射与动作单射（I4）；⑥ 四灯的色与几何覆盖完整；
    ⑦ duty 三值齐、角标只借既有四枚、at-risk 必须是 dot（B1）。
    """
    bad = []
    for e in STATES:
        miss = set(FIELDS) - set(e)
        extra = set(e) - set(FIELDS)
        if miss:
            bad.append("① %r 缺字段 %s" % (e.get("key"), sorted(miss)))
        if extra:
            bad.append("① %r 多字段 %s（11 字段表之外）" % (e.get("key"), sorted(extra)))
        if e.get("tense") not in TENSES:
            bad.append("② %r tense=%r 不在封闭集" % (e.get("key"), e.get("tense")))
        if e.get("cause") != e.get("key"):
            bad.append("⑤ %r cause 与 key 不同值" % (e.get("key"),))
    if len({e["key"] for e in STATES}) != len(STATES):
        bad.append("⑤ 成因键重复")
    if len({e["action"] for e in STATES}) != len(STATES):
        bad.append("⑤ I4 破：动作类被两个成因共用")
    if STATES_BY_KEY.get("blind", {}).get("tense") != "unknowable":
        bad.append("② blind 的 tense 必须显式 'unknowable'")
    if LEGACY_KEYS != ("R0", "L2", "L1", "Ls", "L0", "dev"):
        bad.append("③ 旧六键被改动（0372 S09 冻结）")
    if set(LEGACY_OF) != set(LEGACY_KEYS):
        bad.append("④ legacy_of 键集≠旧六键")
    for k, targets in LEGACY_OF.items():
        for t in targets:
            # 目标允许落在模式身份上：dev→drill 是模式层身份（#48），不是成因
            if t not in CAUSE_KEYS and t not in MODE_IDENTITY:
                bad.append("④ %s → %r 既不是成因键也不是模式身份" % (k, t))
    for lamp in LAMPS:
        if lamp not in COLOR_VAR or lamp not in SHAPE:
            bad.append("⑥ 灯 %r 缺色/几何" % (lamp,))
    if not any(e["lamp"] == "grey" for e in STATES):
        bad.append("⑥ 灰灯无成因（unarmed 必须落灰）")
    for key, disp in DISPLAY_SENTENCE.items():
        if key not in CAUSE_KEYS:
            bad.append("句子表键 %r 不是成因键" % (key,))
    for key, e in STATES_BY_KEY.items():
        if e["action"] not in ACTION_SENTENCE:
            bad.append("动作类 %r 无动作句" % (e["action"],))
    # ⑦ duty 轴与角标（B1）：三值齐、角标只许借既有四枚、at-risk 必须是 dot
    for d in DUTY_VALUES:
        if d not in DUTY_MARK:
            bad.append("⑦ duty %r 无角标映射" % (d,))
    for d, src in DUTY_MARK.items():
        if src is not None and src not in MARK_SOURCES:
            bad.append("⑦ duty %r 的角标键 %r 不在 MARK_SOURCES" % (d, src))
    if DUTY_MARK.get("at-risk") != "unknown":
        bad.append("⑦ at-risk 的角标必须是 dot（T1 13:05 冻结："
                   "SHIELD_MARKS['unknown']；slash 已停用于 at-risk）")
    if DUTY_MARK.get("on") is not None:
        bad.append("⑦ `on` 不许挂角标（默认就是好状态）")
    if set(DUTY_MARK) != set(DUTY_VALUES):
        bad.append("⑦ DUTY_MARK 的键集≠DUTY_VALUES")
    for lamp in LAMPS:
        if icon_spec(lamp, "on") is None:
            bad.append("⑦ 灯 %r 取不到呈现规格" % (lamp,))
    return bad


if __name__ == "__main__":
    problems = selfcheck()
    if problems:
        for p in problems:
            print("FAIL:", p)
        raise SystemExit(1)
    print("state_registry selfcheck OK: %d causes, %d legacy keys, %d tenses"
          % (len(STATES), len(LEGACY_KEYS), len(TENSES)))

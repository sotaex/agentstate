# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
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

# --- 值勤轴与角标几何（B1，2026-10-22）------------------------------------------
#: 值勤轴（duty）：四轴之一（模式／值勤／可信／后果）。
#: ★ **与 `shield`（监理态）不是同一根轴**，虽然两轴都有 `on` / `off` 两个词：
#:   值勤说「他今天该不该在岗」，监理态说「他此刻在不在岗」。把两轴的键
#:   混进同一张「键 → 图案」表，`on` 与 `off` 立刻成为同一个键的两个含义。
DUTY = ("on", "at-risk", "off")

#: ★ 角标几何（形状＋颜色）的**唯一真源**。
#:   为什么不在 `tools/mk_icons.py` 里再写一行：T1 决议（创始人 13:05）把
#:   at-risk 定成 dot 蓝 `0x2a5db0`，而 mk_icons 里已有一枚**同形状同色**的
#:   `unknown`。若在那边加一行 `"at-risk": {"kind": "dot", ...}`，同一枚角标
#:   就有了两处字面量 —— 本仓复发最多的事故族（一个事实两个变量）。
#:   ⇒ 几何只在这里写一次，`MARK_OF` 只负责「哪个名字借哪一枚」。
#:   `None` 是**显式登记**「这一档不画角标」，不是「查不到」。
DUTY_MARK = {
    "on": None,
    "at-risk": {"kind": "ring", "color": (0x2A, 0x5D, 0xB0)},
    "off": {"kind": "bar", "color": (0x5F, 0x5E, 0x5A)},
}

#: 名字 → 角标几何。**两条轴共用一张查表**，但每个键的来历必须分得清：
#:   值勤轴（新）：`on` / `at-risk` / `off`
#:   监理态轴（旧）：`on` / `unposted` / `unknown` / `off`
#:     ——这四键就是 `tools/tray.ps1`、`tools/logo.ps1` 与
#:     `assets/icons/*.ico` 沿用至今的文件名后缀。
#:   ★ 0.55.0：`at-risk` 挣到了自己的后缀 `-at-risk`（第五个文件字键），
#:     于是本表的键集与 `inbox_tray.SHIELD_SUFFIX` **不再相同** ——
#:     `at-risk` 在旧轴里没有对应，`unposted` 在值勤轴里没有对应。
#:     两边都变五键不是巧合，但**交集不是全部**，别拿一张表当另一张用。
#: `unposted`（slash 红）保留为**旧键能力**，不再用于 at-risk。
MARK_OF = {
    "on": DUTY_MARK["on"],
    "at-risk": DUTY_MARK["at-risk"],
    "off": DUTY_MARK["off"],
    # ★ 0.55.0 改判：`unknown`（盲区）与 `at-risk`（在岗但将断粮）**不再共用一枚角标**。
    #   旧裁决（T1）的理由是「角标只有一枚，改成不共享就要造第二种形状」——
    #   实测把这条理由拆了一半：造形状的成本只是 `_alpha_at_shield` 里一个 `if`
    #   分支，而共享的代价是托盘上「在险」与「探不到」**逐像素相同**（F2 的视觉版：
    #   两种不同处境，同一个输出）。
    #   现在：unknown＝实心 dot（看不见），at-risk＝空心 ring（看得到、但快断）。
    #   ⚠️ 诚实标注：16px 托盘上角标区只有 5×4 像素，dot 与任何形状都分不开
    #   （实测 dot 与 bar 差 0 像素）⇒ **16px 的通道是 tooltip，不是图标**。
    #   本改动兑现的是 ≥32px（高分屏托盘、页面、哨标）的可辨性。
    "unknown": {"kind": "dot", "color": (0x2A, 0x5D, 0xB0)},
    "unposted": {"kind": "slash", "color": (0x9B, 0x22, 0x26)},
}

#: 角标图案的封闭集（画得出来的四种＋不画）。
#: 0.55.0 加 `ring`（at-risk 的空心环）—— 它同时是「四种图案」这个数字的来源，
#: 判据里凡是写「三种」的地方都要跟着数一遍（`MARK_KINDS` 是唯一真源）。
MARK_KINDS = ("dot", "slash", "bar", "ring")


def mark_of(name):
    """名字 → 角标几何。`None` 有确切含义：**查到了，这一档不画角标**。

    ★ 查不到时**抛 KeyError**，不返回 `None`。理由是本仓 0.55.0 修 F2 的那条：
      一个空值只许表示一件事。若查不到也返回 `None`，「我不认识这个名字」
      与「在岗」画出来**逐像素相同**，且没有任何地方会出声。
      （实测：改前 `build_ico(..., shield="at-risk")` 与 `shield=None` 的
       sha256 完全相同，25 格里 5 格如此。）
    """
    try:
        return MARK_OF[name]
    except KeyError:
        raise KeyError("没有名为 %r 的角标（合法：%s）"
                       % (name, "、".join(sorted(MARK_OF))))


#: 资产文件字键（**文件名那一族**，与值勤名分开）。
#: 这五个名字各对应一份 `{灯}{后缀}.ico`，是 `assets/icons/` 的命名依据。
#: ★ 与 `inbox_tray.SHIELD_SUFFIX` 的键集必须逐字相同 —— 那份是运行期读图用的。
#:   本模块是纯数据、零 import，不能反向依赖它 ⇒ **两处存在是事实**，
#:   由判据钉死（`output/_p_asset_names.py` C①），不靠人记得同步。
#: ★ 0.55.0 加 `at-risk`：它原来借 `unknown` 的文件，于是托盘上「在险」与
#:   「探不到」不但图形相同、连文件名都相同 —— 那条路上**没有任何一处**
#:   能区分两者。给它一份自己的文件是让 `asset_key_of` 有正确答案可返回，
#:   而不是继续在「借谁的」这件事上做隐式推断。
FILE_KEYS = ("on", "at-risk", "unposted", "unknown", "off")


def asset_key_of(name):
    """名字 → **读哪一份资产**。返回文件字键；`None`＝复用基础图标。

    ★ 为什么需要这一层：B1 之后 `at-risk` 画得出来（借 `unknown` 那枚 dot），
      但**没有一处回答它读哪份 `.ico`**。`inbox_tray` 的两处入口
      （`icon_file`、`write_state`）都拿 `in shield in SHIELD_SUFFIX` 判域外
      并静默回落：图标回落成无角标（与 `on` 逐字节相同），`tray.json`
      回落成 `unknown`（＝盲区）。两件事互不相同，且都不出声。

    ★ 0.55.0 之前 `at-risk` 借 `unknown` 的几何与文件，本函数的任务就是
      把「借谁的」这件事答出来。实测发现那条路有两个哑口：
      `inbox_tray` 的两处入口（`icon_file`、`write_state`）都用
      `name in SHIELD_SUFFIX` 判域外并**静默回落**：图标回落成无角标
      （与 `on` 逐字节相同），`tray.json` 回落成 `unknown`（＝盲区）。
      两件事互不相同，且都不出声。
      ⇒ 0.55.0 给 `at-risk` 一份自己的资产（`-at-risk`，空心环角标），
      于是本函数对值勤三档都能答出一份**它自己的**文件，不再借。

    ★ 查不到抛 `KeyError`（与 `mark_of` 同一条理由）：返回 `None` 会让
      「我不认识这个名字」与「这一档不画角标」走同一条路。
    """
    if name in DUTY_MARK:                   # 值勤三档（含 on）
        mk = DUTY_MARK[name]
        if mk is None:
            return None
        for k in FILE_KEYS:
            if MARK_OF[k] is mk:
                return k
        raise KeyError("值勤档 %r 有几何，但没有哪份资产承载它"
                       "（%s 里没有同形的一份）" % (name, "、".join(FILE_KEYS)))
    if name in MARK_OF:                     # 监理态旧键本身就是文件字键
        return None if MARK_OF[name] is None else name
    raise KeyError("没有名为 %r 的资产（合法：%s）"
                   % (name, "、".join(sorted(set(MARK_OF) | set(DUTY_MARK)))))


def _asset_guard_problems():
    """**「画得出来 ⇒ 必须有文件承载」**——B1 那个洞的类层面守卫。

    守的不是 `at-risk` 这一个实例，而是它的形状：谁往 `DUTY_MARK` 里加一格、
    却没让它在 `FILE_KEYS` 里找到同形的一份，这里就红。抽成命名函数是
    为让负控能换掉同一份实现（`_p_asset_names.py` N④）。
    """
    bad = []
    for d in DUTY:
        try:
            k = asset_key_of(d)
        except KeyError as exc:
            bad.append("⑧ %s" % (exc,))
            continue
        if k is not None and k not in FILE_KEYS:
            bad.append("⑧ %s → %r 不在 FILE_KEYS" % (d, k))
    for k in FILE_KEYS:
        if k not in MARK_OF:
            bad.append("⑧ 文件字键 %r 在 MARK_OF 里没有几何" % (k,))
    return bad


#: 八成因条目（顺序＝矩阵 CAUSES 顺序；`cause` 与 `key` 同值：本表就是成因表）
STATES = [
    {"key": "unarmed", "lamp": "grey", "cause": "unarmed",
     "label": "未启用", "def_sentence": "还没开启，现在不拦也不记账。",
     "shape": "L0", "color_var": "--lgrey", "badge": [],
     "action": "arm", "tense": "never"},
    {"key": "absent", "lamp": "red", "cause": "absent",
     "label": "失守", "def_sentence": "监理不在岗，且这段时间有东西没被挡。",
     "shape": "R0", "color_var": "--r0", "badge": [],
     "action": "revive+assess", "tense": "now"},
    {"key": "breach", "lamp": "red", "cause": "breach",
     "label": "有缺口", "def_sentence": "监理在岗，但有该挡的没挡住，到现在没修。",
     "shape": "R0", "color_var": "--r0", "badge": [],
     "action": "fix-listed", "tense": "now"},
    {"key": "blind", "lamp": "red", "cause": "blind",
     "label": "看不清",
     "def_sentence": "监理认不出自己是不是在守，说得出缺什么就只报那一项。",
     "shape": "R0", "color_var": "--r0", "badge": [],
     "action": "verify-reinstall", "tense": "unknowable"},
    {"key": "partial", "lamp": "yellow", "cause": "partial",
     "label": "有一项没查到", "def_sentence": "有一项没查到，已按有问题算。",
     "shape": "L2", "color_var": "--l2", "badge": [],
     "action": "check-item", "tense": "now"},        # #48：tense 派生
    {"key": "paused", "lamp": "yellow", "cause": "paused",
     "label": "暂停中", "def_sentence": "监理不在岗，但这段时间没有要管的东西。",
     "shape": "L2", "color_var": "--l2", "badge": [],
     "action": "revive", "tense": "past"},
    {"key": "draining", "lamp": "yellow", "cause": "draining",
     "label": "快没粮了", "def_sentence": "监理在岗，但哨兵的口粮快用完。",
     "shape": "L2", "color_var": "--l2",
     # N6-a/b/c 三源全落 draining（夹具 §5.3），故与成因固定绑定的徽标键在此时
     "badge": ["granary_low", "heartbeat_will_stall", "disk_write_full"],
     "action": "topup", "tense": "future"},
    {"key": "ok", "lamp": "green", "cause": "ok",
     "label": "值守中", "def_sentence": "监理在岗，这段时间没查出缺口。",
     "shape": "L0", "color_var": "--l0", "badge": [],
     "action": "none", "tense": "now"},
]

#: ★ `icon` 不手写，派生自 `SHAPE[lamp]`（B1）。
#:   改前：8 条里 `shape` 与 `icon` 各写一遍、8 条值逐条相同。两处一旦漂，
#:   画出来的是 A、判据读的是 B，**两边都不报错**。派生之后"写第二份"在
#:   源码里不再存在——探针用 AST 查"有没有 icon 的字典字面量"来守这一点
#:   （走结构不走文本：本注释里就写着这个词，文本数法会把自己判成违规）。
for _e in STATES:
    _e["icon"] = SHAPE[_e["lamp"]]

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


def selfcheck():
    """结构自检（0a 验收的可执行版）。返回问题列表，空＝全绿。

    验八条：① 11 字段齐全；② tense 五值封闭且 blind 显式 unknowable；
    ③ 旧六键逐字保留；④ legacy_of 键集＝旧六键、值⊆成因键、全仓唯一；
    ⑤ 灯/成因单射与动作单射（I4）；⑥ 四灯的色与几何覆盖完整；
    ⑦ 角标几何（两条轴的键都在、图案在封闭集、值勤三档全覆盖）；
    ⑧ **画得出来 ⇒ 必须有资产文件承载**（值勤每档都能在 `FILE_KEYS`
    里找到同形的一份，见 `_asset_guard_problems`）。
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
    # ⑦ 角标几何（B1）：值勤三档必须都查得到；图案只许三种＋不画
    for d in DUTY:
        if d not in MARK_OF:
            bad.append("⑦ 值勤 %r 在 MARK_OF 里取不到" % (d,))
    for name, mk in MARK_OF.items():
        if mk is None:
            continue                      # 显式登记「不画角标」
        if mk.get("kind") not in MARK_KINDS:
            bad.append("⑦ %r 的角标形状 %r 不在封闭集 %r"
                       % (name, mk.get("kind"), MARK_KINDS))
        col = mk.get("color")
        if not (isinstance(col, tuple) and len(col) == 3
                and all(isinstance(c, int) and 0 <= c <= 255 for c in col)):
            bad.append("⑦ %r 的角标颜色 %r 不是 RGB 三元组" % (name, col))
    # 旧四键不许因为新增值勤轴而丢：`SHIELD_SUFFIX`／`tray.ps1`／`logo.ps1`
    # 与 `assets/icons/*.ico` 的文件名后缀全按这四个键走（0360 会逐格查产物）。
    # ★ 这个集合现在有了名字＝`FILE_KEYS`，由 ⑧ 的守卫统一查，
    #   这里不再写第二份字面量。
    bad.extend(_asset_guard_problems())
    return bad


if __name__ == "__main__":
    problems = selfcheck()
    if problems:
        for p in problems:
            print("FAIL:", p)
        raise SystemExit(1)
    print("state_registry selfcheck OK: %d causes, %d legacy keys, %d tenses"
          % (len(STATES), len(LEGACY_KEYS), len(TENSES)))

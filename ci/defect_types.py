# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""缺陷类型登记簿（元层）：每个缺陷先归类，每类必须有人守。

★ 为什么需要它（与"防复发十道机制/回归闸门"的分工）
  回归闸门（`ci/regression_gate.py`）答的是一个问题：

      「这次改动，有没有把**某个已修好的具体缺陷**弄回去？」

  它按缺陷逐条设判据。缺点是**只覆盖已经想到过的缺陷** ——
  一个**新类型**的缺陷第一次出现时，闸门里没有任何判据守着它。

  登记簿答的是另一个问题：

      「**这类**错，仓里有没有人守？今天有几类没人守？」

  分工：闸门管"个案不回退"，登记簿管"类型覆盖"。
  ★ 两者互补，不是替代 —— 没有登记簿，闸门会无限增长且仍留盲区；
    没有闸门，登记簿只是张不会响的表格。

★★ 三条设计纪律（都从 2026-10-12 的实测教训来）
  ① **每类必须有人守，或者显式申报为守不住**。
     "有人守"＝至少一个**真实存在于闸门注册表**的判据 ID（不许写幻想 ID）。
     "守不住"＝`blind: True` ＋ 一条 `discipline`（人必须遵守的替代动作）。
     **未申报又无判据 ⇒ 判据红**。申报过的盲区比隐藏的盲区安全得多
     —— 隐藏的盲区会被当成清白。
  ② **实例不许借判据充数**：实例的 `guard` 必须属于它声明类型的 `guards`。
     否则"这类病有药"是假的（药是别人类型的）。
  ③ **未闭合的实例必须暴露**：`status="open"` 且类型是 blind ⇒ 允许
     （这是申报盲区的正常状态），但报告必须逐条列出来；
     `status="open"` 且类型是 guarded ⇒ **红**（有病无药）。

★★★ 用法
  python ci/defect_types.py --report         # 人读：覆盖现状 + 未闭合清单
  python ci/defect_types.py --gate-ids       # 机器读：从闸门注册表提取判据 ID
  python ci/defect_types.py --check          # 自检：登记簿自身一致性（供判据调用）

  新缺陷的标准动作（这就是"机制"二字的意思）：
    1. 归类到某个 T-xx；归不进去 ⇒ 新增类型
    2. 新增类型时**必须同时**决定：配判据，还是申报 blind + 写 discipline
    3. 登记实例（X-xxx），指向守护它的判据
    4. 跑 `--report` 看覆盖变化
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)

# =====================================================================
# 一、类型表
#   每类字段：
#     name        类型名（人读）
#     definition  判据：凭什么被归到这类（一句话，可检验）
#     guards      守护判据 ID 列表（必须是闸门注册表里真实存在的 ID）
#     blind       True ⇒ 守不住，必须配 discipline（人工替代动作）
#     discipline  人工纪律（blind 类型必填）
# =====================================================================

TYPES = {
    "T-01": {
        "name": "会说谎的数字",
        "definition": ("界面显示的数值在渲染那一刻冻结，不随时间或状态更新，"
                       "而用户会以为它是活的"),
        "guards": ["D-26"],
        "blind": False,
        "discipline": ("要显示「N 分钟前」类读数，必须同时有自动刷新或陈旧守卫；"
                       "两者皆无 ⇒ 删掉这个读数，别显示它"),
    },
    "T-02": {
        "name": "活数据追不上死快照",
        "definition": ("一份数据按日/按事件滚动，另一份是发布时快照；"
                       "快照必然逐次落后，且没有人负责追平"),
        "guards": ["D-25", "D-36"],
        "blind": False,
        "discipline": ("滚动目录与快照文件的配对必须有判据守着；"
                       "修法用 _reconcile_chain_manifest.py 或 _resign_manifest.py --roll；"
                       "**「源码 vs 快照哈希」是同一类的另一半**（D-25 只查文件在不在、"
                       "D-36 查字节还是不是那个）：凡改动被 manifest 钉住的源码，"
                       "提交前必须重签（`python _tools_034/_resign_manifest.py`）"),
    },
    "T-03": {
        "name": "量具自身有缺陷",
        "definition": ("检查工具自己的口径、fixture、自报与真仓不一致，"
                       "导致假红、假绿，或照错值写回破坏数据"),
        "guards": ["D-27", "D-28", "C-01", "S47"],
        "blind": False,
        "discipline": ("量具改动后先跑「干净状态不误报」，再跑负控；"
                       "量具的哈希/比对口径一律 import 产品模块，不许二次实现；"
                       "**凡依赖并发/时序/机器状态的夹具，必须自证夹具成立**"
                       "（会合栅栏 ＋ 前置条件强制化 ＋ 两臂对照），"
                       "把「测不出」与「测出来是对的」分开"),
    },
    "T-04": {
        "name": "红而无出路",
        "definition": ("判据变红了，但文档承诺的修法不存在或跑不通 —— "
                       "知道错了也改不了"),
        "guards": ["D-29"],
        "blind": False,
        "discipline": ("判据 docstring 里写的工具/参数/命令，必须是跑得通的那个；"
                       "红之前先自己跑一遍修法"),
    },
    "T-05": {
        "name": "边界误伤",
        "definition": ("用宽泛匹配认对象，把非目标对象当成目标处理"
                       "（误关用户窗口、误判文件归属）"),
        "guards": ["G-05"],
        "blind": False,
        "discipline": ("认对象的判据必须收窄到「本次运行」的范围"
                       "（白名单/令牌尾缀），不许只按标题前缀猜"),
    },
    "T-06": {
        "name": "文档与代码不同锚",
        "definition": ("文档/docstring 承诺的路径、参数、命令在代码里不存在，"
                       "照着文档做必错"),
        "guards": ["D-30"],
        "blind": False,
        "discipline": ("文档里出现仓内路径或工具参数前，先确认它存在；"
                       "判据 docstring 承诺的工具参数必须真实可跑"),
    },
    "T-07": {
        "name": "间接引用漏检",
        "definition": ("用 grep/字面匹配得出「无人引用 X」的结论，"
                       "漏掉通过中间文件（manifest/配置/生成物）的间接引用"),
        "guards": [],
        "blind": True,
        "discipline": ("下「无人引用 X」的结论前，必须跑对照实验"
                       "（改动前后各跑一次判据），不许只凭 grep；"
                       "本类无法机械守护 —— 没有人能在写代码时预知哪种间接引用会漏"),
    },
    # ── 2026-10-13 效率升级那一轮归纳出来的三型（创始人拍板补登记）──
    "T-08": {
        "name": "查不到就下结论",
        "definition": ("一次查询/读取**失败或读不到**，被折叠成"
                       "「事实是空的／否定的」，并据此下结论或据此动作"),
        "guards": ["D-32", "S19", "W-05", "S80"],
        "blind": False,
        "discipline": ("凡「查询型」调用（进程在不在／端口谁占着／心跳链读到没）"
                       "一律三态：真值 ／ 真否 ／ **查不到**；"
                       "查不到必须出声或落盲区，**绝不折叠成否定**"),
    },
    "T-09": {
        "name": "同一事实两套口径",
        "definition": ("同一个事实有两份各自演化的实现（两份文案、两份清单、"
                       "源件与部署件、两份读数），且**没有任何判据**守着它们一致"),
        "guards": ["D-22", "D-33", "W-03"],
        "blind": False,
        "discipline": ("同一事实只许一个写入口／一个真源；"
                       "凡「源件 vs 派生件」（部署件、托盘文案、缓存快照）"
                       "必须有判据断言逐字一致"),
    },
    "T-10": {
        "name": "静默降级",
        "definition": ("降级／跳过／失败**发生了**，但没有任何输出说明它发生了 —— "
                       "账面看起来与「全部跑过」一样"),
        "guards": ["D-34", "D-35"],
        "blind": False,
        "discipline": ("凡「少做了一部分」（快道跳过、锁拿不到、查不了、fixture 缺件）"
                       "必须**逐条打印**；只给一个数字不算出声"),
    },
}

# =====================================================================
# 二、实例账
#   每条字段：
#     id      实例编号
#     type    归属类型（必须在 TYPES 里）
#     what    这个具体缺陷是什么（一句话）
#     guard   守护它的判据 ID（blind 类型可为 None）
#     status  fixed（已修且有人守）/ open（未闭合）
#     date    ISO 日期
#     note   补充（修法/教训）
# =====================================================================

INSTANCES = [
    {
        "id": "X-001",
        "type": "T-01",
        "what": "值守台顶部条「哨兵在岗，最后心跳 N 分钟前」——页面零自动刷新，"
                "N 是渲染时冻结的值，页面开一小时不换数",
        "guard": "D-26",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "删 why 里的心跳，读数留 evidence.heartbeat_age；"
                "缺岗分支「心跳断档 N 分钟」保留（事件态决策信息）",
    },
    {
        "id": "X-002",
        "type": "T-02",
        "what": "psl/manifest.json 登记 challenge/chain/2026-09-23.jsonl，"
                "而链已被远端 bot 滚到 2026-10-11.jsonl，成指向不存在文件的死条目",
        "guard": "D-25",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "merge 并入远端 21 条时 git 识别为 rename；"
                "0483 S2 由 11 绿/1 红转 12 绿/0 红，--manifest exit 1 转 0",
    },
    {
        "id": "X-003",
        "type": "T-03",
        "what": "_resign_manifest.py 用裸 sha256，构建器对 VERSION_BEARING_CHAIN_FILES "
                "先归一化版本行再算；误跑把 hooks/pre_tool_use.py 判成需重签并写回，"
                "让 --manifest 由绿变红",
        "guard": "D-27",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "改为 import host_shield 拿归一化口径；并加量具自检（写回前验口径，"
                "不一致即拒绝写回）",
    },
    {
        "id": "X-004",
        "type": "T-03",
        "what": "负控 fixture 只复制 7 个目录，manifest 里 assets/、challenge/ 条目"
                "在 fixture 里全部「不存在」⇒ D-25 在每一条负控里连带假红，"
                "输出污染成「D-25 | D-25」，读者分不清哪条才是被注入的",
        "guard": "D-28",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "fixture 按 manifest 条目补复制（合计仅 3.2 MB）",
    },
    {
        "id": "X-005",
        "type": "T-04",
        "what": "D-25 docstring 承诺追平工具 _resign_manifest.py --roll，"
                "但该参数当时并不存在 —— 判据红了给不出修法",
        "guard": "D-29",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "实现 --roll（死条目结构化对齐：同目录+同扩展名+唯一且未登记）；"
                "猜不出唯一解 ⇒ STUCK 并 exit 1，不猜",
    },
    {
        "id": "X-006",
        "type": "T-06",
        "what": "regression_gate.py 自己的 docstring 写 python scripts/regression_gate.py，"
                "文件实际在 ci/ 下 —— 照着 docstring 跑必报找不到文件",
        "guard": "D-30",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "由 D-30 注册前的自扫发现；修 docstring 后该判据才注册",
    },
    {
        "id": "X-007",
        "type": "T-05",
        "what": "认窗判据曾用宽泛匹配（标题前缀）认「本次运行的窗口」，"
                "误把用户自己的记事本当成值守台窗口处理（0.36.5）",
        "guard": "G-05",
        "status": "fixed",
        "date": "2026-10-12",
        "note": "守卫 inbox_guards_0360 专守 SV.PAGE_TITLES 白名单（715-742 行）；"
                "登记时按版本号追认，实例日期以登记日计",
    },
    {
        "id": "X-008",
        "type": "T-07",
        "what": "我曾断言「delivery_gate 的 29 个套件零引用 merge 改动的路径」，"
                "实际 0483 通过读 manifest 间接引用了被改名的链文件 —— "
                "grep 抓不到间接引用，据此下了错结论",
        "guard": None,
        "status": "open",
        "date": "2026-10-12",
        "note": "本类申报为守不住（blind）；修法是流程纪律：下「无人引用」结论前"
                "必须跑对照实验。保持 open —— 它没有被机械守护，下次还可能漏",
    },
    # ── 2026-10-13：A1／A2／B2 ＋ 效率升级那一轮归纳出的实例 ──
    {
        "id": "X-009",
        "type": "T-08",
        "what": "delivery_gate._pid_alive 把「查不了」折叠成「不在」："
                "import audit_chain 因 sys.path 没有仓根而必然失败 ⇒ 判活恒为「死」"
                "⇒ 活锁被判成陈旧锁（Windows 上侥幸没偷成，POSIX 上会真被偷）",
        "guard": "D-32",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：仓根进 sys.path ＋ 判活改三态（None＝查不了）＋ 拿不准一律按占用；"
                "D-32 正/负控实测（把变异体跑起来，它真的把活锁偷走了 ⇒ 判据会红）",
    },
    {
        "id": "X-010",
        "type": "T-08",
        "what": "B2：默认端口被占时静默换临时端口 —— 用户手输打不开，"
                "也无从得知实际端口；占用方进程号查不到时连「谁占的」都说不出来",
        "guard": "W-05",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "真守卫在 ci/inbox_guards_0490.py W-05/N-W05；修法：报 drift"
                "（want/got/owner）＋ stderr 出声 ＋ 落盘 want_port ＋ 托盘 tip 带端口；"
                "查不到占用方时必须说「没查到」（不许编一个）",
    },
    {
        "id": "X-011",
        "type": "T-08",
        "what": "A1：心跳链目录按**读者**包根猜 ⇒ 哨兵与读者不同包根时读到另一条链，"
                "guard_posture 判「心跳断档」并渲染成 R0 红 —— 而哨兵进程活着",
        "guard": "S19",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "真守卫在 ci/inbox_guards_0372.py S19/N-S19（登记簿 2026-10-13 扩口径"
                "之后才认得出它）；修法：在岗但读不到心跳链 ⇒ POSTURE_UNKNOWN（L1 盲区）",
    },
    {
        "id": "X-012",
        "type": "T-09",
        "what": ".git/hooks/pre-commit 是 09-28 拷的（跑 regression_gate，22 条），"
                "而仓内源 10-07 已升级为 delivery_gate --quick —— 部署件 6 天没跟源，"
                "28 套快档判据在这 6 天里一次都没在提交时跑过",
        "guard": "D-33",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：源改快道（--hook）＋ 重新部署 ＋ D-33 正面守"
                "「部署件与仓内源逐字一致」（负控：改坏源的参数 ⇒ 立刻漂移 ⇒ 红）",
    },
    {
        "id": "X-013",
        "type": "T-09",
        "what": "A2：托盘事件态走旧合并读（24h 账里的历史 R0 抬灯），"
                "页面自 0.39.0 起走 current_state() ⇒ 同一时刻托盘「有过失守」"
                "vs 页面「拦截」",
        "guard": "W-03",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "真守卫在 ci/inbox_guards_0490.py W-03/N-W03；"
                "修法：托盘状态词改走 light_explain（与 Web 逐字同源）",
    },
    {
        "id": "X-014",
        "type": "T-10",
        "what": "交付闸门实测 1161s（19.3 分钟）、主闸门 68s ⇒「全量跑」退化成靠自觉；"
                "而引入快道后新风险是**快道悄悄少跑** —— 少跑的没人知道，"
                "与「没有闸门」等价",
        "guard": "D-34",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：--hook 快道把「预算外／影响面外」**逐条列明**（含历史秒数）；"
                "D-34 行为级断言「装不下的每一个名字都必须出现在输出里」",
    },
    {
        "id": "X-015",
        "type": "T-10",
        "what": "运行锁的陈旧让开失败原本 `except OSError: pass`（静默）——"
                "锁清不掉却不说，下一次仍然拿不到；"
                "以及 19 分钟的全量闸门因整块缓冲「一个字都看不到」",
        "guard": "D-34",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：让开失败必须返回带原因与手工修法的消息；"
                "闸门输出改行缓冲 ＋ 结果一律落 .psl/gate/last_run.json",
    },
    {
        "id": "X-016",
        "type": "T-10",
        "what": "`delivery_gate._touch_files()` 只认产品源码（.py ＋ 闸门自身文件），"
                "而 `--hook` 用「探不到改动 ⇒ 回退全量」兜底 ⇒ **纯文档改动**"
                "（改 docs/*.md）被判成「探不到」 ⇒ 回退全量 30 套（实测 22 min）"
                "⇒ 前台 `git commit` 跑钩子超时被杀 ⇒ 人只好 `--no-verify` "
                "—— 把 0.48.5 刚接好的「一处入口」又拆了（T-10 复发在**钩子层**）",
        "guard": "D-35",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：把「改动探测」与「影响面」拆两层 —— 探测认一切改动"
                "（只答「要不要回退全量」），影响面只认产品源码（答「跑哪几套」）；"
                "纯文档 ⇒ 影响面 0 套、只跑主闸门快档。逻辑抽成纯函数 `_select_suites`，"
                "D-35 直接调它（判据不许二次实现）＋ 负控注入「把两层重新折叠」必须红。",
    },
    {
        "id": "X-017",
        "type": "T-08",
        "what": "`ci/inbox_guards_0460.py` 的 S80/S81 依赖 git 子进程（`check-ignore` / "
                "`rev-parse`），而 `VCT_TIMEOUT = 2.0s`；机器高负载时 git 实测 1.70s "
                "⇒ 撞超时 ⇒ 走出口丙 ⇒ 两票**取不到信号**（`vote1` 为 `''` 或 "
                "`unavailable`）。旧判据把「取不到信号」与「裁决错误」混为一谈，"
                "都报「两票裁决不符」 ⇒ 把**机器天气**说成**产品缺陷**"
                "（T-08「查不到就下结论」复发在**量具层**）",
        "guard": "S80",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：夹具**自证成立**（`_fixture_live` control probe，取不到信号 ⇒ "
                "报「夹具失效」而非「裁决不符」）＋ `_no_signal` 把两种取不到信号的"
                "形状（空串 / unavailable）与「取到了但值不对」分开；"
                "负控 N-S80b 让 git 一律失败，断言 S80 必须报「夹具失效」且"
                "**不许**报「两票裁决不符」。",
    },
    {
        "id": "X-018",
        "type": "T-03",
        "what": "负控（量具）**自己的**故障冒充产品红：N-U13 把头部 mp4 形态加回时 "
                "变异 args 少给一个 `M.STATE_VAR[st]`，变异渲染抛 "
                "`TypeError: not enough arguments for format string`。负控的职责是"
                "「证明**正判据**会红」，结果它**自己先崩了** ⇒ 量具故障伪装成产品问题，"
                "人得读 traceback 才分辨得出",
        "guard": "C-01",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法：负控**模板化两步** —— `_mut_render()` 做第一步（变异模块"
                "「能 import ＋ 最小渲染不抛」，不过即判「负控自身失效，不算通过」）；"
                "12 处渲染型负控全部改走它。元判据 C-01 用 `ast` 扫「负控块里"
                "还有没有裸的 `.render_page(`」（正则会误咬字符串里的变异文本，"
                "首跑真咬到自己人）＋ 负控 N-C-01（换回裸渲染 ⇒ 元判据必红）。",
    },
    {
        "id": "X-019",
        "type": "T-08",
        "what": "0490 的 W-05 夹具 `_w05_assert()` 依赖 `_port_owner()`（Windows "
                "`netstat -ano`／POSIX `lsof`，**外部子进程**）；机器高负载时查询取不到 "
                "⇒ `owner=None` ⇒ 断言 `owner == 本进程` 假红（实测撞到一次："
                "「漂移没点出占用方进程号：owner=None（应 26332）」）。"
                "**与 X-017 同一类**：量具把「取不到信号」当成了「裁决错误」",
        "guard": "W-05",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法（**已落地**，照 M-A 的形状）：① `_w05_assert()` ①② 里凡依赖"
                "「占用方 pid」的那一项改**条件断言** —— 红在该项时**当场**再问一次仪表"
                "（`_w05_owner_probe()`）：仪表通 ⇒ 真缺陷红；不通 ⇒ 这一轮算机器天气、"
                "重试（`_W05_TRIES=3`）；始终不通 ⇒ 报**「夹具失效」**。"
                "② `n_w05` 三个子块先过 `_w05_negctl_guard()` —— 夹具失效时**直接判测不出**，"
                "不许让「夹具坏了」冒充「负控咬错了地方」（更不许冒充通过）。"
                "③ 新负控 **N-W05b**：仪表恒盲 ⇒ 必须报夹具失效；仪表通而值错 ⇒ 必须报"
                "真缺陷（证明条件断言没把真缺陷一起放过）；负控闸三条对照。"
                "0490 → 37 绿 / 0 红。"
                "★ 残留风险如实记：仪表**通**而产品**没报** owner 时，仍靠重试窗口区分"
                "（3 轮），理论上仍有极小概率把天气算成缺陷 —— 比原来的「一次即红」"
                "小约两个量级。",
    },
    {
        "id": "X-020",
        "type": "T-03",
        "what": "两道**并发负控**把「撞不撞得上」交给了调度运气 —— "
                "`0470 N-S98`（8 进程 × 20 次无锁读改写）与 `0450 N-S75`"
                "（6 进程抢临界区，窗口 50ms）。两者的栅栏都是「等一个 go 文件」，"
                "而 go 文件**治不了启动错峰**：`Popen` 返回快，但解释器启动有先后"
                "（本机每个 ≈100–200ms），**迟到的进程看见 go 已存在就直接冲**，"
                "等于没等 ⇒ 「同时冲」退化成「排队冲」，窗口一短就一次都撞不上。"
                "实测：N-S98 本机复跑 6 轮 **5 撞 / 1 不撞**，全量交付闸门里假红一次"
                "（报「4 轮并发守恒均成立（total=160, missed=0）」）；"
                "N-S75 打包闸门里假红一次（0450 12 绿 / 1 红），随后连跑 3 次又全绿"
                "—— 典型**时红时绿**。本仓铁律「一个时红时绿的量具比恒红的更坏」",
        "guard": "S47",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法（机制化，不是就地打补丁）：新增**唯一实现** `ci/race_amp.py` —— "
                "① 会合栅栏（等的是**兄弟进程本身**，全部到齐才放行）；"
                "② 前置条件强制化（N-S98 的变异只在「锁取不到」时现形，"
                "就把 `acquire_lock` 打成恒返回 None；**只强制前置，不强制结论**）；"
                "③ **两臂对照**（同一套夹具只差「修复在不在」：对照臂必须守恒，"
                "变异臂必须破坏 —— 对照臂是②的许可证，否则放大窗口＝自证其罪）。"
                "N-S98 单轮从 20–70s 降到 ≈8s 且 5/5 撞上；N-S75 5/5 撞上。"
                "元判据 **S47**（在 `guard_instrument_selfaudit.py`）机械禁止"
                "「N 路齐冲却不走会合栅栏」，并**反空转**（`race_amp` 无人使用即红）。",
    },
    {
        "id": "X-021",
        "type": "T-02",
        "what": "A1（`2397451`）改了 `host_shield.py`，而 `psl/manifest.json` 停在 "
                "`914c5dc` **未重签** ⇒ 源树里的 manifest 是「落后快照」⇒ "
                "`host_shield.self_check()` 报「host_shield.py 与 manifest 不符」"
                "⇒ `is_dev_build()` 为 False（登记版本 0.48.4 ≥ 代码 0.48.4）"
                "⇒ `spawn_sentinel()` **硬拦** ⇒ **哨兵拉不起来**"
                "（链上实测 135 条 `host_shield_spawn_failed`，最近 2026-10-13T18:44:27）。"
                "**没有人负责追平**：唯一覆盖 manifest 哈希的 D-27 只查 "
                "`VERSION_BEARING_CHAIN_FILES` 一件（`hooks/pre_tool_use.py`），"
                "而 `host_shield.py`／另 3 个告警链路件／`rules/hosts/*.json` 全无判据 "
                "⇒ 发现它的唯一途径是**用户报障**。**与 X-002 同型**（同一类型的"
                "哈希面：X-002 是快照指向不存在的文件，本条是快照里的字节已过期）",
        "guard": "D-36",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法两步。① 重签 manifest（9 条哈希，含 host_shield.py "
                "5ef15c8c… → 1c97b17f…）⇒ `self_check()` → `(True, [])` ⇒ "
                "`spawn_sentinel()` → `ok=True pid=8460 mode=detached`，"
                "+25s 仍在岗（on_duty=True，心跳新鲜）。② 机制：主闸门新增正面判据 "
                "**D-36**（直接调 `host_shield.self_check()`，不二次实现）＋ 反空转 ＋ "
                "负控（改 host_shield.py 不重签 ⇒ 必红）。"
                "附带修：`_tools_034/_resign_manifest.py` 写回缩进 `indent=2` → `1`"
                "（与构建器 `json.dumps(..., indent=1)` 逐字一致）—— 否则每次重签都把"
                "整份 manifest 重排（实测 148 增 / 148 删），属 T-09「同一事实两套口径」。",
    },
    {
        "id": "X-022",
        "type": "T-03",
        "what": "**X-004 同型复发**（fixture 自身的畸形让判据在每条负控里连带假红）："
                "D-33 那次为给 fixture 带上「已部署的钩子」，只 `mkdir` 出 `.git/hooks/` "
                "⇒ 留下一个「**只含 hooks/ 的 .git**」—— 现实中不可能存在的形态。"
                "而 `_index_build_artifacts()` 用 `(root/'.git').exists()` 当「这是不是 "
                "git 工作树」的代理 ⇒ 代理成立、`git ls-files` 却报 "
                "`fatal: not a git repository` ⇒ **D-24 在 26/26 条负控里都连带变红**"
                "（`--selfcheck` 输出里 △ 那一栏被常量噪声占满 ⇒ 失去分辨力）",
        "guard": "D-28",
        "status": "fixed",
        "date": "2026-10-13",
        "note": "修法（照 X-004 的先例：**修 fixture，不修判据**）：`_build_negctl_fixture` "
                "在放钩子**之前**先 `git init -q` ⇒ fixture 成为**有效工作树**，D-24 由 "
                "FAIL 转 PASS。对照实验（同一 fixture 加/不加 `git init`）实测："
                "**除 D-24 外全部判据判定零变化**，闸门 rc 1 → 0；复跑 `--selfcheck` 后 "
                "**△ 里再没有 D-24**（26/26 → 0），26 条负控仍全 RED(好)。"
                "机制化：**D-28** 扩一条断言 —— fixture 若存在 `.git`，它必须是**有效工作树**"
                "（`git rev-parse --show-toplevel` == fixture 根），否则报红并给出修法；"
                "负控：把 `git init` 那行换掉 ⇒ D-28 必红。",
    },
]

# =====================================================================
# 三、一致性检查（正判据核心）
# =====================================================================

def check_consistency(gate_ids):
    """检查登记簿自身一致性。

    `gate_ids`：闸门注册表里真实存在的判据 ID 集合（如 {"D-25", "D-26", ...}）。

    返回 `(ok, problems)`，problems 为人类可读字符串列表。
    """
    problems = []

    # ---- 1. 类型结构完整 ----
    for tid, t in sorted(TYPES.items()):
        for field in ("name", "definition"):
            if not t.get(field):
                problems.append("%s 缺字段 %s" % (tid, field))
        guards = t.get("guards")
        if not isinstance(guards, list):
            problems.append("%s 的 guards 不是列表" % tid)
            continue
        blind = bool(t.get("blind"))
        if not blind and not guards:
            problems.append("%s 既非 blind 又没有任何守护判据" % tid)
        if blind:
            if guards:
                problems.append("%s 是 blind 类型却配了判据（自相矛盾）" % tid)
            if not t.get("discipline"):
                problems.append("%s 申报盲区却没写 discipline（人工替代动作）" % tid)

    # ---- 2. guarded 类型的判据必须真实存在于闸门注册表 ----
    for tid, t in sorted(TYPES.items()):
        if t.get("blind"):
            continue
        for g in t.get("guards", []):
            if g not in gate_ids:
                problems.append("%s 的守护判据 %s 不在闸门注册表里"
                                "（幻想 ID＝这类病其实没人守）" % (tid, g))

    # ---- 3. 实例结构 ----
    seen_ids = set()
    for ins in INSTANCES:
        iid = ins.get("id")
        if not iid:
            problems.append("有条目缺 id")
            continue
        if iid in seen_ids:
            problems.append("实例编号重复：%s" % iid)
        seen_ids.add(iid)

        tid = ins.get("type")
        if tid not in TYPES:
            problems.append("%s 归到不存在的类型 %s" % (iid, tid))
            continue
        t = TYPES[tid]

        if not ins.get("what"):
            problems.append("%s 缺 what（这条实例到底是什么缺陷）" % iid)
        st = ins.get("status")
        if st not in ("fixed", "open"):
            problems.append("%s 的 status 只能是 fixed/open，实际 %r" % (iid, st))

        g = ins.get("guard")
        if g is not None:
            # ---- 4. 实例不许借判据充数 ----
            if g not in t.get("guards", []):
                problems.append("%s 借了判据 %s，但它不属于类型 %s 的 guards"
                                "（有病无药 or 张冠李戴）" % (iid, g, tid))
            if g not in gate_ids:
                problems.append("%s 的守护判据 %s 不在闸门注册表里" % (iid, g))
        else:
            if not t.get("blind"):
                problems.append("%s 无守护判据，但类型 %s 不是 blind 类型"
                                "（未申报又无判据）" % (iid, tid))

        # ---- 5. open 实例的暴露 ----
        if st == "open" and not t.get("blind") and g is None:
            problems.append("%s 未闭合（open）且无判据守护 —— 有病无药" % iid)

    return (not problems), problems


def _suites_files():
    """交付闸门 `SUITES` 里的判据文件清单（**真会被跑**的那些）。

    ★ 为什么用 `ast` 解析而不是 `import`：`import` 会执行模块级代码
      （且会把 `sys.path` 搅进另一个进程的形态）；`ast.literal_eval` 只读字面量，
      读的仍是**真源**（`ci/delivery_gate.py` 的 `SUITES`），不是另抄一份清单。
    """
    import ast
    p = os.path.join(HERE, "delivery_gate.py")
    if not os.path.isfile(p):
        return []
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            tree = ast.parse(f.read())
    except (OSError, SyntaxError):
        return []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == "SUITES":
                try:
                    return [row[1] for row in ast.literal_eval(node.value)]
                except Exception:                          # noqa: BLE001
                    return []
    return []


#: 判据 ID 的三种真实写法：`@check("W-05 …")` / `("D-25 …", fn)` / `( "D-25…`
_ID_PATS = (
    re.compile(r'@check\(\s*"([A-Za-z]+-?\d+)'),
    re.compile(r'\("((?:D|G)-\d+)\s'),
    re.compile(r'\(\s*"((?:D|G)-\d+)'),
)


def gate_ids_from_registry():
    """从**真会被跑**的守卫文件里提取判据 ID（登记簿"有人守"的判据口径）。

    ★★ 2026-10-13 口径修正（原来只读 `ci/regression_gate.py`）：
      原口径下"有人守"**只认主闸门**。可本仓的守卫**分布在 30 套判据里**
      （0490 的 `W-03`、0372 的 `S19`…），而它们**每次交付闸门都会真跑**。
      只认主闸门会逼出两种坏结果：
        ① 一个**真被守住**的类型被判成"没人守"（例如 T-08：A1 由 S19 守着，
           而 S19 不在主闸门里 ⇒ 登记簿会报"有病无药"）；
        ② 为了让表格好看，在主闸门里**再写一份同样的判据** ——
           而"同一事实两套实现"正是本仓 **T-09 本身**（自相矛盾）。
      ⇒ 口径：**真会被跑的文件** ＝ 主闸门 ＋ 交付闸门 `SUITES` 里的每一套。
        "真会被跑"由 `delivery_gate.SUITES` 定义（**不另写一份清单**）。
      ★ 这不放松纪律①（不许幻想 ID）：提取的仍是**磁盘上真实存在**的判据声明，
        只是把"存在"的范围从"主闸门"扩到"真会跑的全部守卫"。
    """
    ids = set()
    p = os.path.join(HERE, "regression_gate.py")
    if os.path.isfile(p):
        with open(p, encoding="utf-8", errors="replace") as f:
            src = f.read()
        for pat in _ID_PATS:
            ids |= set(pat.findall(src))
    for rel in _suites_files():
        fp = os.path.join(PKG, rel)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                s = f.read()
        except OSError:
            continue
        for pat in _ID_PATS:
            ids |= set(pat.findall(s))
    return ids


def coverage(gate_ids=None):
    """返回 (真已守, 声明未兑现, 申报盲区, open 实例列表, 无实例的类型列表)。

    ★★ 2026-10-12 F40 补丁（交接件 §4.6）——**同一份报告两个口径的病**：
      原实现用 `not blind` 计「已守」，那是**声明口径**（结构上配了判据的
      类型数）；而逐行「失守!」用**注册表口径**（判据真在闸门注册表里）。
      表头把「声明了但判据不存在」的 4 类算成已守，与逐行自相矛盾 ——
      F40（口径混装）在登记簿自己身上的复现。
      现在三个数全部按**注册表口径**计，且 真已守＋声明未兑现＋申报盲区
      **恒等于类型总数**（三个数可以用手加出来，可对账）。
    """
    if gate_ids is None:
        gate_ids = gate_ids_from_registry()
    guarded, unfulfilled, blind, opens, no_instance = [], [], [], [], []
    for t, v in TYPES.items():
        if v.get("blind"):
            blind.append(t)
            continue
        gs = v.get("guards") or []
        if not gs:
            # 非 blind 却没配判据 —— check_consistency 会把它判红（有病无药）
            unfulfilled.append(t)
            continue
        missing = [g for g in gs if g not in gate_ids]
        (unfulfilled if missing else guarded).append(t)
    opens = [i for i in INSTANCES if i.get("status") == "open"]
    no_instance = [t for t in TYPES
                   if not any(i.get("type") == t for i in INSTANCES)]
    return guarded, unfulfilled, blind, opens, no_instance


def report(gate_ids=None):
    """人类可读报告（--report）。"""
    if gate_ids is None:
        gate_ids = gate_ids_from_registry()
    guarded, unfulfilled, blind, opens, no_instance = coverage(gate_ids)
    L = []
    L.append("缺陷类型登记簿 —— 覆盖现状")
    L.append("=" * 60)
    # ★ F40 补丁：表头三个数 ＝ 注册表口径，相加 ＝ 类型总数（可对账）
    L.append("类型 %d 类：已守 %d ／ 声明未兑现 %d ／ 申报盲区 %d"
             "（三者相加 ＝ %d）" % (len(TYPES), len(guarded), len(unfulfilled),
                                len(blind), len(TYPES)))
    L.append("实例 %d 条：已闭合 %d ／ 未闭合 %d"
             % (len(INSTANCES), len(INSTANCES) - len(opens), len(opens)))
    L.append("")
    L.append("%-7s %-14s %-8s %s" % ("ID", "名称", "状态", "守护判据"))
    L.append("-" * 60)
    for tid in sorted(TYPES):
        t = TYPES[tid]
        if t.get("blind"):
            st = "盲区"
            gd = "（人工纪律）"
        else:
            missing = [g for g in t.get("guards", []) if g not in gate_ids]
            st = "已守" if not missing else "失守!"
            gd = "、".join(t.get("guards", []))
            if missing:
                gd += " ← 不在注册表: %s" % "、".join(missing)
        L.append("%-7s %-14s %-8s %s" % (tid, t.get("name", "?"), st, gd))
    if no_instance:
        L.append("")
        L.append("▲ 没有实例的类型（还没遇到过，或遇到过没登记）：%s"
                 % "、".join("%s %s" % (t, TYPES[t]["name"]) for t in no_instance))
    if opens:
        L.append("")
        L.append("▲ 未闭合实例（这类错没有被机械守护，或修法未落地）：")
        for i in opens:
            L.append("   %s [%s %s] %s"
                     % (i["id"], i["type"], TYPES[i["type"]]["name"], i["what"]))
            if TYPES[i["type"]].get("discipline"):
                L.append("        人工纪律：%s" % TYPES[i["type"]]["discipline"])
    ok, problems = check_consistency(gate_ids)
    L.append("")
    L.append("-" * 60)
    if ok:
        L.append("★ 登记簿自身一致：每个类型都有人守或已申报盲区")
    else:
        L.append("★ 登记簿有 %d 处不一致：" % len(problems))
        for p in problems:
            L.append("   · %s" % p)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="缺陷类型登记簿")
    ap.add_argument("--report", action="store_true", help="人读报告")
    ap.add_argument("--check", action="store_true", help="只跑一致性自检")
    ap.add_argument("--gate-ids", action="store_true",
                    help="打印从闸门注册表提取的判据 ID")
    ap.add_argument("--json", action="store_true", help="机器可读")
    a = ap.parse_args()

    ids = gate_ids_from_registry()
    if a.gate_ids:
        print(" ".join(sorted(ids)))
        return 0
    if a.json:
        ok, problems = check_consistency(ids)
        # ★ F40 补丁（同源修改）：--json 与 --report 表头**同一口径**
        #   （注册表口径）。原实现的 "guarded" 用 `not blind` 声明口径计，
        #   与人读报告打架 —— 机器读的口径和人读的口径继续各说各话。
        guarded, unfulfilled, blind, opens, no_instance = coverage(ids)
        print(json.dumps({
            "types": len(TYPES),
            "guarded": len(guarded),
            "declared_unfulfilled": len(unfulfilled),
            "blind": len(blind),
            "instances": len(INSTANCES),
            "open": len(opens),
            "gate_ids": sorted(ids),
            "ok": ok,
            "problems": problems,
        }, ensure_ascii=False, indent=1))
        return 0 if ok else 1
    if a.check:
        ok, problems = check_consistency(ids)
        print("判据 ID（闸门注册表提取）：%s" % ("、".join(sorted(ids)) or "空"))
        if ok:
            print("★ 一致：每个类型都有人守或已申报盲区")
            return 0
        print("★ %d 处不一致：" % len(problems))
        for p in problems:
            print("   · %s" % p)
        return 1
    # 默认：报告
    print(report(ids))
    ok, _ = check_consistency(ids)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""★★ 统一交付闸门 —— 0.36.5：把「所有判据」收进**一个入口、三处强制点**。

★★★ 这份文件存在的理由（创始人 2026-10-07 提问，一字不改地记在这里）：

    「自检器目前是独立脚本，还没接任何强制执行点。
      纪律有了，执行点没接上 —— 这是收敛机制的最后一块缺口。」

  这句话**只点出了缺口的一半**。实测把全仓判据清点一遍，真实形状是：

    ┌─────────────────────┬──────────┬────────────────────────────┐
    │ 判据集│ 条数 │ 改造前的调用方           │
    ├─────────────────────┼──────────┼────────────────────────────┤
    │ inbox_guards_0360   │ 52       │ **无**│
    │ inbox_guards_0362│ 31       │ **无**                      │
    │ inbox_guards_0363   │ 13       │ **无**                      │
    │ inbox_guards_0364   │ 17       │ **无**                      │
    │ _p_delivery_selfcheck│ 7       │ 只有它自己的负控引用        │
    │ regression_gate     │ 13       │ pre-commit ＋ CI（已接）    │
    │ version_check       │  6│ CI（已接）                 │
    └─────────────────────┴──────────┴────────────────────────────┘

  ⇒ **113 条Antinel 监理判据 + 7 条自检，一条都没接执行点。**
    而这不是"忘了接线"这么轻：`0363` 有一条红、`0364` 有一条红，
    **已经红了一段时间却没人知道** —— 因为没人跑。
    ⇒ 这就是本仓铁律「**无检查项的禁令＝没禁令**」的镜像：
      **有检查项但没人跑 ＝ 同样等于没有。**
      两个方向都是"看起来有防护，实际没有"。

★ 三条设计纪律（照抄 regression_gate 的成熟做法，不重新发明）：
  ① **判据不许二次实现** —— 本文件**不重写任何判据逻辑**，
     只负责「按固定顺序调起 + 汇总退出码 + 区分红与崩」。
     任何一条判据的增删改都在它自己的文件里做。
  ② **必须能区分「没跑到」与「跑到了」** —— 判据脚本**不存在**时报
     💥 SKIP 并**计为红**。理由：缺失的判据和通过的判据在退出码上
     若都返回 0，那「删掉一个判据文件」就成了让闸门变绿的手段。
     （这与 regression_gate 判据 ③「测不出的情况报 SKIP，绝不报 PASS」同源。）
  ③ **负控必须能红** —— `--selfcheck` 模式：把一条判据的**定义**
     临时改坏，断言本闸门**必须**变红。不红的闸门是装饰。

用法：
    python ci/delivery_gate.py                # 跑全套
    python ci/delivery_gate.py --quick        # 跳过慢的那套（< 10 秒档）
    python ci/delivery_gate.py --only 0364    # 只跑某一套（排查用）
    python ci/delivery_gate.py --json         # 机器可读（CI 用）
    python ci/delivery_gate.py --selfcheck    # 负控：判据被改坏时本闸门必须红
"""
from __future__ import annotations

import argparse
import ast
import atexit
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(_HERE)
RESULTS = []

#: ★★ 2026-10-13：把仓根放进 `sys.path`。
#:   为什么必须有（这不是洁癖，是实测出来的根因）：本文件以
#:   `python ci/delivery_gate.py` 启动时 `sys.path[0]` 是 **`ci/`** 而不是仓根
#:   ⇒ `import audit_chain`（判活要用）抛 `ModuleNotFoundError`
#:   ⇒ 判活**静默**恒为"死" ⇒ 活锁被判成陈旧锁 ⇒ **可被偷**。
#:   30 套判据早就各自 `sys.path.insert(0, ROOT)`（本仓惯例），只有闸门自己漏了。
#:   ★ 用 append 不用 insert(0)：仓根里若哪天出现与标准库同名的模块，
#:     append 保证标准库仍然优先（insert(0) 会让产品文件**顶掉**标准库）。
if PKG not in sys.path:
    sys.path.append(PKG)


# ────────────────────────────────────────────── 判据清单（唯一真源）
#: `(键, 相对路径, 分档)`。分档：
#:   fast = 进程内、轻（默认与 --quick 都跑）
#:   slow = 会起子进程、改文件，或依赖仓外原件（--quick 跳过；打包前必跑）
#:
#: ★★ 2026-10-13 修正一处**分档注释在说谎**（T-06 同型，实测）：
#:   原文写「fast = 进程内、**秒级**」—— 而 fast 档里 0470 实测 **245s**、
#:   JDG 207s、0360 154s。它们"不起子进程"是真的，"秒级"是假的。
#:   ⇒ 分档是**结构口径**（起不起子进程、依不依赖仓外原件），**不是耗时口径**；
#:     耗时另有一本账 `.psl/gate/suite_durations.json`，每次真跑合并写入，
#:     快道（`--hook`）按它做预算。两件事分开记，
#:     才不会再出现"名字在说一个数、实测是另一个数"。
#:
#: ★ 清单必须与磁盘**实际存在的文件**对齐，且两者不一致时判红 ——
#:   否则「删掉一个判据文件」就能让闸门变绿。
#:
#: ★★ 0353 归 slow 档的理由（实测，不是猜）：它 `import inbox_guards` 脚手架、
#:   且 `PSL_ROOT` 指向仓外 `D:\2026\PSL` 的规格原件 —— 缺件时它**退出码仍是 0
#:   但零输出**。若归 fast 档，一次"全绿但什么都没跑"会被读成通过。
#:   ⇒ 归 slow 档 + 下面 `_looks_like_noop()` 显式识别"零输出即假绿"。
SUITES = [
    ("0353", "ci/inbox_guards_0353.py", "slow"),
    ("0360", "ci/inbox_guards_0360.py", "fast"),
    ("0362", "ci/inbox_guards_0362.py", "fast"),
    ("0363", "ci/inbox_guards_0363.py", "fast"),
    ("0364", "ci/inbox_guards_0364.py", "fast"),
    ("0366", "ci/inbox_guards_0366.py", "fast"),
    # ★ 0.37.3：S 族（六态封闭 ＋ 已敲定词表不漂移）。
    #   为什么进 SUITES 而不是只登记：它守的是创始人反复强调的那句
    #   「一定要机制上解决」—— 六态与已敲定的词表**必须**在每次交付前被机械复核，
    #   靠人记得就等于没有。它是 fast 档：全部负控走**内存变异**，不写任何产品文件
    #   （因此可以安全地留在打包前的闸门里，不需要单列 negctl 档）。
    ("0372", "ci/inbox_guards_0372.py", "fast"),
    # ★ 0.38.0：粮（哨兵口粮）的三条铁律 ＋ 账本边界。
    #   为什么进 SUITES：把"现阶段不卖／不可转让／不可兑换／两本账不混"从
    #   `granary.py` 的**注释**变成"每次交付前必跑、会报红、有负控"的**机制**
    #   （负控全走内存变异，不写任何产品文件 ⇒ 可安全留在打包前的闸门里）。
    ("granary", "ci/guard_granary.py", "fast"),
    # ★ 0.39.0：**灯＝此刻**（不许拿 24h 历史账冒充"当前状态"）。
    #   为什么进 SUITES：创始人 2026-10-09 二次裁定「一定要让值守台反应当前的
    #   准确状态，没有失守却显示失守，就是错误的……要从机制上修正，防范再犯」——
    #   把这条从"注释里的约定"变成"每次交付前必跑、会报红、有负控"的机制。
    #   ★ 它与 0372 是**同一族**（都是"机制上解决"的产物），但方向相反：
    #     0372 守"六态不许长第七个"，0380 守"灯不许答非此刻"。两条都要在。
    #   fast 档：负控全走内存变异，不写任何产品文件。
    ("0380", "ci/inbox_guards_0380.py", "fast"),
    # ★ 0.40.0：**四行失守的根因修复**（A1–A5 ＋ B2）＋ **B1 撤回的防复发**。
    #   为什么进 SUITES：创始人 2026-10-09「要把所有相关机制都建立和用上，
    #   这个最重要，确保解决的是根因，修得彻底，绝不会再复发」——
    #   这一套把"A/B 两组改动"从**代码里的事实**变成"每次交付前必跑、会报红、
    #   有负控"的**机制**。缺了它，同型的"修了又复发"会从后门长回来。
    #   ★ 它是 0380 的同型后续：0380 守"灯不许答非此刻"，0400 守
    #     "四行失守的**每一个污染源**都被堵死且不许放宽"（源①账本串味、
    #     源②静默撤防、源③研发态被当篡改）。
    #   fast 档：全部负控走**内存/临时目录**变异，不写任何产品文件。
    ("0400", "ci/inbox_guards_0400.py", "fast"),
    # ★ 0.42.0：**hook_slow 从「记了却没人看」到「报告里看得见」**（P5-1）。
    #   为什么进 SUITES：`AUDIT_SCHEMA.md` §4 登记了它、写入侧写得忠实
    #   （89 条、最差 ≈41 分钟），而**消费侧是零** —— 唯一可能看见它的那一行
    #   `elif action == "alert"` 不分 type，89 条真实信号被一个匿名计数吸收。
    #   这与 0.29.0 D-1（sec_path_whitelisted）、0.18.0 HP-47（hook_error）
    #   是同一条纪律的第三次落地：**"记了"不等于"看得见"**。
    #   fast 档：全部负控走内存变异（exec 变异后的 report.py 源码），不写产品文件。
    ("0420", "ci/inbox_guards_0420.py", "fast"),
    # ★ 0.43.0：**自愈事件不得再顶 R0**（A3 收口）＋ **去星号不许只治一半**。
    #   为什么进 SUITES：2026-10-10 复核"还有没有虚报"时实测抓到 ——
    #   链上 17 条 `recovered=true` 的记录仍 `severity=critical`（定档按类型一刀切），
    #   页面于是长出自相矛盾标题「失守：…（已自动恢复）」；而分桶又把它们判进 info
    #   ⇒ 同一条记录档位说失守、分桶说不用管（两处口径各判一半）。
    #   同时 `**不等于**` 在**命令行**仍原样露出（0.42.0 只治了网页两条路）。
    #   fast 档：全部负控走内存变异（exec 变异后的 inbox_model / inbox_cli 源码）。
    ("0430", "ci/inbox_guards_0430.py", "fast"),
    # ★ 0.43.1：**右下冒泡根治**（十维）＋ **研发态可达性/其根因**（两维）。
    #   为什么进 SUITES：创始人 2026-10-10 两次交办 ——
    #   ①「右下冒泡的旧病复发了……需要彻查清楚，参考今天的多维机制，彻底解决」
    #     ⇒ 三条互不相干的发射路径（钩子内联 PS / Antinel 监理 / 哨兵）收口为**单一漏斗**
    #       ＋ **单一决策源** ＋ **可见性闸**；同一条自愈记录不再在"值守中"时弹窗。
    #   ②「目前状态是失守，这是不对的……是不是机制上有欠缺，给补上」
    #     ⇒ 根因在 `ci/version_check.py`（把**构建产物** manifest 当成手工承载件
    #       ⇒ 升版刷平它 ⇒ `is_dev_build()` 版本落差永远为 0 ⇒ 研发态结构性失效）；
    #       S67 钉"触发器只认版本落差"、S69 钉"构建产物不许冒充手工承载件"。
    #   fast 档：全部负控走**内存变异**（exec 变异后的源码），不写任何产品文件。
    ("0431", "ci/inbox_guards_0431.py", "fast"),
    # ★ 0.44.0：**第一处根治：命令结构化** —— 误拦的根因不是"缺目标判据"，
    #   而是"一句 shell 变量赋值把整条命令的只读资格连带否掉了"（方案 v2.0 §2.2 对照实验）。
    #   为什么进 SUITES：两处改动都在**判定热路径**上（拦与放的结果会变），必须常驻守：
    #   S70-440 赋值+只读不再误拦（5 正例）、N-S70-440 摘掉中性段处理 ⇒ 正例必红、
    #   N-S70b 去掉引号感知 ⇒ 值带空格的正例必红（分辨力样本）、
    #   S71 七类真删除 + 硬纪律（赋值成 dist 再删）仍拦、S72 结构锚在位。
    #   ★ 2026-10-14 P0-2：S70/N-S70 已改名 S70-440/N-S70-440（与 0431 的 S70 重名，
    #     set 口径折叠 ⇒ 解名；先声明保留裸 ID、后声明加 -<批次>）。
    #   fast 档：全部负控走**内存变异**（exec 变异后的源码 / 换模块正则），不写产品文件。
    ("0440", "ci/inbox_guards_0440.py", "fast"),
    # ★ 0.45.0：**第二处根治：状态写入**（甲单一入口收编 ＋ 乙接线既有锁 ＋ 丙名片租约）。
    #   为什么进 SUITES：这一批动的全是**并发下的判定结果**（谁赢、判不判在岗、读不读得到），
    #   一旦回归就是"静默丢状态 / 凭空多拉哨兵"，肉眼看不见，必须常驻守：
    #   S73 整份写回=0、S74 忽略返回值=0、S75 真进程互斥恰一个赢家、S76 没保住必须出声、
    #   S77 进程号复用⇒判不在岗、S78 并发读读不到半截；
    #   N-S73/N-S74/N-S75/N-S77/N-S78/N-S78b 逐条负控（N-S78b 实测：裸替换被并发读打断）。
    #   fast 档：变异只在内存；并发用**真进程**（纪律 10.7）。
    ("0450", "ci/inbox_guards_0450.py", "fast"),
    # ★ 0.46.0：**第三处根治：删除许可（VCT）** —— 从「看名字像不像产物」
    #   换成「用户声明 ＋ 可再生事实」，兜底名单降级为最后退路。
    #   为什么进 SUITES：这一批动的全是**拦与放的结果**（判定热路径），
    #   且引入了仓外查询（版本工具）与安全语义取舍，一旦回归就是
    #   「最日常的清理动作又被误拦」或「该拦的删除被一个许可顺带放行」。
    #   S80 两票并且、S81 常见写法归一、S82 两票先于名单、S83 工作树外走出口丙、
    #   S84 中文路径只看返回码、S85 退出口不许静默、S86 一个许可只开一扇门、
    #   S87 第二票隔离；N-S80/81/82/83/84/86/87 逐条负控；S88 连带对照。
    #   fast 档：变异只在内存；夹具只落临时目录。
    ("0460", "ci/inbox_guards_0460.py", "fast"),
    # ★ 0.47.0：**步 5 —— 告警预算 ＋ 篡改分通道 ＋ 界面必带分母**（方案 v3.0 §5）。
    #   为什么进 SUITES：三件事各自都是"静默失真"型回归 ——
    #   ① 预算：一旦回归就是「合并变成静默丢弃」（原始条数被吃掉，用户永远
    #      看不到自己被提醒过几次）⇒ S92 守三项守恒 ＋ N-S92 守"不记账直接返回"；
    #   ② 分通道：一旦回归就是「我自己在改代码」与「有人动了我的防护文件」
    #      重新挤在同一盏浅黄灯下（0.46.0 实测三条不同性质同灯）⇒ S93 守不共灯、
    #      N-S93 打在"共用的那个 L1 桶"上（★ 首跑踩过：只摘 dev 分支会掉回 L0，
    #      两条仍不同灯 ⇒ 负控没有分辨力）、N-S93b 守 dev 灯分支本身在承重；
    #   ③ 分母：一旦回归就是界面重新冒出无窗口无分母的裸数字（F40 同族）
    #      ⇒ S95 守四处位点、N-S95 守 `count_text` 退回裸分子。
    #   另：S94 守「失守」标题只归 tamper（方向反了就是把"我在改代码"说成"防线失守"）、
    #   S96 守保护自报（维五：限额类机制必须答得出「今天生效了几次」）。
    #   fast 档：变异只在内存；账本与链只落临时目录，不写任何产品文件。
    ("0470", "ci/inbox_guards_0470.py", "fast"),
    # ★ 0.48.1：许可分层六条（策略 v1.1 落地）。为什么进 SUITES：
    #   G7-3 已付过一次学费（附加段把 GitHub 识别压到「Other」），且「修了源头
    #   没修已发布实例」复发过一次；MIT 自足性在核验报告 v1.0 §1 实测断裂。
    #   fast 档：全部走文件比对与内存变异，不写任何产品文件、不依赖网络。
    ("0481", "ci/inbox_guards_0481.py", "fast"),
    # ★ 0.48.2：**三条 P0 的防复发** —— 用户旅程模拟（ci/j2_pypi_e2e.py）逼出来的
    #   呈现/可达性修复：① 顶层 -h/--help 无出口（用户第一直觉命令报错）；
    #   ② README/SKILL/NOTICE 里 14 条随包脚本命令写成相对项目根形，装完**全部不可达**；
    #   ③ A6 收入边界声明对 wheel 用户不可达却未在指针里说清。
    #   铁律：**页面上不许教跑不通的命令**。fast 档：结构比对 + 内存变异 + 少量真跑入口。
    ("0482", "ci/inbox_guards_0482.py", "fast"),
    # ★ 0.48.3：**随包清单口径 ＋ 命名空间件分发**的防复发 —— 装后模拟
    #   （ci/j2_pypi_e2e.py）实测：README 第 16/17/18 行「别信我们，自己验」
    #   三条命令在**纯净 wheel 安装**下全部不成立（一条报 1/21 missing、一条报
    #   15/124 missing、一条 No such file）。根因：签名清单不随任何分发包，
    #   却是随包 judgment 的 digest、随包 manifest 的成员、随包工具的必需输入；
    #   外加随包 manifest 主体取自暂存包、wheel 却从仓根构建 ⇒ 双向错配。
    #   ★ 注：**清单 vs 实测 wheel 的集合对账**放在 scripts/verify_release.py 的
    #     [E] 步（那一步能读到真 wheel；闸门跑在出包**之前**，读不到）。
    ("0483", "ci/inbox_guards_0483.py", "fast"),
    # ★ 0.48.5：**Antinel 监理细节修订 19 条**（交接件 v1.1 §5，2026-10-12）。
    #   为什么进 SUITES：19 条全是「页面承诺了它维持不住的东西」同族 ——
    #   甲组会说谎的数字（窗口冻结/分母撒谎）、丙组异质单位并排、乙组六种说法、
    #   丁组噪音、戊组视觉倒挂。判据落点单一文件、按批次生长（U-01…U-15），
    #   每批一个 commit；红不了的（视觉排布）走截图验收，不许假装有判据。
    #   批次 1（U-01 甲2/U-03 甲4＋丙2/U-08 丙1）先行，负控 N-U01/N-U03a/b/N-U08
    #   逐条实测见红；U-97 连带对照守 0.47.0 分母纪律与术语表定义处不松。
    #   fast 档：变异只在内存；夹具只落临时目录，不写任何产品文件。
    ("0490", "ci/inbox_guards_0490.py", "fast"),
    # ★ 0.49.0：**窗口/图标/冒泡/漂浮四件事的防复发**（2026-10-14 夜，截图实证）。
    #   为什么进 SUITES：四件全是「静默失真」型回归，且都已在本机复发过一次 ——
    #   ① W-08 默认宽度 520 低于 CSS 窄屏断点 620 ⇒ 面板一出生就窄布局
    #      （顶行折行压字；用户手动拉宽才正常 —— 要靠用户手动补救的默认值就是错的）；
    #   ② W-09 术语浮层被窗口裁掉 ⇒ 平移优先/贴边撑开/还原不抢方向盘/露不全如实；
    #   ③ U-17 0.48.5 戊1 把动效图标换成静态图 ⇒ "好了但是死了"（规格 v1.2 逐项锁
    #      ＋ Node 真跑状态机 25 秒量几何量，node 缺失报 SKIP 不假绿）；
    #   ④ B-02…B-08 冒泡（界面同源/不闪退/声音/节流 ack/可见性闸/起不来如实/
    #      一次一枚）与 FLO-01…FLO-05 漂浮哨标（ps1 契约同规格/退役先于起/
    #      顺序即安全/展开即退役）。路由换代本身由 inbox_guards 的 B-01 守。
    #   fast 档：负控全走内存变异/临时目录；唯一外部依赖是 node，缺则 SKIP。
    ("0514", "ci/inbox_guards_0514.py", "fast"),
    # ★ 0.50.4（P0-3/P0-2）：antinel.cmd 一键入口 ＋ 判据 ID 唯一化。
    #   为什么进 SUITES：`antinel.cmd` 是本机一键入口，**从未跑通过** —
    #   裸 LF（CRLF=0）＋ UTF-8 中文注释在 CP936 控制台下被 cmd 当命令执行
    #   （实测两个叠加根因；只修 CRLF 不够，修法＝CRLF＋全 ASCII）。
    #   P0-2：判据 ID 跨套件重名曾达 25 组，`gate_ids_from_registry()` 的
    #   `set()` 把同名折叠成一个 ⇒「有人守」会被另一套件冒充（假绿）；
    #   本套件守新口径（`gate_id_map`/`duplicate_gate_ids`）与解名后的真树。
    #   fast 档：变异全在内存/临时目录；唯一外部依赖是 cmd.exe（Windows）。
    ("0515", "ci/inbox_guards_0515.py", "fast"),
    # ★ 0.50.4（P1-2）：打包缺件四件套 —— 五个未跟踪新件（inbox_bubble/
    #   inbox_logo/assets/sounds/alert.wav/tools/logo.ps1/tools/mk_sound.py）
    #   从未进过任何清单，且工作区变体构建曾走「暂存包内容」fallback 口径
    #   （final 不存在 ⇒ 清单 128 项双向错配：14 件只进 sdist／15 件真进
    #   wheel 未覆盖 ⇒ 同步它 [E] 更红）。本套件守：四处登记在位 ＋
    #   真实 wheel/sdist 含焦点五件 ＋ 产品 [E] 集合对账（129==131−2）＋
    #   两个负控（声明移除一条/清单少一条均实测判红）＋ 运行时资源路径
    #   可解析。fast 档：夹具全在临时目录；唯一外部依赖是
    #   setuptools>=68 的解释器（缺则 SKIP，不假绿）。
    ("0516", "ci/inbox_guards_0516.py", "fast"),
    # ★ 2026-10-14：**窗口寿命** —— 「起得来、活不久」（inbox window 报已就位、
    #   窗口秒死）的四件套判据。为什么进 SUITES：病根是「谁来起窗口」——
    #   CLI 直起时 msedge 挂 CLI 进程树下，调用方退出连带杀窗；daemon
    #   （长命 supervise）起的窗跨边界存活（同机四路实证）⇒ cmd_window
    #   必须先委托 daemon。全注入式判据，不起真浏览器。
    ("0517", "ci/inbox_guards_0517.py", "fast"),
    # ★ 0.50.7：「五条违和」的**同类可抓**（L2 品质触发层 v1.2 升级后的机制层，
    #   2026-10-16 创始人截图标出五条违和 ＋ 「相关机制层能做到升级后抓住这五条
    #   类似的问题吗，如果能，升级」）—— J1 同一图形两处入口／J2 枚举断行 /
    #   J3 同屏括号 / J4 异质量并排无单位。
    #   ★★ 2026-10-16 按 A2/P5 并入 0514（**不再单列**）：五条判据与 0514 同域
    #      （消费面同为 inbox_server.py 渲染产物）⇒ P5「扩展优先」自答不满足
    #      ⇒ 正确动作是并入，不是立新套件。J1–J5 已随 0514 跑（判据 ID 一字未改，
    #      登记簿 T-11 与 inbox_server.py 注释仍按 ID 引用）；原文件改名让开，
    #      出处在 `ci/suite_retirement.json`（status=done）。
    # ★ 0.42.0：**dist 卫生** —— 「旧版发布件让开」从手工动作变成构建器自己的机制。
    #   为什么进 SUITES：2026-10-09 实测**第三次同族复发** —— 0.40.0/0.41.0 两轮
    #   "把旧版件 mv 去 _archive_dist" 都是我手工做的，0.42.0 忘了 ⇒ dist 里躺着
    #   0.41.0 两件 ⇒ D-23/JDG-06 同时判红 ⇒ 白跑一轮 4 分钟闸门。
    #   根因不是粗心，是这个动作**没有机制保证它发生**（"靠人记得就等于没有"）。
    #   本套件守预防侧：S38 行为（旧版挪走/本版留/更新版硬失败/垃圾不碰/零删除）、
    #   S39 顺序（挪旧件必须在跑闸门**之前**）。检测侧 D-23/JDG-06 保留为兜底。
    ("dist-hygiene", "ci/guard_dist_hygiene.py", "fast"),
    # ★ 0.42.0：**发布入口不许退化成"建了没人用"**。
    #   为什么进 SUITES：本班新建了 `scripts/verify_release.py`（发布验收），
    #   写完**零调用方** —— 一个没有调用方的脚本等于不存在，这正是"修了又复发"
    #   的标准形状（与 M11 双 dist-info 坏 wheel 同族：机制建了，没挂上）。
    #   ⇒ `scripts/release.py` 把「装配验证 → 出 wheel/sdist → 发布验收」串成
    #     一条命令；本套件守这条链本身：S40 三步必须都在、S41 版本号只从源码读、
    #     S42 出包解释器必须验 setuptools>=68（本机 C:\Python311 是 65.5.0 会被拒）。
    ("release-entry", "ci/guard_release_entry.py", "fast"),
    # ★ 0.42.0：**自证卡的刷新点必须在 harness 之后**。
    #   为什么进 SUITES：本班一道**结构性死锁** —— 装配时那份判定记录描述的是
    #   **上一次的字节**（本次刚改过受覆盖文件）⇒ 自证卡必然写成 false ⇒
    #   `_merge(pkg, final)` 把它覆盖回源码仓（final 就是仓本身），而
    #   `_reconcile_src` 只看守 run_harness.py ⇒ 无人发现 ⇒ 闸门红 ⇒ 构建被拦
    #   ⇒ harness 不跑 ⇒ 记录不刷新 ⇒ 死锁。0.41.0 那轮是**手工**破的局。
    #   ⇒ S43 顺序（harness < 刷新 < reconcile）、S44 失败不许刷成 true。
    ("selfcert-timing", "ci/guard_selfcert_timing.py", "fast"),
    # ★ 0.42.0 meta 判据：**量具先量自己**。
    #   为什么进 SUITES：本班我写判据时**五次**踩同一个坑，每次当场都觉得
    #   "那么写很自然" —— 把结构化事实序列化成字符串再用子串匹配：
    #     ① "68" in ast.dump(g) 命中 docstring ⇒ 阈值改坏仍绿（负控失效）
    #     ② "sys.executable" in dump —— 它在 AST 里是 Attribute 不是常量
    #     ③ "return False" in dump —— AST 里是 Return(Constant(False))
    #     ④ ast.walk 遍历顺序当源码顺序 ⇒ 顺序判据假绿
    #     ⑤ 正向判据改了、负控里同一句忘了改 ⇒ 两侧不同步
    #   自然的错要靠机械检查抓，不靠自觉。⇒ S45 禁 dump 子串匹配、
    #   S46 禁"无唯一性约束的取第一个"。
    ("instrument-selfaudit", "ci/guard_instrument_selfaudit.py", "fast"),
    ("JDG", "ci/jdg_guards_0368.py", "fast"),
    # ★ 0.37.0：PCM（问题数单调收敛闸门）。为什么进 SUITES 而不是只登记：
    #   它回答的是整条收敛管道**唯一还没回答的问题**——「问题总量有没有在变小、
    #   变小是真变小还是账面变小」（JDG/0366 回答的是「这次多了什么、红是真是假」）。
    #   它是 fast 档：只读 judgment.json 与 .psl/gate/pcm_ledger.json 两份 JSON，
    #   不起子进程、不写产品文件（负控全在内存态，不需要 negctl 单列档）。
    ("PCM", "ci/pcm_gate_0370.py", "fast"),
    ("selfcheck", "ci/_p_delivery_selfcheck.py", "fast"),
    ("version", "ci/version_check.py", "fast"),
    ("regression", "ci/regression_gate.py", "slow"),
]

#: ★★ 第四档 `negctl`：**会临时改坏产品文件再还原**的负控脚本。
#:
#: 为什么单列一档、且**默认不跑**（实测踩过，不是假想）：
#:   负控的机制是"把一条判据改坏 → 断言它变红 → 还原"。
#:   ⇒ 它运行期间，**产品代码处于损坏状态**。
#:   若把它放进打包前的闸门：打包进程中途被杀 / 断电 / 超时，
#:   变异的代码就会**随包发出去**。
#:   ⇒ 「强制执行点」与「会污染产物」这两件事**不能共处一个调用时机**。
#:
#: 那怎么保证它不被删掉、不被"优化"掉？
#:   —— 登记进 `REQUIRED`（存在性检查照旧），
#:     **但不打进 `SUITES`** ⇒ 闸门只查它在不在，不跑它。
#:   ⇒ 删它 ⇒ 结构检查判红；跑它 ⇒ 显式 `python ci/delivery_gate.py --negctl`。
#:   这就是「有检查项但没人跑＝等于没有」的**另一半解法**：
#:     不是硬塞进所有路径，而是**让它该跑的时候跑、该查的时候查**。
REQUIRED_EXTRA = [
    "_p_bubble_negctl.py",
    "_p_selfcheck_negctl.py",
    "_p_guards_mutation.py",
    "_p_contract_negctl.py",
    "ci/version_check_negctl.py",
    # ★ 0.36.8：harness（判定账本的生成器）登记为**必须存在**但不进 SUITES。
    #   为什么不进 SUITES：`_run` 单套超时 900s，而 harness 实测约 22–25 分钟，
    #   塞进去只会以「CRASH 超时」假失败收场（那是量具失真，不是发现）。
    #   为什么必须登记：负控衰减最致命的地方（公开判定账本）恰好是
    #   收敛机制唯一没伸到的一寸 ⇒ 它不许被静默删掉。
    #   ⇒ 存在性守这里；真跑由打包序列显式执行（`python -m scripts.run_harness`）。
    "scripts/run_harness.py",
    # ★ 0.36.9：两条**判据引用的探针**补登记（0.36.8 实测抓到的契约空洞）。
    #   `ci/inbox_guards_0360.py` 引用 `_p_badge_probe.py`、旧版
    #   `ci/inbox_guards.py` 引用 `_p_p11_negctl_mutation.py`，两个都
    #   从未入库 ⇒ 本机全绿、新克隆必红（判据契约在新机器上不成立）。
    #   为什么必须登记在这里：`.gitignore` 的 `_p_*` 会把未入库探针从
    #   `git status` 藏起来 ⇒ 缺口从「可见」变「隐藏」，比不忽略更危险。
    #   真正堵死它的是 JDG-04（契约自包含：判据引用的本地文件必须已入库）。
    "_p_badge_probe.py",
    "_p_p11_negctl_mutation.py",
]

#: 必须存在的判据文件。少任何一个 ⇒ 报红（不许静默少跑）。
REQUIRED = [rel for _k, rel, _d in SUITES] + REQUIRED_EXTRA


# ═══════════════════════════ 机制层 ①：基线快照 ＋ 差分归因 ═══════════════════════
#
#: ★★★ 为什么这是**错误收敛速度**的关键（0.36.6 实测推导，不是设计构想）：
#:
#:   看本轮真实发生过的链条：
#:     ① 我改 `inbox_window.py`（补页面名白名单）
#:     ② 跑闸门 ⇒ **P15 报红**
#:     ③ 我花了一轮才分清「这是判据的错，不是产品的错」
#:
#:   而第③步之所以贵，是因为**闸门只会说「现在有红」，不会说「相对上次多/少了什么」**。
#:   ⇒ 于是每次红都必须重新做一次「归因」—— 而归因是本仓最贵的一步
#:     （要查是哪次改动引入的、判据测的是谁、红项指向的代码有没有犯过这个错）。
#:
#: ★ 收敛的正确形态不是「永不出错」（那不可能），是：
#:     **出错 → 立刻知道「多了什么」→ 立刻知道该改判据还是改产品。**
#:   快照就是把「多/少了什么」变成**机器算出来的**，不再靠人重跑一遍去回忆。
#
#: ★ 落盘口径（三条，都不是可选项）：
#:   · 写在 `.psl/` 下（项目状态目录），**不写进包、不进 manifest**
#:     ⇒ 快照不是产品的一部分，是**对产品的观察**。
#:   · **带闸门脚本自己的指纹**：改了 SUITES 或判据清单，快照自动失效
#:     ⇒ 避免「判据换了却拿旧快照比」的假差分。
#:   · **保留上一次**（`.prev`）⇒ 连续红两次时能看出「这次是同一红还是新红」。

#: ★★ 0.57.0（第 26 条）：闸门**自身状态**的落点，允许重定向。
#:   为什么需要（实测撞出来的，不是预防性设计）：判据 D-41 必须**真跑一次闸门**
#:   才能证明它不会把"0 套"报成绿，而提交钩子此刻正持有
#:   `PKG/.psl/gate/run.lock` ⇒ 判据的子进程抢不到锁 ⇒ rc=3
#:   （`★ 闸门未启动：…`）⇒ 判据在钩子里**必然红** ⇒ 提交被自己拦下。
#:   另外子进程还会覆盖真仓的 `last_run.json`，把"这次到底谁跑的"读乱。
#:   ⇒ 给这类**只读排查**一个独立状态目录：锁不冲突、基线不串、读数不脏。
#:   生产路径**不变**：不设这个变量就是 `PKG/.psl/gate`。
_SNAP_DIR = (os.environ.get("ANTINEL_GATE_STATE_DIR")
             or os.path.join(PKG, ".psl", "gate"))
_SNAP = os.path.join(_SNAP_DIR, "baseline.json")
_SNAP_PREV = os.path.join(_SNAP_DIR, "baseline.prev.json")

#: 运行锁 ＋ 最近一次结果文件（2026-10-13 新增，见 `_acquire_lock` 的由来）。
_LOCK = os.path.join(_SNAP_DIR, "run.lock")
_LAST_RUN = os.path.join(_SNAP_DIR, "last_run.json")

#: 每套判据的**历史耗时账**（2026-10-13 新增）。由每次真跑合并写入；
#: 快道（`--hook`）用它做预算 —— 让"这次能跑多少"由**实测数据**决定，
#: 而不是由我拍一个阈值。
#: ★ 局限（明写，不假装覆盖）：它是一份会**陈旧**的快照 —— 某套突然变慢时
#:   预算会估小。所以它只影响**快道挑哪些**，不影响全量闸门（全量永远全跑）；
#:   且快道跳过的每一条都会**逐条列出来**（T-10 的反面）。
_DUR = os.path.join(_SNAP_DIR, "suite_durations.json")

#: 提交钩子的**套件**预算（秒，**不含主闸门** —— 主闸门永远跑）。
#: 为什么是"预算"而不是"单条阈值"：受影响的套件可能同时含 0470（245s）
#: 与 0380（4.7s），只卡单条阈值挡不住"很多条 10 秒的"叠起来。
#: 目标墙钟 ≈ 主闸门快档（实测 ~15s）＋ 本预算 ＝ ~27s。
_HOOK_BUDGET = 12.0


# ══════════════════════════════════════════════════════════════════════
# 机制层①（A1）：建机制前置门 —— P1–P5 逐条作答块
# ══════════════════════════════════════════════════════════════════════
#: 2026-10-15 落地，依据 `docs/Antinel·机制层可行性与净收益分析 v1.1（2026-10-15）.md`
#: §8 行动清单第 1 条（该文档唯一强烈建议立即做的一条）：
#:   「把 P1–P5 立成建机制前置门 —— 这本身是一条 L0 机制，从此每个新机制
#:     提案必须带五判据作答，缺一项不进入设计。」
#:
#: 形态选择（为什么落在闸门自身而不是新套件）：
#:   新套件会消耗 A2 的 29 常驻预算（机制层②），且前置门守的是
#:   「登记动作」本身 —— 与 `_orphaned_guard_files`（漏登记）、
#:   `_missing_required`（删判据）同族，都是结构性检查，属闸门自身职责。
#:
#: 规则：**新登记**进 SUITES 的套件，文件头必须含 P1–P5 逐条作答块；
#:   缺块 ⇒ 登记红（结构检查不过 ⇒ 闸门不过）。**现有套件不追溯**。
#:
#: 作答块的机械判据（不读语义，只读形状 —— 语义归 A4 的 L2 人判）：
#:   文件头（前 60 行）内，`P1:`…`P5:` 五行俱全且每行有非空答案。
#:   为什么要"逐条"：机制论文档 §3 的五判据是**与**关系（五条全满足
#:   才允许建机制），缺一条的作答块等于没有作答。
_P1P5_HEADER_LINES = 60
# ★ 双向同步：此正则在 hooks/pre_tool_use.py 有**自包含副本**（_GOV_P1P5，
#   GOV-01 写入时刻拦截）——钩子在安装态运行、ci/ 不保证在旁，故复制。
#   改这里必须同步那里，反之亦然。
_P1P5_LINE = re.compile(r"^\s*P([1-5])\s*[:：]\s*\S")

#: 现有套件不追溯清单 ＝ A1 落地时点（2026-10-15）SUITES 已登记的全部键。
#: ★ 为什么硬编码快照而不是"今天之前注册的都算"：git 时间戳在本仓不可靠
#:   （85 个未推送提交、研发态版本漂移），而"哪些算现有"必须是**可复核的
#:   确定集合**。新键一律受检，直到永远。
_P1P5_GRANDFATHERED = frozenset({
    "0353", "0360", "0362", "0363", "0364", "0366", "0372", "granary",
    "0380", "0400", "0420", "0430", "0431", "0440", "0450", "0460",
    "0470", "0481", "0482", "0483", "0490", "0514", "0515", "0516",
    "0517", "dist-hygiene", "release-entry", "selfcert-timing",
    "instrument-selfaudit", "JDG", "PCM", "selfcheck", "version",
    "regression",
})


def _p1p5_block_ok(text):
    """套件文件头是否含 P1–P5 逐条作答块（机械判据：形状，不读语义）。"""
    seen = set()
    for ln in text.splitlines()[:_P1P5_HEADER_LINES]:
        m = _P1P5_LINE.match(ln)
        if m:
            seen.add(m.group(1))
    return seen >= {"1", "2", "3", "4", "5"}


def suites_missing_p1p5(suites=None, grandfathered=None):
    """缺 P1–P5 作答块的**新**套件清单（现有套件不追溯）。

    纯函数（suites/grandfathered 可注入）⇒ 负控能拿合成清单跑同一把尺子。
    """
    suites = SUITES if suites is None else suites
    grandfathered = _P1P5_GRANDFATHERED if grandfathered is None else grandfathered
    bad = []
    for key, rel, _tier in suites:
        if key in grandfathered:
            continue
        fp = os.path.join(PKG, rel)
        try:
            with io.open(fp, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            bad.append((key, rel, "文件读不到"))
            continue
        if not _p1p5_block_ok(text):
            bad.append((key, rel, "文件头缺 P1–P5 逐条作答块"))
    return bad


# ══════════════════════════════════════════════════════════════════════
# 机制层②（A2）：常驻套件上限 29 ＋ 退休登记簿
# ══════════════════════════════════════════════════════════════════════
#: 2026-10-15 落地，依据机制论文档 §6-1 与 §8 行动清单第 2 条：
#:   「常驻套件上限 ＝ 现有数（29）：新增一套件须先退休或合并一个，
#:     否则 gate 自红。这把 §4.4 的共享成本变成提出者付得起的价。」
#:
#: 口径（F40：分母必须显式）：**29 ＝ SUITES 里 `ci/inbox_guards_*` 与
#:   `ci/guard_*` 两类文件的登记数**（与机制论文档 §1 的计数方法同一把尺子：
#:   磁盘 29 件全部登记、零孤儿，本轮实测复核）。JDG/PCM/selfcheck/
#:   version/regression 五条是基础设施项，不计入 29。
#:
#: 退休/合并记录（`ci/suite_retirement.json`）是唯一合法超限途径：
#:   · 每条须带 套件/日期/原因/替代者 四字段，status=pending 时计额度；
#:   · pending 额度 30 天过期（防"登了记永不退休"把上限软化成没有）；
#:   · 超额且额度不足 ⇒ struct_bad ⇒ 闸门红。
RESIDENT_SUITE_CAP = 29
# ★ 双向同步：29 这个数在 hooks/pre_tool_use.py 有自包含副本（_GOV_CAP，
#   GOV-01 写入时刻拦截）——改这里必须同步那里，反之亦然。
_RETIREMENT_LEDGER = os.path.join(_HERE, "suite_retirement.json")
_RETIREMENT_GRACE_DAYS = 30


def resident_suite_count(suites=None):
    """常驻套件数（29 口径：SUITES 里 inbox_guards_* 与 guard_*）。"""
    suites = SUITES if suites is None else suites
    return sum(1 for _k, rel, _t in suites
               if rel.startswith("ci/inbox_guards_")
               or rel.startswith("ci/guard_"))


def _load_retirement_ledger():
    """读退休登记簿；读不到/坏 ⇒ 空簿（不是"都退休了"）。"""
    try:
        with io.open(_RETIREMENT_LEDGER, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                                   # noqa: BLE001
        return {}


def cap_violation(suites=None, ledger=None, today=None):
    """常驻套件上限检查。返回 `(hard_red, notes)`。

    hard_red=True ⇒ 结构检查不过（闸门红）；notes 供人读。
    纯函数（三个参数可注入）⇒ 负控能合成超限清单跑同一把尺子。
    """
    import datetime
    suites = SUITES if suites is None else suites
    ledger = _load_retirement_ledger() if ledger is None else ledger
    today = today or datetime.date.today()
    n = resident_suite_count(suites)
    if n <= RESIDENT_SUITE_CAP:
        return False, []
    excess = n - RESIDENT_SUITE_CAP
    pending = []
    for rec in ledger.get("retirements", []):
        if rec.get("status") != "pending":
            continue
        try:
            d = datetime.date.fromisoformat(str(rec.get("date", "")))
        except ValueError:
            continue
        if (today - d).days > _RETIREMENT_GRACE_DAYS:
            continue                       # 过期额度不计（防软化成没有）
        if not rec.get("replacement"):
            continue                       # 无替代者不计（合并须说清并到哪）
        pending.append(rec)
    if len(pending) >= excess:
        return False, [
            "常驻套件 %d > 上限 %d，但已有 %d 条 pending 退休/合并记录"
            "（额度 %d ≥ 超限 %d）—— 退休记录是超限的唯一合法途径"
            % (n, RESIDENT_SUITE_CAP, len(pending), len(pending), excess)]
    return True, [
        "常驻套件 %d > 上限 %d，pending 退休/合并记录 %d < 超限 %d"
        "（须先退休或合并一个；记录写入 ci/suite_retirement.json）"
        % (n, RESIDENT_SUITE_CAP, len(pending), excess)]


def _load_durations():
    """读历史耗时账。读不到 ⇒ 空表（**不是**"都很慢"，由 `_apply_budget` 兜）。"""
    try:
        with open(_DUR, encoding="utf-8") as f:
            d = json.load(f)
        return {k: float(v) for k, v in d.items() if isinstance(v, (int, float))}
    except Exception:                                   # noqa: BLE001
        return {}


def _merge_durations(prev, results):
    """把本次**真跑到**的耗时并进账；没跑的保持旧值（不许清零、不许删键）。"""
    out = dict(prev)
    for r in results:
        m = re.search(r"\[([\d.]+)s\]", r.get("detail") or "")
        if m:
            out[r["suite"]] = float(m.group(1))
    return out


def _apply_budget(pick, must=("regression",)):
    """快道预算：按**历史耗时升序**尽量多装，装不下的**逐条列出来**。

    ★ 为什么按升序：同样预算下"跑得多"比"跑得贵"更能挡回归
      （一条 245s 的端到端套件换成 5 条秒级套件，挡住的缺陷面通常更宽）。
    ★ `must`（必跑，**不参与预算**）：默认含主闸门 —— 它是"已修缺陷的总账"，
      快道存在的理由就是它。调用方还会在"闸门自身文件被改"时把 `selfcheck`
      加进来：那种情况下闸门自检恰恰是**最该跑**的那套，
      让预算把它挤掉就是"闸门自己改了却没人复验闸门"。
    ★ 没有历史耗时 ⇒ **按"跑"处理**（宁可超预算，不许因为"不知道它多慢"就跳）。
    ★★ 跳过的必须**逐条打印含历史秒数**：快道不许"悄悄少跑"，
      只许"明说自己少跑了什么"。这条由 D-34 守着。
    """
    hist = _load_durations()
    took = [s for s in pick if s[0] in must]
    rest = [s for s in pick if s[0] not in must]
    rest.sort(key=lambda s: hist.get(s[0], -1.0))
    over, spent = [], 0.0
    for s in rest:
        d = hist.get(s[0])
        if d is None:
            took.append(s)
            print("      · 无历史耗时 ⇒ 按跑处理：%s" % s[0])
            continue
        if spent + d > _HOOK_BUDGET:
            over.append((s[0], d))
            continue
        spent += d
        took.append(s)
    print("  ◇ 快道预算 %.0fs（**只算非必跑套件**）：本次跑 %d 套"
          "（套件历史耗时合计 %.1fs）；必跑：%s"
          % (_HOOK_BUDGET, len(took), spent, "、".join(sorted(must))))
    _reg = hist.get("regression")
    print("      ⏱ 预计墙钟 ≈ 主闸门快档 %s ＋ 套件 %.1fs ＝ %.0fs（历史口径）"
          % (("%.0fs" % _reg) if _reg else "（无历史）", spent,
             (spent + (_reg or 0.0))))
    if over:
        print("      ⏭ **预算外**（快道没跑，留给打包前/CI 的全量闸门）—— 逐条列明：")
        for k, d in sorted(over, key=lambda x: -x[1]):
            print("          %-20s 历史 %7.1fs" % (k, d))
    return took


def _pid_alive(pid):
    """那个进程号还在不在。**三态**：`True` 在 ／ `False` 确实不在 ／ `None` 查不了。

    ★ 判活口径 import 产品模块（维七：不许二次实现）。

    ★★ 为什么必须是三态（2026-10-13 实测修，本轮抓到的最严重一处）：
      本函数第一版写成 `except Exception: return False` —— 把「**查不了**」
      折叠成了「**不在**」。而它恰恰会查不了：`import audit_chain` 在
      `python ci/delivery_gate.py` 下因 `sys.path` 没有仓根而**必然失败**。
      后果不是"报个错"，而是：**活锁被判成陈旧锁 ⇒ 让开 ⇒ 被偷**。
      产品模块 `audit_chain.pid_alive` 自己的纪律写着「查询失败/异常按存活
      （宁可 sidecar，不可误偷活锁 —— Run B 教训）」—— 我这一版**正好反着做**。
      ⇒ 查不了 ⇒ `None` ⇒ 调用方**按占用处理**（宁可拒绝并发，绝不偷活锁）。
    """
    try:
        import audit_chain as _AC
    except Exception:                                   # noqa: BLE001
        return None                                     # 查不了 ≠ 不在
    try:
        return bool(_AC.pid_alive(int(pid)))
    except Exception:                                   # noqa: BLE001
        return None                                     # 查不了 ≠ 不在


def _read_lock_pid():
    """读锁文件里的 pid。**空串 ≠ 没有锁**（这是第二个坑，见 `_acquire_lock`）。

    ★ `os.open(O_EXCL)` 与 `os.write(pid)` 之间有一个微秒级窗口，
      此刻锁文件**存在但为空**。若把空串当成"没锁"，就会去让开一把**活锁**。
      ⇒ 短暂重读几次；仍为空 ⇒ 返回空串，由调用方按**占用中（pid 未知）**处理。
    """
    for _ in range(6):
        try:
            with open(_LOCK, encoding="utf-8") as f:
                s = f.read().strip()
        except OSError:
            return ""
        if s:
            return s
        time.sleep(0.05)
    return ""


def _acquire_lock():
    """拿闸门运行锁。返回 `(fd, None)`；拿不到 ⇒ `(None, 说明串)`。

    ★★ 为什么必须有它（2026-10-13 实测，血的教训）：
      两个闸门进程同时跑 ⇒ **两个都写 `baseline.json`、都写同一个日志文件**。
      日志被交错写入，读出来是一行 "0481 RED" ⇒ 我追了 **20 分钟幽灵红**，
      最后靠基线快照才证明那次其实是 30/30 全绿。
      这与本仓铁律同型：**同一语义只能有一个写入口** —— 闸门的**输出**也是。
    ★ 陈旧锁必须能自动让开（崩一次不能把闸门永久锁死）：
      pid 不在了 ⇒ 把锁**改名让开**（本仓纪律：不删文件）后重试一次。
    ★★ 判活是**三态**的，且"拿不准"一律按**占用**处理：
      · `old == ""`（写 pid 的空窗）  ⇒ 占用中（pid 未知）
      · `_pid_alive(old) is None`（查不了）⇒ 占用中
      · 只有**明确查实"这个 pid 不在了"**才允许让开。
      —— 反面（把查不了当不在）在 2026-10-13 真发生过，后果是**活锁可被偷**
         （详见 `_pid_alive`）。判据 D-32 锁的就是这条。
    """
    os.makedirs(_SNAP_DIR, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("ascii"))
            return fd, None
        except FileExistsError:
            old = _read_lock_pid()
            alive = _pid_alive(old) if old else None
            if alive is not False:                      # None＝查不了 ⇒ 按占用
                who = ("（pid %s）" % old) if old else \
                      "（占用方进程号还没写进去或查不到）"
                return None, ("另有一次闸门正在跑%s —— **不许并发**：两个进程会互写"
                              "基线快照与日志（2026-10-13 实测踩到，追了 20 分钟"
                              "幽灵红）。等它跑完再来。" % who)
            try:                                        # 陈旧锁：改名让开，不删
                os.replace(_LOCK, _LOCK + ".stale")
            except OSError as e:                        # noqa: BLE001
                return None, ("锁被判为陈旧（pid %s 已不在），但让开失败：%r"
                              " —— 锁文件可能仍被占用。确认后手工删掉 %s 再跑"
                              % (old, e, _LOCK))
        except OSError as e:                            # noqa: BLE001
            return None, "拿不到运行锁：%r" % (e,)
    return None, "锁文件反复拿不到（陈旧锁让开后仍被占）"


def _release_lock(fd):
    """放锁（**改名让开**，不删文件）。"""
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.replace(_LOCK, _LOCK + ".done")
    except OSError:
        pass


def _gate_fingerprint():
    """闸门自身的指纹：判据清单 ＋ 被跑文件的 mtime/size ＋ **闸门文件自己**。

    ★★ 必须含 mtime：改了 `inbox_guards_0360.py` 里的判据，
      判据数量可能不变（还是 52 条）但**内容变了** ⇒ 只比数量会漏。

    ★★★ 0.36.6 实测抓到本函数**第二版**的缺陷（第一版是漏了闸门自己）：
      改用**内容哈希**而不是 `mtime:size` ——
      因为 **`0366` 的负控会在闸门运行时写注释再还原**，
      **还原后 mtime 变了而内容没变** ⇒ 用 mtime 会让指纹**每次跑都变**
      ⇒ 差分永远用不上（实测连跑三次都是「指纹不同，已失效」）。
      ⇒ 与本仓那条「**行为对 ≠ 说法对**」同族：文件被读/被写时间戳变了，
        但它**算不算"变过"** 取决于内容，不取决于 mtime。
      ★ 代价：哈希要读全部内容（9 个文件几十 KB），
        **但闸门本来就要把它们全跑一遍** —— 这点开销可以忽略。
    """
    parts = ["|".join(sorted(rel for _k, rel, _d in SUITES))]
    for rel in sorted([r for _k, r, _d in SUITES] + ["ci/delivery_gate.py"]):
        p = os.path.join(PKG, rel)
        try:
            with open(p, "rb") as f:
                parts.append("%s:%s" % (
                    rel, hashlib.sha256(f.read()).hexdigest()[:16]))
        except OSError:
            parts.append("%s:MISSING" % rel)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _red_fingerprint(text):
    """把一段红项文本压成稳定指纹（去掉耗时/秒数这类每次都变的数字）。"""
    t = re.sub(r"\[\d+(?:\.\d+)?s\]", "[Xs]", text or "")
    t = re.sub(r"\d+(?:\.\d+)?\s*(?:ms|s\b|秒|分钟)", "N单位", t)
    return hashlib.sha256(t.strip().encode("utf-8")).hexdigest()[:16]


def _load_snapshot():
    try:
        with open(_SNAP, encoding="utf-8") as f:
            return json.load(f)
    except Exception:                                          # noqa: BLE001
        return None


def _save_snapshot(results, fp):
    """写快照。**先把旧的挪成 .prev**（零删除，与全仓纪律一致）。"""
    try:
        os.makedirs(_SNAP_DIR, exist_ok=True)
        if os.path.isfile(_SNAP):
            os.replace(_SNAP, _SNAP_PREV)
        snap = {
            "fingerprint": fp,
            "ts": time.time(),
            "suites": {r["suite"]: {"status": r["status"],
                                   "red_fp": _red_fingerprint(r.get("red", ""))}
                       for r in results},
        }
        with open(_SNAP, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
    except Exception:                                          # noqa: BLE001
        pass


def _diff_against_baseline(results, fp):
    """对照上一次快照，输出**新增红**与**已修复**。

    ★ 返回 `(新增红列表, 已修复列表, 说明)`；快照不可用时说明原因，
      **不许静默跳过** —— 「对照不上」与「没有新增」必须能区分。
    """
    old = _load_snapshot()
    if not old:
        return [], [], "无上次快照（首次运行）—— 本次建立基线"
    if old.get("fingerprint") != fp:
        return [], [], ("上次快照的闸门指纹与现在不同（判据清单或判据文件变过）"
                        "—— 快照已失效，本次重新建立基线")
    olds = old.get("suites") or {}
    new_red, fixed = [], []
    for r in results:
        o = olds.get(r["suite"])
        if o is None:
            if r["status"] != "PASS":
                new_red.append((r["suite"], r["status"] + "｜新增判据集"))
            continue
        was_red = o.get("status") != "PASS"
        now_red = r["status"] != "PASS"
        # ★★★ 0.36.6 补一个**污染源**：崩了/缺失**不是红**。
        #   若把它们也算进「新增红」，那么一次"判据文件被误删/判据自身崩了"
        #   就会以"我改出了新红"的形态出现在收敛线索里 ⇒ **污染账本**，
        #   而收敛线索一旦被污染，人就会开始怀疑整套机制、进而不再看它
        #   （与「零输出被当通过」同族：那都是**账面失真**）。
        #   ⇒ 崩/缺失**单独成一类**，红项仍照常打印、仍阻断，只是不许进「新增红」。
        st = r["status"]
        if st in ("CRASH", "MISSING", "NOOP"):
            if not was_red:
                new_red.append((r["suite"], st + "｜**这不是红，是判据没跑成**"
                                           "（账上单列，不与真缺陷混算）"))
            continue
        if now_red and not was_red:
            # ★ 不用 `%` 格式化：红项文本里**可能含百分号**（实测踩到：
            #   判据回报里有 "99%"，被当成格式符 ⇒ 整个闸门崩在收尾段）。
            #   崩在这里的后果特别坏：**红项已经打出来了，却因为收尾崩而丢掉结论**，
            #   退出码非零却看不到「新增红是哪几条」。
            #   ⇒ 一律用字符串拼接（`+`），不存在格式串解析。
            head = (r.get("red") or "").strip().splitlines()
            head = head[0][:110] if head and head[0].strip() else st
            new_red.append((r["suite"], st + "｜" + head))
        elif was_red and not now_red:
            fixed.append(r["suite"])
    return new_red, fixed, "已对照 %d 个判据集的上一状态" % len(olds)



# ═══════════════ 机制层 ②：影响面自动点名（改了什么 → 必须复验什么）═══════════════
#
#: ★★★ 这条机制的由来是本轮真实踩到的一句话（0.36.6）：
#:
#:     「规则变更必须同时验证它没弄坏别的题。」—— 0.36.4 v1.1 修好 C02 却让 C08 回归
#:
#:   而它的**危险形态**不是「忘了跑全套」，是「跑���全套，但不知道该看哪几条的红」：
#:     8 套一起跑、几十秒、输出一屏 ⇒ 你看到一堆 ✅ 和几个 ❌，
#:     但**分不出这个 ❌ 是我这次改出来的，还是上一轮就在那儿的老账**。
#:   ⇒ 于是每次改动后都要**把全套红项逐条读一遍去找哪个是自己弄的**——
#:     这是纯人力活，且必然漏。
#:
#: ★ 机制化的做法：把「我改了哪些产品文件」变成**输入**，
#:   用**静态依赖图**算出「哪些判据直接读这些文件」，
#:   输出成**必须复验的名单**。没有名单 ⇒ 那是"跑了但不知道该看哪条"。
#
#: ★ 为什么用静态 import 图而不是运行时追踪：
#:   运行时追踪更准，但要在判据里插桩 —— 判据本身就被污染了
#:   （与本仓「判据不许二次实现」同源：观察不该改变被观察的东西）。
#:   静态图会漏「动态 getattr / importlib.import_module」，⇒ 明写局限，不假装覆盖。

_STDLIB_HINT = {
    "os", "sys", "re", "json", "io", "time", "ast", "subprocess", "hashlib",
    "textwrap", "platform", "tempfile", "shutil", "glob", "argparse", "types",
    "copy", "datetime", "collections", "itertools", "functools", "unittest",
    "traceback", "random", "string", "math", "zipfile", "base64", "threading",
    "ctypes", "wintypes", "abc", "enum", "contextlib", "signal", "socket",
    "urllib", "http", "html", "xml", "csv", "sqlite3", "ssl", "pickle",
    "struct", "uuid", "stat", "codecs", "locale", "unicodedata", "calendar",
    "decimal", "fractions", "numbers", "statistics", "inspect", "tokenize",
    "pathlib", "importlib", "unittest.mock",
}


def _suite_deps(rel):
    """静态算出这套判据**直接 import** 的本仓模块集合。"""
    try:
        with io.open(os.path.join(PKG, rel), encoding="utf-8") as f:
            txt = f.read()
    except OSError:
        return set()
    mods = set(re.findall(r"^\s*(?:import|from)\s+(\w+)", txt, re.M))
    local = {m for m in mods if m not in _STDLIB_HINT}
    # `inbox_guards_xxxx` 是判据自身互引，不算产品依赖
    return {m for m in local if not m.startswith("inbox_guards")
            and m not in ("delivery_gate",)}


_DEP_CACHE = {}

#: 闸门**自身**的文件。改它们必须复验 `selfcheck`（闸门自检套件）——
#: 见 `impacted_suites` 里那段"0 套"的实测。主闸门由调用方强制加入。
_GATE_SELF_FILES = {
    "ci/delivery_gate.py",
    "ci/regression_gate.py",
    "ci/defect_types.py",
    "ci/git-hooks/pre-commit",
    "ci/_p_delivery_selfcheck.py",
}


def impacted_suites(changed_files):
    """改动文件 → 必须复验的判据集。返回 `(集合, 说明行列表)`。

    ★ 口径：**只看直接 import**，宁可多点名（多跑一遍不亏），
      绝不漏点名（漏了＝那条判据等于没跑，与本仓铁律同型）。
    """
    if not _DEP_CACHE:
        for key, rel, _d in SUITES:
            _DEP_CACHE[key] = _suite_deps(rel)
    stems = {os.path.splitext(os.path.basename(p))[0] for p in changed_files}
    hit = {k for k, deps in _DEP_CACHE.items() if deps & stems}
    # ★★ 0.48.5：**闸门自身的文件**不在任何套件的 import 图里。
    #   实测：改 `ci/delivery_gate.py` ⇒ `impacted_suites` 返回 **0 套**
    #   ⇒ 快道会认为"这次改动不需要复验任何东西"。
    #   而"闸门自己改了却没人复验闸门"是最不该有的盲区 ——
    #   快道存在的理由就是替提交把关，它**自己不验自己**等于把把关权交给自己。
    #   ⇒ 改这些文件必须复验 `selfcheck`（闸门自检套件）；主闸门由调用方强制加入。
    if {os.path.normpath(p).replace("\\", "/") for p in changed_files} & _GATE_SELF_FILES:
        hit.add("selfcheck")
    note = []
    for k in sorted(hit):
        note.append("%s ← 直接 import %s" % (
            k, "、".join(sorted(_DEP_CACHE[k] & stems)) or "（闸门自身文件）"))
    if not hit:
        note.append("（没点名到任何判据 ⇒ 改动文件不在任何判据的 import 图里，"
                    "**这不是「不需要复验」，而是判据没覆盖它**）")
    return hit, note


# ═══════════════ 机制层 ③：判据自身的可信度分级（红项是真是假）══════════════════
#
#: ★ 为什么需要它：0.36.5–0.36.6 连续两次遇到「红项指向的代码没有犯过这个错」。
#:   一次是 `_matches_title`（已被删的死函数），一次是 P15（判据自己的正则锚点）。
#:   ⇒ 「红」不是结论，**「红是判据的错还是产品的错」才是结论**，
#:     而这一步过去每次都要人来分。
#
#: ★ 机械化做法：**判据崩了（CRASH）与判据红了（RED）分开计数**（本闸门已做），
#:   再加一条：**红项里若指名的代码在本次改动中没被改过，就提示"可能与本次改动无关"**。
#:   —— 不是判它无罪（红仍然是红，仍然阻断），
#:     只是把"这条红可能是老账"这一事实**摆到眼前**，避免在它上面浪费时间。

_TOUCH_EXCLUDE = re.compile(
    r"(^|/)(\.git|__pycache__|\.psl|dist|build|.*\.egg-info|\.pytest_cache|"
    r"\.mypy_cache|\.idea|node_modules)(/|$)|\.pyc$|^\.")


def red_names_touched_modules(red_text, touched_stems):
    """红项文案里提到了哪些**本次改动过的模块**。

    ★ 独立成函数而不是在 main() 内联 —— 有两个理由：
      ① 它是**机制的一部分**（可被单独判据验），内联就只能靠"跑一次闸门看输出"来测；
      ② 本仓纪律「判据不许二次实现」：守卫里若再写一份正则，
         两份正则必然漂移 ⇒ 守卫测的是一个**不存在的**机制。
    """
    return {n for n in re.findall(r"\b([a-z_][a-z0-9_]{2,})\b", red_text or "")
            if n in (touched_stems or set())}


# ═══════════════ 机制层 ④：注释承诺 vs 实现 —— **试过两版，都无效，已撤**════════════
#
#: ★★★ 这里**故意留一个空机制位**，把失败的尝试和它的死因写在原地。
#:   理由：本仓铁律「有检查项但没人跑 ＝ 等于没有」的姊妹条更狠 ——
#:     **「有检查项但它抓不到目标 ＝ 比没有更坏」**，
#:     因为它会让人以为这一层已被覆盖，从而**不再去人工看**。
#:
#: 目标：自动抓「注释承诺了 X、代码没做 X」（本轮两处真缺口的同型）：
#:   · _mark_at_tail() 注释写「页面前缀必须是已知页面名之一」，那层代码**从没写过**
#:     ⇒ 功能表面正常、**没有任何判据会红**（缺陷不在行为里，在注释与实现的落差里）
#:   · _matches_title 注释写「不是 in 子串」，实现正是 suffix in actual
#:
#: 实测结论（两版启发式，数据留着，别再重做）：
#:   第一版「找含强制词（必须/不得/一律）的注释行」
#:     ⇒ 报 11 处，逐条看过**几乎全误报**：那些注释是**解释**不是**承诺**
#:       （「标记必须在末尾」后面就紧跟着真代码）。误报约 9/11。
#:   第二版「找否定式（不是/不再/不许）＋反引号内容真出现在代码里」
#:     ⇒ 报 12 处，**更差**：注释里解释某个常量名/函数名本就是正常写法，
#:       而那个名字当然出现在代码里。误报接近 100%。
#:   ★ 两版都**抓不到**本轮那处真缺口 —— 因为修好它时，那行注释**已被删掉**。
#:
#: ★★★ 死因（这才是可复用的部分）：
#:   这类缺陷的本体是**「缺失」**。缺失的东西不会留下痕迹给机器看，
#:   而留下的（注释）**恰好是最不像证据的东西** ——
#:   注释不需要能运行，所以**永远不会自己失败**。
#:   ⇒ 任何「扫现存注释找缺口」的路子，都在扫一个**没有失败标记的系统**。
#:   ⇒ 真正有效的只有两条：
#:     (a) 把承诺**改写成实现** —— 让两者不可能不一致；
#:         本轮正是如此：那层白名单直接写成代码，并配 P15 的实测用例。
#:     (b) 让人**看见** —— 但本轮那两处都不是靠扫描发现的，
#:         是靠**真去测一个具体场景**（「用户窗口标题里恰好含 · Antinel 监理#xxx」）撞出来的。
#:   ⇒ 结论（当纪律用）：**不要试图机器检查「承诺与实现一致」，
#:     要把承诺变成实现。判据能检查的是「行为对不对」，不是「注释真不真」。**
#:   ⇒ 落地纪律：「发现功能缺口时，先问『有没有一条注释在承诺它』；
#:     有 ⇒ 把它变成判据/代码，而不是把它变成注释。」
#:     （本轮已兑现两次：④ 层白名单 ＋ P15 新增 4 类误伤用例。）
#
#: ★★ 因此本机制**没有代码**是**故意的**：留着这段失败记录，
#:   免得下一轮又有人（包括我自己）顺手加个扫描器，
#:   然后得到一堆误报还以为自己加了防护。

def _changed_files():
    """本次**被改动的所有文件**（任意类型；git 可用时以 git 为准）。

    ★★ 为什么必须与 `_touch_files()` 拆成两层（2026-10-13 实测，血的教训）：
      `_touch_files()` 只认**产品源码**（`.py` ＋ 闸门自身文件）。而 `--hook`
      用「**探不到改动 ⇒ 回退全量**」做兜底 —— 于是**纯文档改动**（改
      `docs/*.md`）会被判成"探不到改动" ⇒ 回退全量 30 套（实测 **22 min**）
      ⇒ 前台 `git commit` 跑钩子**超时被 SIGTERM**，提交不了 ⇒ 人只好
      `git commit --no-verify`。而「**会被绕过的钩子等于没有钩子**」正是
      快道（0.48.5）存在的全部理由 —— 这个回退分支把它又拆了。

      ⇒ 口径拆两层：
        · **探测层**（本函数）认**一切**改动 —— 只用来回答"要不要回退全量"；
        · **影响面层**（`_touch_files`）只认产品源码 —— 用来回答"跑哪几套"。
      纯文档改动 ⇒ 探测层非空、影响面层为空 ⇒ **影响面 0 套，只跑主闸门快档**，
      绝不回退全量。判据 D-35 锁这条（`_select_suites` 是纯函数，它直接调）。
    """
    try:
        r = subprocess.run(["git", "status", "--porcelain"],
                           capture_output=True, text=True, cwd=PKG, timeout=30)
        if r.returncode == 0:
            got = set()
            for line in (r.stdout or "").splitlines():
                if len(line) < 4:
                    continue
                p = line[3:].strip()
                if " -> " in p:                     # 重命名：取新名
                    p = p.split(" -> ", 1)[1]
                got.add(os.path.normpath(p.strip('"')))
            return got
    except Exception:                                          # noqa: BLE001
        pass
    import time as _t
    now = _t.time()
    out = set()
    for fn in os.listdir(PKG):
        p = os.path.join(PKG, fn)
        if os.path.isfile(p) and fn.endswith(".py"):
            try:
                if now - os.path.getmtime(p) < 1800:
                    out.add(os.path.normpath(fn))
            except OSError:
                pass
    return out


def _touch_files():
    """本次改动碰过的**产品**文件（git 可用时取 diff，否则退回 mtime 近 30 分钟）。

    ★ 用 git 而不是 mtime 的理由：mtime 会把「跑闸门时读一遍文件」
      之外的无关文件也算进来（Python 写 .pyc 也改 mtime）⇒ 误报一堆。

    ★★ 必须过滤构建产物（0.36.6 实测踩到）：
      本仓大量文件从未提交过（`git status` 有 107 个 `??`），
      `git diff HEAD` 于是报出 58 个「改动」，其中混着
      `*.egg-info`、`__pycache__`、`dist/`、`build/` —— 它们是**构建产物**，
      不是「我改了产品」。
      ⇒ 不过滤的话，影响面名单会长到 58 条、点名 7 套判据，
        **和"全跑一遍"没区别 ⇒ 名单失去筛选意义（而这是它存在的全部理由）。**
      ⇒ 口径：**只认产品源码**（顶层 .py / ci/ / tools/ / scripts/ 里的 .py）。

    ★★ 0.48.5（2026-10-13）改用 `git status --porcelain`，两个理由：
      ① `git diff --name-only HEAD` **看不见新文件**（untracked）。
         而"新加一个判据文件"恰恰是最需要复验的情形之一 ——
         看不见它 ⇒ 快道会认为"没改动" ⇒ 要么空跑要么回退全量。
         （`.gitignore` 里的 `_p_*`、`dist/` 等不会出现在 porcelain 里，
          所以顺带少了那 107 个 `??` 里的噪声。）
      ② git 可用时**以 git 为准**（返回空集也算准）：原实现在
         "git 可用但工作区干净"时会掉进 mtime 启发式 ⇒ 把
         "刚提交过的文件"当成"本次改动" ⇒ 影响面凭空变大。

    ★★ 与 `_changed_files()` 的分工（2026-10-13）：
      探测层认**一切**改动（回答"要不要回退全量"），本函数只认**产品源码**
      （回答"跑哪几套"）。纯文档改动 ⇒ `_changed_files()` 非空、本函数为空
      ⇒ 影响面 0 套、只跑主闸门快档，**不回退全量**。判据 D-35 锁这条。
    """
    return {p for p in _changed_files()
            if (not _TOUCH_EXCLUDE.search(p.replace("\\", "/"))
                and p.endswith(".py"))
            # ★★ 闸门**自身**的文件不受"只认 .py"限制：
            #   `ci/git-hooks/pre-commit` 是 shell 脚本，实测被这条过滤掉过
            #   ⇒ 改钩子不会触发 selfcheck（而"闸门自身文件"里恰恰只有它
            #     不是 .py）。2026-10-13 由 `--hook` 实测发现。
            or p.replace("\\", "/") in _GATE_SELF_FILES}


def resolve_only(only_arg, suites=None):
    """★★ 0.57.0（行动清单第 26 条）：把 `--only` 解析成 `(选中的套件, 未登记的键)`。

    **唯一实现**：`main()` 与判据 D-41 共用，判据不二次实现。

    为什么要有这个函数 —— 实测复现出来的那段假绿：

        python ci/delivery_gate.py --only inbox_guards_0514
        （`SUITES` 的键是 `0514`，写文件名就是拼错）

      ⇒ 旧代码 `[s for s in SUITES if s[0] in only]` 过滤成**空表**
      ⇒ `for` 循环空转，`RESULTS == []`，四个计数器全是 0
      ⇒ 落进 else 分支，打印
        「★ 闸门全绿：所有已登记判据均通过（**本次实际执行 0 套**）」
      ⇒ **rc=0**。

    同一份输出里「全绿」与「0 套」并存。人会只读前半句；CI **只看退出码**，
    于是**一次拼写错误＝一次静默放行**。

    这不是边界情况：它恰好发生在我「用闸门排查问题」的时候，也就是我最依赖
    这个判断的时刻。判断工具自己会说谎时，之后所有结论都不可信。

    返回空集**永远**不等于通过 —— 由 `main()` 里的空集守卫落成 rc=2。
    """
    want = {x.strip() for x in (only_arg or "").split(",") if x.strip()}
    table = list(SUITES if suites is None else suites)
    if not want:
        return [], []
    known = [s for s in table if s[0] in want]
    unknown = sorted(want - {s[0] for s in table})
    return known, unknown


def empty_selection_verdict(unknown, suites):
    """★★ 0.57.0（行动清单第 26 条）：**0 套 ≠ 通过** —— 唯一判定入口。

    返回 `(退出码, 要打印的行列表)`；`(0, [])` 表示可以继续跑。

    两种"没有东西可跑"的形态，同一处判、同一个码：

      ① `--only` 里有**未登记**的键 —— 用户想要的套件一套都没选中。
         诊断要点名那个键并列出合法键，否则下一个人只会再拼错一次。
      ② 选出来的套件是**空表** —— 不论是 `--only` 拼错、`--affected`
         推不出、`--hook` 预算为 0，还是判据清单本身空了。

    为什么要收成一处：这两条守卫曾经分别写在 `main()` 的两段里，于是
    「负控单点注入」只能拆掉其中一条、另一条兜住 ⇒ 看起来"拆不坏"，
    而"拆不坏"会被误读成"判据没有牙"。收成一处之后，注入这一个函数
    就能同时废掉两条守卫 ⇒ 负控能咬住，且**恰好**咬在它该咬的地方。

    ★ 旧的失败形态（实测复现过，见 `resolve_only` 的 docstring）：
      `--only inbox_guards_0514` ⇒ 空表 ⇒ 空循环 ⇒ 四个计数器全是 0
      ⇒ 打印「闸门全绿…（本次实际执行 0 套）」且 **rc=0**。
    """
    if unknown:
        return 2, [
            "",
            "★ `--only` 里有**未登记**的键：%s" % "、".join(unknown),
            "  合法键（%d 个）：%s" % (len(SUITES), "、".join(s[0] for s in SUITES)),
            "  ⚠ 键名写错时旧行为是「跑 0 套却打印全绿、rc=0」—— 现在直接拒绝。",
            "  规则：**0 套不等于通过**（判据 D-41）。",
        ]
    if not suites:
        return 2, [
            "",
            "★ 没有任何套件要跑 —— **0 套不等于通过**。",
            "  可能原因：--only 没选中任何键 / 影响面推不出套件 / 判据清单为空。",
            "  规则：判据 D-41；空集一律 rc=2，不当通过。",
        ]
    return 0, []


def _select_suites(changed, touched, hook):
    """纯函数：由「改动集」决定跑哪几套。返回 `(suites, mode, notes)`。

    ★★ 为什么抽成**纯函数**（判据不许二次实现）：
      判据 D-35 要正面守「纯文档改动不许回退全量」—— 它必须**调真逻辑**，
      不许在判据里再写一份"应该跑几套"的推理（那就是 T-09 同一事实两套口径）。
      ⇒ 逻辑留在这里，`__main__` 与判据共用。

    `mode` ∈ `{"all", "affected"}`：`all`＝回退全量（**唯一允许的触发条件是
    "探测层一个改动都没有"**）；`affected`＝按影响面跑。
    """
    if not changed:
        return list(SUITES), "all", [
            "  ⚠️  探不到**任何**改动（git 无变更且无近 30 分钟修改的 .py）"
            "⇒ **回退全量**（宁多跑，不漏跑）"]
    if not touched:
        # 有改动，但没有产品源码（纯文档/资产）⇒ 影响面 0 套，只跑主闸门。
        return [s for s in SUITES if s[0] == "regression"], "affected", [
            "  ◇ 改动 %d 个文件，但**无产品源码**（纯文档/资产）⇒ 影响面 0 套，"
            "只跑主闸门快档；全量留给打包前/CI" % len(changed)]
    hit, note = impacted_suites(touched)
    hit.add("regression")               # 主闸门永远跑（它是"已修缺陷"的总账）
    suites = [s for s in SUITES if s[0] in hit]
    skipped = [s[0] for s in SUITES if s[0] not in hit]
    notes = ["  ◇ 改动 %d 个文件 ⇒ 在影响面内 %d 套 / 不在影响面 %d 套"
             % (len(touched), len(suites), len(skipped))]
    notes += ["      · %s" % ln for ln in note[:12]]
    if skipped:
        notes.append("      ⏭ 不在影响面：%s" % "、".join(skipped))
    if hook:
        # ★ 闸门**自身**的文件被改 ⇒ `selfcheck` 必须跑，且**不参与预算**
        #   （预算把它挤掉＝"闸门自己改了却没人复验闸门"）。
        must = {"regression"}
        if {os.path.normpath(p).replace("\\", "/")
                for p in touched} & _GATE_SELF_FILES:
            must.add("selfcheck")
        suites = _apply_budget(suites, must=must)
    return suites, "affected", notes


def _env_warn():
    """★★ M-A 第二半（2026-10-13）：**全量开跑前的环境预检**。

    为什么必须有：S80/S81/S84 一类判据依赖 git 子进程，而 `VCT_TIMEOUT = 2.0s`；
    机器 I/O 慢（杀软实时扫描 / TEMP 残留）时 git 会撞超时 ⇒ 判据报「夹具失效」。
    旧流程要等**全量 22 分钟跑完**才看到那条红 —— 那时人已经在怀疑产品了。
    ⇒ 开跑前先量一次 git 延迟：超预算就**出声**（**不阻断**，只预警），
      把"22 分钟后才发现机器测不了"变成"开跑前就知道"。

    ★ 不阻断的理由：预警是**提示**，不是判据 —— 判据的事归判据（D-32/D-35 那一族）。
      把"机器慢"做成阻断条件，等于让环境替产品做决定（那正是 T-08 的反面）。
    """
    import time as _t
    try:
        t0 = _t.time()
        subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=PKG,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=30)
        dt = _t.time() - t0
    except Exception:                                          # noqa: BLE001
        print("  ⚠️  环境预检：git 子进程起不来 —— 依赖 git 的判据（0460 S80/S81/S84）"
              "会报「夹具失效」（那不是产品缺陷）。")
        return
    if dt > 1.0:
        print("  ⚠️  环境预检：git 子进程 **%.2fs**（正常 ~0.1s，判据超时线 2.0s）"
              "—— 本机 I/O 偏慢，依赖 git 的判据**可能假红**（报「夹具失效」"
              "而非产品缺陷）。若出现，先修环境（杀软实时扫描 / TEMP）再重跑。" % dt)

#:
#: ★★ 这不是假想，是 0.36.5 实测到的：0353 在缺仓外原件时
#:   `exit 0` 且**一个字符都不打印**。若只看退出码，它会被记成 PASS，
#:   于是「一条判据都没跑」与「全部判据通过」在账面上完全一样。
#:   ⇒ 这正是本仓铁律「**查不出来 ≠ 查出来是好的**」在闸门层的形态。
_NOOP_MIN_CHARS = 1


def _looks_like_noop(out):
    return len((out or "").strip()) < _NOOP_MIN_CHARS


def _run(rel, timeout=900, extra=None):
    """跑一套判据。返回 `(状态, 明细)`，状态 ∈ PASS / RED / CRASH / MISSING / NOOP。

    ★ `extra`：附加给判据脚本的参数（2026-10-13 新增）。快道用它把
      **主闸门**切到快档（`regression_gate.py --quick`：跳过 3 条真跑打包/安装
      管线的判据，逐条打印）。不传 ⇒ 与原来完全一样（全量）。

    ★ 为什么要把 CRASH 与 RED 分开（本轮踩过同型）：
      自检器自己的注释里记着一条教训 ——「工具崩了不算判据红，
      但两者混在一起就会把『工具自己坏了』误读成『检查发现了很多问题』」。
      反过来同样成立：**工具崩了若报成"0 红"，就是假绿**。
      ⇒ 这里五种状态互不折叠，main() 里除 PASS 外全部计入退出码非零。
    """
    p = os.path.join(PKG, rel)
    if not os.path.isfile(p):
        return "MISSING", "判据文件不存在：%s" % rel
    env = dict(os.environ)
    env["ANTINEL_PKG"] = PKG          # 让判据认准主仓，不被上级陈旧 manifest 干扰
    t0 = time.time()
    try:
        r = subprocess.run([sys.executable, p] + list(extra or []),
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=timeout, env=env, cwd=PKG)
    except subprocess.TimeoutExpired:
        return "CRASH", "超时 > %ds（判据卡住与判据变红必须能区分）" % timeout
    except Exception as e:                                    # noqa: BLE001
        return "CRASH", "起不动：%s: %s" % (type(e).__name__, e)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    dt = time.time() - t0
    tail = out.splitlines()[-1] if out else "(无输出)"
    if _looks_like_noop(out):
        # 退出码 0 但零输出 —— 必须报出来，且**不许**报 PASS
        return "NOOP", "退出码 %d 但**零输出** ⇒ 判据没真跑（缺依赖／提前 return），不是通过" % r.returncode
    if r.returncode == 0:
        return "PASS", "%s  [%.1fs]" % (tail[:96], dt)
    # ★★ 0.36.5：变红时**必须带上红项明细**，不能只给最后一行。
    #   实测踩到三次 —— 各套判据的红项形态**各不相同**，只认一部分就漏一类：
    #     ① 0364  用 `❌ D2 …`（红项同一行）
    #     ② regression 用 `[FAIL] D-6 …`（红项同一行）
    #     ③ 0363  用 `RED  R06 …` ＋**下一行缩进**给明细 ⇒ 同一行匹配漏掉明细
    #     ④ version 用 `-  版本 X 出现在：…`（**无任何标记**，只靠缩进破折号）
    #   ⇒ 纪律：① 判断依据不许建立在你没拿到的信息上；
    #           ② 收集红项不许只认部分标记（漏一种形态＝漏一种真实缺陷）。
    lines = out.splitlines()
    red = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if ("❌" in s or "[FAIL]" in s or s.startswith("RED ") or "💥" in s
                or (re.match(r"^-\s", s) and "出现在" in s)):
            seg = s
            # ③ 明细在**下一行**（缩进续行）⇒ 一并带上
            #   ⚠️ 续行长度上限从 120 放宽到 300：0363 的根因诊断
            #   「…属 manifest 哈希级联」在第 ~150 字符，120 会把它切掉
            #   ⇒ 又是"信息死在格式化里"。同一条纪律，不再犯第二次。
            if i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                if nxt.startswith(("└", "—", "-")) or (
                        nxt and not nxt.startswith(("GREEN", "RED", "0.", "共"))):
                    seg += " ｜ " + nxt[:300]
            red.append(seg)
    detail = "%s  [%.1fs]" % (tail[:56], dt)
    if red:
        # ★★ 0.36.5：截断长度从 220 提到 600。
        #   实测踩到：0363 的根因诊断（「…属 manifest 哈希级联」）在第 ~200 字符，
        #   而红项文本被截到 220 ⇒ **"级联"两字被切掉** ⇒ 自举豁免匹配不上。
        #   ⇒ 症状看起来像"豁免机制坏了"，实际是**信息在传递途中被截断**。
        #   ⇒ 纪律：**别让承载判断的信息死在格式化里**。
        #     宁可输出长一点，也不要让下游拿不到依据。
        detail += "  ｜红项：" + " ／ ".join(red[:3])[:600]
    return "RED", detail


def _mentions_other(text, carriers):
    """红项文本的「落后者」半句里，是否点名了 **manifest 以外**的承载件。"""
    m = re.search(r"(落后者[：:]\s*.{0,240})", text)
    if m:
        return any(c in m.group(1) for c in carriers)
    return False


def _mentions_carrier(text, carrier):
    """红项文本里**是否点名了某个版本承载件**（用于自举豁免的收窄判断）。

    ★ 为什么需要独立函数（而不是 `carrier in text`）：
      `version_check` 的输出**同时**列出多数派与落后者，例如：
        「版本 0.36.5 出现在：pyproject.toml; server.json; antinel.py …」
      这行里**提到了** pyproject，但它是在说"**一致**"的那一批，
      **不是**落后者。⇒ 直接 `in` 判断会把"已一致"误读成"也落后了"
      ⇒ 真正的版本分叉反而**豁免掉**。这正是本轮差点犯的错。
      ⇒ 正确做法：**只认「落后者」那半句**。
    """
    return _mentions_other(text, (carrier,))


def _missing_required():
    """清单里的判据文件必须都在。少一个就报红（防止"删判据即变绿"）。"""
    gone = [rel for rel in REQUIRED
            if not os.path.isfile(os.path.join(PKG, rel))]
    return gone


def _orphaned_guard_files():
    """★ 反向：仓里若还有**没进清单**的 `inbox_guards_*.py`，必须报出来。

    为什么必须做反向检查（这是本轮最关键的一条设计）：
      只检查「清单里的文件都在」，挡不住**反向漏登记** ——
      有人新写了 `inbox_guards_0365.py` 却忘了加进 `SUITES`，
      那么它一条都不会跑，而闸门**照样全绿**。
      ⇒ 「有判据但没人跑」这个缺陷会从后门重新长出来。
      ⇒ 判据：仓里的守卫文件集合 **⊆** 清单登记的集合，差集非空即红。
    """
    listed = {os.path.basename(r) for _k, r, _d in SUITES}
    try:
        # ★ 0.36.8：模式从 inbox_guards_ 扩到 inbox_guards_｜jdg_guards_——
        #   原模式只认 inbox_guards_*，JDG 族写成 jdg_guards_* 后
        #   「写了没登记」会从后门漏掉（这正是本检查存在的全部理由）。
        # ★ 0.37.0：再扩到 pcm_gate_ —— PCM 族与 JDG 族同构（版本后缀命名），
        #   漏登记的后果同样是一条都不跑而闸门照样全绿。
        # ★ 0.38.0：再扩到 guard_ —— 粮族（guard_granary.py）用的是
        #   `guard_<领域>.py` 命名，若不纳入，同样会"写了没登记、一条都不跑"。
        on_disk = {f for f in os.listdir(os.path.join(PKG, "ci"))
                   if (f.startswith("inbox_guards_") or f.startswith("jdg_guards_")
                       or f.startswith("pcm_gate_") or f.startswith("guard_"))
                   and f.endswith(".py")}
    except OSError:
        return ["读不到 ci/ 目录"]
    # `inbox_guards.py` 是历史基线件（无版本后缀），已并入 regression 体系，不在本清单
    on_disk = {f for f in on_disk if f != "inbox_guards.py"}
    return ["%s（在 ci/ 里但没登记进 SUITES ⇒ 一条都不会跑）" % f
            for f in sorted(on_disk - listed)]


# ────────────────────────────────────────────── 负控
def selfcheck():
    """★★ 负控：把一条判据的**判定结果**改坏，断言本闸门**必须**变红。

    ★ 为什么注入的是「把 `return True` 改成 `return False`」：
      这是对「假守卫」最直接的模拟 —— 判据文件还在、条数不变、
      语法正确、**只是判据判错了**。
      如果本闸门在这种注入下仍然全绿，说明它根本没在调这套判据
      （或调了但吞掉了退出码）⇒ 本闸门是装饰。

    ★ 注入点选 0363 而不是 0364（实测踩过一次）：
      0364 全部判据是 `assert` 驱动（红 = 抛 AssertionError），
      **文件里根本没有 `return True`** ⇒ 照 `return True` 注入会 SKIP。
      而 SKIP 若被当成"通过"，负控就变成了永远绿的装饰。
      ⇒ 选一个确实含 `return True` 的判据集，并在 SKIP 时**返回非零**。
      ⇒ 教训（与本轮 `_p_selfcheck_negctl` 同型）：**负控自身失配必须报红，
        不许报"通过"** —— 否则负控是假绿。

    注入用**改名让开 + 无条件还原**，不删文件（本机删除配额会被平台守卫硬杀）。
    """
    victim_rel = "ci/inbox_guards_0363.py"
    victim = os.path.join(PKG, victim_rel)
    if not os.path.isfile(victim):
        print("  [💥] 找不到 %s，无法做负控（这不是通过）" % victim_rel)
        return 1
    src = io.open(victim, encoding="utf-8").read()
    if "\n    return True" not in src:
        print("  [💥] %s 里没有可注入的 'return True'，负控注入点失配（需更新负控）"
              % victim_rel)
        return 1
    mutated = src.replace("\n    return True", "\n    return False", 1)
    bk = victim + ".gate_negctl.bk"
    try:
        io.open(victim, "w", encoding="utf-8", newline="\n").write(mutated)
        st, why = _run(victim_rel)
        if st == "RED":
            print("  [RED(好)] 判据被改坏后本闸门报红：%s" % why)
            return 0
        print("  [★GREEN(坏)] 判据被改坏（一条判据永远红）本闸门仍报 %s —— "
              "它是装饰，不是闸门" % st)
        return 1
    finally:
        # 无条件还原：负控异常残留会污染产品代码（本轮踩过）
        try:
            io.open(victim, "w", encoding="utf-8", newline="\n").write(src)
        finally:
            if os.path.exists(bk):
                os.replace(bk, victim)
        # 还原后必须逐字节复核 —— 「以为还原了」不算还原
        back = io.open(victim, encoding="utf-8").read()
        if back != src:
            print("  ★ 还原失败：%s 内容与注入前不一致，需人工核对" % victim_rel)
            return 1
        print("  [ok] 判据文件已逐字节还原")


# ────────────────────────────────────────────── 主流程
def main():
    # ★ 0.48.5：输出**行缓冲**。重定向到文件时 Python 默认整块缓冲 ⇒ 跑 19 分钟的
    #   闸门"一个字都看不到"，只能干等（2026-10-13 实测；我当时改用 `tr` 管道，
    #   结果缓冲更狠）。**进度可见是"不用干等"的前提**，也是效率的一部分。
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:                                   # noqa: BLE001
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="跳过 slow 档（< 10 秒）")
    ap.add_argument("--only", default="", help="只跑指定键（逗号分隔）")
    ap.add_argument("--affected", action="store_true",
                    help="只跑**受影响**的套件（按 import 图从本次改动推出，"
                         "始终含主闸门 regression）；探不到改动 ⇒ 回退全量")
    ap.add_argument("--hook", action="store_true",
                    help="提交钩子快道：受影响套件按历史耗时做预算（跳过什么一律"
                         "逐条列出）＋ 主闸门；**不写基线快照**。"
                         "★ 快道不是全量凭证 —— 全量只有 `python ci/delivery_gate.py`")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--selfcheck", action="store_true", help="负控：判据被改坏时本闸门必须红")
    a = ap.parse_args()

    if a.selfcheck:
        print("=" * 74)
        print("统一交付闸门 · 负控：把一条判据改坏 → 本闸门必须报红（先红后绿）")
        print("=" * 74)
        return selfcheck()

    if not os.path.isdir(PKG):
        print("★ 找不到仓根 %s" % PKG)
        return 2

    _fd, _why_lock = _acquire_lock()
    if _fd is None:
        print("★ 闸门未启动：%s" % _why_lock)
        return 3
    atexit.register(_release_lock, _fd)

    print("=" * 78)
    print("统一交付闸门 —— 一处入口 · %d 套判据 · 红即阻断" % len(SUITES))
    print("仓路径：%s" % PKG)
    print("=" * 78)

    # ── 结构性检查（先跑：它们决定后面该不该跑） ──
    gone = _missing_required()
    orphans = _orphaned_guard_files()
    p1p5_missing = suites_missing_p1p5()
    cap_red, cap_notes = cap_violation()
    if gone:
        print("  💥 %-46s %s" % ("判据文件缺失（删判据＝让闸门变绿）",
                              "、".join(gone)))
    if orphans:
        print("  💥 %-46s %d 处" % ("有守卫文件没登记进 SUITES（不会跑）", len(orphans)))
        for o in orphans:
            print("       - %s" % o)
    if p1p5_missing:
        print("  💥 %-46s %d 处" % ("新套件缺 P1–P5 前置门作答块（A1）",
                                  len(p1p5_missing)))
        for key, rel, why in p1p5_missing:
            print("       - %s（%s）：%s" % (key, rel, why))
    if cap_red:
        print("  💥 %-46s %s" % ("常驻套件超上限 29（A2）", cap_notes[0]))
    elif cap_notes:
        print("  ⚠  %-46s %s" % ("常驻套件超上限但有退休记录", cap_notes[0]))
    if not gone and not orphans and not p1p5_missing and not cap_red:
        print("  ✅ %-46s %d 套判据齐全，无未登记的守卫文件，"
              "前置门与上限检查通过（常驻 %d/%d）"
              % ("判据清单与磁盘一致", len(SUITES),
                 resident_suite_count(), RESIDENT_SUITE_CAP))

    # ★★ 0.57.0（第 26 条）：`--only` 一律走 `resolve_only()`，**未登记的键直接拒绝**。
    #   旧写法 `[s for s in SUITES if s[0] in only]` 在拼错时静默给出空表，
    #   而空表的运行结果与"全绿"在退出码上不可区分（见 resolve_only 的 docstring）。
    #   ★ 部分匹配也拒：`--only 0514,typo` 里的 typo 没跑 ⇒ 意图未被完整执行，
    #     那次的结论不能当"0514 这一族都过了"用。
    only, _unknown = resolve_only(a.only)
    suites = SUITES
    if a.only.strip():
        # 给了 --only 就**只**用它的结果 —— 可能是空表，交给下面那道唯一守卫；
        # 绝不在"拼错"时悄悄退回全量（那会跑 25 分钟还让人以为只跑了想跑的那套）。
        suites = only
    elif a.affected or a.hook:
        # ★★ 0.48.5 快道（2026-10-13）：复用**现成**的 import 图（`impacted_suites`）。
        #   它原来只"打印"受影响范围，于是每次改动要么全量 19 分钟、要么人肉挑——
        #   这与交接件 §3.3 附加要求二「闸门要快到没有理由跳过」正面冲突：
        #   **慢到 19 分钟的闸门，全量跑就退化成靠自觉**。现在把它变成可执行的模式。
        #   ★ 口径：**探不到改动 ⇒ 回退全量**（宁多跑，绝不漏跑）。
        # ★★ 0.48.6（2026-10-13）：探测层/影响面层**拆开**（见 `_changed_files`）。
        #   原口径「探不到**产品**改动 ⇒ 回退全量」有个致命副作用：**纯文档改动**
        #   也被算成"探不到" ⇒ 回退全量 22 min ⇒ 钩子超时 ⇒ 人用 `--no-verify`
        #   绕过（= 把 0.48.5 刚接好的"一处入口"又拆了）。
        #   ⇒ 现在「回退全量」的唯一合法触发条件是**探测层一个改动都没有**；
        #     纯文档改动 ⇒ 影响面 0 套、只跑主闸门快档。逻辑在纯函数
        #     `_select_suites` 里，判据 D-35 直接调它（判据不许二次实现）。
        suites, _mode, _notes = _select_suites(_changed_files(), _touch_files(),
                                               a.hook)
        for _ln in _notes:
            print(_ln)

    # ★★ 0.57.0（第 26 条）：**0 套 ≠ 通过** —— 唯一判定入口（见 `empty_selection_verdict`）。
    #   这一处兜住所有"选不出套件"的路径（--only 拼错 / --affected 推不出 /
    #   --hook 预算为 0 / 清单为空）。放在 `_env_warn()` **之前**：没有东西要跑时
    #   连环境预检都不必做，且报错要出现在任何"看起来在干活"的输出之前。
    _rc, _lines = empty_selection_verdict(_unknown, suites)
    if _rc:
        for _ln in _lines:
            print(_ln)
        return _rc

    # ★★ M-A：全量开跑前先做**环境预检**（只预警、不阻断）—— 见 `_env_warn`。
    if not a.hook:
        _env_warn()

    for key, rel, tier in suites:
        if a.quick and tier == "slow" and not (a.hook and key == "regression"):
            print("  ⏭  %-46s slow 档，--quick 跳过" % key)
            continue
        # ★ 快道：主闸门切快档（它内部逐条打印跳过了哪 3 条）。
        #   为什么主闸门也要快档：实测 22 条 66s，其中 3 条真跑打包/安装管线占 51s
        #   ⇒ 不减这一刀，钩子必然 >30s，而 >30s 的钩子会被 --no-verify 绕过。
        _extra = ["--quick"] if (a.hook and key == "regression") else None
        st, why = _run(rel, extra=_extra)
        icon = {"PASS": "✅", "RED": "❌", "CRASH": "💥",
                "MISSING": "💥", "NOOP": "⚠️"}[st]
        print("  %s %-46s %s" % (icon, key, why))
        RESULTS.append({"suite": key, "rel": rel, "tier": tier,
                        "status": st, "detail": why})
    # ★★★ 0.36.5：**自举死锁**的显式处理（实测踩到，不是假想）。
    #   现象：升版后打包被拦，理由是「psl/manifest.json 停在旧版」；
    #        而 manifest 恰恰**由打包生成** ⇒ 不先打包就永远过不了。
    #   ⇒ 闸门自己认得出这一类，且**只豁免这一类**。
    #
    #   ⚠️⚠️ 豁免判据必须**窄到能区分"manifest 单独落后"与"真缺陷"**：
    #     形态（取自各判据真实输出）：
    #       ✔ 豁免：红项**只**提到 manifest 落后 / 与 manifest 不符
    #       ✘ 不豁免：红项里出现**其他承载件**（那是真版本分叉，必须红）
    #     ⇒ 放宽成"提到 manifest 就放过"，真分叉会被一起放过 ——
    #       而那正是 D-6 存在的全部意义。**豁免一个症状，不许豁免一个类别。**
    #   ⚠️ 必须先确认**红项明细拿到了**（`_run` 只回 tail 时一律不豁免）——
    #     否则就是"判断依据建立在你没拿到的信息上"（本轮已踩过一次）。
    _bs_exempt = []
    if os.environ.get("ANTINEL_BOOTSTRAP") == "1":
        #: 唯一允许出现在红项里的承载件（它由本次打包生成）
        _ONLY_ALLOWED = "psl/manifest.json"
        #: 出现即判"真缺陷"的其他承载件
        _OTHER_CARRIERS = ("pyproject", "antinel.py", "antinel_mcp", "server.json",
                           "pre_tool_use", "build_package", "rules/default.json",
                           "AUDIT_SCHEMA", "SKILL.md")
        for rec in RESULTS:
            if rec["status"] != "RED":
                continue
            m = re.search(r"红项：(.{0,800})", rec["detail"])
            if not m:
                continue                     # 没拿到红项明细 ⇒ 不豁免
            red_txt = m.group(1)
            # ★ 形态一：**版本落后**（version / regression）
            #   只有"落后者"那半句里出现非 manifest 承载件 ⇒ 真分叉，不豁免。
            if "落后者" in red_txt or "出现在" in red_txt:
                if _mentions_other(red_txt, _OTHER_CARRIERS):
                    continue
                rec["status"] = "PASS"
                rec["detail"] = ("【自举豁免】红项只涉及 %s —— 它由本次打包生成，"
                                 "打包前必然落后" % _ONLY_ALLOWED)
                _bs_exempt.append(rec["suite"])
                continue
            # ★ 形态二：**哈希不符**（0363 R06 / 0364 D2）
            #   判据：红项里点名的文件，**是否都是打包会刷新哈希的那些**
            #   （即它们与 manifest 失配，而不是"版本号写错了"）。
            #   ⚠️ `hooks/pre_tool_use.py` 的哈希失配**也**由打包刷新 ——
            #     它是 manifest 覆盖的告警链路文件之一。把它当"其他承载件"
            #     会让自举永远解不开（实测踩过：豁免对 0363/0364 一直不生效）。
            #   ⇒ 判据按**根因**分，不按文件名分：
            #     · 只说「与 manifest 不符 / 没登记进 manifest」⇒ 哈希类，自举豁免
            #     · 出现「版本号/不一致/落后者」字样 ⇒ 版本类，另判
            #   ★ 形态二之二（0363 R06）：判据自己会把根因写进回报 ——
            #     「根因：self_check 不符 ⇒ 属 manifest 哈希级联」/「真缺陷」。
            #     ⇒ 只有**明写"级联"**才豁免；明写"真缺陷"的一律不豁免。
            #     这比"猜根因"可靠得多 —— 依据是判据自己的诊断，不是闸门的推测。
            if "根因：self_check" in red_txt:
                if "真缺陷" in red_txt or "不可豁免" in red_txt:
                    continue                 # 判据自己说了是真缺陷 ⇒ 不豁免
                if "级联" in red_txt:
                    rec["status"] = "PASS"
                    rec["detail"] = "【自举豁免】判据自报根因为 manifest 哈希级联"
                    _bs_exempt.append(rec["suite"])
                continue
            if "与 manifest 不符" in red_txt or "没登记进 manifest" in red_txt \
                    or "与manifest不符" in red_txt:
                if re.search(r"版本(号)?(不一致|分叉|落后)", red_txt):
                    continue                 # 混了版本问题 ⇒ 不豁免
                rec["status"] = "PASS"
                rec["detail"] = ("【自举豁免】红项是 manifest 哈希类失配 —— "
                                 "本次打包会重新登记这些文件的哈希")
                _bs_exempt.append(rec["suite"])
                continue
            # 与 manifest 无关 ⇒ 不豁免
            if "manifest" not in red_txt:
                continue

    n_red = sum(1 for r in RESULTS if r["status"] == "RED")
    n_crash = sum(1 for r in RESULTS if r["status"] in ("CRASH", "MISSING"))
    n_noop = sum(1 for r in RESULTS if r["status"] == "NOOP")
    n_pass = sum(1 for r in RESULTS if r["status"] == "PASS")
    struct_bad = 1 if (gone or orphans or p1p5_missing or cap_red) else 0

    for k in _bs_exempt:
        print("  ⬆  %-46s 自举豁免：manifest 由本次打包生成，打包前必然落后" % k)

    # ── 机制层①：差分归因（让「多了什么」成为机器算出来的，不必重跑去回忆）──
    # ★★ 0.48.5：**只有全量跑才写基线快照**。2026-10-13 实测：`--only 0481` 一次
    #   就把 30 套的基线换成 1 套 ⇒ 下一次全量的"新增红 / 已转绿"（收敛的第一手
    #   线索）当场失真，**而且没有任何判据会发现**。局部运行同样不参与基线对照。
    _ran = {r["suite"] for r in RESULTS}
    _all = {s[0] for s in SUITES}
    _full = _ran == _all
    _fp = _gate_fingerprint()
    # ★★ 2026-10-15 修一处**闸门工具自身崩**（盲区，比红更坏）：`new_red`／`fixed`
    #   原先只在 `_full`（全量跑）时由 `_diff_against_baseline` 赋值 —— 局部跑
    #   （含提交钩子的影响面跑法）一旦有红，走到下面 `if new_red:` 就是
    #   UnboundLocalError ⇒ 闸门在“正要说清红项”时崩掉，钩子只剩 traceback。
    #   实测：WIP 提交钩子局部跑 10 套遇 0517 红 ⇒ 当场崩。修法：先初始化。
    new_red, fixed = [], []
    if _full:
        new_red, fixed, snap_note = _diff_against_baseline(RESULTS, _fp)
        if new_red:
            print("-" * 78)
            print("  ★ 本次**新增**红（相对上次快照）—— 收敛的第一手线索：")
            for suite, why in new_red:
                print("      · %-44s %s" % (suite, why))
            print("    ⇒ 新增红才是要查的对象；一直红着的那条另有原因，不要混在一起查。")
        if fixed:
            print("  ✔ 本次已转绿（相对上次快照）：%s" % "、".join(fixed))
        print("  ⓘ 基线对照：%s" % snap_note)
        _save_snapshot(RESULTS, _fp)
    else:
        print("  ⓘ 本次是**局部运行**（跑了 %d / %d 套）⇒ 不写基线快照、不参与基线对照"
              " —— 局部结果会把全量基线覆盖成假的（2026-10-13 实测）"
              % (len(_ran), len(_all)))
        if a.hook:
            print("      ★ 快道（提交钩子）**不是全量凭证** —— 它明说自己没跑什么。"
                  "全量凭证只有 `python ci/delivery_gate.py`（打包前/CI）。")

    # ── 机制层②：本次改动的影响面 ──
    _touched = _touch_files()
    if _touched:
        _imp, _why = impacted_suites(_touched)
        print("-" * 78)
        print("  ◇ 本次改动碰到 %d 个文件；**重点复验**这些判据：" % len(_touched))
        for ln in _why[:10]:
            print("      · %s" % ln)
        if _imp:
            print("  ⇒ 上面这些是**本次改动的直接受害者**；"
                  "若红项不在其中，多半是老账（机制层③会再提一次）。")
    else:
        print("  ◇ 未探测到本次改动（git 无变更且无近 30 分钟修改的 .py）"
              "⇒ 无法点名重点复验范围")

    # ── 机制层③：红项是本次引入的，还是老账？ ──
    _touched_stems = {os.path.splitext(os.path.basename(p))[0] for p in _touched}
    for _r in RESULTS:
        if _r["status"] == "PASS" or not (_r.get("red") or "").strip():
            continue
        _named = red_names_touched_modules(_r["red"], _touched_stems)
        if not _named:
            print("  ⓘ 红项 %s：文案里**没有**本次改动的模块名 ⇒ 可能与本次改动无关"
                  "（红仍然是红、仍然阻断，只是不必优先查它）" % _r["suite"])

    print("-" * 78)
    print("  %d 套判据：全绿 %d / 变红 %d / 工具崩或缺失 %d / 零输出假绿 %d%s"
          % (len(RESULTS), n_pass, n_red, n_crash, n_noop,
             (" ＋结构检查 %d 项不通过" % struct_bad) if struct_bad else ""))

    if struct_bad or n_crash or n_red or n_noop:
        print("★ 闸门未通过。")
        print("  · 变红 ⇒ 有判据检出缺陷（或判据自身需更新），**先看红项再决定改哪边**。")
        print("  · 工具崩/缺失 ⇒ 判据没跑成，**这不是通过，是盲区**。")
        print("  · 零输出 ⇒ 判据提前退出（缺依赖），**退出码 0 也不许当通过**。")
        print("  · 结构不通过 ⇒ 判据清单与磁盘不一致，先对齐清单。")
        if new_red:
            print("  · 本次新增红 ⇒ **先查新增的那几条**，别去翻一直红着的旧账。")
        print("  确知要绕过：git commit --no-verify（会在审计链留痕，不是悄悄溜过去）")
    else:
        print("★ 闸门全绿：所有已登记判据均通过（本次实际执行 %d 套）" % n_pass)

    # ★★ 0.48.5：结果**一律落盘**一份机器可读的（不再只在 `--json` 时）。
    #   为什么：2026-10-13 我是从控制台日志读结论的，撞上并发交错 ＋ 重定向缓冲，
    #   读到的是一行被写坏的 "0481 RED" ⇒ 追了 20 分钟幽灵红。
    #   ⇒ 结论必须有一个**不受终端形态影响**的通道。`full` 字段同时说明这次是
    #     全量还是局部（**局部结果不可当收敛基线用**）。
    try:
        with open(_LAST_RUN, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"ts": time.time(), "full": _full,
                       "suites_run": sorted(_ran), "suites_total": len(_all),
                       "pass": n_pass, "red": n_red, "crash": n_crash,
                       "noop": n_noop, "struct_bad": struct_bad,
                       "orphans": orphans, "missing": gone,
                       "p1p5_missing": [list(x) for x in p1p5_missing],
                       "cap_red": cap_red, "cap_notes": cap_notes,
                       "results": RESULTS}, f, ensure_ascii=False, indent=1)
        print("  ⓘ 结果文件：%s" % _LAST_RUN)
    except Exception as e:                              # noqa: BLE001
        print("  !! 结果文件没写成（%r）—— 这是「看不见结论」的一个来源" % (e,))

    # ★★ 0.48.5：把本次真跑到的耗时并进**历史耗时账**（快道预算的数据源）。
    #   没跑到的套件保持旧值 —— 不许清零（清一次快道就会"因为不知道多慢而全跑"）。
    try:
        _merged = _merge_durations(_load_durations(), RESULTS)
        with open(_DUR, "w", encoding="utf-8", newline="\n") as f:
            json.dump(_merged, f, ensure_ascii=False, indent=1, sort_keys=True)
    except Exception as e:                              # noqa: BLE001
        print("  !! 耗时账没写成（%r）—— 快道下次会退化成「不知道多慢就全跑」" % (e,))

    if a.json:
        print(json.dumps({"results": RESULTS, "pass": n_pass, "red": n_red,
                          "crash": n_crash, "noop": n_noop,
                          "struct_bad": struct_bad,
                          "orphans": orphans, "missing": gone},
                         ensure_ascii=False, indent=1))
    return 0 if not (struct_bad or n_crash or n_red or n_noop) else 1


if __name__ == "__main__":
    sys.exit(main())

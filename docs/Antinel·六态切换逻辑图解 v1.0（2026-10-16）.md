<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel · 六态切换逻辑图解 v1.0（2026-10-16）

> **这份文档是什么**：把《六态切换逻辑规格》两轮迭代里画过的 **8 张图解**
> 收进仓里**存档**（原来只活在会话的 `output/_widgets/` 临时目录里，会话一过就没了）。
> 每张图两段：**这张图说什么**（纯文字精华，图烂了信息还在）＋ **原样 SVG**（逐字快照）。
>
> **不要手工编辑本文件里的 SVG 块** —— 它们由 `_p_doc_figures.py` 从
> `output/_widgets/*.svg` **逐字**生成。要改图就改 SVG，再重跑那个脚本。
> 可看版（八张图内联渲染）：`output/figures_六态切换逻辑图解.html`。

**图与规格的对应**：图 1–3 是 **v1.2（三通道显示模型）** 的图；
图 4–5 与图 6–8 是 **v1.0 规格审核期** 的诊断图（保留作历史证据，
它们记录的是「旧单值灯为什么必须被拆掉」的推导现场）。

| # | 图 | 出处 | 一句话 |
|---|---|---|---|
| 1 | 三通道显示模型 | v1.2 核心方案 | 同时为真的事实，各走各的通道 —— 谁也不掩盖谁。 |
| 2 | 保持期时间线 | v1.2 核心方案 | 拦截/注意亮多久：info 桶只在保持期 H 内抬灯，超期转「待阅」；action 桶是待办，不按新闻处理。 |
| 3 | 研发中双信号 | v1.2 核心方案 | 「研发中」由版本比对驱动、常驻显示；与既有安全路径（自检解释）互不依赖，可同时为真。 |
| 4 | 六态封闭集合与来源分工 | v1.0 审核期留档 | R0 / L2 / L1 / Ls / L0 / dev 六态：性质、唯一来源、颜色动效，底部是光梯优先级。 |
| 5 | 当前实现的四步切换流程 | v1.0 审核期留档 | 姿态经「基础档 → 事件抬灯 → 篡改分通道 → 粮」得到灯态；红框标出事件维不过桶的断点。 |
| 6 | 同一批 49 条记录在两种口径下的灯态 | v1.0 审核期留档 | 24h 窗口内 49 条未处理记录：口径 A（数裸记录）得 L2 拦截，口径 B（只数要处理桶）得 L0。 |
| 7 | 判据 S10 与 S15 的矛盾及修法 | v1.0 审核期留档 | 两条判据期待相反却各自绿；修法是补 S10 夹具、把 S15 改为机制级可达。 |
| 8 | 修法三策边界影响对照 | v1.0 审核期留档 | 维持现状 / 上策（只有要处理桶抬灯）/ 中策（预留待认领拦截语义位）五维对照。 |

---

## 一、v1.2 核心方案的三张图

### 图 1 · 三通道显示模型

**这张图说什么**：同时为真的事实，各走各的通道 —— 谁也不掩盖谁。

| 维度 | 说法 |
|---|---|
| 主灯（互斥） | R0 / L2 / L1 / L0 —— 答「此刻什么情况」，同一维度取最高 |
| 徽标（并存） | 研发中 / 缺粮 —— 答「还有哪些并存态」，常驻、可多枚 |
| 计数（待办/待阅） | 要处理 N / 待阅 N —— 答「多少事没办、没看」，不互斥 |
| 来源分工 | 姿态·此刻 ⇒ 基础档；事件账·24h ⇒ 只抬 L2/L1；粮 ⇒ 徽标；版本 ⇒ 徽标 |
| 一句话判据 | 研发中 ＋ 失守 ＋ 要处理 N 可**同时显示**（旧单值梯只能出一个） |

**原样 SVG**（源文件 `output/_widgets/figV12_1_three_channels.svg`）：

```svg
<svg viewBox="0 0 680 404" width="100%" role="img">
  <title>三通道显示模型</title>
  <desc>主灯互斥、徽标并存、计数待办；同时为真的事实各走各的通道，互不掩盖</desc>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>
  <text class="th" x="340" y="26" text-anchor="middle">三通道显示模型：同时为真的事实，各走各的通道</text>

  <g>
    <rect x="40" y="64" width="118" height="44" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="99" y="86" text-anchor="middle" dominant-baseline="central">姿态 · 此刻</text>
    <rect x="40" y="128" width="118" height="44" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="99" y="150" text-anchor="middle" dominant-baseline="central">事件账 · 24h</text>
    <rect x="40" y="196" width="118" height="44" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="99" y="218" text-anchor="middle" dominant-baseline="central">粮 · 口粮/积分</text>
    <rect x="40" y="260" width="118" height="44" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="99" y="282" text-anchor="middle" dominant-baseline="central">版本 · 本机/PyPI</text>
  </g>

  <path class="arr" d="M158 86 L218 86" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M158 144 L218 96" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M158 158 L218 306" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M158 218 L218 218" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M158 276 L218 238" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>

  <g>
    <rect x="224" y="48" width="252" height="76" rx="12" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
    <text class="th" x="236" y="66" dominant-baseline="central" fill="#0C447C">主灯 · 此刻什么情况（互斥取最高）</text>
    <rect x="236" y="80" width="40" height="24" rx="6" fill="#FCEBEB" stroke="#A32D2D" stroke-width="0.5"/>
    <text class="ts" x="256" y="92" text-anchor="middle" dominant-baseline="central" fill="#791F1F">R0</text>
    <rect x="284" y="80" width="40" height="24" rx="6" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
    <text class="ts" x="304" y="92" text-anchor="middle" dominant-baseline="central" fill="#633806">L2</text>
    <rect x="332" y="80" width="40" height="24" rx="6" fill="#FAEEDA" stroke="#BA7517" stroke-width="0.5"/>
    <text class="ts" x="352" y="92" text-anchor="middle" dominant-baseline="central" fill="#854F0B">L1</text>
    <rect x="380" y="80" width="44" height="24" rx="6" fill="#EAF3DE" stroke="#3B6D11" stroke-width="0.5"/>
    <text class="ts" x="402" y="92" text-anchor="middle" dominant-baseline="central" fill="#27500A">L0</text>
    <text class="ts" x="236" y="114" dominant-baseline="central" fill="#0C447C">姿态定基础档；事件只抬 L2/L1；R0 绝不由账给</text>
  </g>

  <g>
    <rect x="224" y="180" width="252" height="76" rx="12" fill="#EEEDFE" stroke="#534AB7" stroke-width="0.5"/>
    <text class="th" x="236" y="198" dominant-baseline="central" fill="#3C3489">徽标 · 并存态（常驻，不跟灯抢档）</text>
    <rect x="236" y="212" width="72" height="24" rx="6" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
    <text class="ts" x="272" y="224" text-anchor="middle" dominant-baseline="central" fill="#0C447C">研发中</text>
    <rect x="316" y="212" width="60" height="24" rx="6" fill="#EEEDFE" stroke="#534AB7" stroke-width="0.5"/>
    <text class="ts" x="346" y="224" text-anchor="middle" dominant-baseline="central" fill="#3C3489">缺粮</text>
    <text class="ts" x="236" y="246" dominant-baseline="central" fill="#3C3489">研发中＝版本高于 PyPI；缺粮＝口粮低或积分未补</text>
  </g>

  <g>
    <rect x="224" y="288" width="252" height="76" rx="12" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="th" x="236" y="306" dominant-baseline="central">计数 · 没办 / 没看</text>
    <rect x="236" y="320" width="84" height="24" rx="6" fill="#fff" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="278" y="332" text-anchor="middle" dominant-baseline="central">要处理 N</text>
    <rect x="328" y="320" width="76" height="24" rx="6" fill="#fff" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="ts" x="366" y="332" text-anchor="middle" dominant-baseline="central">待阅 N</text>
    <text class="ts" x="236" y="354" dominant-baseline="central">action 桶件事 / info 桶未处理（含过保持期的）</text>
  </g>

  <path class="arr" d="M476 92 L516 168" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M476 232 L516 196" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>
  <path class="arr" d="M476 322 L516 224" fill="none" stroke="#5F5E5A" marker-end="url(#arrow)"/>

  <g>
    <rect x="520" y="116" width="120" height="180" rx="12" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
    <text class="th" x="580" y="140" text-anchor="middle" dominant-baseline="central">渲染面</text>
    <text class="ts" x="532" y="168" dominant-baseline="central">窗口标题 · 主灯</text>
    <text class="ts" x="532" y="194" dominant-baseline="central">页面条 · 主灯＋徽标</text>
    <text class="ts" x="532" y="220" dominant-baseline="central">托盘 · 主灯＋徽标</text>
    <text class="ts" x="532" y="246" dominant-baseline="central">归因面板 · 全量</text>
    <text class="ts" x="532" y="272" dominant-baseline="central">标题带不带徽标</text>
    <text class="ts" x="532" y="288" dominant-baseline="central">待拍板</text>
  </g>

  <text class="ts" x="340" y="388" text-anchor="middle" dominant-baseline="central">例：研发中的机器此刻失守 ＝ dev 徽标 ＋ R0 主灯 ＋ 要处理 N —— 三个事实同时显示，互不掩盖</text>
</svg>
```

### 图 2 · 保持期时间线

**这张图说什么**：拦截/注意亮多久：info 桶只在保持期 H 内抬灯，超期转「待阅」；action 桶是待办，不按新闻处理。

| 维度 | 说法 |
|---|---|
| info 桶（自动处理） | T0 → T0＋H 内且未读 ⇒ 亮灯；过 H 或已读 ⇒ 只进「待阅 N」；T0＋24h ⇒ 归档 |
| action 桶（要你处理） | 持续亮到处理完（24h 窗口内；超期进归档）—— 待办不是新闻 |
| 修掉的两条旧账 | ① 22 小时前的自动拦截把灯钉死；② 已读不提前结束（OPEN_STATES 含 read） |
| R0 / 毒通道 | R0 绝不由账给；毒通道（篡改类）永不抬灯 —— 两条都**不**受保持期影响 |

**原样 SVG**（源文件 `output/_widgets/figV12_2_hold_period.svg`）：

```svg
<svg viewBox="0 0 680 336" width="100%" role="img">
  <title>保持期时间线</title>
  <desc>info 桶事件只在保持期 H 内抬灯，超期进待阅计数；action 桶待办持续到处理完</desc>
  <defs>
    <marker id="arrow2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>
  <text class="th" x="340" y="26" text-anchor="middle">保持期：拦截/注意亮多久（时间轴断裂，不按比例）</text>

  <line x1="60" y1="64" x2="620" y2="64" stroke="#888780" stroke-width="1"/>
  <line x1="240" y1="58" x2="240" y2="176" stroke="#888780" stroke-width="0.5" stroke-dasharray="4 3"/>
  <line x1="380" y1="198" x2="380" y2="258" stroke="#888780" stroke-width="0.5" stroke-dasharray="4 3"/>
  <path d="M248 64 L254 60 L254 68 Z" fill="#888780"/>
  <path d="M612 64 L606 60 L606 68 Z" fill="#888780"/>
  <text class="ts" x="60" y="84" text-anchor="middle" dominant-baseline="central">T0 拦截发生</text>
  <text class="ts" x="240" y="84" text-anchor="middle" dominant-baseline="central" fill="#633806">T0＋H</text>
  <text class="ts" x="620" y="84" text-anchor="middle" dominant-baseline="central">T0＋24h</text>

  <text class="th" x="40" y="118" dominant-baseline="central">info 桶 · 自动处理的拦截/注意（你知情即可）</text>
  <rect x="60" y="128" width="180" height="40" rx="6" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
  <text class="ts" x="150" y="148" text-anchor="middle" dominant-baseline="central" fill="#633806">拦截（亮灯）</text>
  <rect x="240" y="128" width="380" height="40" rx="6" fill="#EAF3DE" stroke="#3B6D11" stroke-width="0.5"/>
  <text class="ts" x="256" y="148" dominant-baseline="central" fill="#27500A">值守中</text>
  <rect x="330" y="136" width="88" height="24" rx="6" fill="#fff" stroke="#5F5E5A" stroke-width="0.5"/>
  <text class="ts" x="374" y="148" text-anchor="middle" dominant-baseline="central">待阅 N（11）</text>
  <rect x="520" y="136" width="60" height="24" rx="6" fill="#fff" stroke="#5F5E5A" stroke-width="0.5"/>
  <text class="ts" x="550" y="148" text-anchor="middle" dominant-baseline="central">归档</text>

  <text class="th" x="40" y="196" dominant-baseline="central">action 桶 · 要你处理的（待办不是新闻）</text>
  <rect x="60" y="206" width="320" height="40" rx="6" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
  <text class="ts" x="220" y="226" text-anchor="middle" dominant-baseline="central" fill="#633806">持续亮到处理完（24h 窗口内，超期进归档）</text>
  <rect x="380" y="206" width="240" height="40" rx="6" fill="#F1EFE8" stroke="#888780" stroke-width="0.5"/>
  <text class="ts" x="500" y="226" text-anchor="middle" dominant-baseline="central">已处理 · 关闭</text>
  <text class="ts" x="380" y="192" text-anchor="middle" dominant-baseline="central">处理/关闭</text>

  <rect x="40" y="268" width="600" height="52" rx="8" fill="#FCEBEB" stroke="#A32D2D" stroke-width="0.5" stroke-dasharray="5 3"/>
  <text class="ts" x="56" y="286" dominant-baseline="central" fill="#791F1F">现行规则：24h 窗口内未处理即一直亮 —— 今早 11 条 22 小时前的自动拦截把灯钉死在「拦截」</text>
  <text class="ts" x="56" y="306" dominant-baseline="central" fill="#791F1F">且已读不提前结束（未处理＝未读＋已读，OPEN_STATES 含 read）；保持期机制一次修掉这两条</text>
</svg>
```

### 图 3 · 研发中双信号

**这张图说什么**：「研发中」由版本比对驱动、常驻显示；与既有安全路径（自检解释）互不依赖，可同时为真。

| 维度 | 说法 |
|---|---|
| 路径 A（本轮新增） | 本机版本 > PyPI 已发布 ⇒ 研发中徽标；上传成功＋实查回写 ⇒ 自动消失 |
| 路径 B（本轮不动） | 自检不符＋manifest 落差 ⇒ posture=dev / dev_drift —— 解释漂移，不点 dev 灯 |
| 降级纪律 | 取不到版本对照（facts 缺失/解析失败）⇒ 不显示徽标（降级不假阳） |
| 现存缺口 | 今日「研发中」根本不显示 —— 因为旧实现要等自检漂移才出现 |

**原样 SVG**（源文件 `output/_widgets/figV12_3_dev_badge.svg`）：

```svg
<svg viewBox="0 0 680 312" width="100%" role="img">
  <title>研发中双信号</title>
  <desc>版本比对驱动常驻徽标（发布身份）；自检落差服务安全路径（解释漂移）；两套信号互不依赖</desc>
  <defs>
    <marker id="arrow3" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>
  <text class="th" x="340" y="26" text-anchor="middle">研发中：两套信号，两个问题（徽标常驻，安全路径不动）</text>

  <text class="ts" x="40" y="52" dominant-baseline="central" fill="#0C447C">路径 A · 发布身份（本轮新增，驱动徽标）</text>
  <rect x="40" y="62" width="160" height="56" rx="8" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
  <text class="th" x="120" y="82" text-anchor="middle" dominant-baseline="central" fill="#0C447C">本机代码版本</text>
  <text class="ts" x="120" y="102" text-anchor="middle" dominant-baseline="central" fill="#0C447C">0.50.6</text>
  <rect x="236" y="62" width="176" height="56" rx="8" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
  <text class="th" x="324" y="82" text-anchor="middle" dominant-baseline="central" fill="#0C447C">PyPI 已发布版本</text>
  <text class="ts" x="324" y="102" text-anchor="middle" dominant-baseline="central" fill="#0C447C">0.35.1（实查回写）</text>
  <rect x="448" y="62" width="192" height="56" rx="8" fill="#B5D4F4" stroke="#185FA5" stroke-width="0.5"/>
  <text class="th" x="544" y="82" text-anchor="middle" dominant-baseline="central" fill="#042C53">高于 ⇒ 研发中徽标</text>
  <text class="ts" x="544" y="102" text-anchor="middle" dominant-baseline="central" fill="#0C447C">常驻，与主灯同时显示</text>
  <path class="arr" d="M200 90 L230 90" fill="none" stroke="#185FA5" marker-end="url(#arrow3)"/>
  <path class="arr" d="M412 90 L442 90" fill="none" stroke="#185FA5" marker-end="url(#arrow3)"/>
  <rect x="448" y="136" width="192" height="48" rx="8" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
  <text class="ts" x="544" y="153" text-anchor="middle" dominant-baseline="central" fill="#0C447C">上传成功＋实查回写 ⇒ 徽标自动消失</text>
  <text class="ts" x="544" y="171" text-anchor="middle" dominant-baseline="central" fill="#0C447C">（靠事实追平，不靠时间）</text>
  <path class="arr" d="M544 118 L544 130" fill="none" stroke="#185FA5" marker-end="url(#arrow3)"/>
  <rect x="40" y="136" width="372" height="48" rx="8" fill="#F1EFE8" stroke="#888780" stroke-width="0.5" stroke-dasharray="4 3"/>
  <text class="ts" x="56" y="153" dominant-baseline="central">取不到版本对照（facts 缺失/解析失败）⇒ 不显示徽标</text>
  <text class="ts" x="56" y="171" dominant-baseline="central">（降级不假阳；现行 posture=dev 要等自检漂移才出现，所以「研发中」今天根本不显示）</text>
  <path class="arr" d="M448 96 L420 150" fill="none" stroke="#888780" stroke-dasharray="4 3" marker-end="url(#arrow3)"/>

  <text class="ts" x="40" y="212" dominant-baseline="central" fill="#5F5E5A">路径 B · 自检解释（既有安全路径，本轮不动）</text>
  <rect x="40" y="222" width="200" height="56" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
  <text class="th" x="140" y="242" text-anchor="middle" dominant-baseline="central">自检不符＋manifest 落差</text>
  <text class="ts" x="140" y="262" text-anchor="middle" dominant-baseline="central">is_dev_build()（host_shield）</text>
  <rect x="276" y="222" width="180" height="56" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
  <text class="th" x="366" y="242" text-anchor="middle" dominant-baseline="central">posture=dev / dev_drift</text>
  <text class="ts" x="366" y="262" text-anchor="middle" dominant-baseline="central">解释漂移来源；不点 dev 灯</text>
  <rect x="492" y="222" width="148" height="56" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
  <text class="th" x="566" y="242" text-anchor="middle" dominant-baseline="central">安全路径</text>
  <text class="ts" x="566" y="262" text-anchor="middle" dominant-baseline="central">0364 钉的边界，不动</text>
  <path class="arr" d="M240 250 L270 250" fill="none" stroke="#5F5E5A" marker-end="url(#arrow3)"/>
  <path class="arr" d="M456 250 L486 250" fill="none" stroke="#5F5E5A" marker-end="url(#arrow3)"/>

  <text class="ts" x="340" y="300" text-anchor="middle" dominant-baseline="central">徽标回答「这一版发没发出去」；安全路径回答「漂移是不是我自己改的」——互不依赖，可同时为真</text>
</svg>
```

---

## 二、v1.0 规格审核期的五张图（历史留档）

> 留档理由：「旧单值灯为什么必须拆掉」的推导在这五张图里是**可复核的现场**，
> v1.2 §1 的三条证据引用的正是它们。删了图，证据链就只剩结论。

### 图 4 · 六态封闭集合与来源分工

**这张图说什么**：R0 / L2 / L1 / Ls / L0 / dev 六态：性质、唯一来源、颜色动效，底部是光梯优先级。

**原样 SVG**（源文件 `output/_widgets/figV10_1_six_states.svg`）：

```svg
<svg viewBox="0 0 680 400" width="100%" role="img">
<title>六态封闭集合与来源分工</title>
<desc>R0 失守、L2 拦截、L1 注意、Ls 缺粮、L0 值守中、dev 研发中六态，各自标注性质、唯一来源、颜色动效，底部为光梯优先级。</desc>
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</marker>
</defs>
<text x="40" y="26" font-size="14" font-weight="500" fill="#2C2C2A">六态封闭集合 · 来源分工（0.39.0 决议）</text>
<text x="40" y="46" font-size="12" fill="#5F5E5A">短名唯一真源 STATE_LABEL；集合外一律 L1 盲区，绝不打绿</text>
<g>
<rect x="40" y="64" width="186" height="96" rx="10" fill="#FCEBEB" stroke="#A32D2D" stroke-width="0.5"/>
<text x="54" y="88" font-size="14" font-weight="500" fill="#791F1F">R0 · 失守</text>
<text x="54" y="110" font-size="12" fill="#A32D2D">状态态 · 只由此刻</text>
<text x="54" y="128" font-size="12" fill="#5F5E5A">红 · 停摆动效</text>
<text x="54" y="146" font-size="12" fill="#444441">没挡住／没人守门</text>
</g>
<g>
<rect x="246" y="64" width="186" height="96" rx="10" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
<text x="260" y="88" font-size="14" font-weight="500" fill="#633806">L2 · 拦截</text>
<text x="260" y="110" font-size="12" fill="#854F0B">事件态 · 只由账</text>
<text x="260" y="128" font-size="12" fill="#5F5E5A">明黄 · 5.5s 扫描</text>
<text x="260" y="146" font-size="12" fill="#444441">危险操作被挡住了</text>
</g>
<g>
<rect x="452" y="64" width="186" height="96" rx="10" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
<text x="466" y="88" font-size="14" font-weight="500" fill="#633806">L1 · 注意</text>
<text x="466" y="110" font-size="12" fill="#854F0B">兼有 · 此刻＋账</text>
<text x="466" y="128" font-size="12" fill="#5F5E5A">浅黄 · 8s 扫描</text>
<text x="466" y="146" font-size="12" fill="#444441">知情即可的变动</text>
</g>
<g>
<rect x="40" y="176" width="186" height="96" rx="10" fill="#FAEEDA" stroke="#BA7517" stroke-width="0.5"/>
<text x="54" y="200" font-size="14" font-weight="500" fill="#633806">Ls · 缺粮</text>
<text x="54" y="222" font-size="12" fill="#854F0B">状态态 · 只由此刻</text>
<text x="54" y="240" font-size="12" fill="#5F5E5A">橙 · 3.5s 扫描</text>
<text x="54" y="258" font-size="12" fill="#444441">粮低于一周口粮</text>
</g>
<g>
<rect x="246" y="176" width="186" height="96" rx="10" fill="#EAF3DE" stroke="#3B6D11" stroke-width="0.5"/>
<text x="260" y="200" font-size="14" font-weight="500" fill="#27500A">L0 · 值守中</text>
<text x="260" y="222" font-size="12" fill="#3B6D11">状态态 · 只由此刻</text>
<text x="260" y="240" font-size="12" fill="#5F5E5A">绿 · 12s（灰＝未启用）</text>
<text x="260" y="258" font-size="12" fill="#444441">此刻没查到要紧事</text>
</g>
<g>
<rect x="452" y="176" width="186" height="96" rx="10" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
<text x="466" y="200" font-size="14" font-weight="500" fill="#0C447C">dev · 研发中</text>
<text x="466" y="222" font-size="12" fill="#185FA5">状态态 · 只由此刻</text>
<text x="466" y="240" font-size="12" fill="#5F5E5A">蓝 · 复用 L1 动图</text>
<text x="466" y="258" font-size="12" fill="#444441">代码比登记的新</text>
</g>
<text x="40" y="302" font-size="12" fill="#5F5E5A">光梯 PRIORITY —— 越靠上离「领地停摆」越近（品牌动效语法 v1.2：黄梯＝越来越急，红是另一回事）</text>
<g>
<rect x="40" y="316" width="100" height="48" rx="8" fill="#F7C1C1" stroke="#A32D2D" stroke-width="0.5"/>
<text x="90" y="336" font-size="13" font-weight="500" fill="#791F1F" text-anchor="middle" dominant-baseline="central">R0 失守</text>
<text x="90" y="354" font-size="12" fill="#A32D2D" text-anchor="middle" dominant-baseline="central">优先级 5</text>
</g>
<text x="152" y="344" font-size="13" fill="#888780" text-anchor="middle" dominant-baseline="central">&gt;</text>
<g>
<rect x="164" y="316" width="100" height="48" rx="8" fill="#FAC775" stroke="#BA7517" stroke-width="0.5"/>
<text x="214" y="336" font-size="13" font-weight="500" fill="#633806" text-anchor="middle" dominant-baseline="central">Ls 缺粮</text>
<text x="214" y="354" font-size="12" fill="#854F0B" text-anchor="middle" dominant-baseline="central">优先级 4</text>
</g>
<text x="276" y="344" font-size="13" fill="#888780" text-anchor="middle" dominant-baseline="central">&gt;</text>
<g>
<rect x="288" y="316" width="100" height="48" rx="8" fill="#EF9F27" stroke="#854F0B" stroke-width="0.5"/>
<text x="338" y="336" font-size="13" font-weight="500" fill="#412402" text-anchor="middle" dominant-baseline="central">L2 拦截</text>
<text x="338" y="354" font-size="12" fill="#412402" text-anchor="middle" dominant-baseline="central">优先级 3</text>
</g>
<text x="400" y="344" font-size="13" fill="#888780" text-anchor="middle" dominant-baseline="central">&gt;</text>
<g>
<rect x="412" y="316" width="100" height="48" rx="8" fill="#FAEEDA" stroke="#BA7517" stroke-width="0.5"/>
<text x="462" y="336" font-size="13" font-weight="500" fill="#633806" text-anchor="middle" dominant-baseline="central">L1 注意</text>
<text x="462" y="354" font-size="12" fill="#854F0B" text-anchor="middle" dominant-baseline="central">优先级 2</text>
</g>
<text x="524" y="344" font-size="13" fill="#888780" text-anchor="middle" dominant-baseline="central">&gt;</text>
<g>
<rect x="536" y="316" width="100" height="48" rx="8" fill="#C0DD97" stroke="#3B6D11" stroke-width="0.5"/>
<text x="586" y="336" font-size="13" font-weight="500" fill="#27500A" text-anchor="middle" dominant-baseline="central">L0 值守中</text>
<text x="586" y="354" font-size="12" fill="#3B6D11" text-anchor="middle" dominant-baseline="central">优先级 1</text>
</g>
<text x="40" y="388" font-size="12" fill="#5F5E5A">dev 不在光梯上（值 0）：任何真实信号都盖过它；只在无信号时作为解释灯出现（0.36.4：研发中不掩盖真实状况）</text>
</svg>
```

### 图 5 · 当前实现的四步切换流程

**这张图说什么**：姿态经「基础档 → 事件抬灯 → 篡改分通道 → 粮」得到灯态；红框标出事件维不过桶的断点。

**原样 SVG**（源文件 `output/_widgets/figV10_2_four_steps.svg`）：

```svg
<svg viewBox="0 0 680 470" width="100%" role="img">
<title>当前实现的四步切换流程</title>
<desc>此刻姿态经基础档、事件抬灯、篡改分通道、粮四步得到灯态；红框为事件维不过桶的断点，右侧列出 P1、P3、P7 三个界限模糊点。</desc>
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</marker>
</defs>
<text x="40" y="26" font-size="14" font-weight="500" fill="#2C2C2A">当前实现的四步切换（口径 A，inbox_model.py:1169-1223）</text>
<text x="40" y="46" font-size="12" fill="#5F5E5A">红框＝今早拍板的断点；虚线引出另外三处界限模糊点</text>
<g>
<rect x="60" y="62" width="300" height="36" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
<text x="210" y="80" font-size="13" font-weight="500" fill="#444441" text-anchor="middle" dominant-baseline="central">此刻姿态（down/warn/guarding/interrupted/unknown/off/dev）</text>
</g>
<path d="M210 98 L210 112" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="60" y="114" width="300" height="56" rx="8" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
<text x="74" y="136" font-size="13" font-weight="500" fill="#0C447C">Step 0 · 基础档 base_state()</text>
<text x="74" y="156" font-size="12" fill="#185FA5">七姿态各自映射；集合外 ⇒ L1 盲区（绝不打绿）</text>
</g>
<path d="M210 170 L210 184" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="60" y="186" width="300" height="88" rx="8" fill="#FCEBEB" stroke="#A32D2D" stroke-width="1.5"/>
<text x="74" y="208" font-size="13" font-weight="500" fill="#791F1F">Step 1 · 事件抬灯（口径 A）</text>
<text x="74" y="228" font-size="12" fill="#A32D2D">窗口内 OPEN 且级∈(L2,L1) 且非 dev 通道，取最高</text>
<text x="74" y="246" font-size="12" fill="#A32D2D">R0 记录排除（铁律一：历史失守不回溯）</text>
<text x="74" y="264" font-size="12" font-weight="500" fill="#A32D2D">取数口 _window_open：不过桶 ⇐ 断点在这里</text>
</g>
<path d="M210 274 L210 288" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="60" y="290" width="300" height="56" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
<text x="74" y="312" font-size="13" font-weight="500" fill="#444441">Step 2 · 篡改分通道</text>
<text x="74" y="332" font-size="12" fill="#5F5E5A">poison 在场不动；dev 在场且档∈(L0,dev) ⇒ dev</text>
</g>
<path d="M210 346 L210 360" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="60" y="362" width="300" height="48" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
<text x="74" y="382" font-size="13" font-weight="500" fill="#444441">Step 3 · 粮</text>
<text x="74" y="400" font-size="12" fill="#5F5E5A">粮低且姿态∈(在岗,研发) ⇒ Ls，按光梯比级</text>
</g>
<path d="M210 410 L210 424" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="60" y="426" width="300" height="36" rx="8" fill="#444441" stroke="#444441" stroke-width="0.5"/>
<text x="210" y="444" font-size="13" font-weight="500" fill="#FFFFFF" text-anchor="middle" dominant-baseline="central">灯态 current_state() ⇒ 页面唯一真源</text>
</g>
<path d="M360 230 L392 210" fill="none" stroke="#A32D2D" stroke-width="0.5" stroke-dasharray="3 3"/>
<g>
<rect x="394" y="168" width="246" height="92" rx="8" fill="#FCEBEB" stroke="#A32D2D" stroke-width="0.5"/>
<text x="408" y="190" font-size="13" font-weight="500" fill="#791F1F">P1 · 事件维不过桶</text>
<text x="408" y="210" font-size="12" fill="#A32D2D">唯一 L2 kind 就在自动处理黑名单</text>
<text x="408" y="228" font-size="12" fill="#A32D2D">⇒ 灯只能被「不用你动手」的事点亮</text>
<text x="408" y="246" font-size="12" fill="#444441">今早裁定：这种时刻应该是值守中</text>
</g>
<path d="M360 386 L392 330" fill="none" stroke="#888780" stroke-width="0.5" stroke-dasharray="3 3"/>
<g>
<rect x="394" y="286" width="246" height="76" rx="8" fill="#F1EFE8" stroke="#888780" stroke-width="0.5"/>
<text x="408" y="308" font-size="13" font-weight="500" fill="#444441">P3 · off 姿态也抬灯</text>
<text x="408" y="328" font-size="12" fill="#5F5E5A">未启用＋历史 L2 账 ⇒ L2</text>
<text x="408" y="346" font-size="12" fill="#5F5E5A">Step 1 不检查姿态，界限未定义</text>
</g>
<path d="M360 318 L392 420" fill="none" stroke="#888780" stroke-width="0.5" stroke-dasharray="3 3"/>
<g>
<rect x="394" y="388" width="246" height="76" rx="8" fill="#F1EFE8" stroke="#888780" stroke-width="0.5"/>
<text x="408" y="410" font-size="13" font-weight="500" fill="#444441">P7 · 历史记录挂研发中</text>
<text x="408" y="430" font-size="12" fill="#5F5E5A">guarding＋历史 dev_drift ⇒ dev 灯</text>
<text x="408" y="448" font-size="12" fill="#5F5E5A">dev 是身份态，只该由此刻给</text>
</g>
</svg>
```

### 图 6 · 同一批 49 条记录在两种口径下的灯态

**这张图说什么**：24h 窗口内 49 条未处理记录：口径 A（数裸记录）得 L2 拦截，口径 B（只数要处理桶）得 L0。

**原样 SVG**（源文件 `output/_widgets/figV10_3_two_calibers.svg`）：

```svg
<svg viewBox="0 0 680 420" width="100%" role="img">
<title>同一批 49 条窗口记录在两种口径下的灯态</title>
<desc>24 小时窗口内 49 条未处理记录，桶口径全部为看一眼；口径 A 数裸记录得 L2 拦截，口径 B 只数要处理桶得 L0 值守中。</desc>
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</marker>
</defs>
<text x="40" y="26" font-size="14" font-weight="500" fill="#2C2C2A">同一批 49 条窗口记录：两种口径，两个灯态</text>
<text x="40" y="46" font-size="12" fill="#5F5E5A">2026-10-16 早实测（_p_lamp_truth.py）· 姿态 guarding · 要处理 0 条</text>
<g>
<rect x="60" y="66" width="126" height="44" rx="4" fill="#EF9F27" stroke="#854F0B" stroke-width="0.5"/>
<text x="123" y="88" font-size="12" font-weight="500" fill="#412402" text-anchor="middle" dominant-baseline="central">L2 × 11</text>
<rect x="186" y="66" width="434" height="44" rx="4" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
<text x="403" y="88" font-size="12" fill="#633806" text-anchor="middle" dominant-baseline="central">L1 × 38（自愈 18 · 已自愈投毒 14 · 上锁成功 6）</text>
</g>
<text x="60" y="128" font-size="12" fill="#5F5E5A">24h 窗口内未处理（unread/read）共 49 条；左边 11 条是监理拦下的危险操作（AN-020 拦 git checkout 等），右边 38 条是自愈与状态留痕</text>
<g>
<rect x="60" y="142" width="560" height="32" rx="8" fill="#EAF3DE" stroke="#3B6D11" stroke-width="0.5"/>
<text x="340" y="158" font-size="12" font-weight="500" fill="#27500A" text-anchor="middle" dominant-baseline="central">桶口径：要处理 0 · 看一眼 49 · 归档 654 ⇒ 49 条全部「知情即可」</text>
</g>
<path d="M185 178 L185 200" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<path d="M475 178 L475 200" fill="none" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
<g>
<rect x="40" y="202" width="290" height="152" rx="10" fill="#FAEEDA" stroke="#BA7517" stroke-width="1"/>
<text x="56" y="226" font-size="13" font-weight="500" fill="#633806">口径 A（现状）· Step 1 数裸记录</text>
<text x="56" y="246" font-size="12" fill="#854F0B">_window_open：窗口内 OPEN 就要，不过桶</text>
<rect x="56" y="260" width="258" height="40" rx="6" fill="#EF9F27" stroke="#854F0B" stroke-width="0.5"/>
<text x="185" y="280" font-size="15" font-weight="500" fill="#412402" text-anchor="middle" dominant-baseline="central">灯 ⇒ L2 拦截</text>
<text x="56" y="318" font-size="12" fill="#444441">拿「监理自己干得好的活」向你报警</text>
<text x="56" y="338" font-size="12" fill="#A32D2D">违反 0.35.3 与 0.39.0 两条裁定</text>
</g>
<g>
<rect x="350" y="202" width="290" height="152" rx="10" fill="#EAF3DE" stroke="#3B6D11" stroke-width="1.5"/>
<text x="366" y="226" font-size="13" font-weight="500" fill="#27500A">口径 B（上策）· 只有要处理桶抬灯</text>
<text x="366" y="246" font-size="12" fill="#3B6D11">bucket_of()==action 且级∈(L2,L1)，R0 仍排除</text>
<rect x="366" y="260" width="258" height="40" rx="6" fill="#97C459" stroke="#3B6D11" stroke-width="0.5"/>
<text x="495" y="280" font-size="15" font-weight="500" fill="#173404" text-anchor="middle" dominant-baseline="central">灯 ⇒ L0 值守中</text>
<text x="366" y="318" font-size="12" fill="#444441">要处理 0 ⇒ 灯只说此刻：此刻即此刻</text>
<text x="366" y="338" font-size="12" fill="#27500A">符合 0.35.3 + 0.39.0 + 今早裁定</text>
</g>
<text x="40" y="380" font-size="12" fill="#5F5E5A">「拦截」不退场——它仍是收件箱筛选级与事件标题级（「拦截：危险操作被挡下」作为一条记录的标题仍然成立）</text>
<text x="40" y="400" font-size="12" fill="#5F5E5A">代价：L2 当日不可达 ⇒ 0380 S15 须同批重签为「机制级可达」（见下一图）</text>
</svg>
```

### 图 7 · 判据 S10 与 S15 的矛盾及修法

**这张图说什么**：两条判据期待相反却各自绿；修法是补 S10 夹具、把 S15 改为机制级可达。

**原样 SVG**（源文件 `output/_widgets/figV10_4_judge_conflict.svg`）：

```svg
<svg viewBox="0 0 680 420" width="100%" role="img">
<title>判据 S10 与 S15 的矛盾及修法</title>
<desc>S10 期待在岗有账也是 L0 但夹具只有 R0 账；S15 要求在岗加拦截账必须亮 L2。两者期待相反却各自绿。修法是补 S10 夹具并把 S15 改为机制级可达。</desc>
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</marker>
<marker id="arrowl" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</marker>
</defs>
<text x="40" y="26" font-size="14" font-weight="500" fill="#2C2C2A">判据层矛盾：S10 与 S15 对同一输入期待相反，却双双绿</text>
<text x="40" y="46" font-size="12" fill="#5F5E5A">ci/inbox_guards_0380.py —— 判据是「一组抽检」不是「一份规格」，规格矛盾这一类缺陷没有对应物</text>
<g>
<rect x="40" y="62" width="290" height="172" rx="10" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
<text x="56" y="86" font-size="13" font-weight="500" fill="#0C447C">S10 灯＝此刻</text>
<text x="56" y="106" font-size="12" fill="#185FA5">期待表：guarding 有账也必须 L0</text>
<text x="56" y="124" font-size="12" fill="#185FA5">判据名：恒等于此刻态（与 24h 账无关）</text>
<line x1="56" y1="138" x2="314" y2="138" stroke="#B5D4F4" stroke-width="0.5"/>
<text x="56" y="158" font-size="12" fill="#5F5E5A">夹具只有：空 / R0 账 / 已处理 / 48h 前</text>
<text x="56" y="176" font-size="12" font-weight="500" fill="#A32D2D">没有一条 L2 或 L1 账</text>
<text x="56" y="196" font-size="12" fill="#5F5E5A">R0 恰好被铁律一排除 ⇒ 恰好全过</text>
<text x="56" y="216" font-size="12" fill="#A32D2D">⇒ 判据名是「愿望」，与实现不符</text>
</g>
<g>
<rect x="350" y="62" width="290" height="172" rx="10" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
<text x="366" y="86" font-size="13" font-weight="500" fill="#633806">S15 六态逐态可达</text>
<text x="366" y="106" font-size="12" fill="#854F0B">要求 (guarding, tool_call_blocked) ⇒ L2</text>
<text x="366" y="124" font-size="12" fill="#854F0B">否则「有态点不亮」即报红</text>
<line x1="366" y1="138" x2="624" y2="138" stroke="#FAC775" stroke-width="0.5"/>
<text x="366" y="158" font-size="12" fill="#5F5E5A">与 S10 对同一组合的期待正好相反</text>
<text x="366" y="176" font-size="12" font-weight="500" fill="#A32D2D">两边各喂不同夹具 ⇒ 双双绿</text>
<text x="366" y="196" font-size="12" fill="#5F5E5A">规格矛盾永远发现不了</text>
<text x="366" y="216" font-size="12" fill="#5F5E5A">撞见者是创始人截图，不是任何判据</text>
</g>
<path d="M330 148 L350 148" fill="none" stroke="#888780" stroke-width="1" marker-end="url(#arrow)"/>
<path d="M350 160 L330 160" fill="none" stroke="#888780" stroke-width="1" marker-end="url(#arrowl)"/>
<text x="340" y="136" font-size="11" fill="#5F5E5A" text-anchor="middle">guarding + L2 账</text>
<g>
<rect x="40" y="258" width="600" height="132" rx="10" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
<text x="56" y="282" font-size="13" font-weight="500" fill="#444441">修法（与产品策略正交——无论选哪策都要做）</text>
<text x="56" y="306" font-size="12" fill="#444441">① S10 夹具补 L2/L1 账 ⇒ 名字变实；谁把口径 A 改回来，S10 当场红（负控方向自动成立）</text>
<text x="56" y="328" font-size="12" fill="#444441">② S15 重签为「机制级可达」：monkeypatch AUTO_HANDLED_KINDS 造一条要处理桶 L2 记录 ⇒ 灯必须 L2；</text>
<text x="72" y="348" font-size="12" fill="#444441">还原 ⇒ 同一条记录回落看一眼桶 ⇒ 灯必须不是 L2。「L2 可达」不再依赖产品数据巧合</text>
<text x="56" y="372" font-size="12" fill="#444441">③ S11 原因句锚点「没处理」保留不动；文案随口径回「另外……」形态（0380 两条断言仍满足）</text>
</g>
</svg>
```

### 图 8 · 修法三策边界影响对照

**这张图说什么**：维持现状 / 上策（只有要处理桶抬灯）/ 中策（预留待认领拦截语义位）五维对照。

**原样 SVG**（源文件 `output/_widgets/figV10_5_three_plans.svg`）：

```svg
<svg viewBox="0 0 680 440" width="100%" role="img">
<title>修法三策边界影响对照</title>
<desc>维持现状、上策（只有要处理桶抬灯）、中策（预留待认领拦截语义位）三策，在灯态、L2 可达性、判据影响、符合裁定与代价五个维度对照。</desc>
<text x="40" y="26" font-size="14" font-weight="500" fill="#2C2C2A">修法三策：边界影响对照（等你拍板，一行代码未动）</text>
<text x="40" y="46" font-size="12" fill="#5F5E5A">下策（只改原因句不改状态词）已被你今早否掉，不列入</text>
<g>
<rect x="40" y="62" width="180" height="316" rx="10" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
<text x="56" y="86" font-size="13" font-weight="500" fill="#444441">A · 维持现状</text>
<text x="56" y="118" font-size="12" fill="#888780">当前灯态</text>
<text x="56" y="136" font-size="13" font-weight="500" fill="#854F0B">拦截</text>
<text x="56" y="160" font-size="12" fill="#888780">L2 可达性</text>
<text x="56" y="178" font-size="13" font-weight="500" fill="#444441">靠自动处理类</text>
<text x="56" y="202" font-size="12" fill="#888780">0380 S15</text>
<text x="56" y="220" font-size="13" font-weight="500" fill="#444441">绿（名不副实）</text>
<text x="56" y="244" font-size="12" fill="#888780">0380 S10</text>
<text x="56" y="262" font-size="13" font-weight="500" fill="#A32D2D">病（夹具缺口）</text>
<text x="56" y="286" font-size="12" fill="#888780">符合的裁定</text>
<text x="56" y="304" font-size="13" font-weight="500" fill="#444441">0.37.1 黄梯＝事件级</text>
<text x="56" y="328" font-size="12" fill="#888780">主要代价</text>
<text x="56" y="346" font-size="13" font-weight="500" fill="#A32D2D">灯拿「好活」报警</text>
</g>
<g>
<rect x="250" y="62" width="180" height="316" rx="10" fill="#EAF3DE" stroke="#3B6D11" stroke-width="1.5"/>
<rect x="342" y="52" width="68" height="22" rx="11" fill="#3B6D11"/>
<text x="376" y="63" font-size="12" font-weight="500" fill="#FFFFFF" text-anchor="middle" dominant-baseline="central">建议</text>
<text x="266" y="86" font-size="13" font-weight="500" fill="#27500A">B · 上策</text>
<text x="266" y="118" font-size="12" fill="#888780">当前灯态</text>
<text x="266" y="136" font-size="13" font-weight="500" fill="#27500A">值守中</text>
<text x="266" y="160" font-size="12" fill="#888780">L2 可达性</text>
<text x="266" y="178" font-size="13" font-weight="500" fill="#444441">当日不可达</text>
<text x="266" y="202" font-size="12" fill="#888780">0380 S15</text>
<text x="266" y="220" font-size="13" font-weight="500" fill="#444441">须同批重签</text>
<text x="266" y="244" font-size="12" fill="#888780">0380 S10</text>
<text x="266" y="262" font-size="13" font-weight="500" fill="#27500A">补夹具后名实相符</text>
<text x="266" y="286" font-size="12" fill="#888780">符合的裁定</text>
<text x="266" y="304" font-size="13" font-weight="500" fill="#444441">0.35.3＋0.39.0＋今早</text>
<text x="266" y="328" font-size="12" fill="#888780">主要代价</text>
<text x="266" y="346" font-size="13" font-weight="500" fill="#444441">S15 重签要你签字</text>
</g>
<g>
<rect x="460" y="62" width="180" height="316" rx="10" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
<text x="476" y="86" font-size="13" font-weight="500" fill="#0C447C">C · 中策</text>
<text x="476" y="118" font-size="12" fill="#888780">当前灯态</text>
<text x="476" y="136" font-size="13" font-weight="500" fill="#27500A">值守中</text>
<text x="476" y="160" font-size="12" fill="#888780">L2 可达性</text>
<text x="476" y="178" font-size="13" font-weight="500" fill="#444441">靠新 kind 点亮</text>
<text x="476" y="202" font-size="12" fill="#888780">0380 S15</text>
<text x="476" y="220" font-size="13" font-weight="500" fill="#444441">绿（新夹具）</text>
<text x="476" y="244" font-size="12" fill="#888780">0380 S10</text>
<text x="476" y="262" font-size="13" font-weight="500" fill="#27500A">同 B</text>
<text x="476" y="286" font-size="12" fill="#888780">符合的裁定</text>
<text x="476" y="304" font-size="13" font-weight="500" fill="#444441">同 B，另留语义位</text>
<text x="476" y="328" font-size="12" fill="#888780">主要代价</text>
<text x="476" y="346" font-size="13" font-weight="500" fill="#444441">无生产者的 kind</text>
</g>
<text x="40" y="404" font-size="12" fill="#5F5E5A">建议 B：灯回到 0.39.0 那句话的字面——「现在的准确状态」；「拦截」退回收件箱筛选级与事件标题级，不再冒充灯态</text>
<text x="40" y="424" font-size="12" fill="#5F5E5A">三策之外的固定动作：S10 补 L2/L1 夹具、S11 原因句锚点保留、B3（历史研发记录挂灯）独立小修</text>
</svg>
```

---

## 三、怎么把图看出来（内联 SVG 的最小样式）

八张图都用两个 class：`.th`（标题）、`.ts`（正文）；`arr` 路径的描边是内联的。
Markdown 渲染器若支持内联 SVG，把下面这段 `<style>` 放到图前面即可正常显示：

```html
<style>
/* 图解文档的最小样式：SVG 内联时用（自带浅色填充深色字，故配浅底） */
body{margin:0;padding:24px 20px 48px;background:#F7F6F2;
     color:#2C2C2A;font:14px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#6B6B66;font-size:12.5px;margin:0 0 24px}
figure{margin:0 0 30px;background:#fff;border:1px solid #E3E1DA;border-radius:12px;
       padding:14px 16px 18px}
figcaption{font-size:13px;font-weight:600;margin:0 0 4px}
.ess{color:#57564F;font-size:12.5px;margin:0 0 12px}
svg{display:block;width:100%;height:auto}
svg .th{font-size:13px;font-weight:600;fill:#2C2C2A;font-family:inherit}
svg .ts{font-size:11.5px;fill:#3F3F3B;font-family:inherit}
</style>
```

不想折腾样式就直接看 `output/figures_六态切换逻辑图解.html`（已带这段样式）。

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel 监理 UI 缺陷清单与修复计划（0.50.1）

- 盘点日期：2026-10-14
- 盘点范围：Antinel 监理 Web 面板（`inbox_server.py`）、冒泡窗（`inbox_bubble.py`）、漂浮哨标（`inbox_logo.py` ＋ `tools/logo.ps1`）、窗口认领（`inbox_window.py`）
- 本轮口径（用户原话）：**「具体指出来，不用修，列个修的计划即可。」**
- 本轮动作：**只读取证**。未修改任何产品文件；所有结论均由探针实测或逐行读码得出，凡未实测者已标注「需真机确认」。

---

## 0. 取证方法

| 探针 | 干什么 | 关键输出 |
|---|---|---|
| `_probe_reopen.py` | 把页面上每个 form 原样重放（含 `op=read`） | `重开按钮 -> HTTP 200 · application/json · {"ok": true}` |
| `_probe_cookie.py` | 模拟「浏览器禁用 Cookie」，分别发链接与表单 | 链接 → `403`；表单（body 带 `t`）→ **通过守卫** |
| `_probe_win.py` | 内存替换 `enum_windows`，放 5 个标题，比三条 finder | 哨标 finder 命中 `[2,3]`（含用户窗口）、冒泡命中 `[4,5]`；Antinel 监理 finder 正确只命中 `[1]` |
| `_probe_text3.py` | 扫渲染正文的括号嵌套 | `（1 件 / 1（最近 24 小时））` |
| `_probe_text2.py` | 扫空态正文 | 见 B3 原文 |

---

## A. 失效 / 可疑按钮（4 条，全部实测）

### A1 · 「重开」按钮点了落到一页裸 JSON（**真失效**）

**现象**：在「全部记录」或「归档」里展开一条已处置的记录，点「重开」→ 浏览器跳到一个只有一行 `{"ok": true}` 的白页，**没有任何返回入口**。

**根因**（两个入口共用一个 op）：
- `inbox_server.py:1051` 渲染的是**普通表单按钮**：`<form method=post action="/action"><input type=hidden name=op value="read">…`
- `inbox_server.py:2042-2045` 末尾：`if op == "read": return self._json({"ok": True})`
- 这条 JSON 分支是给页面 fetch 用的（`_READ_JS`，`inbox_server.py:356-384`：点开即已读），但 `read` 这个 op 同时被一个真表单复用 ⇒ 浏览器把 JSON 当文档渲染。

**加重项**：状态其实**写成功了**（`S.set_state(iid, "read")` 先执行）⇒ 是「半通」：用户看到 JSON 以为坏了，实际已经重开；按浏览器后退会**重新 POST** 一次。

**为什么 64+ 条守卫没抓到**（这条比缺陷本身更值得记）：
- `c_forms_replay`（`ci/inbox_guards.py:2017-2090`）确实会重放 `f=all` 渲染出的表单，但它的夹具条目恒为 `breach()`＝`unread` ⇒ 页面上**从不出现** `op=read` 的表单（`_item_html` 只在 `state ∈ (done, ignored)` 时才渲染「重开」）。
- 且它把 `st == 200` 当通过（`2080-2081` 只拦 403 与非 200/303）⇒ 即使重放到 `read`，`200 application/json` 也会**绿**。
- 判据覆盖的是「我以为的请求」，不是「用户真会点到的那个请求」——与 0.35.2 那次同型，**这是同族第四次漏网**。

**修法（二选一，都不改业务语义）**
- 方案①（推荐，最干净）：给「重开」单独的 op，例如 `reopen`，走 303 回 `/?v=inbox&f=<原筛选>`；`read` 从此只服务 fetch。
- 方案②（最小改动）：保留 `op=read`，在 `do_POST` 里按**已有**的请求头区分——`X-Antinel-Read: 1`（`_READ_JS` 已经带）⇒ 回 JSON；无此头 ⇒ 回 303。区分依据现成，不用新造。

**四件套**
- 正判据 `c_reopen_form_lands_on_page`：把页面上 `op=read` 的表单**原样重放**，断言 `303` 且 `Location` 指向 `/?v=inbox`，并且 **Content-Type 不是** `application/json`。
- 负控 `n_reopen_...`：把区分依据（`X-Antinel-Read` 判定／独立 op）拔掉 ⇒ 必须回到 `200 application/json` ⇒ 判据变红。**负控必须实测见过红**。
- 连带对照：`c_forms_replay` 的夹具补一条 `done` 状态的条目，让 `op=read` 进入重放集合（否则同族第四次漏网照旧）；同时把 `200` 从"通过"改成"**必须** 303 或 200-html"。
- 可观测：状态码 + `Content-Type` + `Location` 三样一起断言。

---

### A2 · 点漂浮哨标：哨标消失、面板不开（**半通**）

**现象**：用户点了屏幕上唯一的那枚哨标 ⇒ 它**自己退场**，Antinel 监理**没开**，什么都没发生。

**根因**：哨标点击的语义是「写一行 `open` 到 `tray_action.txt` ＋ 自己退场」（`tools/logo.ps1` 文件头协议注释、`inbox_logo.py:10`）。而 `open` 的**消费者只有两个**：
- `inbox_daemon.handle_actions()`（`inbox_daemon.py:255-274`，由守护进程循环在 `:436` 调用）
- 托盘自己的消费者（`inbox_tray.py:407`）

`grep handle_actions` 全仓仅此两处 ⇒ **Antinel 监理服务本身不消费动作**（`inbox_server.py` 里没有 `poll_actions`）。于是当现场只有「Antinel 监理服务 ＋ 哨标」（例如用 CLI 起的 `antinel inbox console --open`，没有常驻 daemon/tray）时：
1. 点击 → 动作写盘；
2. 哨标退出；
3. **没人来取** ⇒ 用户两手空空；
4. 动作文件留在盘上，等 daemon 下次启动时被取走 ⇒ 那时会**突然弹出一个Antinel 监理**，比不弹更怪。

这正是本仓最恨的形状（「点了没反应」），且它出现在**漂浮最小态的唯一交互**上。

**修法（按代价从低到高）**
- ① 哨标点击时**自己直接把面板开出来**（复用 `inbox_daemon.open_console_now`），动作文件只作留痕、不再依赖外部消费者。
- ② 或：写动作后**不退场**，并在 tip 上如实说「已登记，等Antinel 监理服务取走」——用户知道自己在等什么。
- ③ 或：服务端也起一个轻量消费者。安全前提已具备（`poll_actions` 用 `os.rename` 整文件改名＝原子消费，daemon/tray/服务三方同跑也**不会双开**，见 `inbox_daemon.py:261-262`）。

**四件套**
- 正判据 `c_logo_click_opens_without_consumer`：注入「现场没有 daemon/tray 消费者」＋ 假 `opener`，模拟点击 ⇒ 断言面板被打开（`opener` 被调用、窗口数 +1）。
- 负控：把 `opener` 换成"什么都不做" ⇒ 判据必须红（证明判据测的是"真开出来了"，不是"写了文件"）。
- 连带对照：既有的「点击写出 `open`」语义判据保留（它现在守的是**留痕**，不是**触达**）；新增的这条守**触达**。两者缺一，就会把"写了文件"当"开出来了"。
- 可观测：断言动作文件被消费（改名为 `.taken-*`）**或**面板窗口数 +1，二者取「真开出来」那一支。

---

### A3 · 未启用（`off`）时页面不给任何「下一步」

**现象**：灯是「未启用」，页面上既没有修复按钮，也**没有**「怎么开启」那句话。

**根因**（一句话：`fix_hint` 算了但没人显示）：
- `inbox_server.py:562-573`：`if p.get("can_fix"): …` → `off` 时 `can_fix=False`；
  接着 `elif p.get("state") in ("down", "warn", "interrupted"):` → `POSTURE_OFF = "off"`（`host_shield.py:2984`）**不在白名单** ⇒ `fix` 保持空串。
- 而 `host_shield.py:3173` 明确给了 `fix_hint = "要开启，在终端执行一次：antinel host-shield enable"`。

**后果**：用户看到「未启用」，却拿不到开启命令 —— 与 0.37.2 自己立的规矩（「失守/认不出/缺岗时必须给得出下一步」「绝不留一个点了没反应的按钮」）相悖。

**修法**：把 `elif` 的条件从「状态白名单」改成「**有 `fix_hint` 就显示**」：
```python
elif (p.get("fix_hint") or "").strip():
    fix = '<span class="fixnote"><b>怎么解决：</b>%s</span>' % _esc(p["fix_hint"])
```
`off` / `unknown` 一并覆盖；注意与 `can_fix` 分支互斥（`if/elif` 已保证）。

**四件套**
- 正判据 `c_off_state_shows_next_step`：造一个 `state=off` 的姿态，断言页面上出现 `antinel host-shield enable`。
- 负控：把 `fix_hint` 抽成空串 ⇒ 必须**不**出现（证明判据不是恒真）。
- 连带对照：`down` 状态的 `fixnote` 既有语义不许回退（同一分支，改动即回归面）。
- 可观测：断言 `class="fixnote"` 节点存在且文本含关键串（走 `PC.body()`，S48 纪律）。

---

### A4 · 修复按钮的文字是一整句（按钮当成了说明）

**现象**：按钮上写着「马上修复（重新拉起哨兵，让它重新登记心跳链）」（23 字）。

**根因**：`inbox_server.py:567-568` 把 `p.get("fix_hint")` 直接当按钮 label；`host_shield.py:3312` / `:3343` 的 `fix_hint` 就是整句。

**违和**：按钮是**动作**，括号里的是**理由**。理由该落在按钮旁边的 `fixnote`，不该挤进按钮。

**修法**：按钮固定短标签（「马上修复」）；`fix_hint` 的括号内容作 `fixnote` 显示在按钮旁。注意 `_bar` 里 `can_fix` 分支与 A3 的 `fixnote` 分支会同时存在，别重复输出。

**四件套**
- 正判据 `c_fix_button_label_is_short`：断言 `class="fixbtn"` 的文本 ≤ 6 字且**不含** `（`。
- 负控：把长 label 塞回去 ⇒ 红。
- 连带对照：`fixnote` 里必须**仍能看到**那句解释（「解释没丢」——防"为了短而把话说没了"）。
- 可观测：按钮文本长度 + `fixnote` 文本各断言一次。

---

## B. 语句违和（6 条）

### B1 · 403 页说「点任何链接/按钮都会被拒」——**对按钮是假的**

**实测**（`_probe_cookie.py`，模拟浏览器禁用 Cookie）：

| 请求 | 结果 |
|---|---|
| `GET /?v=inbox&f=all`（＝页面上的链接，不带 `?t=`） | `403` |
| `POST /action`，body 带 `t=`（＝页面表单按钮的原样请求） | **通过守卫**（拿到 409 业务拒绝，不是 403） |

**根因**：口令来源有优先级链（`inbox_server.py:1767-1791`）：query `?t=` → 请求头 → **cookie** → **POST body**。表单把口令放在 body 的 hidden 字段（`_form`，`inbox_server.py:1023-1037`）⇒ 禁用 Cookie 后**按钮仍能提交**，只有**链接**（不带 `?t=`）会 403。

**原文**（`inbox_server.py:1747-1749`）：
> 另一种可能：你的浏览器**禁用了 Cookie**。本页的口令靠一枚 HttpOnly cookie 在站内携带；禁用后页面能打开，**但点任何链接/按钮都会被拒**。请在浏览器设置里允许本站使用 Cookie。

**后果**：把"按钮也全废"的错话写给用户 —— 用户可能因此放弃点击、跑去改浏览器设置，而真实情况是"链接坏了、按钮还活着，但按钮的落点体验也不完整"。

**修法**：要么把话说准（「点页面里的**链接**会被拒；表单按钮仍能提交」），要么更干脆——禁用 Cookie 时**首屏就把口令留在 URL 上**（回退到 0.48.6 之前的 `?t=` 导航），让整页可用。

**四件套**：正判据 `c_deny_copy_is_accurate`（断言该段**不含**「按钮都会被拒」这类断言、且出现「链接」字样）；负控：把旧句塞回去 ⇒ 红；连带：`c_deny_has_back_link`（既有）；可观测：文案断言走 `PC.body()`。

---

### B2 · 顶栏后缀「括号套括号」

**实测**（`_probe_text3.py`，运行状态页与日报页均命中）：

```
（1 件 / 1（最近 24 小时））
```

**根因**：`_bar`（`inbox_server.py:559-561`）把 `M.count_text()` 又包了一层 `（…）`；而 `count_text`（`inbox_model.py:834-843`）自带窗口后缀且**本身就用全角括号**：`"%d %s / %d（最近 %d 小时）"`。

**修法**：`count_text` 增一个"不带窗口后缀"的形态，或 `_bar` 改用间隔号（`· 1 件 / 1 · 最近 24 小时`）。两层括号是排版事故，不是信息问题。

**四件套**：正判据 `c_no_nested_parens`（扫渲染正文，`（[^（）]*（` 零命中）；负控：人为写回两层括号 ⇒ 红；连带：`count_text` 的既有判据（0470 S）不许红；可观测：扫 `PC.body()`。

---

### B3 · 空态正文与标题**说错对象**

**实测**（`_probe_text2.py`，在「看一眼」档、无记录时）：

> 当前「看一眼」中没有记录。**「要处理」只放只有你本人动手才能解决的事。Antinel 自己已拦下或自愈的事项在「看一眼」。**更早的事项只会在其链文件仍被读取时显示在「归档」；本页不是永久全历史清单。

**根因**：`inbox_server.py:1343-1358` —— `empty_title` 已按 `filt` 分支（本轮已修），但它后面那段 `<p class="note">` 是**无条件同一段**。于是站在「看一眼」空态上，正文第二句还在解释「要处理」，第三句在解释"你正在看的这一档"。

**修法**：`note` 也按 `filt` 分支（至少 action / info / archive 三份）；或在非 action 档去掉首句。

**四件套**：正判据 `c_empty_note_matches_tab`（断言 info 档空态正文**不含**「「要处理」只放」）；负控：改回同一段 ⇒ 红；连带：action 档仍**必须**保留该句；可观测：`PC.body_without_terms()`。

---

### B4 · 冒泡/哨标的「按标题认窗」与Antinel 监理**不是同一口径**，docstring 却声称"同源同构"

**实测**（`_probe_win.py`，内存替换枚举，放 5 个标题）：

| 标题 | 是谁 | `find_console_windows` | `find_logo_windows` | `find_bubble_windows` |
|---|---|---|---|---|
| `收件箱 · Antinel 监理#abc123` | 本次Antinel 监理 | ✅ `[1]` | — | — |
| `我的 · 哨标 收藏夹` | **用户窗口** | — | ❌ 被命中 | — |
| `Antinel · 哨标#abc123` | 本次哨标 | — | ✅ | — |
| `整理一下 · 冒泡 记录` | **用户窗口** | — | — | ❌ 被命中 |
| `需要你处理 · 冒泡#abc123` | 本次冒泡 | — | — | ✅ |

**根因**：三条 finder 的**宽泛分支**（不给 `run_id` 时）口径不同：
- `find_console_windows` → `is_console_title(title, None)` → `_mark_at_tail()`：标记必须在**末尾**，前面必须是**白名单页面名/状态词**，且不含窗口标题分隔符与可执行扩展名（`inbox_window.py:576-624`、`627-680`）。这是 0.36.5 实测修出来的**真判据**。
- `find_logo_windows`（`inbox_window.py:851-867`）与 `find_bubble_windows`（`:870-884`）→ `elif mark in title`：**任意位置子串**。

而两个新函数的 docstring 都写着「与 `find_console_windows` **同源同构**（两级匹配）」—— 这是**假声明**（T-11：声明的能力与实现脱节）。

**后果（重）**：这两条宽泛路径都通向 `WM_CLOSE`：
- `find_bubble_windows()` 被 `close_bubble_windows()` 用（`inbox_window.py:887-908`），而后者被 `inbox_bubble.pop()` 的「一次只留一枚：收旧冒泡」调用（`inbox_bubble.py:262`）。
- `find_logo_windows()` 被 `close_logo_windows()` 用（`:911-931`），是 `retire()` 的兜底。

⇒ 一个标题里恰好含 ` · 冒泡` 或 ` · 哨标` 的**用户窗口**（记事本、编辑器、自己的浏览器标签……）会被**关掉**。这正是 0.36.5 在Antinel 监理上踩过、并在注释里写明「**关用户窗口是不可接受的**（本仓明文纪律）」的那个祸，**在冒泡/哨标两个新函数上原样复发**。

**修法**：把 `_mark_at_tail` 泛化为 `_mark_at_tail(title, mark)`，三条路径**共用同一份实现**（「一个事实一个实现」），删掉两处 `mark in title`；同时把 docstring 的"同源同构"改成陈述事实（或让它变真）。

**四件套**
- 正判据 `c_window_mark_caliber_single`：假桌面放上面 5 个标题，断言三条 finder 各自**只**命中自己那一枚，且两个用户窗口**都不被命中**；再加一条结构判据：三个函数体的宽泛分支必须是**同一个函数调用**（禁止第二份子串匹配）。
- 负控：把宽泛分支改回 `mark in title` ⇒ 必须红。
- 连带对照：`is_console_title` 的既有判据（0360 P15）不许回退。
- 可观测：断言返回的 hwnd 列表。

---

### B5 · 403 页第一段把责任一口咬定为「程序缺陷」

**原文**（`inbox_server.py:1742-1743`）：
> 如果你是从Antinel 监理页面点过来的，说明这个按钮的请求没带上访问口令 —— **那是程序缺陷，请把它报出来。**

**违和**：口令不匹配还可能只是**服务重启后旧页面还在**（token 变了），或用户手工改了 URL。把用户往"报缺陷"上引，是白跑一趟。建议改为「口令不匹配（可能是服务重启后旧页面还在，或这个请求没带上口令）」。与 B1 同页，可**合并成一次文案重写 + 一条判据**。

---

### B6 · 禁用按钮的解释写在 `title` 上，浏览器里多半看不到

**位置**：`inbox_server.py:1645-1647`
```html
<button class="btn" disabled title="将来上线账号后才可用，现在没有这个能力">认领到账号（未启用）</button>
```
**违和**：`disabled` 控件在 Chromium 系**不派发指针事件** ⇒ `title` 提示通常**不出现** ⇒ 那句解释可能永远到不了用户。而这一条恰好踩在本仓明文的忌上（「看见疑问却无法得到答案」）。

**状态**：**需真机确认**（本机 Chrome/Edge 里 hover 一次即可判定）。
**修法**：解释放到按钮**旁边**的可见小字（或 `aria-describedby` + 可见文本）。

**四件套**：正判据 `c_disabled_button_reason_visible`（断言解释是**可见节点**，不是仅 `title` 属性）；负控：只留 `title` ⇒ 红。

---

## C. 修复计划（分批、含落点）

| 批次 | 条目 | 为什么排这儿 | 预计回归面 |
|---|---|---|---|
| **批一 · 真失效** | A1 重开 JSON 死页<br>A2 哨标点击无消费者<br>B4 误关用户窗口 | 用户真会撞上，后果重（死页 / 无反应 / 关错窗） | `ci/inbox_guards.py`(P3/P12)、`0514`(FLO/B)、主闸门 |
| **批二 · 该给的话没给到** | A3 未启用无下一步<br>A4 按钮是整句 | 声明了却到不了用户（T-11 同族） | `0360`(P*)、`0514`(UI*)、S48 文案层 |
| **批三 · 文案与排版** | B1+B5 403 页口径<br>B2 括号套括号<br>B3 空态说错对象<br>B6 禁用理由不可见 | 不改行为，改可信度 | S48 selfaudit、`0360`(Q*)、`0514`(UICOPY1) |

**执行纪律（沿用本仓铁律）**
1. 每条**先立判据再改码**；判据的**负控必须实测见过红**才允许收工。
2. 每条都要有**连带对照**（防止"修好这条、踩坏那条"）——上表已逐条写明。
3. 测不出 ⇒ 报 `SKIP`，**绝不报 PASS**；夹具不忠实比没有更坏（A1 就是夹具条目状态单一造成的第四次漏网）。
4. 每条落进 `ci/defect_types.py` 的实例表（建议沿用 **T-11「声明的能力与实现脱节」**：A2/A3/A4/B4 是它的正例；A1 归入"按钮与路由对不上"，B1/B3 归入"文案与事实不符"）。
5. 全部完成后跑**全量交付闸门**（`ci/delivery_gate.py`）与主闸门（`ci/regression_gate.py --selfcheck`）。

---

## D. 附：本轮**已改**、不计入计划的项（未提交，HEAD 仍 `c84627c`）

> 说明：以下 9 项在上一轮已动手改在**工作区**里，尚未提交；列出来是为了让"清单"与"现状"对得上，**不要再当新任务派**。

1. 冒泡 ack 的 `kind` 错位（`inbox_bubble._url` 补 `bk`、`render` 补 `data-kind`、JS 带 `kind`）。
2. 冒泡确认失败误报成功（改为检查 `r.ok`/`j.ok`，失败保留窗口提示重试）。
3. 钻取链接超出范围（`_group_html` 改 `f=ids:…`，`inbox_model` 支持 `ids:`）。
4. 空态标题说错对象（`empty_title` 已按 5 种档位分支；**正文残留见 B3**）。
5. 已读假装成功（`_READ_JS` 检查 `r.ok`/`j.ok` 才设 `data-readed`，失败清 pending 可重试）。
6. 浮层翻转选择器（`.term.flipx>.tdef`，含窄屏规则）。
7. `winfit` 溢出量非有限数（捕 `(ValueError, OverflowError)`）。
8. 自定义 `root` 失联（`inbox_logo` 全链补 `root=`）。
9. 动作写盘吞错（`tools/logo.ps1` 的 `Write-Action` 返回 bool、失败改 tip）。

---

## E. 未覆盖 / 需真机确认

- **真浏览器逐点一遍**：A2（哨标点击，且现场**故意不起** daemon/tray）、B6（禁用按钮 hover）必须真机验；A1 已用 HTTP 原样重放验完，无需真机。
- `_rem_pick_buttons` 的 `info` 分支（归因模块不可用时给「打开运行状态页」链接，`inbox_server.py:1187-1192`）本轮已加，**未真机点过**。
- 与本清单**并行的另一条线**：全量交付闸门仍有 7 处红（0360 P04、0362 Q06/Q08c、0481 L1(SPDX)、0490 N-U10/N-U13、instrument-selfaudit S48、JDG-04、selfcheck M1），另行处置，不在本计划内。
- 本清单**未**覆盖：CSS 视觉细节、动效参数与规格表的逐项比对（那有 U-17 专门锁着）、打包缺件（已改待验）。

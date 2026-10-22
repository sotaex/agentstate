<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- 由 `antinel routes --markdown` 生成；与 help 同源（ROUTES） -->
当用户表达下列意图时，运行对应命令（命令幂等；配置变更自动进审计链）。

★ 语义匹配，不是词表匹配：下面的用户话语只是示例，不是触发条件。
用户用任何说法表达同类意图。下面这些只是例子：「胡搞/乱来/越界/偷传/不乖/瞎动」，将来出现新说法也一样。
都应执行对应命令。语义对上就执行，不要等词对上。

- 「给我一页能交差的纸 / 我要给领导或客户交代这件事」→ antinel brief（决策层一页纸：有没有外发、比上期、该做什么）
- 「查一查我的电脑 / 我有没有中招（要一个能点的页面）」→ antinel ui（在你自己电脑的浏览器里点一下就查；结果不会离开你的电脑）
- 「这个会话花了多少」→ antinel report --session latest
- 「今天/昨天干了什么，拦了什么」→ antinel digest [--days N] [--scope all]
- 「今天这个AI工具有没有胡搞/乱来/出格」→ antinel digest --days 1 ＋ antinel host-audit
- 「这台电脑上的 AI 工具在往哪发数据 / 谁在后台发」→ antinel egress
- 「这台电脑装了哪些 AI 工具 / 哪个在偷数据」→ antinel host-scan（你电脑上的全部工具 ＋ 分级 ＋ 证据 ＋ 裁决状态）
- 「帮我放个源码金丝雀 / 埋个外传检测标记」→ antinel canary plant（读取会提醒；标记出现在输出即外传证据，report 可见）
- 「今日日报 / 日报 / 昨天干了什么」→ antinel digest --days 1（工作区=项目根）
- 「确认放行某个落点 / 不放行就挡下它」→ antinel host-shield decide <路径> allow_always｜deny（放行须本人在终端）
- 「把 D:\xxx 加进项目路径/白名单」→ antinel roots add D:\\xxx ｜ antinel paths add <前缀>
- 「xxx 域名放行（装包老报警）」→ antinel domains add xxx
- 「预算快超了提醒我 / 给会话设个预算」→ antinel settings set budget_tokens_per_session <N>
- 「记一下积分余额」→ antinel credits snapshot <余额> [--reward N@到期日] [--cycle 到期日]
- 「积分还够不够 / 什么时候烧完」→ antinel credits forecast
- 「订阅和API直付哪个划算（对账）」→ antinel credits reconcile
- 「看一下我的粮 / 监理还能站多久」→ antinel 粮（余额 / 明细 / 规则）
- 「阻止Agent外传 / 开安全区」→ antinel settings set net_mode block ＋ antinel zone add <目录>
- 「证据链有没有被动过」→ antinel verify
- 「跨工具汇总（多个AI工具一起看）」→ antinel digest --scope all
- 「看 Antinel 监理 / 有什么要处理的」→ antinel inbox list
- 「今天日报 / 值守情况」→ antinel inbox report
- 「antinel / 帮助 / 你能做什么」→ antinel（help 清单）
- 多宿主共存的机器上，Agent 应自报所在宿主：antinel --host zcode …（workbuddy|zcode|qoder|claude-code）。不报的话，记账方式按这台电脑探测到的显示。

<!-- 由 `antinel routes --markdown` 生成；与 help 同源（ROUTES） -->
当用户表达下列意图时，运行对应命令（命令幂等；配置变更自动进审计链）。

**★ 语义匹配，不是词表匹配**：下面的用户话语只是**示例**，不是触发条件。
用户用任何说法表达同类意图——「胡搞/乱来/越界/偷传/不乖/瞎动」或未来任何新说法——
都应执行对应命令：**语义对上就执行，不要等词对上**。

- 「这个会话花了多少 / 烧了多少积分」→ `antinel report --session latest ＋ antinel credits forecast`
- 「今天/昨天干了什么，拦了什么」→ `antinel digest [--days N] [--scope all]`
- 「今天这个AI工具有没有胡搞/乱来/出格」→ `antinel digest --days 1 ＋ antinel host-audit`
- 「今日日报 / 日报 / 昨天干了什么」→ `antinel digest --days 1（工作区=项目根）`
- 「把 D:\xxx 加进项目路径/白名单」→ `antinel roots add D:\\xxx ｜ antinel paths add <前缀>`
- 「xxx 域名放行（装包老报警）」→ `antinel domains add xxx`
- 「预算快超了提醒我 / 给会话设个预算」→ `antinel settings set budget_tokens_per_session <N>`
- 「记一下积分余额」→ `antinel credits snapshot <余额> [--reward N@到期日] [--cycle 到期日]`
- 「积分还够不够 / 什么时候烧完」→ `antinel credits forecast`
- 「订阅和API直付哪个划算（对账）」→ `antinel credits reconcile`
- 「阻止Agent外传 / 开安全区」→ `antinel settings set net_mode block ＋ antinel zone add <目录>`
- 「证据链有没有被动过」→ `antinel verify`
- 「跨工具汇总（多个AI工具一起看）」→ `antinel digest --scope all`
- 「antinel / 帮助 / 你能做什么」→ `antinel`（help 清单）
- 多宿主共存的机器上，Agent 应自报所在宿主：`antinel --host zcode …`（workbuddy|zcode|qoder|claude-code），否则记账口径按本机探测显示。
